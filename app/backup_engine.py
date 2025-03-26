import os
import time
import zipfile
import shutil
import hashlib
import json
import logging
from datetime import datetime
from flask import current_app
from app import db
from app.models import BackupLog, BackupConfig

# Setup logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class BackupError(Exception):
    """Base exception for backup errors"""
    pass

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file for verification"""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()

def get_file_list(directory):
    """Get a list of all files in a directory recursively"""
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)
            file_stat = os.stat(full_path)
            file_list.append({
                'path': rel_path,
                'size': file_stat.st_size,
                'modified': file_stat.st_mtime,
                'hash': None  # Will be calculated for modified files in incremental mode
            })
    return file_list

def compare_file_lists(new_list, old_list_data):
    """Compare file lists to find modified files for incremental backup"""
    old_list = {}
    if old_list_data:
        old_list = {f['path']: f for f in old_list_data}
    
    modified_files = []
    for file in new_list:
        # If file doesn't exist in old list or has different size/modification time
        if (file['path'] not in old_list or
                file['size'] != old_list[file['path']]['size'] or
                file['modified'] > old_list[file['path']]['modified']):
            modified_files.append(file['path'])
    
    return modified_files

def create_backup_directory(config_id):
    """Create a directory for a specific backup configuration"""
    base_dir = current_app.config['BACKUP_STORAGE_PATH']
    logger.info(f"Base backup directory: {base_dir}")
    
    backup_dir = os.path.join(base_dir, f'config_{config_id}')
    logger.info(f"Creating backup directory: {backup_dir}")
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        logger.info(f"Created backup directory: {backup_dir}")
    return backup_dir

def create_backup(config_id, manual=False):
    """Create a backup based on the given configuration"""
    # Get the backup configuration
    config = BackupConfig.query.get(config_id)
    if not config:
        raise BackupError(f"Backup configuration with ID {config_id} not found")
    
    logger.info(f"Starting backup for config {config_id}: {config.name}")
    logger.info(f"Source path: {config.source_path}")
    logger.info(f"Destination path: {config.destination_path}")
    
    # Create a backup log entry
    log = BackupLog(
        status='running',
        config_id=config.id,
        user_id=config.user_id,
        start_time=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
    logger.info(f"Created backup log entry: {log.id}")
    
    # Ensure paths exist
    if not os.path.exists(config.source_path):
        log.status = 'error'
        log.message = f"Source path does not exist: {config.source_path}"
        log.end_time = datetime.utcnow()
        db.session.commit()
        logger.error(f"Source path does not exist: {config.source_path}")
        return log
    
    try:
        # Create backup directory if it doesn't exist
        if not os.path.exists(config.destination_path):
            logger.info(f"Creating destination path: {config.destination_path}")
            os.makedirs(config.destination_path)
        
        # Start the backup process
        logger.info("Starting backup process...")
        perform_backup(config, log, manual)
        return log
    except Exception as e:
        log.status = 'error'
        log.message = f"Failed to start backup: {str(e)}"
        log.end_time = datetime.utcnow()
        db.session.commit()
        logger.error(f"Backup error: {str(e)}")
        raise BackupError(str(e))

def perform_backup(config, log, manual=False):
    """Perform the actual backup process"""
    try:
        add_log_entry(log, 'info', f"Starting backup for {config.name}")
        
        # Generate timestamp for the backup filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}"
        if manual:
            backup_filename += "_manual"
        
        # Check if this is an incremental backup
        modified_files = None
        if config.incremental:
            # Get the most recent successful backup for this config
            last_backup = BackupLog.query.filter_by(
                config_id=config.id,
                status='success'
            ).order_by(BackupLog.end_time.desc()).first()
            
            if last_backup and last_backup.detailed_log:
                try:
                    detailed_log = json.loads(last_backup.detailed_log)
                    for entry in detailed_log:
                        if entry.get('type') == 'file_list':
                            # Compare file lists to find modified files
                            current_files = get_file_list(config.source_path)
                            modified_files = compare_file_lists(current_files, entry.get('data', []))
                            add_log_entry(log, 'info', f"Found {len(modified_files)} modified files")
                            break
                except Exception as e:
                    add_log_entry(log, 'warning', f"Could not process last backup data: {str(e)}")
        
        # Create temporary directory for files to be backed up
        temp_dir = os.path.join(config.destination_path, 'temp')
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # Copy files to temporary directory
        total_size = 0
        files_count = 0
        
        # Copy files
        if modified_files is not None:
            # Copy only modified files for incremental backup
            add_log_entry(log, 'info', "Performing incremental backup")
            logger.info(f"Performing incremental backup with {len(modified_files)} files")
            
            for file_path in modified_files:
                source_file = os.path.join(config.source_path, file_path)
                if os.path.exists(source_file) and os.path.isfile(source_file):
                    dest_file = os.path.join(temp_dir, file_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(source_file, dest_file)
                    file_stat = os.stat(source_file)
                    total_size += file_stat.st_size
                    files_count += 1
                    logger.debug(f"Copied file: {file_path}")
        else:
            # Full backup - copy all files
            add_log_entry(log, 'info', "Performing full backup")
            logger.info("Performing full backup")
            
            for root, _, files in os.walk(config.source_path):
                for file in files:
                    source_file = os.path.join(root, file)
                    rel_path = os.path.relpath(source_file, config.source_path)
                    dest_file = os.path.join(temp_dir, rel_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(source_file, dest_file)
                    file_stat = os.stat(source_file)
                    total_size += file_stat.st_size
                    files_count += 1
                    logger.debug(f"Copied file: {rel_path}")
        
        add_log_entry(log, 'info', f"Copied {files_count} files ({total_size} bytes)")
        logger.info(f"Copied {files_count} files ({total_size} bytes)")
        
        # Create zip archive
        zip_path = os.path.join(config.destination_path, f"{backup_filename}.zip")
        add_log_entry(log, 'info', "Creating ZIP archive")
        logger.info(f"Creating ZIP archive: {zip_path}")
        
        compression = zipfile.ZIP_DEFLATED
        compression_level = config.compression_level
        
        # Create a record of all files for incremental comparison
        file_list = get_file_list(config.source_path)
        add_log_entry(log, 'file_list', file_list)
        
        # Create the zip file
        with zipfile.ZipFile(zip_path, 'w', compression=compression, compresslevel=compression_level) as zipf:
            # Add all files from temp directory to zip
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
                    logger.debug(f"Added to ZIP: {arcname}")
        
        # Get size of the compressed file
        compressed_size = os.path.getsize(zip_path)
        compression_ratio = (total_size / compressed_size) if compressed_size > 0 else 0
        logger.info(f"ZIP created: {zip_path}, size: {compressed_size} bytes, ratio: {compression_ratio}")
        
        # Verify the backup
        add_log_entry(log, 'info', "Verifying backup")
        logger.info("Verifying backup...")
        
        if os.path.exists(zip_path):
            # Check if zip file is valid
            try:
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    # Test zip file integrity
                    test_result = zipf.testzip()
                    if test_result is not None:
                        raise BackupError(f"Zip file is corrupted. First bad file: {test_result}")
                
                log.status = 'success'
                log.message = "Backup completed successfully"
                log.size = compressed_size
                log.files_count = files_count
                log.compression_ratio = compression_ratio
                log.backup_file = zip_path
                logger.info("Backup verified successfully")
            except Exception as e:
                log.status = 'error'
                log.message = f"Backup verification failed: {str(e)}"
                add_log_entry(log, 'error', str(e))
                logger.error(f"Backup verification failed: {str(e)}")
        else:
            log.status = 'error'
            log.message = "Backup file was not created"
            logger.error("Backup file was not created")
        
        # Clean up temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")
        
        # Complete the log entry
        log.end_time = datetime.utcnow()
        db.session.commit()
        logger.info(f"Backup completed with status: {log.status}")
        
    except Exception as e:
        logger.error(f"Backup error: {str(e)}")
        
        # Update log with error
        log.status = 'error'
        log.message = f"Backup failed: {str(e)}"
        add_log_entry(log, 'error', str(e))
        log.end_time = datetime.utcnow()
        db.session.commit()

def add_log_entry(log, entry_type, message):
    """Add an entry to the detailed log"""
    log_entries = []
    if log.detailed_log:
        try:
            log_entries = json.loads(log.detailed_log)
        except:
            log_entries = []
    
    log_entries.append({
        'timestamp': datetime.utcnow().isoformat(),
        'type': entry_type,
        'message': message if not isinstance(message, (dict, list)) else 'data'
    })
    
    log.detailed_log = json.dumps(log_entries)
    db.session.commit()