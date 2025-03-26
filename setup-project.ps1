# Script di generazione automatica del progetto Flask Backup System
# Salvalo come setup-project.ps1 nella cartella flask_backup_new ed eseguilo

# Verifica percorso corrente
$projectPath = Get-Location
Write-Host "Generazione del progetto in: $projectPath" -ForegroundColor Green

# Crea struttura cartelle
$folders = @(
    "app/templates/auth",
    "app/templates/includes",
    "app/static/css",
    "app/static/js",
    "app/static/img",
    "app/main",
    "backups"
)

foreach ($folder in $folders) {
    $path = Join-Path -Path $projectPath -ChildPath $folder
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
        Write-Host "Creata cartella: $folder" -ForegroundColor Cyan
    }
}

# Funzione per creare file
function Create-ProjectFile {
    param (
        [string]$filePath,
        [string]$content
    )
    
    $fullPath = Join-Path -Path $projectPath -ChildPath $filePath
    $content | Out-File -FilePath $fullPath -Encoding utf8 -Force
    Write-Host "Creato file: $filePath" -ForegroundColor Yellow
}

# Definizione file config.py
$configPy = @'
import os
from datetime import timedelta

class Config:
    # General Config
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_key_change_in_production")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///backup_app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Backup Config
    BACKUP_STORAGE_PATH = os.environ.get("BACKUP_STORAGE_PATH", 
                                         os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups"))
    
    # Session Config
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    DEBUG = False
    
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}
'@

# Definizione file app/__init__.py
$initPy = @'
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import os

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    
    # Configurazione
    app.config["SECRET_KEY"] = "dev-key-change-in-production"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///backup_app.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["BACKUP_STORAGE_PATH"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backups")
    
    # Inizializza estensioni
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Accedi per visualizzare questa pagina."
    login_manager.login_message_category = "info"
    
    # Assicurati che la directory di backup esista
    if not os.path.exists(app.config["BACKUP_STORAGE_PATH"]):
        os.makedirs(app.config["BACKUP_STORAGE_PATH"])
    
    # Registra i blueprint
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    return app
'@

# Definizione file app/models.py
$modelsPy = @'
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import json
from app import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    configs = db.relationship("BackupConfig", backref="user", lazy="dynamic")
    logs = db.relationship("BackupLog", backref="user", lazy="dynamic")
    
    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")
        
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class BackupConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    source_path = db.Column(db.String(256))
    destination_path = db.Column(db.String(256))
    schedule_type = db.Column(db.String(32))  # "daily", "weekly", "monthly"
    schedule_time = db.Column(db.Time)
    schedule_days = db.Column(db.String(64))  # JSON string of days
    incremental = db.Column(db.Boolean, default=True)
    compression_level = db.Column(db.Integer, default=5)  # 0-9
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    logs = db.relationship("BackupLog", backref="config", lazy="dynamic")
    
    def get_schedule_days(self):
        if self.schedule_days:
            return json.loads(self.schedule_days)
        return []
    
    def set_schedule_days(self, days):
        self.schedule_days = json.dumps(days)

class BackupLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(32))  # "success", "error", "warning", "running"
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    size = db.Column(db.BigInteger)
    files_count = db.Column(db.Integer)
    compression_ratio = db.Column(db.Float)
    message = db.Column(db.Text)
    detailed_log = db.Column(db.Text)  # JSON string with detailed log entries
    backup_file = db.Column(db.String(256))  # Path to the backup file
    config_id = db.Column(db.Integer, db.ForeignKey("backup_config.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def get_detailed_log(self):
        if self.detailed_log:
            return json.loads(self.detailed_log)
        return []
    
    def add_log_entry(self, entry_type, message):
        log_entries = self.get_detailed_log()
        log_entries.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": entry_type,
            "message": message
        })
        self.detailed_log = json.dumps(log_entries)
'@

# Definizione file app/auth.py
$authPy = @'
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app import db
from app.models import User
from werkzeug.urls import url_parse

auth = Blueprint("auth", __name__)

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Ricordami")
    submit = SubmitField("Accedi")

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(1, 64)])
    email = StringField("Email", validators=[DataRequired(), Length(1, 120), Email()])
    password = PasswordField("Password", validators=[
        DataRequired(), Length(min=8),
        EqualTo("password2", message="Le password devono corrispondere")
    ])
    password2 = PasswordField("Conferma Password", validators=[DataRequired()])
    submit = SubmitField("Registrati")
    
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username già in uso")
    
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email già registrata")

@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash("Username o password non validi", "danger")
            return redirect(url_for("auth.login"))
        
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("main.dashboard")
        
        flash("Accesso effettuato con successo", "success")
        return redirect(next_page)
    
    return render_template("auth/login.html", title="Accedi", form=form)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Hai effettuato il logout", "info")
    return redirect(url_for("main.index"))

@auth.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data
        )
        db.session.add(user)
        db.session.commit()
        
        flash("Registrazione completata con successo. Ora puoi accedere.", "success")
        return redirect(url_for("auth.login"))
    
    return render_template("auth/register.html", title="Registrati", form=form)
'@

# Definizione file app/main/__init__.py
$mainInitPy = @'
from flask import Blueprint

main = Blueprint("main", __name__)

from . import routes
'@

# Definizione file app/main/routes.py
$mainRoutesPy = @'
from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from app import db
from app.models import BackupConfig, BackupLog
from app.main import main
from app.main.forms import BackupConfigForm
from app.backup_engine import create_backup, BackupError
import os
from datetime import datetime

@main.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")

@main.route("/dashboard")
@login_required
def dashboard():
    # Ottieni le configurazioni di backup dell'utente
    configs = BackupConfig.query.filter_by(user_id=current_user.id).all()
    
    # Ottieni i log di backup recenti
    recent_logs = BackupLog.query.filter_by(user_id=current_user.id).order_by(BackupLog.start_time.desc()).limit(5).all()
    
    # Calcola alcune statistiche
    stats = {
        "total_configs": len(configs),
        "active_configs": sum(1 for c in configs if c.active),
        "total_backups": BackupLog.query.filter_by(user_id=current_user.id).count(),
        "successful_backups": BackupLog.query.filter_by(user_id=current_user.id, status="success").count(),
        "failed_backups": BackupLog.query.filter_by(user_id=current_user.id, status="error").count(),
    }
    
    return render_template(
        "dashboard.html", 
        configs=configs, 
        recent_logs=recent_logs, 
        stats=stats
    )

@main.route("/configs")
@login_required
def configs():
    configs = BackupConfig.query.filter_by(user_id=current_user.id).all()
    return render_template("configs.html", configs=configs)

@main.route("/configs/add", methods=["GET", "POST"])
@login_required
def add_config():
    form = BackupConfigForm()
    
    if form.validate_on_submit():
        # Crea nuova configurazione
        config = BackupConfig(
            name=form.name.data,
            source_path=form.source_path.data,
            destination_path=form.destination_path.data,
            schedule_type=form.schedule_type.data,
            schedule_time=form.schedule_time.data,
            incremental=form.incremental.data,
            compression_level=form.compression_level.data,
            user_id=current_user.id,
            active=True
        )
        
        # Gestisci i giorni della settimana per i backup settimanali
        if form.schedule_type.data == "weekly" and form.schedule_days.data:
            days = [day.strip().lower() for day in form.schedule_days.data.split(",")]
            valid_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
            days = [day for day in days if day in valid_days]
            config.set_schedule_days(days)
        
        # Salva nel database
        db.session.add(config)
        db.session.commit()
        
        flash("Configurazione di backup aggiunta con successo", "success")
        return redirect(url_for("main.configs"))
    
    return render_template("config_form.html", form=form, title="Aggiungi Configurazione")

@main.route("/configs/<int:config_id>/start", methods=["POST"])
@login_required
def start_backup(config_id):
    config = BackupConfig.query.get_or_404(config_id)
    
    # Controlla se l'utente è il proprietario
    if config.user_id != current_user.id:
        flash("Non hai il permesso di avviare questo backup", "danger")
        return redirect(url_for("main.configs"))
    
    try:
        # Avvia il backup
        log = create_backup(current_app, config.id, manual=True)
        flash("Backup avviato con successo", "success")
        return redirect(url_for("main.logs"))
    except BackupError as e:
        flash(f"Errore nell'avvio del backup: {str(e)}", "danger")
        return redirect(url_for("main.configs"))

@main.route("/logs")
@login_required
def logs():
    page = request.args.get("page", 1, type=int)
    logs = BackupLog.query.filter_by(user_id=current_user.id).order_by(BackupLog.start_time.desc()).paginate(
        page=page, per_page=10
    )
    return render_template("logs.html", logs=logs)
'@

# Definizione file app/main/forms.py
$mainFormsPy = @'
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TimeField, BooleanField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Length, Optional, NumberRange

class BackupConfigForm(FlaskForm):
    name = StringField("Nome Backup", validators=[DataRequired(), Length(1, 64)])
    source_path = StringField("Percorso Sorgente", validators=[DataRequired(), Length(1, 256)])
    destination_path = StringField("Percorso Destinazione", validators=[DataRequired(), Length(1, 256)])
    schedule_type = SelectField("Tipo di Pianificazione", choices=[
        ("manual", "Solo Manuale"),
        ("daily", "Giornaliero"),
        ("weekly", "Settimanale"),
        ("monthly", "Mensile")
    ])
    schedule_time = TimeField("Orario Pianificazione", validators=[Optional()])
    schedule_days = StringField("Giorni Pianificazione (per settimanale)", validators=[Optional()])
    incremental = BooleanField("Backup Incrementale", default=True)
    compression_level = IntegerField("Livello di Compressione (0-9)", validators=[NumberRange(min=0, max=9)], default=5)
    submit = SubmitField("Salva Configurazione")
'@

# Definizione file app/backup_engine.py
$backupEnginePy = @'
import os
import time
import zipfile
import shutil
import json
import logging
from datetime import datetime
from app import db
from app.models import BackupLog, BackupConfig

logger = logging.getLogger(__name__)

class BackupError(Exception):
    """Base exception for backup errors"""
    pass

def get_file_list(directory):
    """Get a list of all files in a directory recursively"""
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)
            file_stat = os.stat(full_path)
            file_list.append({
                "path": rel_path,
                "size": file_stat.st_size,
                "modified": file_stat.st_mtime
            })
    return file_list

def compare_file_lists(new_list, old_list_data):
    """Compare file lists to find modified files for incremental backup"""
    old_list = {}
    if old_list_data:
        old_list = {f["path"]: f for f in old_list_data}
    
    modified_files = []
    for file in new_list:
        # If file doesn't exist in old list or has different size/modification time
        if (file["path"] not in old_list or
                file["size"] != old_list[file["path"]]["size"] or
                file["modified"] > old_list[file["path"]]["modified"]):
            modified_files.append(file["path"])
    
    return modified_files

def create_backup_directory(app, config_id):
    """Create a directory for a specific backup configuration"""
    base_dir = app.config["BACKUP_STORAGE_PATH"]
    backup_dir = os.path.join(base_dir, f"config_{config_id}")
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    return backup_dir

def create_backup(app, config_id, manual=False):
    """Create a backup based on the given configuration"""
    # Get the backup configuration
    config = BackupConfig.query.get(config_id)
    if not config:
        raise BackupError(f"Backup configuration with ID {config_id} not found")
    
    # Create a backup log entry
    log = BackupLog(
        status="running",
        config_id=config.id,
        user_id=config.user_id,
        start_time=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
    
    # Ensure paths exist
    if not os.path.exists(config.source_path):
        log.status = "error"
        log.message = f"Source path does not exist: {config.source_path}"
        log.end_time = datetime.utcnow()
        db.session.commit()
        return log
    
    # Create backup directory if it doesn't exist
    backup_dir = create_backup_directory(app, config.id)
    
    try:
        # Perform the backup
        log.add_log_entry("info", f"Starting backup for {config.name}")
        
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
                status="success"
            ).order_by(BackupLog.end_time.desc()).first()
            
            if last_backup and last_backup.detailed_log:
                try:
                    detailed_log = json.loads(last_backup.detailed_log)
                    for entry in detailed_log:
                        if entry.get("type") == "file_list":
                            # Compare file lists to find modified files
                            current_files = get_file_list(config.source_path)
                            modified_files = compare_file_lists(current_files, entry.get("data", []))
                            log.add_log_entry("info", f"Found {len(modified_files)} modified files")
                            break
                except Exception as e:
                    log.add_log_entry("warning", f"Could not process last backup data: {str(e)}")
        
        # Create temporary directory for files to be backed up
        temp_dir = os.path.join(backup_dir, "temp")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        # Copy files to temporary directory
        total_size = 0
        files_count = 0
        
        if modified_files is not None:
            # Copy only modified files for incremental backup
            log.add_log_entry("info", "Performing incremental backup")
            for file_path in modified_files:
                source_file = os.path.join(config.source_path, file_path)
                if os.path.exists(source_file) and os.path.isfile(source_file):
                    dest_file = os.path.join(temp_dir, file_path)
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(source_file, dest_file)
                    file_stat = os.stat(source_file)
                    total_size += file_stat.st_size
                    files_count += 1
        else:
            # Full backup - copy all files
            log.add_log_entry("info", "Performing full backup")
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
        
        log.add_log_entry("info", f"Copied {files_count} files ({total_size} bytes)")
        
        # Create zip archive
        zip_path = os.path.join(backup_dir, f"{backup_filename}.zip")
        log.add_log_entry("info", "Creating ZIP archive")
        
        compression = zipfile.ZIP_DEFLATED
        compression_level = config.compression_level
        
        # Create a record of all files for incremental comparison
        file_list = get_file_list(config.source_path)
        log.add_log_entry("file_list", file_list)
        
        # Create the zip file
        with zipfile.ZipFile(zip_path, "w", compression=compression, compresslevel=compression_level) as zipf:
            # Add all files from temp directory to zip
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
        
        # Get size of the compressed file
        compressed_size = os.path.getsize(zip_path)
        compression_ratio = (total_size / compressed_size) if compressed_size > 0 else 0
        
        # Verify the backup
        log.add_log_entry("info", "Verifying backup")
        
        if os.path.exists(zip_path):
            # Check if zip file is valid
            try:
                with zipfile.ZipFile(zip_path, "r") as zipf:
                    # Test zip file integrity
                    test_result = zipf.testzip()
                    if test_result is not None:
                        raise BackupError(f"Zip file is corrupted. First bad file: {test_result}")
                
                log.status = "success"
                log.message = "Backup completed successfully"
                log.size = compressed_size
                log.files_count = files_count
                log.compression_ratio = compression_ratio
                log.backup_file = zip_path
            except Exception as e:
                log.status = "error"
                log.message = f"Backup verification failed: {str(e)}"
                log.add_log_entry("error", str(e))
        else:
            log.status = "error"
            log.message = "Backup file was not created"
        
        # Clean up temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        # Complete the log entry
        log.end_time = datetime.utcnow()
        db.session.commit()
        
        return log
        
    except Exception as e:
        logger.error(f"Backup error: {str(e)}")
        
        # Update log with error
        log.status = "error"
        log.message = f"Backup failed: {str(e)}"
        log.add_log_entry("error", str(e))
        log.end_time = datetime.utcnow()
        db.session.commit()
        
        raise BackupError(str(e))
'@

# Definizione file run.py
$runPy = @'
import os
from app import create_app, db

app = create_app()

@app.cli.command("create-db")
def create_db():
    """Create database tables"""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

@app.cli.command("create-test-user")
def create_test_user():
    """Create a test user for development"""
    from app.models import User
    
    username = "admin"
    email = "admin@example.com"
    password = "password"
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User {username} already exists")
            return
        
        user = User(username=username, email=email, password=password, is_admin=True)
        db.session.add(user)
        db.session.commit()
        print(f"Test user {username} created")

if __name__ == "__main__":
    with app.app_context():
        # Create database tables if they don't exist
        db.create_all()
    app.run(debug=True)
'@

# Definizione file .flaskenv
$flaskEnv = @'
FLASK_APP=run.py
FLASK_ENV=development
'@

# Definizione file templates/base.html
$baseHtml = @'
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Sistema di Backup{% endblock %}</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .content {
            flex: 1;
        }
        .navbar-brand {
            font-weight: 700;
        }
        .card {
            border-radius: 8px;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            margin-bottom: 20px;
        }
        .card-header {
            background-color: rgba(0, 0, 0, 0.03);
            border-bottom: 1px solid rgba(0, 0, 0, 0.125);
        }
        footer {
            margin-top: auto;
            padding: 1rem 0;
            background-color: #f8f9fa;
            border-top: 1px solid #dee2e6;
        }
    </style>
    {% block styles %}{% endblock %}
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('main.index') }}">
                <i class="fas fa-hdd me-2"></i>Sistema di Backup
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'main.dashboard' %}active{% endif %}" href="{{ url_for('main.dashboard') }}">
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'main.configs' %}active{% endif %}" href="{{ url_for('main.configs') }}">
                            <i class="fas fa-cogs me-1"></i>Configurazioni
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'main.logs' %}active{% endif %}" href="{{ url_for('main.logs') }}">
                            <i class="fas fa-clipboard-list me-1"></i>Log Backup
                        </a>
                    </li>
                    {% endif %}
                </ul>
                <ul class="navbar-nav">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i>{{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('auth.logout') }}"><i class="fas fa-sign-out-alt me-1"></i>Logout</a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'auth.login' %}active{% endif %}" href="{{ url_for('auth.login') }}">
                            <i class="fas fa-sign-in-alt me-1"></i>Accedi
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link {% if request.endpoint == 'auth.register' %}active{% endif %}" href="{{ url_for('auth.register') }}">
                            <i class="fas fa-user-plus me-1"></i>Registrati
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <!-- Flash Messages -->
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
            <div class="alert alert-{{ category }} alert-dismissible fade show">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
            {% endfor %}
        {% endif %}
        {% endwith %}
    </div>

    <!-- Main Content -->
    <div class="container my-4 content">
        {% block content %}{% endblock %}
    </div>

    <!-- Footer -->
    <footer>
        <div class="container text-center">
            <p class="text-muted mb-0">Sistema di Backup &copy; 2023</p>
        </div>
    </footer>

    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
'@

# Definizione file templates/index.html
$indexHtml = @'
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-10">
        <div class="card border-0 shadow-lg">
            <div class="card-body p-5">
                <div class="row">
                    <div class="col-md-6">
                        <h1 class="display-4 fw-bold mb-4">Sistema di Backup</h1>
                        <p class="lead">Una soluzione completa per gestire i tuoi backup con facilità.</p>
                        <p class="mb-4">Il nostro sistema di backup offre un'interfaccia web intuitiva per configurare, monitorare e gestire i tuoi backup. Con funzionalità come pianificazione e compressione, puoi garantire che i tuoi dati siano sempre al sicuro.</p>
                        
                        <div class="mb-4">
                            <h5><i class="fas fa-check-circle text-success me-2"></i>Funzionalità Principali</h5>
                            <ul class="list-unstyled ms-4">
                                <li><i class="fas fa-angle-right me-2"></i>Backup automatici pianificati</li>
                                <li><i class="fas fa-angle-right me-2"></i>Monitoraggio in tempo reale</li>
                                <li><i class="fas fa-angle-right me-2"></i>Supporto backup incrementali</li>
                                <li><i class="fas fa-angle-right me-2"></i>Compressione dei file</li>
                            </ul>
                        </div>
                        
                        <div class="d-grid gap-2 d-md-flex">
                            <a href="{{ url_for('auth.register') }}" class="btn btn-primary btn-lg me-md-2">
                                <i class="fas fa-user-plus me-2"></i>Registrati ora
                            </a>
                            <a href="{{ url_for('auth.login') }}" class="btn btn-outline-primary btn-lg">
                                <i class="fas fa-sign-in-alt me-2"></i>Accedi
                            </a>
                        </div>
                    </div>
                    <div class="col-md-6 d-flex align-items-center">
                        <img src="https://via.placeholder.com/500x300?text=Backup+System" alt="Backup System" class="img-fluid">
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'@

# Definizione file templates/auth/login.html
$loginHtml = @'
{% extends "base.html" %}

{% block title %}Accedi - Sistema di Backup{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card shadow">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-sign-in-alt me-2"></i>Accedi</h4>
            </div>
            <div class="card-body">
                <form method="post">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control" + (" is-invalid" if form.username.errors else ""), placeholder="Inserisci username") }}
                        {% if form.username.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.username.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control" + (" is-invalid" if form.password.errors else ""), placeholder="Inserisci password") }}
                        {% if form.password.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.password.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3 form-check">
                        {{ form.remember_me(class="form-check-input") }}
                        {{ form.remember_me.label(class="form-check-label") }}
                    </div>
                    
                    <div class="d-grid gap-2">
                        {{ form.submit(class="btn btn-primary") }}
                    </div>
                </form>
            </div>
            <div class="card-footer text-center">
                <p class="mb-0">Non hai un account? <a href="{{ url_for('auth.register') }}">Registrati qui</a></p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'@

# Definizione file templates/auth/register.html
$registerHtml = @'
{% extends "base.html" %}

{% block title %}Registrati - Sistema di Backup{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card shadow">
            <div class="card-header bg-primary text-white">
                <h4 class="mb-0"><i class="fas fa-user-plus me-2"></i>Registrati</h4>
            </div>
            <div class="card-body">
                <form method="post">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control" + (" is-invalid" if form.username.errors else ""), placeholder="Scegli uno username") }}
                        {% if form.username.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.username.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-control" + (" is-invalid" if form.email.errors else ""), placeholder="Inserisci la tua email") }}
                        {% if form.email.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.email.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control" + (" is-invalid" if form.password.errors else ""), placeholder="Scegli una password") }}
                        {% if form.password.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.password.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password2.label(class="form-label") }}
                        {{ form.password2(class="form-control" + (" is-invalid" if form.password2.errors else ""), placeholder="Conferma la password") }}
                        {% if form.password2.errors %}
                        <div class="invalid-feedback">
                            {% for error in form.password2.errors %}
                            {{ error }}
                            {% endfor %}
                        </div>
                        {% endif %}
                    </div>
                    
                    <div class="d-grid gap-2">
                        {{ form.submit(class="btn btn-primary") }}
                    </div>
                </form>
            </div>
            <div class="card-footer text-center">
                <p class="mb-0">Hai già un account? <a href="{{ url_for('auth.login') }}">Accedi qui</a></p>
            </div>
        </div>
    </div>
</div>
{% endblock %}
'@

# Definizione file templates/dashboard.html
$dashboardHtml = @'
{% extends "base.html" %}

{% block title %}Dashboard - Sistema di Backup{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="mb-4"><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h1>
    </div>
</div>

<!-- Stats Cards -->
<div class="row mb-4">
    <div class="col-md-4">
        <div class="card border-0 bg-primary text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title text-white-50">Configurazioni Totali</h6>
                        <h2 class="mb-0">{{ stats.total_configs }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-cogs fa-2x opacity-50"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card border-0 bg-success text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title text-white-50">Backup Riusciti</h6>
                        <h2 class="mb-0">{{ stats.successful_backups }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-check-circle fa-2x opacity-50"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card border-0 bg-danger text-white h-100">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="card-title text-white-50">Backup Falliti</h6>
                        <h2 class="mb-0">{{ stats.failed_backups }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-times-circle fa-2x opacity-50"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <!-- Backup Configurations -->
    <div class="col-md-6">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-white">
                <div class="d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="fas fa-cogs me-2"></i>Configurazioni Backup</h5>
                    <a href="{{ url_for('main.add_config') }}" class="btn btn-primary btn-sm">
                        <i class="fas fa-plus me-1"></i>Aggiungi Nuova
                    </a>
                </div>
            </div>
            <div class="card-body p-0">
                {% if configs %}
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Nome</th>
                                <th>Pianificazione</th>
                                <th>Stato</th>
                                <th>Azioni</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for config in configs %}
                            <tr>
                                <td>{{ config.name }}</td>
                                <td>
                                    {% if config.schedule_type == 'manual' %}
                                    <span class="badge bg-secondary">Solo Manuale</span>
                                    {% elif config.schedule_type == 'daily' %}
                                    <span class="badge bg-info">Giornaliero</span>
                                    {% elif config.schedule_type == 'weekly' %}
                                    <span class="badge bg-primary">Settimanale</span>
                                    {% elif config.schedule_type == 'monthly' %}
                                    <span class="badge bg-warning">Mensile</span>
                                    {% endif %}
                                </td>
                                <td>
                                    {% if config.active %}
                                    <span class="badge bg-success">Attivo</span>
                                    {% else %}
                                    <span class="badge bg-danger">Inattivo</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <form method="post" action="{{ url_for('main.start_backup', config_id=config.id) }}">
                                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
                                            <button type="submit" class="btn btn-outline-primary">
                                                <i class="fas fa-play"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-4">
                    <p class="text-muted mb-0">Nessuna configurazione di backup trovata.</p>
                    <p>
                        <a href="{{ url_for('main.add_config') }}" class="btn btn-primary mt-2">
                            <i class="fas fa-plus me-1"></i>Aggiungi La Tua Prima Configurazione
                        </a>
                    </p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>

    <!-- Recent Backup Logs -->
    <div class="col-md-6">
        <div class="card shadow-sm mb-4">
            <div class="card-header bg-white">
                <div class="d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="fas fa-clipboard-list me-2"></i>Log Backup Recenti</h5>
                    <a href="{{ url_for('main.logs') }}" class="btn btn-outline-primary btn-sm">
                        <i class="fas fa-eye me-1"></i>Vedi Tutti
                    </a>
                </div>
            </div>
            <div class="card-body p-0">
                {% if recent_logs %}
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Config</th>
                                <th>Stato</th>
                                <th>Data</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in recent_logs %}
                            <tr>
                                <td>{{ log.config.name if log.config else 'Sconosciuto' }}</td>
                                <td>
                                    {% if log.status == 'success' %}
                                    <span class="badge bg-success">Successo</span>
                                    {% elif log.status == 'error' %}
                                    <span class="badge bg-danger">Errore</span>
                                    {% elif log.status == 'running' %}
                                    <span class="badge bg-primary">In esecuzione</span>
                                    {% else %}
                                    <span class="badge bg-secondary">{{ log.status|capitalize }}</span>
                                    {% endif %}
                                </td>
                                <td>{{ log.start_time.strftime('%Y-%m-%d %H:%M') }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-4">
                    <p class="text-muted">Nessun log di backup trovato.</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
'@

# Crea tutti i file base
$files = @{
    "config.py" = $configPy
    "app/__init__.py" = $initPy
    "app/models.py" = $modelsPy
    "app/auth.py" = $authPy
    "app/main/__init__.py" = $mainInitPy
    "app/main/routes.py" = $mainRoutesPy
    "app/main/forms.py" = $mainFormsPy
    "app/backup_engine.py" = $backupEnginePy
    "run.py" = $runPy
    ".flaskenv" = $flaskEnv
    "app/templates/base.html" = $baseHtml
    "app/templates/index.html" = $indexHtml
    "app/templates/auth/login.html" = $loginHtml
    "app/templates/auth/register.html" = $registerHtml
    "app/templates/dashboard.html" = $dashboardHtml
}

foreach ($file in $files.Keys) {
    Create-ProjectFile -filePath $file -content $files[$file]
}

# Configura l'ambiente
Write-Host "Installazione delle dipendenze necessarie..." -ForegroundColor Green
pip install flask flask-sqlalchemy flask-login flask-wtf python-dotenv | Out-Null

# Crea il database
Write-Host "Creazione del database..." -ForegroundColor Green
$env:FLASK_APP = "run.py"
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database creato!')" | Out-Null

# Crea utente admin
Write-Host "Creazione utente admin..." -ForegroundColor Green
python -c "from app import create_app, db; from app.models import User; app = create_app(); app.app_context().push(); admin = User(username='admin', email='admin@example.com', password='password', is_admin=True); db.session.add(admin); db.session.commit(); print('Utente admin creato!')" | Out-Null

Write-Host "`nSetup completato!" -ForegroundColor Green
Write-Host "`nPer avviare l'applicazione, esegui:" -ForegroundColor Cyan
Write-Host "python run.py" -ForegroundColor Yellow
Write-Host "`nPotrai accedere con:" -ForegroundColor Cyan
Write-Host "Username: admin" -ForegroundColor Yellow
Write-Host "Password: password" -ForegroundColor Yellow