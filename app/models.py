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
