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
