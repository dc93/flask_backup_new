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
