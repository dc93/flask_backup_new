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
    
    # Controlla se l'utente Ã¨ il proprietario
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
