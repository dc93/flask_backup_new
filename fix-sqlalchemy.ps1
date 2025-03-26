# Disinstalla le versioni attuali
Write-Host "Disinstallazione delle versioni attuali..." -ForegroundColor Yellow
pip uninstall -y flask flask-sqlalchemy sqlalchemy werkzeug

# Installa versioni specifiche compatibili
Write-Host "Installazione delle versioni compatibili..." -ForegroundColor Green
pip install flask==2.0.1 
pip install werkzeug==2.0.1 
pip install sqlalchemy==1.4.46 
pip install flask-sqlalchemy==2.5.1
pip install flask-login==0.5.0 
pip install flask-wtf==0.15.1 
pip install python-dotenv
pip install email-validator

# Verifica versioni installate
Write-Host "`nVersioni installate:" -ForegroundColor Cyan
pip list | Select-String -Pattern "flask|sqlalchemy|werkzeug"

# Inizializza il database
Write-Host "`nCreazione del database..." -ForegroundColor Green
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database creato con successo!')"

# Crea utente admin
Write-Host "Creazione utente admin..." -ForegroundColor Green
python -c "from app import create_app, db; from app.models import User; app = create_app(); app.app_context().push(); user = User.query.filter_by(username='admin').first(); if not user: admin = User(username='admin', email='admin@example.com', password='password', is_admin=True); db.session.add(admin); db.session.commit(); print('Utente admin creato!'); else: print('Utente admin giÃ  esistente');"

Write-Host "`nInstallazione completata con successo!" -ForegroundColor Green
Write-Host "Puoi avviare l'applicazione con:" -ForegroundColor Cyan
Write-Host "python run.py" -ForegroundColor Yellow
