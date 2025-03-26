# Crea uno script fix-imports.ps1
New-Item -Path fix-imports.ps1 -Value @'
# Verifica la versione di Werkzeug
$werkzeugVersion = python -c "import werkzeug; print(werkzeug.__version__)"
Write-Host "Versione di Werkzeug rilevata: $werkzeugVersion" -ForegroundColor Yellow

# Aggiorna il file auth.py per utilizzare la corretta importazione
$authPyPath = "app/auth.py"
$authPyContent = Get-Content $authPyPath -Raw

if ([Version]$werkzeugVersion -ge [Version]"2.3.0") {
    Write-Host "Aggiornamento delle importazioni per Werkzeug >= 2.3.0..." -ForegroundColor Green
    
    $authPyContent = $authPyContent.Replace(
        "from werkzeug.urls import url_parse",
        "from werkzeug.urls import url_parse as _url_parse`n# Compatibilità con Werkzeug 2.3.0+`ndef url_parse(url): return _url_parse(url)"
    )
    
    if (-not $authPyContent.Contains("from werkzeug.urls import url_parse")) {
        # Se l\'importazione è diversa o non presente, utilizziamo l\'approccio diretto
        $authPyContent = $authPyContent.Replace(
            "from flask import Blueprint, render_template, redirect, url_for, flash, request",
            "from flask import Blueprint, render_template, redirect, url_for, flash, request`nfrom werkzeug.urls import urlparse as url_parse"
        )
    }
} else {
    Write-Host "Nessun aggiornamento necessario per Werkzeug < 2.3.0" -ForegroundColor Green
}

# Salva il file aggiornato
$authPyContent | Out-File -FilePath $authPyPath -Encoding utf8 -Force
Write-Host "File $authPyPath aggiornato con successo" -ForegroundColor Green

# Ricrea il database
Write-Host "Creazione del database..." -ForegroundColor Green
try {
    python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database creato!')"
    
    # Crea utente admin
    Write-Host "Creazione utente admin..." -ForegroundColor Green
    python -c "from app import create_app, db; from app.models import User; app = create_app(); app.app_context().push(); admin = User(username='admin', email='admin@example.com', password='password', is_admin=True); db.session.add(admin); db.session.commit(); print('Utente admin creato!')"
} catch {
    Write-Host "Errore durante la creazione del database: $_" -ForegroundColor Red
}

Write-Host "`nProvare ad avviare l'applicazione con:" -ForegroundColor Cyan
Write-Host "python run.py" -ForegroundColor Yellow
'@

# Installa le versioni specifiche delle dipendenze per garantire compatibilità
Write-Host "Installazione di versioni specifiche delle dipendenze..." -ForegroundColor Green
pip install flask==2.0.1 werkzeug==2.0.1 flask-sqlalchemy==2.5.1 flask-login==0.5.0 flask-wtf==0.15.1 python-dotenv

# Esegui lo script di correzione
Write-Host "Eseguendo lo script di correzione..." -ForegroundColor Green
.\fix-imports.ps1