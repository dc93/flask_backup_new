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
