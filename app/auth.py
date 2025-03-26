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
            raise ValidationError("Username giÃ  in uso")
    
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("Email giÃ  registrata")

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
