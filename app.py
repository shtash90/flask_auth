from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length
import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ WTForms
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Parol", validators=[InputRequired(), Length(min=6)])
    submit = SubmitField("Ro'yxatdan o'tish")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email()])
    password = PasswordField("Parol", validators=[InputRequired()])
    submit = SubmitField("Kirish")

# 🔽 Routes
@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Muvaffaqiyatli ro‘yxatdan o‘tdingiz!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Login yoki parol noto‘g‘ri", "danger")
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# Baza va ilova yaratilib bo‘lgandan keyin:
admin = Admin(app, name="Admin Panel", template_mode='bootstrap4')
admin.add_view(ModelView(User, db.session))


# 🧱 Baza yaratish
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
