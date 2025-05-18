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
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import InputRequired, Email
from wtforms import PasswordField
from wtforms.validators import EqualTo
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user

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

class EditProfileForm(FlaskForm):
    username = StringField("Yangi foydalanuvchi nomi", validators=[InputRequired()])
    email = StringField("Yangi email", validators=[InputRequired(), Email()])
    submit = SubmitField("Saqlash")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Eski parol", validators=[InputRequired()])
    new_password = PasswordField("Yangi parol", validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField("Yangi parol (tasdiqlang)", validators=[
        InputRequired(), EqualTo('new_password', message="Parollar mos emas")])
    submit = SubmitField("Parolni o‘zgartirish")

# 🔒 Custom admin panelni faqat adminlarga ruxsat beramiz
class AdminOnlyView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

class AdminHome(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login'))
        return super().index()


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

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash("Profil yangilandi!", "success")
        return redirect(url_for('profile'))

    # Avvalgi qiymatlarni forma ichiga to‘ldirib ko‘rsatamiz
    form.username.data = current_user.username
    form.email.data = current_user.email
    return render_template('edit_profile.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_password.data):
            hashed = generate_password_hash(form.new_password.data)
            current_user.password = hashed
            db.session.commit()
            flash("Parol muvaffaqiyatli o‘zgartirildi!", "success")
            return redirect(url_for('profile'))
        else:
            flash("Eski parol noto‘g‘ri!", "danger")

    return render_template('change_password.html', form=form)

# Baza va ilova yaratilib bo‘lgandan keyin:
# admin = Admin(app, name="Admin Panel", template_mode='bootstrap4')
# admin.add_view(ModelView(User, db.session))

# Admin panel sozlamasi
admin = Admin(app, name="Admin Panel", template_mode='bootstrap4', index_view=AdminHome())
admin.add_view(AdminOnlyView(User, db.session))

# 🧱 Baza yaratish
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
