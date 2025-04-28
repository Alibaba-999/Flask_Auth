from flask import render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash
from flask_login import login_user, logout_user, login_required
from . import auth
from ..models import db, User

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Verifica si el usuario existe
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Nombre de usuario o contraseña incorrectos', 'danger')
            return redirect(url_for('auth.login'))

        # Inicia sesión del usuario
        login_user(user)
        flash('Inicio de sesión exitoso', 'success')
        return redirect(url_for('auth.dashboard'))

    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesion correctamente', 'success')
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Verifica si el usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya existe', 'danger')
            return redirect(url_for('auth.register'))

        # Crea un nuevo usuario
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Usuario registrado correctamente. Puedes iniciar sesión ahora.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth.route('/dashboard')
@login_required
def dashboard():
    return "Bienvenido al panel de control. Solo los usuarios registrados pueden ver esto."