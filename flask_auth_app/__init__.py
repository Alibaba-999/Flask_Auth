from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .models import User

# Inicializa extensiones
db = SQLAlchemy()
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)

    # Configuraciones
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicializa extensiones
    db.init_app(app)
    login_manager.init_app(app)

    # Vista de inicio de sesión
    login_manager.login_view = 'auth.login'

    # Registra blueprints
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    return app