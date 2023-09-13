"""This program is used to run the website"""

from os import path
import secrets
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_change_password import ChangePassword
from flask_bcrypt import Bcrypt

key = secrets.token_hex(16)
db = SQLAlchemy()
bcrypt = Bcrypt()
DB_NAME = "database.db"


def create_app():
    """This is used for the application of the website"""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = key
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_NAME}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize extensions with the app:
    db.init_app(app)
    bcrypt.init_app(app)  # <-- initialize Bcrypt with the app
    flask_change_password = ChangePassword(
        min_password_length=12, rules=dict(long_password_override=2)
    )
    flask_change_password.init_app(app)

    from .views import views
    from .auth import auth
    from .models import User

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/")
    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        """Loads user data"""
        return User.query.get(int(id))

    return app


def create_database(app):
    """Creates the database"""
    if not path.exists("website/" + DB_NAME):
        with app.app_context():
            db.create_all()
        print("Created Database!")
