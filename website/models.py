"""This program is used for models for the database and user information"""

from flask_login import UserMixin
from sqlalchemy import func
from website import db


class User(db.Model, UserMixin):
    """Class for database"""

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
