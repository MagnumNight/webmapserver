"""This will handle the pages that are viewed by the website user"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user

# Variables that will be called in the website
views = Blueprint("views", __name__)


@views.route("/")
@login_required
def home():
    """Home route that calls home.html"""
    return render_template("home.html", user=current_user)


@views.route("/map")
def openstreetmap():
    """Map route that calls map.html"""
    return render_template("map.html", user=current_user)
