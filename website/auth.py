"""This is used for authorization to use the website"""
from datetime import datetime
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
from .models import User
from . import db, bcrypt
import logging

auth = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)

with open("CommonPassword.txt", encoding="utf-8") as f:
    COMMON_PASSWORDS_SET = set(line.strip() for line in f)


def add_log(ip_address):
    """Log failed login attempts."""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    logger.warning(f"{date_time} {ip_address} Failed Login")


@auth.route("/login", methods=["GET", "POST"])
def login():
    # Get client IP address
    ip_address = request.remote_addr

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            flash(
                "An error occurred while accessing the database. Please try again.",
                category="error",
            )
            logger.error("Database error when querying for user during login: %s", e)
            return render_template(
                "login.html", user=current_user, ip_address=ip_address
            )

        if user:
            if not bcrypt.check_password_hash(user.password, password):
                flash("Incorrect password, try again.", category="error")
                add_log(ip_address)
            else:
                flash("Logged in successfully!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
        else:
            flash("User does not exist.", category="error")
            add_log(ip_address)

    return render_template("login.html", user=current_user, ip_address=ip_address)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    ip_address = request.remote_addr

    if request.method == "POST":
        email = request.form.get("email")
        first_name = request.form.get("firstName")
        last_name = request.form.get("lastName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            flash(
                "An error occurred while accessing the database. Please try again.",
                category="error",
            )
            logger.error("Database error when querying for user during sign-up: %s", e)
            return render_template(
                "sign_up.html", user=current_user, ip_address=ip_address
            )

        if user:
            flash("Email already exists.", category="error")
        elif password1 != password2:
            flash("Passwords don't match.", category="error")
        elif len(password1) < 12:
            flash("Password must be at least 12 characters.", category="error")
        elif password1 in COMMON_PASSWORDS_SET:
            flash(
                "Password is easily guessable. Consider changing it.", category="error"
            )
        else:
            hashed_password = bcrypt.generate_password_hash(password1).decode("utf-8")
            new_user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=hashed_password,
            )

            try:
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash("Account created!", category="success")
                return redirect(url_for("views.home"))
            except Exception as e:
                db.session.rollback()
                flash(
                    "An error occurred while creating your account. Please try again.",
                    category="error",
                )
                logger.error(
                    "Database error when adding new user during sign-up: %s", e
                )

    return render_template("sign_up.html", user=current_user, ip_address=ip_address)


@auth.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        if not validate_change_request():
            return render_template("change.html", user=current_user)

        hashed_new_password = bcrypt.generate_password_hash(
            request.form.get("password3")
        ).decode("utf-8")

        try:
            current_user.password = hashed_new_password
            db.session.commit()
            flash("Password Changed!", category="success")
            return redirect(url_for("views.home"))
        except Exception as e:
            db.session.rollback()
            flash(
                "An error occurred while changing your password. Please try again.",
                category="error",
            )
            logger.error("Database error when updating user password: %s", e)
            return render_template("change.html", user=current_user)

    return render_template("change.html", user=current_user)


def validate_change_request():
    current_password = request.form.get("currentPassword")
    new_pass = request.form.get("password3")
    new_pass_conf = request.form.get("password4")

    if not bcrypt.check_password_hash(current_user.password, current_password):
        flash("Current password is incorrect.", category="error")
        return False
    elif new_pass == current_password:
        flash("New password is the same as the current password.", category="error")
        return False
    elif new_pass != new_pass_conf:
        flash("New Passwords don't match.", category="error")
        return False
    elif len(new_pass) < 12:
        flash("Password must be at least 12 characters.", category="error")
        return False
    elif new_pass in COMMON_PASSWORDS_SET:
        flash("Password is easily guessable. Consider changing it.", category="error")
        return False

    return True
