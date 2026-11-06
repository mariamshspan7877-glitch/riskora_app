from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import User, db
from services.audit_service import log_event

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not full_name or not email or not password:
            flash("Please complete all required fields.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html", full_name=full_name, email=email)
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html", full_name=full_name, email=email)
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html", full_name=full_name, email=email)

        user = User(full_name=full_name, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        log_event(user, "auth", "registered", "success", f"User {email} created account")
        flash("Registration successful. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log_event(user, "auth", "login", "success", f"Logged in as {email}")
            flash("Welcome back to Riskora.", "success")
            return redirect(url_for("user.dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_event(current_user, "auth", "logout", "success", "User logged out")
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))
