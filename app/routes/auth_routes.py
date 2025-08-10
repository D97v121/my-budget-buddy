from flask import Blueprint, render_template, redirect, session, jsonify, request, url_for
from flask_wtf.csrf import generate_csrf
from app.forms import LoginForm
from app.models import User
from flask_login import login_required
from werkzeug.security import check_password_hash
from app.helpers import populate_tags
import logging
from app import db, csrf
from werkzeug.security import generate_password_hash
from flask_login import login_user

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.hash, password):
            logging.warning("Invalid login attempt")
            return render_template("login.html", form=form, error_message="Incorrect username or password")

        # ✅ Log the user in properly
        login_user(user)

        # Optional: regenerate CSRF and redirect
        session["csrf_token"] = generate_csrf()
        logging.info(f"User logged in: {user.username}")
        return redirect("/")

    return render_template("login.html", form=form)

@auth_bp.route("/logout")
@login_required
def logout():
    session.clear()
    session["csrf_token"] = generate_csrf()
    return redirect("/login")

@auth_bp.route("/register", methods=["GET", "POST"])
@csrf.exempt
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if User.query.filter_by(username=username).first():
            return render_template("register.html", username_error="Username already taken")

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, username=username, hash=password_hash)

        try:
            logging.debug(f"name: {name} username: {username} password: {password}")
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            populate_tags(db, new_user.id)

            return redirect(url_for("profile.profile_questions"))
        except Exception as e:
            print("Registration error:", e)
            db.session.rollback()
            return render_template("register.html", error_message=f"An error occurred: {e}")
    return render_template("register.html")

@auth_bp.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrfToken": session["csrf_token"]})
