from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session as ServerSession
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate
import logging
from datetime import timedelta
from pathlib import Path
from sqlalchemy.exc import IntegrityError
import os
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
load_dotenv()  # will pick up the same .env in dev
# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
server_session = ServerSession()
migrate = Migrate()


def create_app():
    app = Flask(__name__)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "money.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "super-secret-key")
    app.config["SESSION_TYPE"] = "filesystem"
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_USE_SIGNER"] = True
    app.config["SESSION_COOKIE_SECURE"] = True  # set False only if you’re truly on HTTP
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "connect_args": {"check_same_thread": False},
    }

    # Init extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    server_session.init_app(app)
    migrate.init_app(app, db)
    login_manager.login_view = "auth.login"

    # Consistent import
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Jinja filters
    from app.helpers import usd, timestamp_editor
    app.jinja_env.filters["usd"] = usd
    app.jinja_env.filters["timestamp_editor"] = timestamp_editor

    # --- Ensure tables + seed BEFORE routes ---
    with app.app_context():
        db.create_all()
        _ensure_demo_user(app)

    # Now register routes
    from app.routes import register_routes
    register_routes(app)

    @app.get("/healthz")
    def healthz():
        return "ok", 200

    return app

def _ensure_demo_user(app):
    """Create a demo user once, if missing. Safe to call every boot."""
    from app import db
    from app.models.user import User  # adjust import if your path differs

    demo_username = os.getenv("DEMO_USERNAME", "demo")
    demo_password = os.getenv("DEMO_PASSWORD", "demo123")

    with app.app_context():
        # create tables if they don't exist (harmless if they do)
        db.create_all()

        if User.query.filter_by(username=demo_username).first():
            return  # already there

        u = User(username=demo_username, name="Demo User")
        # your model uses 'hash' for the password hash:
        u.hash = generate_password_hash(demo_password)

        db.session.add(u)
        try:
            db.session.commit()
            print(f"[seed] Demo user created: {demo_username}/{demo_password}")
        except IntegrityError:
            db.session.rollback()
            print("[seed] Demo user already exists; skipped")
