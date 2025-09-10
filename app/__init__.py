from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session as ServerSession
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate
from flask.cli import with_appcontext
import click
import logging
from datetime import timedelta
from pathlib import Path
from sqlalchemy.exc import IntegrityError
import os
from sqlalchemy import inspect
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()  # will pick up the same .env in dev

# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
server_session = ServerSession()
migrate = Migrate()

def _database_url(instance_path: str) -> str:
    """
    Prefer DATABASE_URL (for Postgres in prod), otherwise fall back to SQLite in instance folder.
    Also normalize old 'postgres://' URLs to SQLAlchemy's 'postgresql+psycopg://'.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        return url
    return "sqlite:///" + os.path.join(instance_path, "money.db")

def create_app():
    app = Flask(__name__)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db_url = _database_url(app.instance_path)

    app.config["SQLALCHEMY_DATABASE_URI"] = db_url
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

    # Only apply SQLite-specific engine options
    if db_url.startswith("sqlite:///"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "pool_pre_ping": True,
            "connect_args": {"check_same_thread": False},
        }
    else:
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # Init extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    server_session.init_app(app)
    migrate.init_app(app, db)
    login_manager.login_view = "auth.login"

    # Import models for loader
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Jinja filters
    from app.helpers import usd, timestamp_editor
    app.jinja_env.filters["usd"] = usd
    app.jinja_env.filters["timestamp_editor"] = timestamp_editor

    # ---- IMPORTANT: Do NOT create tables or seed here ----
    # (removed: db.create_all(); _ensure_demo_user())

    # Register routes AFTER extensions/models are ready
    from app.routes import register_routes
    register_routes(app)

    # Health check
    @app.get("/healthz")
    def healthz():
        return "ok", 200

    # Register CLI commands for one-off ops
    _register_cli_commands(app)

    return app

def _register_cli_commands(app):
    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Create all tables (use once for SQLite, or during initial setup)."""
        db.create_all()
        click.echo("✔ Database initialized")

    @app.cli.command("seed-demo")
    @with_appcontext
    def seed_demo():
        """Seed a demo user once; safe to re-run (idempotent)."""
        from app.models.user import User

        demo_username = os.getenv("DEMO_USERNAME", "demo")
        demo_password = os.getenv("DEMO_PASSWORD", "demo123")

        if User.query.filter_by(username=demo_username).first():
            click.echo("ℹ Demo user already exists; skipped")
            return

        u = User(username=demo_username, name="Demo User")
        u.hash = generate_password_hash(demo_password)  # your model uses 'hash'
        db.session.add(u)
        try:
            db.session.commit()
            click.echo(f"✔ Demo user created: {demo_username}/{demo_password}")
        except IntegrityError:
            db.session.rollback()
            click.echo("ℹ Demo user exists; skipped")
