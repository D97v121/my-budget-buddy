from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session as ServerSession
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate
from flask.cli import with_appcontext
import click, os
from datetime import timedelta
from pathlib import Path
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
server_session = ServerSession()
migrate = Migrate()

def _database_url(instance_path: str) -> str:
    """
    Priority:
      1) SQLALCHEMY_DATABASE_URI (explicit)
      2) DATABASE_URL (normalize postgres:// -> postgresql+psycopg://)
      3) sqlite at /data (if persistent volume mounted)
      4) sqlite in instance folder (dev/local)
    """
    url = os.getenv("SQLALCHEMY_DATABASE_URI") or os.getenv("DATABASE_URL")
    if url:
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        return url

    data_dir = "/data"
    if os.path.isdir(data_dir):
        return f"sqlite:///{os.path.join(data_dir, 'money.db')}"
    return "sqlite:///" + os.path.join(instance_path, "money.db")

def create_app():
    app = Flask(__name__)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    # Sessions: persist if /data exists, else instance folder
    session_dir = "/data/flask-session" if os.path.isdir("/data") \
                  else os.path.join(app.instance_path, "flask-session")
    Path(session_dir).mkdir(parents=True, exist_ok=True)

    db_url = _database_url(app.instance_path)

    app.config.update(
        SQLALCHEMY_DATABASE_URI=db_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SECRET_KEY=os.getenv("SECRET_KEY", "super-secret-key"),
        SESSION_TYPE="filesystem",
        SESSION_FILE_DIR=session_dir,
        SESSION_PERMANENT=False,
        SESSION_USE_SIGNER=True,
        # Optional: env-based secure cookies (True in prod by default)
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV", "production") == "production",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        WTF_CSRF_ENABLED=True,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SQLALCHEMY_ENGINE_OPTIONS=(
            {"pool_pre_ping": True, "connect_args": {"check_same_thread": False}}
            if db_url.startswith("sqlite:///")
            else {"pool_pre_ping": True}
        ),
    )

    # Init extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    server_session.init_app(app)
    migrate.init_app(app, db)
    login_manager.login_view = "auth.login"

    # Import ALL model modules so metadata is registered
    from . import models  # ensures every model/table is known to SQLAlchemy
    from app.models.user import User  # keep for user_loader typing/lookup

    # --- SQLite safety net: create tables if fresh/empty (no-op if already present) ---
    with app.app_context():
        if db.engine.url.get_backend_name() == "sqlite":
            insp = inspect(db.engine)
            # Check for one known table; change "user" if your metadata differs
            if not insp.has_table("user"):
                db.create_all()

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Jinja filters
    from app.helpers import usd, timestamp_editor
    app.jinja_env.filters["usd"] = usd
    app.jinja_env.filters["timestamp_editor"] = timestamp_editor

    # Register routes AFTER extensions/models are ready
    from app.routes import register_routes
    register_routes(app)

    # Health checks
    @app.get("/healthz")
    def healthz():
        return "ok", 200

    @app.get("/readyz")
    def readyz():
        try:
            # Very light DB touch; fine for SQLite and Postgres
            db.session.execute(text("SELECT 1"))
            return "ready", 200
        except Exception:
            return "not ready", 503

    _register_cli_commands(app)
    return app

def _register_cli_commands(app):
    @app.cli.command("init-db")
    @with_appcontext
    def init_db():
        """Create all tables (use for manual setup)."""
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
            click.echo("ℹ Demo user already exists; skipped"); return
        u = User(username=demo_username, name="Demo User")
        u.hash = generate_password_hash(demo_password)
        db.session.add(u)
        try:
            db.session.commit()
            click.echo(f"✔ Demo user created: {demo_username}/{demo_password}")
        except IntegrityError:
            db.session.rollback()
            click.echo("ℹ Demo user exists; skipped")
