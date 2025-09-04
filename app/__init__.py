from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate
import logging
from datetime import timedelta
from pathlib import Path
import os


from dotenv import load_dotenv
load_dotenv()  # will pick up the same .env in dev
# Initialize extensions
db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
session = Session()
migrate = Migrate()


def create_app():
    app = Flask(__name__)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    # App config
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(app.instance_path, "money.db")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'super-secret-key'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_USE_SIGNER"] = True
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
    print("DB URI AT STARTUP:", app.config.get("SQLALCHEMY_DATABASE_URI"))

    # Initialize extensions
    from app.models import User
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    session.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ✅ Register Jinja filters from helpers
    from app.helpers import usd, timestamp_editor
    app.jinja_env.filters["usd"] = usd
    app.jinja_env.filters["timestamp_editor"] = timestamp_editor

    # ✅ Register blueprints/routes
    from app.routes import register_routes
    register_routes(app)

    return app
