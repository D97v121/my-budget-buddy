import os
from datetime import timedelta
from dotenv import load_dotenv

from flask import Flask
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from app import db
from app.helpers import usd, timestamp_editor
from app.routes import register_routes  # ✅ THIS is all you need for routing

load_dotenv()

app = Flask(__name__)

# --- App Config ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///money.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['WTF_CSRF_ENABLED'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# --- Extensions ---
Session(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
CSRFProtect(app)
db.init_app(app)
migrate = Migrate(app, db)

# --- Jinja Filters ---
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters['timestamp_editor'] = timestamp_editor

# --- Route Registration ---
register_routes(app)  # ✅ All Blueprints registered here

with app.app_context():
    db.create_all()
    print("Tables created successfully")

if __name__ == '__main__':
    app.run(debug=False, port=8080, use_reloader=False)
