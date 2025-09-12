# health.py
from flask import Blueprint, jsonify
from sqlalchemy import text, inspect
from sqlalchemy.exc import OperationalError
import os

bp = Blueprint("health", __name__)

@bp.route("/livez", methods=["GET"])
def livez():
    # Minimal work: process is up, request can be served.
    return jsonify(status="ok"), 200

@bp.route("/readyz", methods=["GET"])
def readyz():
    """
    Readiness means: app can actually serve real traffic.
    Checks:
      1) DB connectivity (SELECT 1)
      2) Critical tables exist (e.g., 'user') => migrations ran
      3) Critical env vars present (e.g., Plaid creds)
    """
    # 3) Env presence (treat missing as not ready)
    required_env = ["PLAID_CLIENT_ID", "PLAID_SECRET"]
    missing = [k for k in required_env if not os.environ.get(k)]
    if missing:
        return jsonify(error=f"Missing env vars: {', '.join(missing)}"), 503

    # 1 & 2) DB connectivity + schema check
    from app import db  # adjust import to your app
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            inspector = inspect(db.engine)
            if not inspector.has_table("user"):
                # Migrations not yet applied
                return jsonify(error="DB not migrated: missing 'user' table"), 503
    except OperationalError as e:
        return jsonify(error=f"DB not reachable: {str(e)}"), 503

    return jsonify(status="ready"), 200
