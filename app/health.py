# app/health.py
from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)

@bp.get("/livez")
def livez():
    # ultra-cheap liveness: process is up
    return jsonify(status="ok"), 200

@bp.get("/healthz")
def healthz():
    # keep for platforms that probe /healthz
    return "ok", 200

@bp.get("/readyz")
def readyz():
    # if you don't want DB gating right now, keep it cheap:
    return jsonify(status="ready"), 200
