My-Budget-Buddy (MBB)

What & Why
My-Budget-Buddy is a personal finance web app that turns bank transactions into simple, actionable budgets. I built it to practice end-to-end engineering—clean Flask architecture, a small budgeting engine, and a production deployment on DigitalOcean. The demo runs without account linking so reviewers can explore quickly.

Live (demo): https://www.my-budget-buddy.com

Tech: Flask · SQLAlchemy · Gunicorn · DigitalOcean App Platform (Postgres-ready)

Highlights

Productionized Flask: WSGI entrypoint (wsgi.py) + Procfile + Gunicorn configuration.

Reliability: health check route, idempotent DB bootstrap, safe defaults for demo mode.

Security basics: secrets via env vars, CSRF enabled, HTTPOnly/SameSite cookies.

Clean structure: Blueprints for routes/services; easy to extend to Postgres + migrations.

Quick Start (demo mode — no Plaid setup)
git clone https://github.com/<D97v121>/My-Budget-Buddy.git
cd My-Budget-Buddy && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
flask --app wsgi run --debug


A demo user is seeded on first run (e.g., demo / demo123) so you can log in immediately.

Screenshots

(Optional — include 1–3 images in docs/screenshots/)




Roadmap

Switch prod to Postgres with Alembic migrations

Tests (pytest) for routes/services

Charts & insights (categorization, trends, cash-flow)
