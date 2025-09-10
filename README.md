My-Budget-Buddy (MBB)

What/Why (1 paragraph)
My-Budget-Buddy is a personal finance web app that connects to bank accounts via Plaid and turns raw transactions into simple, actionable budgets. I built it to practice end-to-end product thinking: secure auth, data ingestion, a lightweight budgeting engine, and real deployment. The focus is reliability (no broken prod flows), clarity (clean routes/blueprints), and portability (runs locally with SQLite + Plaid sandbox; deployable to DigitalOcean App Platform).

Tech Stack

Flask, SQLAlchemy, Gunicorn, Plaid, DigitalOcean App Platform
(Dev DB: SQLite; Prod-ready for Postgres)

Run Locally (Plaid sandbox)
1) Clone & setup
git clone https://github.com/<you>/My-Budget-Buddy.git
cd My-Budget-Buddy
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

2) Environment (.env)

Create a .env at repo root:

# App
SECRET_KEY=dev-secret
FLASK_ENV=development

# Database (dev)
SQLALCHEMY_DATABASE_URI=sqlite:///instance/money.db

# Plaid (sandbox)
PLAID_ENV=sandbox
PLAID_CLIENT_ID=<your_sandbox_client_id>
PLAID_SECRET=<your_sandbox_secret>

3) First-run DB
# If using Flask-Migrate with migrations checked in:
flask --app wsgi db upgrade

# Or simple create-all (ensure models are imported in app/__init__.py):
flask --app wsgi shell -c "from app import db; db.create_all(); print('DB ready')"

4) Start the app
# Debug server
flask --app wsgi run --debug
# or Gunicorn (mirrors prod)
gunicorn wsgi:app -w 1 -b 0.0.0.0:8080

5) Link a sandbox bank (Plaid)

Open the app → start Plaid Link.

In the Link modal, choose a sandbox institution and use Plaid’s sandbox test credentials (e.g., user_good / pass_good; MFA 1234).

After linking, return to the dashboard to see accounts/transactions.

Note: The app has guards to prevent sandbox tokens from being used in production calls.

Deploy (DigitalOcean App Platform)

Repo items required

Procfile

web: gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers ${WEB_CONCURRENCY:-3} --timeout ${GUNICORN_TIMEOUT:-120} --access-logfile - --error-logfile -


.python-version → 3.12

requirements.txt (includes gunicorn, plaid-python, python-dotenv; add psycopg2-binary if using Postgres)

App Platform settings

Build method: Source Code (Python).

Environment Variables:

SECRET_KEY=<long-random>

PLAID_ENV=production (or sandbox for demo)

PLAID_CLIENT_ID=<prod_id>

PLAID_SECRET=<prod_secret>

SQLALCHEMY_DATABASE_URI=

For SQLite (demo only): sqlite:////workspace/instance/money.db and set workers=1 in Procfile

For Postgres (recommended): postgresql+psycopg2://…?sslmode=require

Health check path: /healthz (provided by the app).

Post-deploy

# DO Console
cd /workspace
export FLASK_APP=wsgi.py
# If using migrations:
flask db upgrade
# Or:
python - <<'PY'
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print("Tables created")
PY

Screenshots

(stored under docs/screenshots/ — replace with your actual images)

Login


Dashboard


Plaid Link flow


Reliability

Env/Token Guard: Prevents Plaid sandbox access tokens from being used in production; auto-cleans stale tokens and re-links safely.

Health Check: /healthz endpoint for App Platform probes; avoids hitting auth/Plaid during deploy checks.

DB Bootstrap: Idempotent on-boot table creation (or Alembic migrations); optional demo user seeding for fresh environments.

Security

Secrets via env vars (SECRET_KEY, Plaid keys); no secrets committed.

Session hardening: HTTPOnly, SameSite, secure cookies (prod), CSRF enabled.

Principle of least privilege: Only required Plaid products/permissions requested.

Features

Plaid Integration — accounts & transactions via official SDK

Budgeting Engine — allocate income across save/spend/invest/expenses/give

(WIP) AI queries — natural-language Q→SQL insights (optional module)

Modular API — Flask Blueprints for clean routing & services

Roadmap

Postgres by default in production + full Alembic migration history

Tests (pytest): services, routes, Plaid client guards

Retry/Backoff for Plaid API with request-id logging

Charts & Insights: richer categorization, trends, cash-flow view

Auth polish: password reset, 2FA (optional)

Container dev: optional Docker for local parity

License

MIT (or your preferred license). Replace this section if different.

Links
Live: https://www.my-budget-buddy.com

Repo: https://github.com/
<you>/My-Budget-Buddy
