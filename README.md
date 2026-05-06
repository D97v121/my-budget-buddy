# My-Budget-Buddy (MBB)

## What & Why
My-Budget-Buddy is a full-stack personal finance web app that connects to real bank accounts via the Plaid API, tracks transactions, and helps users visualize and manage their spending across budget categories. It also features a fully integrated AI assistant that lets users interact with and query their financial data conversationally.

Live (demo): https://my-budget-buddy-mgzfh.ondigitalocean.app/
Temporary login with one bank account already linked:  
`username: demo`  
`password: demo123`

Note: The demo uses Plaid's sandbox environment, so all bank data is simulated -- no real accounts are linked.

<img width="1468" height="796" alt="Screenshot 2026-05-05 at 7 01 26 PM" src="https://github.com/user-attachments/assets/d5c296a1-4355-4f9c-a5f5-098944118469" />

## Tech
Flask · SQLAlchemy · DigitalOcean App Platform (Postgres-ready)

## Highlights
- Productionized Flask: WSGI entrypoint (`wsgi.py`) + Procfile + Gunicorn configuration  
- Reliability: health check route, idempotent DB bootstrap, safe defaults for demo mode  
- Security basics: secrets via env vars, CSRF enabled, HTTPOnly/SameSite cookies  
- Clean structure: Blueprints for routes/services; easy to extend to Postgres + migrations  
  
## Quick Start (demo mode — no Plaid setup)
```bash
git clone github.com/D97v121/My-Budget-Buddy.git
cd My-Budget-Buddy && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
flask --app wsgi run --debug
```
A demo user (demo / demo123) is seeded on first run.

## Roadmap
- Migrate prod DB to Postgres with Alembic migrations
- Add pytest coverage for routes/services
- Build charts & insights (categorization, trends, cash flow)
- Complete AI integration
  
## Project Structure

├── .gitignore  
├── .python-version  
├── .vscode/  
├── app/  
│   ├── __init__.py  
│   ├── ai_helpers.py  
│   ├── encryption_utils.py  
│   ├── filters.py  
│   ├── forms.py  
│   ├── health.py  
│   ├── helpers.py  
│   ├── models/  
│   ├── plaid_helpers.py  
│   ├── routes/  
│   ├── static/  
│   └── templates/   
├── instance/  
│   └── money.db  
├── main.py  
├── migrations/  
│   ├── alembic.ini  
│   ├── env.py  
│   ├── README  
│   ├── script.py.mako  
│   └── versions/  
├── models.py  
├── my_budget_buddy.db  
├── Procfile   
├── requirements.txt     
└── wsgi.py  
