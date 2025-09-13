# My-Budget-Buddy (MBB)

## What & Why
My-Budget-Buddy is a personal finance web app that turns bank transactions into simple, actionable budgets and integrates AI fully into the site so that users can easily interact with their data.  

I built it to practice end-to-end engineering. The demo runs without account linking so reviewers can explore quickly. Much of the site is still a work in progress. I am figuring out how to integrate the AI correctly right now.  

Further, the site is set up to be able to run using larger databases (probably through DigitalOcean in the end) and work with all bank accounts, however, due to funding, I do not have access to certain banks yet and am waiting to integrate more fully with DO.  

Live (demo): https://www.my-budget-buddy.com  
Temporary login with one bank account already linked:  
`username: demo`  
`password: demo123`

## Tech
Flask · SQLAlchemy · Gunicorn · DigitalOcean App Platform (Postgres-ready)

## Highlights
- Productionized Flask: WSGI entrypoint (`wsgi.py`) + Procfile + Gunicorn configuration  
- Reliability: health check route, idempotent DB bootstrap, safe defaults for demo mode  
- Security basics: secrets via env vars, CSRF enabled, HTTPOnly/SameSite cookies  
- Clean structure: Blueprints for routes/services; easy to extend to Postgres + migrations  

## Quick Start (demo mode — no Plaid setup)
```bash
git clone https://github.com/<D97v121>/My-Budget-Buddy.git
cd My-Budget-Buddy && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
flask --app wsgi run --debug

A demo user (demo / demo123) is seeded on first run.
```

##Roadmap

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
├── archive/  
│   ├── quick_fixes.py  
│   └── temporary.py  
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
├── quickstart/  
│   ├── .env.example  
│   ├── docker-compose.yml  
│   ├── frontend/  
│   ├── go/  
│   ├── java/  
│   ├── node/  
│   ├── python/  
│   ├── ruby/  
│   └── README.md  
├── requirements.txt  
├── server.nginx  
├── workspace/  
└── wsgi.py  
