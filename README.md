The site is still a work in progress, especially the AI bot. Right now, I am mostly working on the bot and learning how to incorporate AI into my site.
# My-Budget-Buddy (MBB)

A personal finance and budgeting app built with **Flask** and **Plaid**.  
The project focuses on secure financial data integration, modular API design, and simple user-facing insights.

## Features
- **Plaid Integration** — fetch transactions, investments, and asset reports  
- **Budgeting Engine** — allocate income across categories (save, spend, invest, expenses, give)  
- **AI Querying** — ask natural language questions that are parsed into SQL queries for insights  
- **Modular API** — structured with Flask Blueprints (`transactions_api`, `plaid_core_api`, `plaid_extra_features`, etc.)  
- **Data Maintenance** — cleanup scripts for old transactions and Plaid items  

## Tech Stack
- Flask + SQLAlchemy  
- PostgreSQL (with Alembic migrations)  
- Plaid API  
- OpenAI API (for query interpretation)  

## Setup
1. Clone the repo  
2. Create a `.env` file with Plaid and OpenAI credentials  
3. Install dependencies:  
   ```bash
   pip install -r requirements.txt
