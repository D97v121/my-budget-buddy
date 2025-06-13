import csv
import datetime
import pytz
import requests
import urllib
import uuid
import decimal
import os
import re
import datetime as dt
import json
import logging
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from decimal import Decimal
from cryptography.fernet import Fernet
import base64

from flask import redirect, render_template, request, session
from functools import wraps
from models import Save, Give, Spend, Invest, Money, Expense, Tags, TagColor, Transaction

model_map = {
    "save": Save,
    "spend": Spend,
    "give": Give,
    "invest": Invest,
    "expense": Expense
}



def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"?period1={int(start.timestamp())}"
        f"&period2={int(end.timestamp())}"
        f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(
            url,
            cookies={"session": str(uuid.uuid4())},
            headers={"Accept": "*/*", "User-Agent": request.headers.get("User-Agent")},
        )
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        quotes = list(csv.DictReader(response.content.decode("utf-8").splitlines()))
        price = round(float(quotes[-1]["Adj Close"]), 2)
        return {"price": price, "symbol": symbol}
    except (KeyError, IndexError, requests.RequestException, ValueError):
        return None


def usd(value):
    if not value:
        value = 0
    if value < 0:
        return "-${:,.2f}".format(abs(value))
    else:
        return "${:,.2f}".format(value)
    
def exit_usd(usd_string):
    # Remove currency symbols and commas
    cleaned_string = re.sub(r'[^\d.]', '', usd_string)
    # Convert the cleaned string to a float
    return float(cleaned_string)
    
def dollar(value):
    if value is None:
        value = 0
    if value >= 1000 or value <= -1000:
        return f"${value:,.0f}"
    else:
        return usd(value)

def timestamp_editor(value):
    
    return value.strftime("%m/%d/%Y")

def initialize_money_record(db):
    user_id = session.get("user_id")
    money_record = Money.query.filter_by(user_id=user_id).first()
    if money_record is None:
        logging.debug("No existing money record found. Creating a new one.")
        money_record = Money(user_id=user_id, save=0, spend=0, give=0, expense=0)
        db.session.add(money_record)
        db.session.commit()
    return money_record

def calculate_totals_by_division(db, Transaction, user_id, division):
    # Calculate the total amount for transactions with the specified division
    total = (
        Transaction.query.with_entities(db.func.sum(Transaction.amount))
        .filter_by(user_id=user_id, division=division)
        .scalar()
    )
    return total or 0

def cycle_through_money_table(db, money_record):
    if money_record is None:
        logging.error("money_record is None in cycle_through_money_table")
        return

    user_id = session.get("user_id")
    if user_id is None:
        logging.error("User ID is None. Cannot proceed.")
        return

    divisions = ["save", "spend", "give", "invest", "expense"]

    for division in divisions:
        logging.debug(f"Processing transactions for division: {division}")

        # Calculate total amount for the division
        total = calculate_totals_by_division(db, Transaction, user_id, division)

        # Update the money record
        setattr(money_record, division, total)
        logging.debug(f"Updated {division} in money_record to {total}")

    db.session.commit()
    logging.debug("Money record updated successfully")


def calculateCategory(db, Transaction, label, money, category, bank_name, tag_objects, division, date=dt.datetime.now()):
    logging.debug(f"Calculating category: {label} with amount: {money} with date: {date}")
    logging.debug(f"division: { division } ")
    if not division:
        division = "none"
    user_id = session.get("user_id")
    if user_id is None:
        logging.error("User ID is None. Cannot proceed with calculation.")
        return
    
    logging.debug(f"User ID: {user_id}")
    try:  
        logging.debug(f"No existing category record found, creating a new one")
        if tag_objects:
            unique_tags = list({tag.id: tag for tag in tag_objects}.values())  # Filter duplicates
        else:
            unique_tags = []
        if date:
            date=date
        else:
            date=dt.datetime.now()
        if isinstance(date, str):
            date = datetime.strptime(date, '%m/%d/%Y')
        new_record = Transaction(user_id=user_id, amount=money, bank_name=bank_name, category=category, timestamp=dt.datetime.now(), date=date, division=division)
        if unique_tags:
            new_record.tags.extend(unique_tags)

        # Assign unique tags to the transaction
        db.session.add(new_record)
        db.session.commit()
        
        money_record = initialize_money_record(db)
        
        logging.debug(f"Updating existing money record: { money_record }")

        granularity = '%Y-%m-%d %H:%M:%S'
        _, _, last_record = process_data(granularity, Transaction)
     
        setattr(money_record, division, last_record)
        db.session.commit()

        logging.debug("Transaction committed successfully")

    except Exception as e:
        db.session.rollback()
        logging.error(f"Transaction failed and rolled back: {e}")
        raise

#calculate where money goes and what percentage goes there
def calculateAllMoney(db, Transaction, tag_objects, money, category, date, bank_name):
    logging.debug("Calculating all money allocations")
    
    savePercentage = Decimal('0.5')
    givePercentage = Decimal('0.2')
    spendPercentage = Decimal('0.2')
    investPercentage = Decimal('0.1')
    expensePercentage = Decimal('0')

    save_amount = money * float(savePercentage)
    give_amount = money * float(givePercentage)
    spend_amount = money * float(spendPercentage)
    invest_amount = money * float(investPercentage)
    expense_amount = money * float(expensePercentage)
    

    logging.debug(f"Save amount: {save_amount}")
    logging.debug(f"Give amount: {give_amount}")
    logging.debug(f"Spend amount: {spend_amount}")
    logging.debug(f"Invest amount: {invest_amount}")
    logging.debug(f"Expense amount: {expense_amount}")

    calculateCategory(db, Transaction, 'save', save_amount, bank_name=bank_name, division="save", tag_objects=tag_objects, category=category, date=date)
    calculateCategory(db, Transaction, 'give', give_amount, bank_name=bank_name, division="give", tag_objects=tag_objects, category=category, date=date)
    calculateCategory(db, Transaction, 'spend', spend_amount, bank_name=bank_name, division="spend", tag_objects=tag_objects, category=category, date=date)
    calculateCategory(db, Transaction, 'invest', invest_amount, bank_name=bank_name, division="invest", tag_objects=tag_objects, category=category, date=date)
    calculateCategory(db, Transaction, 'expense', expense_amount, bank_name=bank_name, division="expense", tag_objects=tag_objects, category=category, date=date)

def process_data(granularity, Transaction):
        user_id=session.get("user_id")
        amounts_query = Transaction.query.with_entities(Transaction.amount, Transaction.timestamp).order_by(Transaction.timestamp).filter_by(user_id=user_id).all()
        data = []
        unique_dates = set()
        cumulative = 0
        previous_date = None

        for amount, timestamp in amounts_query:
            date_str = timestamp.strftime(granularity)
            unique_dates.add(date_str)

            if previous_date is not None and date_str != previous_date:
                data.append({
                    'date': previous_date,
                    'cumulative_amount': cumulative
                })

            cumulative += amount
            previous_date = date_str

        if previous_date is not None:
            data.append({
                'date': previous_date,
                'cumulative_amount': cumulative
            })

        last_record = data[-1]['cumulative_amount'] if data else None
        
        

        return data, unique_dates, last_record 

    
def graph_records(Transaction):
    # Step 1: Check unique dates by day
    granularity = '%Y-%m-%d'
    data, unique_dates,_ = process_data(granularity, Transaction)

    # Step 2: If fewer than 5 unique days, check by date and time
    if len(unique_dates) < 4:
        granularity = '%Y-%m-%d %H:%M:%S'
        data, unique_dates,_ = process_data(granularity, Transaction)

    # Step 3: If more than 60 unique days, check by months
    elif len(unique_dates) > 60:
        granularity = '%Y-%m'
        data, unique_dates,_ = process_data(granularity, Transaction)


    cumulative_float = [float(entry['cumulative_amount']) for entry in data]
    unique_dates = sorted(list(unique_dates))

    return cumulative_float, unique_dates


def delete_record(db, record_id, Transaction):
    # Replace Money with the appropriate model if necessary
    try:
        user_id = session.get("user_id")
        logging.debug(f"delete record: {record_id}")
        record = Transaction.query.filter_by(id=record_id, user_id=user_id).first()
        db.session.delete(record)
        logging.debug(f"delete successful")
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logging.debug(f"delete not successful {e}")
        return str(e), 500

def populate_tags(db, user_id):
    logging.debug(f"populating table")
    new_tag_save = Tags(name='Save', color_id='#506680', status=True, user_id=user_id)
    new_tag_spend = Tags(name='Spend', color_id='#A1AAB3', status=True, user_id=user_id)
    new_tag_give = Tags(name='Give', color_id='#2E3D4B', status=True, user_id=user_id)
    new_tag_invest = Tags(name='Invest', color_id='#CBD7E3', status=True, user_id=user_id)
    new_tag_expense = Tags(name='Expense', color_id='#395B75', status=True, user_id=user_id)

    tags_to_add = [new_tag_save, new_tag_spend, new_tag_give, new_tag_invest, new_tag_expense]
    db.session.add_all(tags_to_add)
    db.session.commit()
    logging.debug(f"Tags populated for user ID: {user_id}")


