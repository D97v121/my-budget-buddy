import csv
import datetime
import pytz
import requests
import urllib
import uuid
import decimal
import os
import re
import json
import logging
from cs50 import SQL
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from decimal import Decimal

from flask import redirect, render_template, request, session
from functools import wraps
from models import Save, Give, Spend, Invest, Money, Expense, Tags, TagColor

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
        money_record = Money(user_id=user_id, save=0, spend=0, give=0)
        db.session.add(money_record)
        db.session.commit()
    return money_record


def process_data(granularity, LabelModel):
        user_id=session.get("user_id")
        amounts_query = LabelModel.query.with_entities(LabelModel.amount, LabelModel.timestamp).order_by(LabelModel.timestamp).filter_by(user_id=user_id).all()
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

def cycle_through_money_table(db, money_record):
    granularity = '%Y-%m-%d %H:%M:%S'

    for label, model_class in model_map.items():
        logging.debug(f"Processing data for {label} model")

        if money_record is None:
            logging.error("money_record is None in cycle_through_money_table")
            
        
        # Call the process_data function
        _, _, last_record = process_data(granularity, model_class)
        
        # Update the money record with the last_record
        
        setattr(money_record, label, last_record)
        logging.debug(f"{money_record} recorded successfully")
        db.session.commit()

    

def calculateCategory(db, LabelModel, label, money, description, root, tag):
    logging.debug(f"Calculating category: {label} with amount: {money}")
    logging.debug(f"description: { description } ")
    if not description:
        description = "none"
    user_id = session.get("user_id")
    if user_id is None:
        logging.error("User ID is None. Cannot proceed with calculation.")
        return
    
    logging.debug(f"User ID: {user_id}")
    try:
        
        logging.debug(f"No existing category record found, creating a new one")
        new_category_record = LabelModel(user_id=user_id, amount=money, root=root, description=description, tag=tag)
        db.session.add(new_category_record)
        db.session.commit()
        
        money_record = initialize_money_record(db)
        
        logging.debug(f"Updating existing money record: { money_record }")

        granularity = '%Y-%m-%d %H:%M:%S'
        _, _, last_record = process_data(granularity, LabelModel)
     
        setattr(money_record, label, last_record)
        db.session.commit()

        logging.debug("Transaction committed successfully")

    except Exception as e:
        db.session.rollback()
        logging.error(f"Transaction failed and rolled back: {e}")
        raise

#calculate where money goes and what percentage goes there
def calculateAllMoney(db, Money, tag):
    logging.debug("Calculating all money allocations")
    description = request.form.get("transaction_description")
    savePercentage = Decimal('0.5')
    givePercentage = Decimal('0.2')
    spendPercentage = Decimal('0.2')
    investPercentage = Decimal('0.1')
    expensePercentage = Decimal('0')

    money = Decimal(request.form.get("recordedTransaction"))

    save_amount = money * savePercentage
    give_amount = money * givePercentage
    spend_amount = money * spendPercentage
    invest_amount = money * investPercentage
    expense_amount = money * expensePercentage
    

    logging.debug(f"Save amount: {save_amount}")
    logging.debug(f"Give amount: {give_amount}")
    logging.debug(f"Spend amount: {spend_amount}")
    logging.debug(f"Invest amount: {invest_amount}")
    logging.debug(f"Expense amount: {expense_amount}")

    calculateCategory(db, Save, 'save', save_amount, description, root="external", tag=tag)
    calculateCategory(db, Give, 'give', give_amount, description, root="external", tag=tag)
    calculateCategory(db, Spend, 'spend', spend_amount, description, root="external", tag=tag)
    calculateCategory(db, Invest, 'invest', invest_amount, description, root="external", tag=tag)
    calculateCategory(db, Expense, 'expense', expense_amount, description, root="external", tag=tag)

def graph_records(LabelModel):

    # Step 1: Check unique dates by day
    granularity = '%Y-%m-%d'
    data, unique_dates,_ = process_data(granularity, LabelModel)

    # Step 2: If fewer than 5 unique days, check by date and time
    if len(unique_dates) < 4:
        granularity = '%Y-%m-%d %H:%M:%S'
        data, unique_dates,_ = process_data(granularity, LabelModel)

    # Step 3: If more than 60 unique days, check by months
    elif len(unique_dates) > 60:
        granularity = '%Y-%m'
        data, unique_dates,_ = process_data(granularity, LabelModel)


    cumulative_float = [float(entry['cumulative_amount']) for entry in data]
    unique_dates = sorted(list(unique_dates))

    return cumulative_float, unique_dates


def delete_record(db, record_id, LabelModel):
    # Replace Money with the appropriate model if necessary
    try:
        user_id = session.get("user_id")
        logging.debug(f"delete record: {record_id}")
        record = LabelModel.query.filter_by(id=record_id, user_id=user_id).first()
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


