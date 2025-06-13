import os
import re
import logging
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify, Response
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from decimal import Decimal, InvalidOperation
from helpers import apology, login_required, lookup, usd, calculateAllMoney, calculateCategory, dollar, graph_records, timestamp_editor, exit_usd, cycle_through_money_table, delete_record, initialize_money_record, populate_tags
from models import db, Give, Spend, Save, Invest, Money, Expense, User, Tags, TagColor, Note, Goal, PlaidItem, Transaction
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime 
from sqlalchemy.inspection import inspect
from collections import defaultdict
from openai import OpenAI
from flask_login import current_user
import locale
from dotenv import load_dotenv
from plaid import Configuration, Environment
import plaid
from plaid.api import plaid_api
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from plaid.model.transactions_get_request_options import TransactionsGetRequestOptions
from apscheduler.schedulers.background import BackgroundScheduler
from plaid.model.transactions_get_request import TransactionsGetRequest
# Read env vars from .env file
import base64
import os
import datetime as dt
import json
import time
from datetime import date, timedelta
import uuid

from dotenv import load_dotenv
from flask import Flask, request, jsonify
import plaid
from plaid.model.payment_amount import PaymentAmount
from plaid.model.payment_amount_currency import PaymentAmountCurrency
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.recipient_bacs_nullable import RecipientBACSNullable
from plaid.model.payment_initiation_address import PaymentInitiationAddress
from plaid.model.payment_initiation_recipient_create_request import PaymentInitiationRecipientCreateRequest
from plaid.model.payment_initiation_payment_create_request import PaymentInitiationPaymentCreateRequest
from plaid.model.payment_initiation_payment_get_request import PaymentInitiationPaymentGetRequest
from plaid.model.link_token_create_request_payment_initiation import LinkTokenCreateRequestPaymentInitiation
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.user_create_request import UserCreateRequest
from plaid.model.consumer_report_user_identity import ConsumerReportUserIdentity
from plaid.model.asset_report_create_request import AssetReportCreateRequest
from plaid.model.asset_report_create_request_options import AssetReportCreateRequestOptions
from plaid.model.asset_report_user import AssetReportUser
from plaid.model.asset_report_get_request import AssetReportGetRequest
from plaid.model.asset_report_pdf_get_request import AssetReportPDFGetRequest
from plaid.model.auth_get_request import AuthGetRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from plaid.model.identity_get_request import IdentityGetRequest
from plaid.model.investments_transactions_get_request_options import InvestmentsTransactionsGetRequestOptions
from plaid.model.investments_transactions_get_request import InvestmentsTransactionsGetRequest
from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.investments_holdings_get_request import InvestmentsHoldingsGetRequest
from plaid.model.item_get_request import ItemGetRequest
from plaid.model.institutions_get_by_id_request import InstitutionsGetByIdRequest
from plaid.model.transfer_authorization_create_request import TransferAuthorizationCreateRequest
from plaid.model.transfer_create_request import TransferCreateRequest
from plaid.model.transfer_get_request import TransferGetRequest
from plaid.model.transfer_network import TransferNetwork
from plaid.model.transfer_type import TransferType
from plaid.model.transfer_authorization_user_in_request import TransferAuthorizationUserInRequest
from plaid.model.ach_class import ACHClass
from plaid.model.transfer_create_idempotency_key import TransferCreateIdempotencyKey
from plaid.model.transfer_user_address_in_request import TransferUserAddressInRequest
from plaid.model.signal_evaluate_request import SignalEvaluateRequest
from plaid.model.statements_list_request import StatementsListRequest
from plaid.model.link_token_create_request_statements import LinkTokenCreateRequestStatements
from plaid.model.link_token_create_request_cra_options import LinkTokenCreateRequestCraOptions
from plaid.model.statements_download_request import StatementsDownloadRequest
from plaid.model.consumer_report_permissible_purpose import ConsumerReportPermissiblePurpose
from plaid.model.cra_check_report_base_report_get_request import CraCheckReportBaseReportGetRequest
from plaid.model.cra_check_report_pdf_get_request import CraCheckReportPDFGetRequest
from plaid.model.cra_check_report_income_insights_get_request import CraCheckReportIncomeInsightsGetRequest
from plaid.model.cra_check_report_partner_insights_get_request import CraCheckReportPartnerInsightsGetRequest
from plaid.model.cra_pdf_add_ons import CraPDFAddOns
from plaid.api import plaid_api
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from forms import LoginForm, TransactionForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import base64
import json
from cryptography.fernet import Fernet
from flask_talisman import Talisman


logging.basicConfig(level=logging.WARNING)  # Only log WARNING and above

app = Flask(__name__)
load_dotenv()

PLAID_CLIENT_ID = os.getenv('PLAID_CLIENT_ID')
PLAID_SECRET = os.getenv('PLAID_SECRET')
PLAID_ENV = os.getenv('PLAID_ENV', 'production')
PLAID_PRODUCTS = os.getenv('PLAID_PRODUCTS', 'transactions').split(',')
PLAID_COUNTRY_CODES = os.getenv('PLAID_COUNTRY_CODES', 'US').split(',')


def empty_to_none(field):
    value = os.getenv(field)
    if value is None or len(value) == 0:
        return None
    return value

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    print("Received webhook:", data)  # Log the webhook data
    return jsonify({"status": "success"}), 200


if PLAID_ENV == 'sandbox':
    host = Environment.Sandbox

if PLAID_ENV == 'production':
    host = Environment.Production

# Parameters used for the OAuth redirect Link flow.
#
# Set PLAID_REDIRECT_URI to 'http://localhost:3000/'
# The OAuth redirect flow requires an endpoint on the developer's website
# that the bank website should redirect to. You will need to configure
# this redirect URI for your client ID through the Plaid developer dashboard
# at https://dashboard.plaid.com/team/api.
PLAID_REDIRECT_URI = empty_to_none('PLAID_REDIRECT_URI')

configuration = plaid.Configuration(
    host=host,
    api_key={
        'clientId': PLAID_CLIENT_ID,
        'secret': PLAID_SECRET,
        'plaidVersion': '2020-09-14',
        "webhook": "https://my-budget-buddy.com/webhook"
    }
)

api_client = plaid.ApiClient(configuration)
client = plaid_api.PlaidApi(api_client)

products = []
for product in PLAID_PRODUCTS:
    products.append(Products(product))


# We store the access_token in memory - in production, store it in a secure
# persistent data store.
access_token = None
# The payment_id is only relevant for the UK Payment Initiation product.
# We store the payment_id in memory - in production, store it in a secure
# persistent data store.
payment_id = None
# The transfer_id is only relevant for Transfer ACH product.
# We store the transfer_id in memory - in production, store it in a secure
# persistent data store.
transfer_id = None
# We store the user_token in memory - in production, store it in a secure
# persistent data store.
user_token = None

item_id = None


# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters['timestamp_editor'] = timestamp_editor

# Configure session to use filesystem (instead of signed cookies)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///money.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


# Session configuration
app.config["SESSION_TYPE"] = "filesystem" 
app.config["SESSION_PERMANENT"] = False  # Optional, set if needed
app.config["SESSION_USE_SIGNER"] = True  # Prevent tampering
app.config["SESSION_KEY_PREFIX"] = "sess:"  # Prefix session keys
app.config["SESSION_COOKIE_SECURE"] = True  # Only allow HTTPS
app.config["SESSION_USE_SIGNER"] = True 
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevents JavaScript from accessing session cookies
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Prevents CSRF attacks
app.config["WTF_CSRF_ENABLED"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
Session(app)

limiter = Limiter(
    get_remote_address,  # Uses the client's IP address to limit requests
    app=app,  # Attach to the Flask app
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
    storage_uri="memory://"  # In-memory rate limiting (use Redis for production)
)


db.init_app(app)
migrate = Migrate(app, db)

# Initialize SQLAlchemy
model_map = {
    "save": Save,
    "spend": Spend,
    "give": Give,
    "invest": Invest,
    "expense": Expense,
    "transactions": Transaction
}


# Create the database and tables
logging.basicConfig(level=logging.DEBUG)

# Create the database and tables
with app.app_context():
    db.create_all()
    print("Tables created successfully")

if __name__ == '__main__':
    app.run(debug=False, port=8080, use_reloader=False)
    
openai_api_key = OpenAI(
  api_key=os.getenv("OPENAI_API_KEY"))


def predict_transaction_category(transaction):
    """
    Uses OpenAI API to categorize a transaction as Save, Spend, Give, Expense, or Invest.
    """
    logging.info(f"Categorizing transaction ID: {transaction.id} | Amount: {transaction.amount} | Bank: {transaction.bank_account}")

    transaction_text = f"Transaction: {transaction.category}, Amount: {transaction.amount}, Tags: {transaction.tags}, Category: {transaction.category}, Bank: {transaction.bank_account}."
    logging.debug(f"Generated transaction text: {transaction_text}")
    completion = openai_api_key.chat.completions.create(
        model="gpt-4o-mini",
        store=True,
        messages=[
            {"role": "system", "content": "You categorize financial transactions into: Save, Spend, Give, Expense, or Invest. You MUST respond with ONLY one word, and nothing else. Do NOT include explanations."},
            {"role": "user", "content": f"Categorize this transaction: {transaction_text}"}  
        ]
        )
    
    # Extract the AI-generated response
    
    predicted_category = completion.choices[0].message.content.strip().lower()
    logging.warning(f"Received AI response: {predicted_category}")
    

    # Ensure the category is valid
    if predicted_category.lower() not in ["save", "spend", "give", "expense", "invest"]:
        logging.warning(f"Invalid category received: {predicted_category}. Defaulting to 'general'.")
        predicted_category = "general"

    return predicted_category

@app.route('/delete_data', methods=["GET", "POST"])
def delete_data():
    if request.method == "POST":
        category = request.form.get("category", "").lower()
        division_filter = request.form.get("division", "").lower()

        if not category:
            return render_template('delete_data.html', error="No category selected. Please choose a category.")

        try:
            if category == "tags":
                # Delete tags and related colors
                db.session.query(Tags).delete()
                db.session.query(TagColor).delete()
            elif category == "transactions":
                # Filter and delete from transactions
                query = db.session.query(Transaction)
                if division_filter:
                    query = query.filter_by(division=division_filter)
                deleted_count = query.delete()
                if deleted_count == 0:
                    return render_template('delete_data.html', error=f"No transactions found for division: {division_filter}")
            else:
                return render_template('delete_data.html', error=f"Invalid category: {category}")

            db.session.commit()
            success_message = f"All data deleted successfully for category: {category}"
            if category == "transactions" and division_filter:
                success_message = f"Transactions with division '{division_filter}' deleted successfully."
            return render_template('delete_data.html', success=success_message)
        except Exception as e:
            db.session.rollback()
            return render_template('delete_data.html', error=f"Failed to delete {category}: {e}")

    return render_template('delete_data.html')

    
csrf = CSRFProtect(app)
csrf.init_app(app)
@app.before_request
def set_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = generate_csrf()
        print("🔹 New CSRF Token Set:", session["csrf_token"])  # ✅ Debugging

@app.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrfToken": session["csrf_token"]})

# ✅ 4. Login Route with CSRF Protection
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])

@app.before_request
def refresh_session():
    session.permanent = True
    session.modified = True


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    form = LoginForm()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        logging.debug(f"Form CSRF: {form.csrf_token.data}")
        logging.debug(f"Session CSRF: {session.get('csrf_token')}")
    if form.validate_on_submit():  # ✅ Automatically validates CSRF token
        username = form.username.data  # Use form data instead of request.form
        password = form.password.data

        # Query the user by username
        user = User.query.filter_by(username=username).first()

        # Ensure username exists and password is correct
        if user is None or not check_password_hash(user.hash, password):
            error_message = "Incorrect username or password"
            return render_template("login.html", error_message=error_message)

        # Remember which user has logged in
        session.clear()
        session["user_id"] = user.id
        if "csrf_token" not in session:
            session["csrf_token"] = generate_csrf()
        # Populate tags and tag colors for the new user
        
        # Redirect user to home page
        return redirect("/")
        
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()
    session["csrf_token"] = generate_csrf()

    # Redirect user to login form
    return redirect("/login")

give_goal = 1000
@app.route("/register", methods=["GET", "POST"])
@csrf.exempt
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        error_message = None

        if User.query.filter_by(username=username).first() is not None:
            username_error = "Username already taken"
            return render_template("register.html", username_error=username_error)
   
        # Create new user
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, username=username, hash=password_hash)

        try:
            logging.debug(f"name: { name } username: { username } password: { password }")
            db.session.add(new_user)
            db.session.commit()
            
            user_id = new_user.id
            session["user_id"] = user_id

            # Populate tags and tag colors for the new user
            populate_tags(db, user_id)

            return redirect(url_for("profile_questions"))
        
        except Exception as e:
            db.session.rollback()
            error_message = f"An error occurred: {e}"
            return render_template("register.html")

    else:
        return render_template("register.html")

@app.route('/profile_questions', methods=["GET", "POST"])
@csrf.exempt
def profile_questions():
    if request.method == "POST":
        try:
            categories = ['save', 'spend', 'give', 'invest', 'expense']
            category = 'initial balance'
            bank_name = 'manual input'

            for category in categories:
                balance_key = f'starting_{category}_balance'
                label = category
                tag = category.capitalize()
                money_str = request.form.get(balance_key)

                if money_str is None:
                    raise ValueError(f"Starting balance for {category} is missing.")

                try:
                    money = Decimal(money_str)
                except InvalidOperation:
                    raise ValueError(f"Invalid starting balance for {category}.")

                calculateCategory(db, Transaction, label, money, category, bank_name, tag)

            db.session.commit()

            flash("Profile updated successfully.", "success")
            logging.debug("Profile updated successfully")

            return redirect("/login")
        
        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")
            logging.debug("error")
            return render_template("profile_questions.html")
        
    else:
        return render_template("profile_questions.html")
        
@app.route('/print_access_tokens', methods=['GET'])
@login_required
def print_access_tokens():
    user_id = session.get("user_id")  # Get the logged-in user's ID
    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    # Query all PlaidItem entries for the logged-in user
    plaid_items = PlaidItem.query.filter_by(user_id=user_id).all()

    # Print and return access tokens
    if plaid_items:
        access_tokens = [item.access_token for item in plaid_items]
        logging.debug(f"Access tokens for user {user_id}: {access_tokens}")
        return jsonify({"access_tokens": access_tokens})
    else:
        logging.debug(f"No access tokens found for user {user_id}")
        return jsonify({"message": "No access tokens found"})
    
@app.route('/', methods=["GET", "POST"])
@login_required
def index():
    user_id=session.get("user_id")
    form = TransactionForm()

    logging.debug("Index route accessed")
    moneyTable = Money.query.filter_by(user_id=user_id).first()
    category = request.form.get("category")
    division = request.form.get("division")
    form_id = request.form.get('form_id')

    selected_tags = request.form.get('tags[]')
    if selected_tags:
        selected_tags = json.loads(selected_tags)  # Convert JSON string back to list
        logging.debug(f"Selected tags: {selected_tags}")
        tag_objects = Tags.query.filter(Tags.name.in_(selected_tags)).all()
    else:
        logging.debug("No tags selected.")
        tag_objects = []

    if request.method == "POST":
        if form_id == 'transactionForm':
            label = request.form.get("division").lower() 
            amount = Decimal(request.form.get("recordedTransaction"))
            bank_name = "manual input"
            logging.debug(f"Form submitted with category: {label}")
            try:
                if label in model_map:
                    money = Decimal(request.form.get("recordedTransaction"))
                    category = request.form.get("category")
                    calculateCategory(db, Transaction, label, money, category, bank_name, tag_objects, division)
                else:
                    calculateAllMoney(db, Transaction, tag, amount, category, tag_objects=tag_objects, date=dt.datetime.now(), bank_name=bank_name)
                db.session.commit()
                logging.debug("Transaction committed successfully")
                return redirect("/")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Transaction failed and rolled back: {e}")
                return f"Transaction failed and rolled back: {e}", 500
        elif form_id == "transferForm":
            to_label = request.form.get("toCategory").lower()
            from_label = request.form.get("fromCategory").lower()
            bank_name = from_label
            try:
                if to_label in model_map and from_label in model_map:
                    money = Decimal(request.form.get("recordedTransaction"))
                    category = request.form.get("category")
                    calculateCategory(db, Transaction, to_label, money, category, bank_name, tag)
                    calculateCategory(db, Transaction, from_label, -money, category, bank_name="none", tag=tag)
                else:
                    calculateAllMoney(db, Transaction, tag, amount, category, tag_objects=tag_objects, date=dt.datetime.now(), bank_name=bank_name)
                    money = Decimal(request.form.get("recordedTransaction"))
                    calculateCategory(db, Transaction, from_label, -money, category, bank_name, tag)
                db.session.commit()
                logging.debug("Transaction committed successfully")
                return redirect("/")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Transaction failed and rolled back: {e}")
                return f"Transaction failed and rolled back: {e}", 500
        else:
            print("error")

    left_in_spend = moneyTable.spend if moneyTable else 0
    spend_tag_color = Tags.query.filter_by(user_id=user_id, name='Spend').first()
    spending_color = spend_tag_color.color_id if spend_tag_color else '#BBA2C8'
    
    logging.debug(f"Spend tag color from DB: {spending_color}")


    expense_records = Expense.query.filter_by(user_id=user_id).all()
    tag_counter = defaultdict(float)
    for record in expense_records:
        tag_counter[record.tag] += float(record.amount)

    tags_list = Tags.query.filter_by(user_id=user_id, status=True).all()
    tag_color_map = {tag.name: tag.color_id for tag in tags_list if tag.name}

    tag_details = {}
    for tag, count in tag_counter.items():
        if tag in tag_color_map:
            tag_details[tag] = {
                'count': count,
                'color': tag_color_map.get(tag, '#FFFFFF')  # Default color if not in tag_color_map
            }

    colors = [details['color'] for details in tag_details.values()]
    counts = [details['count'] for details in tag_details.values()]
    tag_names = [tag if tag else 'none' for tag in tag_details.keys()]
    
    return render_template("index.html", form=form, moneyTable=moneyTable, left_in_spend=left_in_spend, category=category, tags_list=tags_list, colors=colors, counts=counts, tag_names=tag_names, spending_color=spending_color)


@app.route('/Tracking', methods=["GET", "POST"])
@login_required
def tracking():
    user_id=session.get("user_id")
    money_record = initialize_money_record(db)
    cycle_through_money_table(db, money_record)
    
    moneyTable = Money.query.filter_by(user_id=user_id).first()
    save = moneyTable.save if moneyTable else 0
    spend = moneyTable.spend if moneyTable else 0
    give = moneyTable.give if moneyTable else 0
    invest = moneyTable.invest if moneyTable else 0
    expense = moneyTable.expense if moneyTable else 0

    save_float, save_dates = graph_records(Save)
    spend_float, spend_dates = graph_records(Spend)
    give_float, give_dates = graph_records(Give)
    invest_float, invest_dates = graph_records(Invest)
    expense_float, expense_dates = graph_records(Expense)

    return render_template('Tracking.html',
                       save_data=save_float, save_dates=save_dates,
                       spend_data=spend_float, spend_dates=spend_dates,
                       give_data=give_float, give_dates=give_dates,
                       invest_data=invest_float, invest_dates=invest_dates,
                       expense_data=expense_float, expense_dates=expense_dates, save=dollar(save), spend=dollar(spend), give=dollar(give), invest=dollar(invest), expense=dollar(expense))


@app.route('/Settings', methods=["GET", "POST"])
@login_required
def settings():
    return render_template('Settings.html')

@app.route('/History', methods=["GET", "POST"])
@login_required
def history():
    user_id = session.get("user_id")
    csrf_token=generate_csrf()
    print(f"Fetching history for user_id: {user_id}")
    
    tags_list = Tags.query.filter_by(user_id=user_id).all()
    print(f"Retrieved {len(tags_list)} tags for user_id: {user_id}")
    
    divisions_list = ['none', 'general', 'save', 'spend', 'give', 'invest', 'expense']
    
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date).all()
    print(f"Retrieved {len(transactions)} transactions for user_id: {user_id}")
 
    return render_template("history.html", transactions=transactions, tags_list=tags_list, divisions_list=divisions_list, csrf_token=csrf_token)

@app.route('/invest_history', methods=["GET", "POST"])
@login_required
def invest_history():
    invest_records = Invest.query.all()
    invest_records_data = []
    for record in invest_records:
        invest_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("invest_history.html", invest_records_data=invest_records_data)

@app.route('/save_history', methods=["GET", "POST"])
@login_required
def save_history():
    save_records = Save.query.all()
    save_records_data = []
    for record in save_records:
        save_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("save_history.html", save_records_data=save_records_data)


@app.route('/spend_history', methods=["GET", "POST"])
@login_required
def spend_history():
    spend_records = Spend.query.all()
    spend_records_data = []
    for record in spend_records:
        spend_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("spend_history.html", spend_records_data=spend_records_data)


@app.route('/give_history', methods=["GET", "POST"])
@login_required
def give_history():
    give_records = Give.query.all()
    give_records_data = []
    for record in give_records:
        give_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("give_history.html", give_records_data=give_records_data)

@app.route('/expense_history', methods=["GET", "POST"])
@login_required
def expense_history():
    expense_records = Expense.query.all()
    expense_records_data = []
    for record in expense_records:
        expense_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("expense_history.html", expense_records_data=expense_records_data)

@app.route('/transactions_history', methods=["GET", "POST"])
@login_required
def transactions_history():
    csrf_token=generate_csrf()
    expense_records = Expense.query.all()
    expense_records_data = []
    for record in expense_records:
        expense_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "bank_name": record.bank_name,
            "category": record.category,
            "timestamp": record.timestamp
        })
    return render_template("transactions_history.html", expense_records_data=expense_records_data, csrf_token=csrf_token)


@app.route('/update_record', methods=['POST'])
@login_required
def update_record():
    if request.method == "POST":
        tag = request.form.get('tag')
        category = request.form.get('category')
        record_id = request.form.get('record_id')
        amount = exit_usd(request.form.get('amount'))
        bank_name = request.form.get('bank_name')
        category = request.form.get('category')
        deleteBoolean = request.form.get('deleteBoolean')
        logging.debug(f"tag: {tag}")


        if deleteBoolean == "true":
            logging.debug(f"deleteBoolean is true")
            delete_record(db, record_id, Transaction)
            return redirect(url_for('history'))

        if not record_id:
            logging.debug(f"no record_id")
            return redirect(url_for('history'))

        if Transaction is None:
            logging.debug(f"model was none")
            return redirect(url_for('history'))

        record = Transaction.query.get_or_404(record_id)
        try:
            record.tag = tag
            record.amount = float(amount)
            record.bank_name = bank_name
            record.category = category
            db.session.commit()
    
        except Exception as e:
            db.session.rollback()

        return redirect(url_for('history'))

    return redirect(url_for('history'))

@app.route('/settings/general')
@login_required
def settings_general():
    return render_template('settings/general.html')

@app.route('/settings/tags', methods=["GET", "POST"])
@login_required
def tags():
    logging.debug(f"tags route called")
    user_id = session.get("user_id")
    tags = Tags.query.filter_by(user_id=user_id).all()
    tag_colors = TagColor.query.filter_by(user_id=user_id).all()
    csrf_token=generate_csrf()

    if request.method == "POST":
        # Update existing tags
        for tag in tags:
            tag_id = tag.id
            tag.color_id = request.form.get(f'color_{tag_id}')
            tag.name = request.form.get(f'tagName_{tag_id}')
            tag_status_field = f'tagStatus_{tag_id}'
            tag.status = tag_status_field in request.form
            db.session.commit()
        
        # Add new tag if it exists in the form
        if request.form.get('tagName_new'):
            new_tag = Tags(
                user_id=user_id,
                color_id=request.form.get('color_new'),
                name=request.form.get('tagName_new'),
                status='tagStatus_new' in request.form
            )
            db.session.add(new_tag)
            db.session.commit()

        return redirect(url_for('tags'))

    return render_template("settings/tags.html", tags=tags, tag_colors=tag_colors, csrf_token=csrf_token)
    
@app.route('/delete_tags', methods=["POST"])
@login_required
@csrf.exempt
def delete_tags():
    user_id = session.get("user_id")

    tag_select_data = []
    for tag in Tags.query.filter_by(user_id=user_id).all():
        if f"select_{tag.id}" in request.form:
            tag_select_data.append(tag.id)
    
    for tag_id in tag_select_data:
        tag = Tags.query.filter_by(id=tag_id, user_id=user_id).first()
        if tag:
            db.session.delete(tag)
            db.session.commit()
    return redirect(url_for('tags'))

@app.route('/add_tag', methods=['POST'])
@csrf.exempt
@login_required
def add_tag():
    user_id = session.get("user_id")
    logging.debug(f"New tag being added for { user_id }")

    new_tag_color = request.form.get('color_new')
    new_tag_name = request.form.get('tagName_new')
    new_tag_status= request.form.get('select_new')

    if new_tag_name and new_tag_color:
        new_tag = Tags(
            user_id=user_id,
            color_id=new_tag_color,  # Assuming color_id is a valid color hex valueX
            name=new_tag_name,
            status=True  # Set default status to active, adjust as needed
        )
    db.session.add(new_tag)
    db.session.commit()
    logging.debug(f"New tag added: {new_tag_name} with color {new_tag_color}")

    return redirect(url_for('tags'))

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user_id = session.get("user_id")
    user = User.query.filter_by(id=user_id).first()
    csrf_token = generate_csrf()
    error_message = None
    if request.method == "POST":
        form_id = request.form.get("form_id")

        # Handle Change Password Form
        if form_id == "change_password":
            old_password_input = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")

        # Ensure username exists and password is correct
        if not check_password_hash(user.hash, old_password_input):
            error_message = "Incorrect password"
            return render_template("settings/account.html", error_message=error_message)
        
        if new_password != confirmation:
            error_message = "Passwords must match"
            return render_template("settings/account.html", error_message=error_message)
        
        user.hash = generate_password_hash(new_password, method="pbkdf2:sha256")
        db.session.commit()
        flash("Password has been changed successfully!", "success")
        return redirect("account")
        
    else:
        return render_template("settings/account.html", csrf_token=csrf_token)

@app.route('/notes', methods=["GET", "POST"])
@login_required
def notes():
    user_id = session.get("user_id")
    csrf_token=generate_csrf()

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_note = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_note)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_notes = Note.query.filter_by(user_id=user_id).order_by(Note.timestamp.desc()).all()

    return render_template('notes.html', notes=user_notes, csrf_token=csrf_token)

@app.route('/add_note', methods=["POST"])
@login_required
def add_note():
    content = request.form.get("content")
    if content:
        note = Note(user_id=session["user_id"], content=content, timestamp=datetime.now())
        db.session.add(note)
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/update_note/<int:note_id>', methods=["POST"])
@login_required
def update_note(note_id):
    content = request.form.get("content")
    note = Note.query.filter_by(id=note_id, user_id=session["user_id"]).first()
    if note:
        note.content = content
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/delete_note/<int:note_id>', methods=["POST"])
@login_required
def delete_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=session["user_id"]).first()
    if note:
        db.session.delete(note)
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/goals', methods=["GET", "POST"])
@login_required
def goals():
    user_id = session.get("user_id")
    csrf_token = generate_csrf()

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_goal = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_goal)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_goals = Goal.query.filter_by(user_id=user_id).order_by(Goal.timestamp.desc()).all()

    return render_template('goals.html', goals=user_goals, csrf_token=csrf_token)

@app.route('/add_goal', methods=["POST"])
@login_required
def add_goal():
    content = request.form.get("content")
    if content:
        goal = Goal(user_id=session["user_id"], content=content, timestamp=datetime.now())
        db.session.add(goal)
        db.session.commit()
    return redirect(url_for("goals"))

@app.route('/update_goal/<int:goal_id>', methods=["POST"])
@login_required
def update_goal(goal_id):
    content = request.form.get("content")
    goal = Goal.query.filter_by(id=goal_id, user_id=session["user_id"]).first()
    if goal:
        goal.content = content
        db.session.commit()
    return redirect(url_for("goals"))

@app.route('/delete_goal/<int:goal_id>', methods=["POST"])
@login_required
def delete_goal(goal_id):
    goal = Goal.query.filter_by(id=goal_id, user_id=session["user_id"]).first()
    if goal:
        db.session.delete(goal)
        db.session.commit()
    return redirect(url_for("goals"))


@app.route('/resources', methods=["POST", "GET"])
@login_required
def resources():
    return render_template("resources.html")

@app.route('/verify')
def verify():
    user_id=session.get("user_id")
    # Query all records from each table
    money_records = Money.query.filter_by(user_id=user_id).all()
    user_records = User.query.all()
    tags = Tags.query.filter_by(user_id=user_id).all()
    tag_color = TagColor.query.filter_by(user_id=user_id).all()

    user_data = []
    for record in user_records:
        user_data.append({
            "id": record.id,
            "name": record.name,
            "hash": record.hash,
            "username": record.username,
        })


    money_data = []
    for money_record in money_records:
        money_data.append({
            "id": money_record.id,
            "user_id": money_record.user_id,
            "save": money_record.save,
            "spend": money_record.spend,
            "give": money_record.give,
            "invest": money_record.invest
        })

    tag_data = []
    for tag in tags:
        tag_data.append({
            "name": tag.id,
            "status": tag.status,
            
        })

    tag_color_data = []
    for TagColorData in tag_color:
        tag_color_data.append({
            "color_name": TagColorData.color_name,
            "color_hex": TagColorData.color_hex,
        })
    # Render the template with all the data
    return render_template("verify.html", tags=tags, tag_color=tag_color, user_data=user_data, money_data=money_data, tag_data=tag_data, tag_color_data=tag_color_data)

    

@app.route('/fetch_transactions', methods=['GET'])
@login_required
def fetch_transactions():
    user_id = session.get('user_id')  # Fetch the logged-in user's ID
    print(f"Fetching transactions for user_id: {user_id}")
    
    tags_list = Tags.query.filter_by(user_id=user_id).all()
    print(f"Retrieved {len(tags_list)} tags for user_id: {user_id}")
    
    if not user_id:
        print("User not logged in, redirecting to login page.")
        return redirect(url_for('login'))  # Redirect if not logged in

    # Query the database for transactions belonging to the user
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()
    print(f"Retrieved {len(transactions)} transactions for user_id: {user_id}")
    
    transaction = Transaction.query.filter_by(id=11).first()
    if transaction:
        print(f"Retrieved transaction ID: {transaction.id}")
    else:
        print("Transaction with ID 11 not found.")
    
    populate_tags(db, user_id)
    
    if transaction and transaction.tags:
        print(f"Transaction ID: {transaction.id} has the following tags:")
        for tag in transaction.tags:
            print(f"Tag ID: {tag.id}, Name: {tag.name}, Status: {tag.status}, Color ID: {tag.color_id}")
    else:
        print(f"Transaction ID: {transaction.id if transaction else 'Unknown'} has no tags.")
    
    # Pass transactions to the template
    return render_template('fetch_transactions.html', transactions=transactions, tags_list=tags_list)


@app.route('/update_transaction/<int:transaction_id>', methods=['POST'])
@login_required
def update_transaction(transaction_id):
    if request.method == "POST":
        logging.debug(f"Form data received: {request.form}")
        user_id = session.get('user_id')
        transaction = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first_or_404()

        try:
            tags_from_form = json.loads(request.form.get("tags", "[]"))
        except json.JSONDecodeError:
            tags_from_form = []

        
        # Existing tags
        existing_tags = {tag.name for tag in transaction.tags}

        # Combine new and existing tags
        all_tags = set(tags_from_form).union(existing_tags)

        division = request.form.get('division')
        if division == "none" or not division:  # Only categorize if empty
            predicted_category = predict_transaction_category(transaction)
            division = predicted_category
        record_id = transaction_id
        amount = exit_usd(request.form.get('amount'))
        bank_name = request.form.get('bank_name')
        deleteBoolean = request.form.get('deleteBoolean')
        date = request.form.get('date')
        category = request.form.get('category')
        logging.debug(f"tag: {tags}, amount: {amount}, bank_name: {bank_name}, deleteBoolean: {deleteBoolean}, division: {division}, date: {date}")
        date_str = request.form.get('date')  # Example: '01/02/2025'
        if date_str:
            date = datetime.strptime(date_str, '%m/%d/%Y')
        else:
            date = datetime.now()

        if deleteBoolean == "true":
            logging.debug(f"Delete request for transaction ID: {transaction_id}")
            # Find and delete the record
            record = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()
            if record:
                db.session.delete(record)
                db.session.commit()
                logging.debug(f"Transaction ID {transaction_id} deleted successfully.")
            else:
                logging.error(f"Transaction ID {transaction_id} not found.")
            return redirect(url_for('history'))


        if not record_id:
            logging.debug(f"no record_id")
            return redirect(url_for('history'))

        if Transaction is None:
            logging.debug(f"model was none")
            return redirect(url_for('history'))
        if division == "general":
            tag_objects = Tags.query.filter(Tags.name.in_(all_tags)).all()
            calculateAllMoney(db, Transaction, tag_objects, money=amount, date=date, bank_name=bank_name, category=category)
            
            # Fetch the current transaction and delete it after calculation
            record = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()
            if record:
                db.session.delete(record)
                db.session.commit()
                logging.debug(f"Transaction ID {transaction_id} deleted successfully.")
            else:
                logging.error(f"Transaction ID {transaction_id} not found.")
            return redirect(url_for('history'))
            
        
        record = Transaction.query.filter_by(id=record_id, user_id=user_id).first_or_404()

        try:
            record.amount = float(amount)
            record.bank_name = bank_name
            record.division = division
            record.tags.clear()  # Clear existing tags
            transaction.tags.clear()
            for tag_name in tags_from_form:
                tag = Tags.query.filter_by(name=tag_name, user_id=user_id).first()
                if tag:
                    transaction.tags.append(tag)



            db.session.commit()

        except Exception as e:
            db.session.rollback()

        return redirect(url_for('history'))
    return redirect(url_for('history')) 


@app.route('/api/info', methods=['POST'])
def info():
    global access_token
    global item_id
    return jsonify({
        'item_id': item_id,
        'access_token': access_token,
        'products': PLAID_PRODUCTS
    })


@app.route('/api/create_link_token_for_payment', methods=['POST'])
def create_link_token_for_payment():
    global payment_id
    try:
        request = PaymentInitiationRecipientCreateRequest(
            name='John Doe',
            bacs=RecipientBACSNullable(account='26207729', sort_code='560029'),
            address=PaymentInitiationAddress(
                street=['street name 999'],
                city='city',
                postal_code='99999',
                country='GB'
            )
        )
        response = client.payment_initiation_recipient_create(
            request)
        recipient_id = response['recipient_id']

        request = PaymentInitiationPaymentCreateRequest(
            recipient_id=recipient_id,
            reference='TestPayment',
            amount=PaymentAmount(
                PaymentAmountCurrency('GBP'),
                value=100.00
            )
        )
        response = client.payment_initiation_payment_create(
            request
        )
        pretty_print_response(response.to_dict())
        
        # We store the payment_id in memory for demo purposes - in production, store it in a secure
        # persistent data store along with the Payment metadata, such as userId.
        payment_id = response['payment_id']
        
        linkRequest = LinkTokenCreateRequest(
            # The 'payment_initiation' product has to be the only element in the 'products' list.
            products=[Products('payment_initiation')],
            client_name='Plaid Test',
            # Institutions from all listed countries will be shown.
            country_codes=list(map(lambda x: CountryCode(x), PLAID_COUNTRY_CODES)),
            language='en',
            user=LinkTokenCreateRequestUser(
                # This should correspond to a unique id for the current user.
                # Typically, this will be a user ID number from your application.
                # Personally identifiable information, such as an email address or phone number, should not be used here.
                client_user_id=str(time.time())
            ),
            payment_initiation=LinkTokenCreateRequestPaymentInitiation(
                payment_id=payment_id
            )
        )

        if PLAID_REDIRECT_URI!=None:
            linkRequest['redirect_uri']=PLAID_REDIRECT_URI
        linkResponse = client.link_token_create(linkRequest)
        pretty_print_response(linkResponse.to_dict())
        return jsonify(linkResponse.to_dict())
    except plaid.ApiException as e:
        return json.loads(e.body)


@app.route('/api/create_link_token', methods=['POST'])
def create_link_token():
    user_token = session.get('user_token')
    try:
        request = LinkTokenCreateRequest(
            products=products,
            client_name="Plaid Quickstart",
            country_codes=list(map(lambda x: CountryCode(x), PLAID_COUNTRY_CODES)),
            language='en',
            user=LinkTokenCreateRequestUser(
                client_user_id=str(time.time())
            )
        )
        if PLAID_REDIRECT_URI!=None:
            request['redirect_uri']=PLAID_REDIRECT_URI
        if Products('statements') in products:
            statements=LinkTokenCreateRequestStatements(
                end_date=date.today(),
                start_date=date.today()-timedelta(days=30)
            )
            request['statements']=statements

        cra_products = ["cra_base_report", "cra_income_insights", "cra_partner_insights"]
        if any(product in cra_products for product in PLAID_PRODUCTS):
            request['user_token'] = user_token
            request['consumer_report_permissible_purpose'] = ConsumerReportPermissiblePurpose('ACCOUNT_REVIEW_CREDIT')
            request['cra_options'] = LinkTokenCreateRequestCraOptions(
                days_requested=60
            )
    # create link token
        response = client.link_token_create(request)
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        print(e)
        return json.loads(e.body)

# Create a user token which can be used for Plaid Check, Income, or Multi-Item link flows
# https://plaid.com/docs/api/users/#usercreate
@app.route('/api/create_user_token', methods=['POST'])
def create_user_token():
    user_token = session.get('user_token')
    try:
        consumer_report_user_identity = None
        user_create_request = UserCreateRequest(
            # Typically this will be a user ID number from your application. 
            client_user_id="user_" + str(uuid.uuid4())
        )

        cra_products = ["cra_base_report", "cra_income_insights", "cra_partner_insights"]
        if any(product in cra_products for product in PLAID_PRODUCTS):
            consumer_report_user_identity = ConsumerReportUserIdentity(
                first_name="Harry",
                last_name="Potter",
                phone_numbers= ['+16174567890'],
                emails= ['harrypotter@example.com'],
                primary_address= {
                    "city": 'New York',
                    "region": 'NY',
                    "street": '4 Privet Drive',
                    "postal_code": '11111',
                    "country": 'US'
                }
            )
            user_create_request["consumer_report_user_identity"] = consumer_report_user_identity

        user_response = client.user_create(user_create_request)
        session['user_token'] = user_response['user_token']
        return jsonify(user_response.to_dict())
    except plaid.ApiException as e:
        print(e)
        return jsonify(json.loads(e.body)), e.status


# Exchange token flow - exchange a Link public_token for
# an API access_token
# https://plaid.com/docs/#exchange-token-flow


@app.route('/api/set_access_token', methods=['POST'])
def set_access_token():
    try:
        public_token = request.json.get('public_token')
        user_id = session.get('user_id')
        logging.debug(f"User Id: {user_id}")
        if not public_token:
            return jsonify({"error": "Missing public_token"}), 400

        # Exchange public token for access token
        exchange_request = ItemPublicTokenExchangeRequest(
            public_token=public_token
        )
        exchange_response = client.item_public_token_exchange(exchange_request)

        access_token = exchange_response['access_token']
        item_id = exchange_response['item_id']
        logging.debug(f"access_token: {access_token} item_id: {item_id}")

        # Fetch institution ID using the ItemGet endpoint
        item_request = ItemGetRequest(access_token=access_token)
        item_response = client.item_get(item_request).to_dict()
        logging.debug(f"item_request:{item_request} item_response: {item_response}")

        institution_id = item_response['item'].get('institution_id')
        if not institution_id:
            logging.warning("Institution ID not found in the item response.")
            return jsonify({"error": "Institution ID not found."}), 400

        # Fetch institution details using the institution_id
        institution_request = InstitutionsGetByIdRequest(
            institution_id=institution_id,
            country_codes=[CountryCode('US')]
        )
        institution_response = client.institutions_get_by_id(institution_request)
        institution_name = institution_response.institution.name

        # Check if the institution is already linked
        existing_item = PlaidItem.query.filter_by(user_id=user_id, institution_id=institution_id).first()
        if existing_item:
            logging.warning(f"Institution {institution_name} is already linked for user {user_id}. Updating token.")
            existing_item.access_token = access_token  # Update the existing token
            db.session.commit()
            return jsonify({"message": f"Access token updated for {institution_name}"}), 200

        # Add new PlaidItem to the database
        plaid_item = PlaidItem(
            user_id=user_id,
            access_token=access_token,
            item_id=item_id,
            institution_id=institution_id,
            institution_name=institution_name
        )
        logging.debug(f"Created PlaidItem: user_id={user_id}, institution_id={institution_id}")
        db.session.add(plaid_item)
        logging.debug("Added PlaidItem to session")
        db.session.commit()
        logging.debug(f"Access token set for institution {institution_name} (ID: {institution_id}).")

        logging.debug(f"Access token set for institution {institution_name} (ID: {institution_id}).")

        # Fetch transactions for this account
        transactions_response = get_transactions()
        if isinstance(transactions_response, Response):
            transactions_data = transactions_response.get_json()
        else:
            transactions_data = transactions_response 

        return jsonify({
            "access_token": access_token,
            "item_id": item_id,
            "institution_name": institution_name,
            "transactions": transactions_data
        })
    except plaid.ApiException as e:
        logging.error(f"Plaid API Error: {e}")
        return jsonify({"error": e.body}), e.status
    except Exception as e:
        logging.error(f"Unexpected Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# Retrieve ACH or ETF account numbers for an Item
# https://plaid.com/docs/#auth


@app.route('/api/auth', methods=['GET'])
def get_auth():
    try:
       request = AuthGetRequest(
            access_token=access_token
        )
       response = client.auth_get(request)
       pretty_print_response(response.to_dict())
       return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve Transactions for an Item
# https://plaid.com/docs/#transactions

@app.route('/delete_transactions', methods=['GET', 'POST'])
@login_required
def delete_transactions():
    try:
        # Confirm the user is authenticated
        user_id = session.get('user_id')
        if not user_id:
            logging.warning("Attempt to delete transactions without being logged in.")
            return jsonify({"error": "User not logged in"}), 401

        # Log the operation
        logging.info(f"User {user_id} is deleting all transactions.")

        # Retrieve all transactions for the user
        transactions_to_delete = Transaction.query.filter_by(user_id=user_id).all()

        # Clear all tag associations
        for transaction in transactions_to_delete:
            transaction.tags.clear()
        db.session.commit()  # Commit tag association removal first

        # Delete all transactions
        deleted_count = Transaction.query.filter_by(user_id=user_id).delete()
        db.session.commit()  # Commit transaction deletion

        logging.info(f"Successfully deleted {deleted_count} transactions and associated data from the database.")

        # Return a success response
        return jsonify({"status": "success", "deleted_count": deleted_count}), 200

    except Exception as e:
        logging.error(f"Error deleting transactions: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Failed to delete transactions"}), 500

    
@app.route('/delete_all_plaid_items', methods=['GET', 'POST'])
@login_required
def delete_all_plaid_items():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"error": "User not logged in"}), 401

        # Delete all records in the PlaidItem table
        deleted_count = PlaidItem.query.delete()
        db.session.commit()

        return jsonify({"status": "success", "deleted_count": deleted_count}), 200
    except Exception as e:
        logging.error(f"Error deleting all PlaidItems: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Failed to delete all PlaidItems"}), 500



@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    # Set cursor to empty to receive all historical updates

    # New transaction updates since "cursor"
    all_added = []
    all_modified = []
    all_removed = []
    new_transactions_count = 0
    duplicate_transactions_count = 0
    try:
        # Get the user ID from the session
        user_id = session.get('user_id')
        if not user_id:
            logging.warning("Attempted access to /api/transactions without being logged in.")
            return jsonify({"error": "User not logged in"}), 401
        logging.debug(f"User ID from session: {user_id}")

        # Fetch all access tokens for the user
        plaid_items = PlaidItem.query.filter_by(user_id=user_id).all()
        if not plaid_items:
            logging.warning(f"No Plaid items found for user {user_id}.")
            return jsonify({"error": "No access tokens found for user"}), 400

        logging.debug(f"Found {len(plaid_items)} Plaid items for user {user_id}.")
        

        # Iterate through each account and fetch transactions
        for plaid_item in plaid_items:
            access_token = plaid_item.access_token
            logging.debug(f"Found access token: {access_token}")
            cursor = plaid_item.cursor or ''
            # Get accounts for the current access_token
            bank_name = fetch_institution_name(access_token)
            account_details = get_accounts(access_token)  # Corrected function call

            if account_details is None:
                logging.warning(f"No accounts found for access token {access_token[:6]}...")
                continue  # Skip to the next item if no accounts are found

            # Store accounts in a dictionary for quick lookups
            accounts_map = {
                account['account_id']: {
                    "account_name": account['name'],  # Account name (e.g., "Checking")
                    "bank_name": bank_name            # Bank name (e.g., "Chase")
                }
                for account in account_details['accounts']
            }
            has_more = True

            while has_more:
                logging.debug(f"Fetching transactions for access token {plaid_item.access_token[:6]} with cursor: {cursor or 'initial sync'}")
                
                try:
                    request = TransactionsSyncRequest(
                        access_token=plaid_item.access_token,
                        cursor=cursor,
                    )
                    response = client.transactions_sync(request).to_dict()
                    
                    # Update cursor and save to the database
                    cursor = response.get('next_cursor', '')
                    plaid_item.cursor = cursor
                    db.session.add(plaid_item)
                    
                    has_more = response.get('has_more', False)

                    # Process transactions
                    all_added.extend(response.get('added', []))
                    all_modified.extend(response.get('modified', []))
                    all_removed.extend(response.get('removed', []))
                
                except plaid.ApiException as e:
                    logging.error(f"Plaid API error: {e}")
                    raise
            db.session.commit()

        # Save new transactions to the database
        for transaction in all_added:
            account_id = transaction.get('account_id')
            account_info = accounts_map.get(account_id, {})
            account_name = account_info.get("account_name", "Unknown Account")  # Extract the account name
            bank_name = account_info.get("bank_name", "Unknown Bank")  # Extract the bank name

            txn_id = transaction['transaction_id']
            existing_transaction = Transaction.query.filter_by(transaction_id=txn_id).first()
            
            if not existing_transaction:
                categories = transaction.get('category', [])
                if isinstance(categories, str):
                    categories = [categories]
                categories = [cat.strip() for cat in categories if cat.strip()]

                tag_objects = []
                for category in categories:
                    tag = Tags.query.filter_by(name=category, user_id=user_id).first()
                    if not tag:
                        tag = Tags(name=category, user_id=user_id)
                        db.session.add(tag)
                        db.session.commit()  # Commit to generate the tag ID
                    tag_objects.append(tag)

                new_transaction = Transaction(
                    user_id=user_id,
                    transaction_id=txn_id,
                    date=transaction['date'],
                    name=transaction['name'],
                    category=', '.join(categories),
                    amount=transaction['amount'],
                    account_id=account_id,
                    bank_account=account_name,
                    bank_name=bank_name,
                    pending=transaction.get('pending', False)
                )
                db.session.add(new_transaction)
                db.session.commit()  # Commit to assign the transaction ID

                with db.session.no_autoflush:
                    for tag in tag_objects:
                        if tag not in new_transaction.tags:
                            new_transaction.tags.append(tag)

                new_transactions_count += 1
            else:
                duplicate_transactions_count += 1

        db.session.commit()
        logging.info(f"Committed {new_transactions_count} new transactions to the database.")

        # Fetch and combine all transactions across all accounts
        all_transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()
        for transaction in all_transactions:
            print(f"Transaction ID: {transaction.transaction_id}, Amount: {transaction.amount}")
        
        logging.debug(f"Fetched {len(all_transactions)} total transactions for user {user_id}.")

        recent_transactions_list = [
            {
                "transaction_id": txn.transaction_id,
                "date": txn.date.strftime('%Y-%m-%d'),
                "name": txn.name,
                "category": txn.category,
                "amount": txn.amount
            }
            for txn in all_transactions[:10]  # Ensure transactions are objects, not Response
]

        return jsonify({
            "status": "success",
            "new_transactions": new_transactions_count,
            "duplicate_transactions": duplicate_transactions_count,
            "recent_transactions": recent_transactions_list
        })

    except plaid.ApiException as e:
        logging.error(f"Plaid API Exception: {e}")
        error_response = format_error(e)
        return jsonify(error_response), 500
    except Exception as e:
        logging.error(f"Unexpected Error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/refresh_transactions', methods=['POST'])
@login_required
def refresh_transactions():
    try:
        # Call the get_transactions function
        csrf_token=generate_csrf()
        get_transactions()
        return jsonify({"status": "success", "message": "Transactions refreshed successfully"}), 200
    except Exception as e:
        logging.error(f"Error refreshing transactions: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Failed to refresh transactions"}), 500


@app.route('/api/identity', methods=['GET'])
def get_identity():
    try:
        request = IdentityGetRequest(
            access_token=access_token
        )
        response = client.identity_get(request)
        pretty_print_response(response.to_dict())
        return jsonify(
            {'error': None, 'identity': response.to_dict()['accounts']})
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


@app.route('/api/fetch_institution_name', methods=['GET'])
def fetch_institution_name(access_token):
    try:
        # Use the access token to fetch the item details
        item_request = ItemGetRequest(access_token=access_token)
        item_response = client.item_get(item_request)
        institution_id = item_response['item']['institution_id']

        if not institution_id:
            logging.warning(f"No institution ID found for access token {access_token[:6]}...")
            return "Unknown Bank"

        # Add the required country codes
        institution_request = InstitutionsGetByIdRequest(
            institution_id=institution_id,
            country_codes=[CountryCode('US')]  # Specify the relevant country code(s)
        )
        institution_response = client.institutions_get_by_id(institution_request)
        return institution_response['institution']['name']
    except plaid.ApiException as e:
        logging.error(f"Error fetching institution name: {e}")
        return "Unknown Bank"

@app.route('/api/balance', methods=['GET'])
def get_balance():
    try:
        request = AccountsBalanceGetRequest(
            access_token=access_token
        )
        response = client.accounts_balance_get(request)
        pretty_print_response(response.to_dict())
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve an Item's accounts
# https://plaid.com/docs/#accounts


@app.route('/api/accounts', methods=['GET'])
def get_accounts(access_token):
    try:
        request = AccountsGetRequest(access_token=access_token)
        response = client.accounts_get(request)  # This is a Response object
        return response.to_dict()  # Convert it to a dictionary
    except plaid.ApiException as e:
        logging.error(f"Plaid API error while fetching accounts: {e}")
        return None


# Create and then retrieve an Asset Report for one or more Items. Note that an
# Asset Report can contain up to 100 items, but for simplicity we're only
# including one Item here.
# https://plaid.com/docs/#assets


@app.route('/api/assets', methods=['GET'])
def get_assets():
    try:
        request = AssetReportCreateRequest(
            access_tokens=[access_token],
            days_requested=60,
            options=AssetReportCreateRequestOptions(
                webhook='https://www.example.com',
                client_report_id='123',
                user=AssetReportUser(
                    client_user_id='789',
                    first_name='Jane',
                    middle_name='Leah',
                    last_name='Doe',
                    ssn='123-45-6789',
                    phone_number='(555) 123-4567',
                    email='jane.doe@example.com',
                )
            )
        )

        response = client.asset_report_create(request)
        pretty_print_response(response.to_dict())
        asset_report_token = response['asset_report_token']

        # Poll for the completion of the Asset Report.
        request = AssetReportGetRequest(
            asset_report_token=asset_report_token,
        )
        response = poll_with_retries(lambda: client.asset_report_get(request))
        asset_report_json = response['report']

        request = AssetReportPDFGetRequest(
            asset_report_token=asset_report_token,
        )
        pdf = client.asset_report_pdf_get(request)
        return jsonify({
            'error': None,
            'json': asset_report_json.to_dict(),
            'pdf': base64.b64encode(pdf.read()).decode('utf-8'),
        })
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve investment holdings data for an Item
# https://plaid.com/docs/#investments


@app.route('/api/holdings', methods=['GET'])
def get_holdings():
    try:
        request = InvestmentsHoldingsGetRequest(access_token=access_token)
        response = client.investments_holdings_get(request)
        pretty_print_response(response.to_dict())
        return jsonify({'error': None, 'holdings': response.to_dict()})
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve Investment Transactions for an Item
# https://plaid.com/docs/#investments


@app.route('/api/investments_transactions', methods=['GET'])
def get_investments_transactions():
    # Pull transactions for the last 30 days

    start_date = (dt.datetime.now() - dt.timedelta(days=(30)))
    end_date = dt.datetime.now()
    try:
        options = InvestmentsTransactionsGetRequestOptions()
        request = InvestmentsTransactionsGetRequest(
            access_token=access_token,
            start_date=start_date.date(),
            end_date=end_date.date(),
            options=options
        )
        response = client.investments_transactions_get(
            request)
        pretty_print_response(response.to_dict())
        return jsonify(
            {'error': None, 'investments_transactions': response.to_dict()})

    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# This functionality is only relevant for the ACH Transfer product.
# Authorize a transfer

@app.route('/api/transfer_authorize', methods=['GET'])
def transfer_authorization():
    global authorization_id 
    global account_id
    request = AccountsGetRequest(access_token=access_token)
    response = client.accounts_get(request)
    account_id = response['accounts'][0]['account_id']
    try:
        request = TransferAuthorizationCreateRequest(
            access_token=access_token,
            account_id=account_id,
            type=TransferType('debit'),
            network=TransferNetwork('ach'),
            amount='1.00',
            ach_class=ACHClass('ppd'),
            user=TransferAuthorizationUserInRequest(
                legal_name='FirstName LastName',
                email_address='foobar@email.com',
                address=TransferUserAddressInRequest(
                    street='123 Main St.',
                    city='San Francisco',
                    region='CA',
                    postal_code='94053',
                    country='US'
                ),
            ),
        )
        response = client.transfer_authorization_create(request)
        pretty_print_response(response.to_dict())
        authorization_id = response['authorization']['id']
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# Create Transfer for a specified Transfer ID

@app.route('/api/transfer_create', methods=['GET'])
def transfer():
    try:
        request = TransferCreateRequest(
            access_token=access_token,
            account_id=account_id,
            authorization_id=authorization_id,
            description='Debit')
        response = client.transfer_create(request)
        pretty_print_response(response.to_dict())
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

@app.route('/api/statements', methods=['GET'])
def statements():
    try:
        request = StatementsListRequest(access_token=access_token)
        response = client.statements_list(request)
        pretty_print_response(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)
    try:
        request = StatementsDownloadRequest(
            access_token=access_token,
            statement_id=response['accounts'][0]['statements'][0]['statement_id']
        )
        pdf = client.statements_download(request)
        return jsonify({
            'error': None,
            'json': response.to_dict(),
            'pdf': base64.b64encode(pdf.read()).decode('utf-8'),
        })
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)




@app.route('/api/signal_evaluate', methods=['GET'])
def signal():
    global account_id
    request = AccountsGetRequest(access_token=access_token)
    response = client.accounts_get(request)
    account_id = response['accounts'][0]['account_id']
    try:
        request = SignalEvaluateRequest(
            access_token=access_token,
            account_id=account_id,
            client_transaction_id='txn1234',
            amount=100.00)
        response = client.signal_evaluate(request)
        pretty_print_response(response.to_dict())
        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# This functionality is only relevant for the UK Payment Initiation product.
# Retrieve Payment for a specified Payment ID


@app.route('/api/payment', methods=['GET'])
def payment():
    global payment_id
    try:
        request = PaymentInitiationPaymentGetRequest(payment_id=payment_id)
        response = client.payment_initiation_payment_get(request)
        pretty_print_response(response.to_dict())
        return jsonify({'error': None, 'payment': response.to_dict()})
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve high-level information about an Item
# https://plaid.com/docs/#retrieve-item


@app.route('/api/item', methods=['GET'])
def item():
    try:
        request = ItemGetRequest(access_token=access_token)
        response = client.item_get(request)
        request = InstitutionsGetByIdRequest(
            institution_id=response['item']['institution_id'],
            country_codes=list(map(lambda x: CountryCode(x), PLAID_COUNTRY_CODES))
        )
        institution_response = client.institutions_get_by_id(request)
        pretty_print_response(response.to_dict())
        pretty_print_response(institution_response.to_dict())
        return jsonify({'error': None, 'item': response.to_dict()[
            'item'], 'institution': institution_response.to_dict()['institution']})
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# Retrieve CRA Base Report and PDF
# Base report: https://plaid.com/docs/check/api/#cracheck_reportbase_reportget
# PDF: https://plaid.com/docs/check/api/#cracheck_reportpdfget
@app.route('/api/cra/get_base_report', methods=['GET'])
def cra_check_report():
    try:
        get_response = poll_with_retries(lambda: client.cra_check_report_base_report_get(
            CraCheckReportBaseReportGetRequest(user_token=user_token, item_ids=[])
        ))
        pretty_print_response(get_response.to_dict())

        pdf_response = client.cra_check_report_pdf_get(
            CraCheckReportPDFGetRequest(user_token=user_token)
        )
        return jsonify({
            'report': get_response.to_dict()['report'],
            'pdf': base64.b64encode(pdf_response.read()).decode('utf-8')
        })
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# Retrieve CRA Income Insights and PDF with Insights
# Income insights: https://plaid.com/docs/check/api/#cracheck_reportincome_insightsget
# PDF w/ income insights: https://plaid.com/docs/check/api/#cracheck_reportpdfget
@app.route('/api/cra/get_income_insights', methods=['GET'])
def cra_income_insights():
    try:
        get_response = poll_with_retries(lambda: client.cra_check_report_income_insights_get(
            CraCheckReportIncomeInsightsGetRequest(user_token=user_token))
        )
        pretty_print_response(get_response.to_dict())

        pdf_response = client.cra_check_report_pdf_get(
            CraCheckReportPDFGetRequest(user_token=user_token, add_ons=[CraPDFAddOns('cra_income_insights')]),
        )

        return jsonify({
            'report': get_response.to_dict()['report'],
            'pdf': base64.b64encode(pdf_response.read()).decode('utf-8')
        })
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# Retrieve CRA Partner Insights
# https://plaid.com/docs/check/api/#cracheck_reportpartner_insightsget
@app.route('/api/cra/get_partner_insights', methods=['GET'])
def cra_partner_insights():
    try:
        response = poll_with_retries(lambda: client.cra_check_report_partner_insights_get(
            CraCheckReportPartnerInsightsGetRequest(user_token=user_token)
        ))
        pretty_print_response(response.to_dict())

        return jsonify(response.to_dict())
    except plaid.ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

# Since this quickstart does not support webhooks, this function can be used to poll
# an API that would otherwise be triggered by a webhook.
# For a webhook example, see
# https://github.com/plaid/tutorial-resources or
# https://github.com/plaid/pattern
def poll_with_retries(request_callback, ms=1000, retries_left=20):
    while retries_left > 0:
        try:
            return request_callback()
        except plaid.ApiException as e:
            response = json.loads(e.body)
            if response['error_code'] != 'PRODUCT_NOT_READY':
                raise e
            elif retries_left == 0:
                raise Exception('Ran out of retries while polling') from e
            else:
                retries_left -= 1
                time.sleep(ms / 1000)

def pretty_print_response(response):
  print(json.dumps(response, indent=2, sort_keys=True, default=str))

def format_error(e):
    response = json.loads(e.body)
    return {'error': {'status_code': e.status, 'display_message':
                      response['error_message'], 'error_code': response['error_code'], 'error_type': response['error_type']}}


def delete_old_data():
    """Delete transactions older than retention period"""
    with app.app_context():
        retention_period = 365  # ✅ Keep transactions for 1 year
        cutoff_date = datetime.utcnow() - timedelta(days=retention_period)

        # ✅ Delete old transactions
        deleted_transactions = Transaction.query.filter(Transaction.date < cutoff_date).delete()

        # ✅ Delete old PlaidItem entries for deleted users
        deleted_items = PlaidItem.query.filter(PlaidItem.created_at < cutoff_date).delete()

        db.session.commit()
        print(f"Deleted {deleted_transactions} transactions and {deleted_items} Plaid items")

# ✅ Run every 24 hours


scheduler = BackgroundScheduler()
scheduler.add_job(delete_old_data, 'interval', hours=24)
scheduler.start()

@app.route('/delete_user_data', methods=['POST'])
@login_required
def delete_user_data():
    """Delete all user data on request"""
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    try:
        # ✅ Delete transactions
        Transaction.query.filter_by(user_id=user_id).delete()
        
        # ✅ Delete Plaid-linked data
        PlaidItem.query.filter_by(user_id=user_id).delete()

        # ✅ Delete user account
        User.query.filter_by(id=user_id).delete()

        db.session.commit()
        session.clear()  # Log user out
        return jsonify({"status": "success", "message": "User data deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500