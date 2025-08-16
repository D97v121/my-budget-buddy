import os
import re
import logging
from flask import Flask, flash, redirect, render_template, request as flask_request, session, url_for, jsonify, Response
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from decimal import Decimal, InvalidOperation
from app.helpers import apology, classify_transaction_amount, edit_transaction_name, login_required, lookup, usd, calculateAllMoney, calculateCategory, dollar, graph_records, timestamp_editor, exit_usd, cycle_through_money_table, delete_record, initialize_money_record, populate_tags
from app import db
from app.models.user import User
from app.models.money import Money
from app.models.division_models import Save, Spend, Give, Invest, Expense
from app.models.tag import Tags, TagColor, transaction_tags
from app.models.note import Note
from app.models.goal import Goal
from app.models.plaid import PlaidItem
from app.models.transaction import Transaction
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime 
from plaid.configuration import Configuration, Environment
from sqlalchemy.inspection import inspect
from collections import defaultdict
from openai import OpenAI
from flask_login import current_user
import locale
from plaid.api_client import ApiClient
from sqlalchemy import extract
from dotenv import load_dotenv
import plaid
from plaid.api import plaid_api
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.transactions_sync_request import TransactionsSyncRequest
from plaid.model.transactions_get_request_options import TransactionsGetRequestOptions
from apscheduler.schedulers.background import BackgroundScheduler
from plaid.model.transactions_get_request import TransactionsGetRequest
from plaid.exceptions import ApiException
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
from app.forms import LoginForm, TransactionForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import base64
import json
from cryptography.fernet import Fernet
from sqlalchemy import func, case
from collections import defaultdict
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

configuration = Configuration(
    host=Environment.Production,
    api_key={
        'clientId': PLAID_CLIENT_ID,
        'secret': PLAID_SECRET,
        'plaidVersion': '2020-09-14',
        "webhook": "https://my-budget-buddy.com/webhook"
    }
)

api_client = ApiClient(configuration)
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

print(f"Using Client ID: {PLAID_CLIENT_ID}")
print(f"Using Secret: {PLAID_SECRET[:4]}...")  # for security, don't print full secret
print(f"Using Environment: {PLAID_ENV}")

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
    direction = "INFLOW" if transaction.amount > 0 else "OUTFLOW"
    transaction_text = f"Transaction: {transaction.category}, Amount: {transaction.amount}, Tags: {transaction.tags}, Category: {transaction.category}, Bank: {transaction.bank_account}, Direction: {direction}."
    logging.debug(f"Generated transaction text: {transaction_text}")
    completion = openai_api_key.chat.completions.create(
        model="gpt-4o-mini",
        store=True, 
        messages=[{
            "role": "system",
                "content": (
                    "You are an expert financial assistant. You will categorize bank transactions "
                    "into one of exactly five categories: Save, Spend, Give, Expense, or Invest.\n\n"
                    "Definitions:\n"
                    "- Save: incoming money set aside for future use (e.g., savings transfers)\n"
                    "- Invest: money allocated for returns (e.g., stock purchases, brokerage transfers)\n"
                    "- Give: charitable or personal giving (e.g., donations, gifts to others)\n"
                    "- Expense: reacurring outgoing charges (don't assign this to a transaction unless you see a consistent monthy charge or it says 'subscription' in the name)\n"
                    "- Spend: non-essential outgoing or discretionary purchases (e.g., restaurants, shopping). incoming transactions can also be put in the spend category when small amounts of money are added to a user's accountr\n\n"
                    "RULES:\n"
                    "- Respond with only ONE WORD: Save, Spend, Give, Expense, or Invest.\n"
                    "- Do NOT include any explanation or punctuation.\n"
                    "- If unclear, make your best guess."
                )
            },
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

csrf = CSRFProtect()
csrf.init_app(app)
"""
@app.before_request
def set_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = generate_csrf()
        print("🔹 New CSRF Token Set:", session["csrf_token"])  # ✅ Debugging
"""
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
            return render_template("login.html", form=form, error_message=error_message)

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
            user_id = session.get('user_id')
            if not user_id:
                raise ValueError("User not logged in.")

            user = User.query.get(user_id)
            if not user:
                raise ValueError("User not found.")

            # Get and validate percentages
            save = request.form.get("save_income_percentage")
            spend = request.form.get("spend_income_percentage")
            give = request.form.get("give_income_percentage")
            invest = request.form.get("invest_income_percentage")
            expense = request.form.get("expense_income_percentage")

            if not all([save, spend, give, invest, expense]):
                raise ValueError("All percentages must be provided.")

            try:
                save = Decimal(save)
                spend = Decimal(spend)
                give = Decimal(give)
                invest = Decimal(invest)
                expense = Decimal(expense)
            except InvalidOperation:
                raise ValueError("Invalid percentage format.")

            total = save + spend + give + invest + expense
            if total != Decimal(100):
                raise ValueError("Percentages must add up to 100.")

            # Update user record
            user.savePercentage = save
            user.spendPercentage = spend
            user.givePercentage = give
            user.investPercentage = invest
            user.expensePercentage = expense

            db.session.commit()

            flash("Profile updated successfully.", "success")
            logging.debug("Profile updated successfully")

            return redirect("/login")

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")
            logging.debug(f"Error: {e}")
            return render_template("profile_questions.html")

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
    


@app.route('/Tracking', methods=["GET", "POST"])
@login_required
def tracking():
    user_id = session.get("user_id")

    # Aggregate totals for each division
    totals = db.session.query(
        Transaction.division,
        func.sum(Transaction.amount)
    ).filter_by(user_id=user_id).group_by(Transaction.division).all()

    total_dict = defaultdict(float, {division.lower(): amount for division, amount in totals})

    unique_dates_count = db.session.query(
        func.count(func.distinct(func.strftime('%Y-%m-%d', Transaction.date)))
    ).filter(Transaction.user_id == user_id).scalar()

    date_format = "%Y-%m-%d" if unique_dates_count <= 30 else "%Y-%m"

    # Get time-series data for graphs
    def get_graph_data_for_division(division_name):
        results = db.session.query(
            func.strftime(date_format, Transaction.date).label('period'),
            func.sum(Transaction.amount)
        ).filter_by(user_id=user_id, division=division_name)\
         .group_by('period').order_by('period').all()

        running_total = 0
        dates = []
        values = []

        for period, amount in results:
            running_total += amount
            dates.append(period)
            values.append(running_total)

        return values, dates

    save_float, save_dates = get_graph_data_for_division("save")
    spend_float, spend_dates = get_graph_data_for_division("spend")
    give_float, give_dates = get_graph_data_for_division("give")
    invest_float, invest_dates = get_graph_data_for_division("invest")
    expense_float, expense_dates = get_graph_data_for_division("expense")

    print(spend_float, spend_dates)

    return render_template('Tracking.html',
                           save_data=save_float, save_dates=save_dates,
                           spend_data=spend_float, spend_dates=spend_dates,
                           give_data=give_float, give_dates=give_dates,
                           invest_data=invest_float, invest_dates=invest_dates,
                           expense_data=expense_float, expense_dates=expense_dates,
                           save=usd(total_dict["save"]),
                           spend=usd(total_dict["spend"]),
                           give=usd(total_dict["give"]),
                           invest=usd(total_dict["invest"]),
                           expense=usd(total_dict["expense"]))

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
    
    user_id=session.get("user_id")
    form = TransactionForm()

    
    tags_list = Tags.query.filter_by(user_id=user_id).all()
    print(f"Retrieved {len(tags_list)} tags for user_id: {user_id}")
    
    divisions_list = ['none', 'general', 'save', 'spend', 'give', 'invest', 'expense']
    
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp).all()
    print("Transaction timestamps in order:")
    for txn in transactions:
        print(f"{txn.id}: {txn.timestamp} — {txn.name}")

    
    return render_template("history.html", transactions=transactions, tags_list=tags_list, divisions_list=divisions_list, csrf_token=csrf_token, form=form)

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
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp.desc()).all()
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

        tags_json = request.form.get("tags")
        try:
            tag_names = json.loads(tags_json)
        except (TypeError, json.JSONDecodeError):
            tag_names = []

        
        # Existing tags
        existing_tags = {tag.name for tag in transaction.tags}

        # Combine new and existing tags
        all_tags = set(tag_names).union(existing_tags)

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
        time = request.form.get('time')
        name = request.form.get('name')
        note= request.form.get('note')
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
            user = User.query.get(user_id)
            calculateAllMoney(db, Transaction, tag_objects=tag_objects, money=amount, date=date, bank_name=bank_name, category=category, user=user)
            
            # Fetch the current transaction and delete it after calculation
            record = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()
            if record:
                db.session.delete(record)
                db.session.commit()
                logging.debug(f"Transaction ID {transaction_id} deleted successfully.")
            else:
                logging.error(f"Transaction ID {transaction_id} not found.")
            return redirect(url_for('history'))
        
        time_str = request.form.get('time')
        try:
            # If you're just collecting a time like "14:30", combine it with today's date
            time = datetime.combine(date.date(), datetime.strptime(time_str, '%H:%M').time())
        except (ValueError, TypeError) as e:
            logging.warning(f"Invalid time format received: {time_str}, error: {e}")
            time = datetime.now()

        
        record = Transaction.query.filter_by(id=record_id, user_id=user_id).first_or_404()
        print(f"Parsed time: {time}, name: {name}, note: {note}")
        try:
            record.amount = float(amount)
            record.bank_name = bank_name
            record.division = division
            record.timestamp = time
            record.date = date
            record.name = name
            record.note = note
            record.tags.clear()  # Clear existing tags
            transaction.tags.clear()
            for tag_name in tag_names:
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
    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
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
        print(f"type of transactions_data: {type(transactions_data)}")
        return jsonify({
            "access_token": access_token,
            "item_id": item_id,
            "institution_name": institution_name,
            "transactions": transactions_data
        })
    except ApiException as e:
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
    except ApiException as e:
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
    all_added = []
    all_modified = []
    all_removed = []
    new_transactions_count = 0
    duplicate_transactions_count = 0
    print("==> Entered /api/transactions route")

    try:
        user_id = session.get('user_id')
        print(f"==> Retrieved user_id: {user_id}")
        if not user_id:
            print("==> No user_id in session")
            return jsonify({"error": "User not logged in"}), 401

        item_id_filter = flask_request.args.get('item_id')
        accounts_map = {}
        plaid_items = PlaidItem.query.filter_by(user_id=user_id).all()
        if item_id_filter:
            plaid_items = [item for item in plaid_items if item.item_id == item_id_filter]
            print(f"==> Filtering to Plaid item: {item_id_filter}")
        print(f"==> Retrieved {len(plaid_items)} Plaid items for user {user_id}")
        if not plaid_items:
            print("==> No Plaid items found")
            return jsonify({"error": "No access tokens found for user"}), 400

        for plaid_item in plaid_items:
            access_token = plaid_item.access_token
            cursor = plaid_item.cursor or ''
            print(f"==> Starting sync for access_token {access_token[:6]}..., cursor: {cursor}")

            bank_name = fetch_institution_name(access_token)
            account_details = get_accounts(access_token)
            print(f"==> Got account details for access_token {access_token[:6]}")

            if account_details is None:
                print(f"==> No accounts found for access token {access_token[:6]}")
                continue

            new_accounts = {
                account['account_id']: {
                    "account_name": account['name'],
                    "bank_name": bank_name,
                    "subtype": account.get('subtype', '').lower()
                }
                for account in account_details['accounts']
            }
            accounts_map.update(new_accounts)

            has_more = True
            while has_more:
                print(f"==> Fetching transactions with cursor: {cursor}")
                try:
                    request = TransactionsSyncRequest(
                        access_token=plaid_item.access_token,
                        cursor=cursor,
                    )
                    response = client.transactions_sync(request).to_dict()
                    print(f"==> Raw sync response: {response}")

                    # Handle "NOT_READY" case
                    if response.get('transactions_update_status') == 'NOT_READY':
                        print("==> Transactions not ready yet.")
                        return jsonify({"status": "pending", "message": "Transactions not ready yet."}), 202

                    cursor = response.get('next_cursor', '')
                    plaid_item.cursor = cursor
                    db.session.add(plaid_item)

                    has_more = response.get('has_more', False)
                    all_added.extend(response.get('added', []))
                    all_modified.extend(response.get('modified', []))
                    all_removed.extend(response.get('removed', []))

                except ApiException as e:
                    print(f"==> Plaid API error: {e}")
                    raise
            db.session.commit()
            print(f"==> Committed updated cursor for {access_token[:6]}")

        for transaction in all_added:
            print(f"==> Processing transaction: {transaction['transaction_id']}")
            account_id = transaction.get('account_id')
            account_info = accounts_map.get(account_id, {})
            account_name = account_info.get("account_name", "Unknown Account")
            bank_name = account_info.get("bank_name", "Unknown Bank")
            account_subtype = account_info.get("subtype", "checking")
            raw_datetime = transaction.get("datetime")
            if raw_datetime:
                timestamp_str = str(raw_datetime)
            else:
                date_str = transaction.get("date", "")
                timestamp_str = f"{date_str}T12:00:00"

            try:
                parsed_timestamp = datetime.fromisoformat(timestamp_str)
            except Exception as e:
                print(f"==> Timestamp parse failed: {timestamp_str}, error: {e}")
                parsed_timestamp = datetime.utcnow()

            txn_id = transaction['transaction_id']
            existing_transaction = Transaction.query.filter_by(transaction_id=txn_id).first()

            if not existing_transaction:
                categories = transaction.get('category', [])
                if isinstance(categories, str):
                    categories = [categories]
                if categories is None:
                    categories = []
                categories = [cat.strip() for cat in categories if cat.strip()]

                tag_objects = []
                for category in categories:
                    tag = Tags.query.filter_by(name=category, user_id=user_id).first()
                    if not tag:
                        tag = Tags(name=category, user_id=user_id)
                        db.session.add(tag)
                        db.session.commit()
                    tag_objects.append(tag)

                category = ', '.join(categories)
                amount = classify_transaction_amount(transaction)

                temp_transaction = Transaction(
                    user_id=user_id,
                    transaction_id=txn_id,
                    name=transaction["name"],
                    amount=amount,
                    bank_account=account_name,
                    bank_name=bank_name,
                    pending=transaction.get("pending", False),
                    date=parsed_timestamp.date(),
                    timestamp=parsed_timestamp
                )

                predicted_category = predict_transaction_category(temp_transaction)
                print(f"==> Predicted category: {predicted_category}")

                new_transaction = Transaction(
                    user_id=user_id,
                    transaction_id=txn_id,
                    date=transaction['date'],
                    timestamp=parsed_timestamp,
                    name=edit_transaction_name(transaction["name"]),
                    division=predicted_category,
                    category=category,
                    amount=amount,
                    account_id=account_id,
                    bank_account=account_name,
                    bank_name=bank_name,
                    item_id=plaid_item.item_id,
                    pending=transaction.get('pending', False)
                )
                db.session.add(new_transaction)
                db.session.commit()

                with db.session.no_autoflush:
                    for tag in tag_objects:
                        if tag not in new_transaction.tags:
                            new_transaction.tags.append(tag)

                new_transactions_count += 1
            else:
                print(f"==> Duplicate transaction found: {txn_id}")
                duplicate_transactions_count += 1

        db.session.commit()
        print(f"==> Committed {new_transactions_count} new transactions")

        all_transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp.desc()).all()
        print(f"==> Total transactions fetched: {len(all_transactions)}")
        for transaction in all_transactions:
            print(f"Transaction ID: {transaction.transaction_id}, Amount: {transaction.amount}")

        recent_transactions_list = [
            {
                "transaction_id": txn.transaction_id,
                "date": txn.date.strftime('%Y-%m-%d'),
                "name": txn.name,
                "category": txn.category,
                "amount": txn.amount
            }
            for txn in all_transactions[:10]
        ]

        return jsonify({
            "status": "success",
            "new_transactions": new_transactions_count,
            "duplicate_transactions": duplicate_transactions_count,
            "recent_transactions": recent_transactions_list
        })

    except ApiException as e:
        print(f"==> Caught Plaid ApiException: {e}")
        error_response = format_error(e)
        return jsonify(error_response), 500
    except Exception as e:
        print(f"==> Caught general exception: {e}")
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
    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
        logging.error(f"Plaid API error while fetching accounts: {e}")
        return None
    
@app.route('/bank_accounts')
@login_required
def bank_accounts():
    user_id = session.get('user_id')
    plaid_items = PlaidItem.query.filter_by(user_id=user_id).all()

    accounts_data = []
    for item in plaid_items:
        access_token = item.access_token
        institution_name = fetch_institution_name(access_token)
        institution_logo_url = get_institution_logo_url(access_token)  # You'll need to implement this or use a default
        account_id = item.id  # or use a unique slug if you have one

        accounts_data.append({
            "id": account_id,
            "name": institution_name,
            "logo_url": institution_logo_url or url_for('static', filename='images/default-bank.png'),
        })

    return render_template("bank_accounts.html", accounts=accounts_data)

@app.route('/delete_bank_account/<int:plaid_item_id>', methods=["POST"])
@login_required
def delete_bank_account(plaid_item_id):
    user_id = session.get("user_id")

    # Find the Plaid item
    item = PlaidItem.query.filter_by(id=plaid_item_id, user_id=user_id).first_or_404()

    # Delete all related transactions
    deleted = Transaction.query.filter_by(item_id=item.item_id, user_id=user_id).delete()
    print(f"Deleted {deleted} transactions")
    # Delete the item itself
    db.session.delete(item)
    db.session.commit()

    flash("Bank account and all associated transactions have been deleted.", "success")
    return redirect(url_for("bank_accounts"))


@app.route('/accounts/<int:item_id>')
@login_required
def account_detail(item_id):
    user_id = session.get('user_id')

    # Get the PlaidItem
    plaid_item = PlaidItem.query.filter_by(id=item_id, user_id=user_id).first_or_404()

    # Pull account_ids associated with this item
    # Ideally, you already have a cached list of accounts somewhere.
    # But if not, you'll need to hit Plaid again to fetch account_ids for this item.
    access_token = plaid_item.decrypted_access_token
    account_data = get_accounts(access_token)

    if not account_data:
        return "Could not retrieve accounts", 500

    item_account_ids = [acct["account_id"] for acct in account_data["accounts"]]

    # Now query transactions based on matching account_ids
    transactions = Transaction.query \
        .filter(Transaction.account_id.in_(item_account_ids), Transaction.user_id == user_id) \
        .order_by(Transaction.timestamp.desc()) \
        .all()

    return render_template("account_detail.html", item=plaid_item, transactions=transactions)

def get_institution_logo_url(access_token):
    try:
        request = ItemGetRequest(access_token=access_token)
        item_response = client.item_get(request).to_dict()
        institution_id = item_response["item"].get("institution_id")

        if institution_id:
            inst_request = InstitutionsGetByIdRequest(
                institution_id=institution_id,
                country_codes=[CountryCode('US')]
            )
            institution = client.institutions_get_by_id(inst_request).to_dict()
            return institution["institution"].get("logo")
    except Exception as e:
        logging.warning(f"Could not fetch logo: {e}")
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
    except ApiException as e:
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
    except ApiException as e:
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

    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

@app.route('/api/statements', methods=['GET'])
def statements():
    try:
        request = StatementsListRequest(access_token=access_token)
        response = client.statements_list(request)
        pretty_print_response(response.to_dict())
    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)


# Retrieve high-level information about an Item
# https://plaid.com/docs/#retrieve-item




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
    except ApiException as e:
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
    except ApiException as e:
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
    except ApiException as e:
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
        except ApiException as e:
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
    
"""delete everything below before pushing"""
@app.route('/api/refresh_categories', methods=['POST'])
@login_required
def refresh_categories():
    try:
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"status": "error", "message": "User not logged in"}), 401

        transactions = Transaction.query.filter_by(user_id=user_id).all()
        updated_count = 0

        for txn in transactions:
            new_division = predict_transaction_category(txn)
            txn.division = new_division
            db.session.add(txn)
            updated_count += 1

        db.session.commit()
        return jsonify({
            "status": "success",
            "message": f"Updated categories for {updated_count} transactions."
        }), 200

    except Exception as e:
        logging.error(f"Error refreshing categories: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to refresh categories."}), 500
    
@app.route('/graphs_data')
@login_required
def graphs_data():
    user_id = session.get("user_id")
    now = datetime.now()
    this_month = now.strftime('%Y-%m')
    def sum_for_category(filter_):
        return db.session.query(func.sum(Transaction.amount))\
            .filter(Transaction.user_id == user_id)\
            .filter(filter_)\
            .scalar() or 0

    # Monthly spending by division
    division_data_monthly = db.session.query(
        Transaction.division,
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        func.strftime('%Y-%m', Transaction.date) == this_month
    ).group_by(Transaction.division).all()

    # Tag spending
    tag_data = db.session.query(
        Tags.name,
        func.sum(Transaction.amount).label('total')
    ).select_from(Tags)\
     .join(transaction_tags, Tags.id == transaction_tags.c.tag_id)\
     .join(Transaction, Transaction.id == transaction_tags.c.transaction_id)\
     .filter(Tags.user_id == user_id)\
     .group_by(Tags.name).all()

    # Monthly cash flow
    monthly_flow = db.session.query(
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(Transaction.amount).label('net_flow')
    ).filter(Transaction.user_id == user_id)\
     .group_by('month').order_by('month').all()

    # Cumulative division over time
    cumulative = db.session.query(
        Transaction.division,
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(Transaction.amount).label('total')
    ).filter(Transaction.user_id == user_id)\
     .group_by(Transaction.division, 'month').order_by('month').all()

    
    # You could map your categories/tags to fixed/flexible
    fixed_total = 1200  # mock
    flexible_total = 600  # mock


    

    # Income vs expense per month (positive vs negative transactions)
    income_expense_raw = db.session.query(
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(case((Transaction.amount > 0, Transaction.amount), else_=0)).label('income'),
        func.sum(case((Transaction.amount < 0, Transaction.amount), else_=0)).label('expense')
    ).filter(Transaction.user_id == user_id)\
    .group_by('month').order_by('month').all()
    income_expense = [
        {
            'month': m,
            'income': i,
            'expense': e
        } for m, i, e in income_expense_raw
    ]

     # Spending vs budget by category (mock budgets)
    budget_data = db.session.query(
        Transaction.category,
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(Transaction.amount).label('actual')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.amount < 0
    ).group_by('month', Transaction.category).all()

    mock_budgets = {
        'food': -500,
        'rent': -1200,
        'entertainment': -200,
        'utilities': -150
    }
    heatmap_data = [
        {'day': day, 'total': (day * 3) % 100}
        for day in range(1, 31)
    ]

    spend_budget = []
    for cat, month, actual in budget_data:
        spend_budget.append({
            'category': cat,
            'month': month,
            'actual': actual,
            'budget': mock_budgets.get(cat, 0)
        })

    # Savings progress over time
    savings_over_time = db.session.query(
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.division == 'save'
    ).group_by('month').order_by('month').all()

    # Spending by bank account
    account_spend = db.session.query(
        Transaction.bank_name,
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.amount < 0
    ).group_by(Transaction.bank_name).all()

    # Recurring subscriptions (mock detection)
    subscriptions = db.session.query(
        Transaction.name,
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.category.ilike('%subscription%')
    ).group_by(Transaction.name).all()

    # Cash flow waterfall
    income = sum_for_category(Transaction.amount > 0)
    taxes = sum_for_category(Transaction.category.ilike('%tax%'))
    rent = sum_for_category(Transaction.category.ilike('%rent%'))
    food = sum_for_category(Transaction.category.ilike('%food%'))
    savings = sum_for_category(Transaction.division == 'save')
    other = income - abs(taxes) - abs(rent) - abs(food) - abs(savings)


    return jsonify({
        'division_breakdown_month': [{'division': d, 'total': t} for d, t in division_data_monthly],
        'tag_breakdown': [{'tag': t, 'total': amt} for t, amt in tag_data],
        'monthly_flow': [{'month': m, 'net_flow': f} for m, f in monthly_flow],
        'cumulative': [{'division': d, 'month': m, 'total': t} for d, m, t in cumulative],
        'cash_flow_waterfall': {
            'categories': ['Income', 'Taxes', 'Rent', 'Food', 'Savings', 'Other'],
            'values': [income, -abs(taxes), -abs(rent), -abs(food), -abs(savings), -abs(other)]
        },
        'goal_progress': {
            'target': 2000,  # Replace with goal query
            'current': savings  # Assuming savings division sum is progress
        },
        'income_expense': income_expense,
        'heatmap': heatmap_data,
        'spend_budget': spend_budget,
        'savings_over_time': [{'month': m, 'total': t} for m, t in savings_over_time],
        'account_spend': [{'bank': b or 'Unknown', 'total': t} for b, t in account_spend],
        'subscriptions': [{'name': n, 'total': t} for n, t in subscriptions],
    })

@app.route('/graph_experimentation')
@login_required
def graph_experimentation():
    return render_template('graph_experimentation.html')

