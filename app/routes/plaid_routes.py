from flask import Blueprint, jsonify, request, session, redirect, url_for, flash, Response
from flask_login import login_required
from datetime import datetime, timedelta, date
import logging, json, uuid, time
import os
from plaid.model import *
from plaid.api import plaid_api
from plaid.exceptions import ApiException
from plaid import Configuration, ApiClient
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.country_code import CountryCode
from plaid.model.products import Products
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.payment_initiation_payment_create_request import PaymentInitiationPaymentCreateRequest
from plaid.model.payment_amount import PaymentAmount
from plaid.model.payment_amount_currency import PaymentAmountCurrency
from plaid.model.payment_initiation_recipient_create_request import PaymentInitiationRecipientCreateRequest
from plaid.model.payment_initiation_address import PaymentInitiationAddress
from plaid.model.recipient_bacs_nullable import RecipientBACSNullable
from plaid.model.link_token_create_request_payment_initiation import LinkTokenCreateRequestPaymentInitiation
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.item_get_request import ItemGetRequest
from plaid.model.institutions_get_by_id_request import InstitutionsGetByIdRequest
from plaid.model.auth_get_request import AuthGetRequest
from plaid.model.user_create_request import UserCreateRequest
from plaid.model.consumer_report_user_identity import ConsumerReportUserIdentity
from plaid.model.consumer_report_permissible_purpose import ConsumerReportPermissiblePurpose
from plaid.model.link_token_create_request_statements import LinkTokenCreateRequestStatements
from plaid.model.link_token_create_request_cra_options import LinkTokenCreateRequestCraOptions
from flask_login import current_user
from app import db
from app.plaid_helpers import client
from app.models import PlaidItem
from app.routes.api_transactions import get_transactions
from app.helpers import format_error, pretty_print_response


plaid_bp = Blueprint('plaid', __name__)

def empty_to_none(field):
    value = os.getenv(field)
    if value is None or len(value) == 0:
        return None
    return value
PLAID_REDIRECT_URI = empty_to_none('PLAID_REDIRECT_URI')
PLAID_CLIENT_ID = os.getenv('PLAID_CLIENT_ID')
PLAID_SECRET = os.getenv('PLAID_SECRET')
PLAID_ENV = os.getenv('PLAID_ENV', 'sandbox')
PLAID_PRODUCTS = os.getenv('PLAID_PRODUCTS', 'transactions').split(',')
PLAID_COUNTRY_CODES = os.getenv('PLAID_COUNTRY_CODES', 'US').split(',')

products = []
for product in PLAID_PRODUCTS:
    products.append(Products(product))

@plaid_bp.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    print("Received webhook:", data)
    return jsonify({"status": "success"}), 200


@plaid_bp.route('/api/info', methods=['POST'])
def info():
    global access_token
    global item_id
    return jsonify({
        'item_id': item_id,
        'access_token': access_token,
        'products': PLAID_PRODUCTS
    })


@plaid_bp.route('/api/create_link_token_for_payment', methods=['POST'])
@login_required
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


@plaid_bp.route('/api/create_link_token', methods=['POST'])
@login_required
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
@plaid_bp.route('/api/create_user_token', methods=['POST'])
@login_required
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


@plaid_bp.route('/api/set_access_token', methods=['POST'])
@login_required
def set_access_token():
    try:
        public_token = request.json.get('public_token')
        user_id = current_user.id
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


@plaid_bp.route('/api/auth', methods=['GET'])
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
    

@plaid_bp.route('/api/item', methods=['GET'])
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
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)