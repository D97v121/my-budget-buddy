from flask import Blueprint, jsonify, request
from app.plaid_helpers import client, get_accounts, fetch_institution_name
from app.helpers import format_error, pretty_print_response
from plaid.exceptions import ApiException
from plaid.model.accounts_balance_get_request import AccountsBalanceGetRequest
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.identity_get_request import IdentityGetRequest
from plaid.model.item_get_request import ItemGetRequest
from plaid.model.institutions_get_by_id_request import InstitutionsGetByIdRequest
from plaid.model.country_code import CountryCode
from models import PlaidItem
from sqlalchemy.orm import session
from models import PlaidItem
from flask_login import login_required
from flask_login import current_user


api_accounts = Blueprint('api_accounts', __name__)

@api_accounts.route('/api/identity', methods=['GET'])
@login_required
def get_identity():
    try:
        user_id = current_user.id
        plaid_item = PlaidItem.query.filter_by(user_id=user_id).first()
        if not plaid_item:
            return jsonify({"error": "No Plaid account found"}), 400

        access_token = plaid_item.access_token

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



@api_accounts.route('/api/balance', methods=['GET'])
@login_required
def get_balance():
    try:
        user_id = current_user.id
        plaid_item = PlaidItem.query.filter_by(user_id=user_id).first()
        if not plaid_item:
            return jsonify({"error": "No Plaid account found"}), 400

        access_token = plaid_item.access_token

        request = IdentityGetRequest(
            access_token=access_token
        )
        response = client.accounts_balance_get(request)
        pretty_print_response(response.to_dict())
        return jsonify(response.to_dict())
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

