from flask import Blueprint, jsonify
from plaid.model.asset_report_create_request import AssetReportCreateRequest
from plaid.model.asset_report_create_request_options import AssetReportCreateRequestOptions
from plaid.model.asset_report_user import AssetReportUser
from plaid.model.asset_report_get_request import AssetReportGetRequest
from plaid.model.asset_report_pdf_get_request import AssetReportPDFGetRequest
from plaid.model.country_code import CountryCode
from plaid.exceptions import ApiException
from plaid.model.investments_transactions_get_request_options import InvestmentsTransactionsGetRequestOptions
from plaid.model.investments_transactions_get_request import InvestmentsTransactionsGetRequest
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.payment_initiation_payment_get_request import PaymentInitiationPaymentGetRequest
from plaid.model.investments_holdings_get_request import InvestmentsHoldingsGetRequest
from plaid.model.transfer_authorization_create_request import TransferAuthorizationCreateRequest
from plaid.model.transfer_create_request import TransferCreateRequest
from plaid.model.transfer_type import TransferType
from plaid.model.transfer_authorization_user_in_request import TransferAuthorizationUserInRequest
from plaid.model.ach_class import ACHClass
from plaid.model.transfer_user_address_in_request import TransferUserAddressInRequest
from plaid.model.signal_evaluate_request import SignalEvaluateRequest
from plaid.model.statements_list_request import StatementsListRequest
from plaid.model.statements_download_request import StatementsDownloadRequest
from plaid.model.transfer_network import TransferNetwork
from plaid.model.transfer_type import TransferType

import datetime as dt
import base64
import logging

from app.helpers import pretty_print_response, poll_with_retries, client
from app.helpers import format_error
from flask_login import current_user
from app.plaid_helpers import get_access_token_for_user 

plaid_extra_features = Blueprint('plaid_extra_features', __name__)


@plaid_extra_features.route('/api/assets', methods=['GET'])
def get_assets():
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
    try:
        request = AssetReportCreateRequest(
            user_id = current_user.id,
            access_token = get_access_token_for_user(user_id),
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


@plaid_extra_features.route('/api/holdings', methods=['GET'])
def get_holdings():
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
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


@plaid_extra_features.route('/api/investments_transactions', methods=['GET'])
def get_investments_transactions():
    # Pull transactions for the last 30 days

    start_date = (dt.datetime.now() - dt.timedelta(days=(30)))
    end_date = dt.datetime.now()
    try:
        user_id = current_user.id
        access_token = get_access_token_for_user(user_id)
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

@plaid_extra_features.route('/api/transfer_authorize', methods=['GET'])
def transfer_authorization():
    global authorization_id 
    global account_id
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
    request = AccountsGetRequest(access_token=access_token)
    response = client.accounts_get(request)
    account_id = response['accounts'][0]['account_id']
    try:
        request = TransferAuthorizationCreateRequest(
            user_id = current_user.id,
            access_token = get_access_token_for_user(user_id),
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

@plaid_extra_features.route('/api/transfer_create', methods=['GET'])
def transfer():
    try:
        user_id = current_user.id
        request = TransferCreateRequest(
            user_id = current_user.id,
            access_token = get_access_token_for_user(user_id),
            account_id=account_id,
            authorization_id=authorization_id,
            description='Debit')
        response = client.transfer_create(request)
        pretty_print_response(response.to_dict())
        return jsonify(response.to_dict())
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)

@plaid_extra_features.route('/api/statements', methods=['GET'])
def statements():
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
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
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)




@plaid_extra_features.route('/api/signal_evaluate', methods=['GET'])
def signal():
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
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


@plaid_extra_features.route('/api/payment', methods=['GET'])
def payment():
    global payment_id
    user_id = current_user.id
    access_token = get_access_token_for_user(user_id)
    try:
        request = PaymentInitiationPaymentGetRequest(payment_id=payment_id)
        response = client.payment_initiation_payment_get(request)
        pretty_print_response(response.to_dict())
        return jsonify({'error': None, 'payment': response.to_dict()})
    except ApiException as e:
        error_response = format_error(e)
        return jsonify(error_response)
