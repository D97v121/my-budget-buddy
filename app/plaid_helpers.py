import os
import logging
from dotenv import load_dotenv

from plaid.configuration import Configuration, Environment
from plaid.api_client import ApiClient
from plaid.api import plaid_api
from plaid.exceptions import ApiException
from plaid.model.accounts_get_request import AccountsGetRequest
from plaid.model.item_get_request import ItemGetRequest
from plaid.model.institutions_get_by_id_request import InstitutionsGetByIdRequest
from plaid.model.country_code import CountryCode


from app.models.plaid import PlaidItem

load_dotenv()

# --- Plaid Client Setup ---
PLAID_CLIENT_ID = os.getenv('PLAID_CLIENT_ID')
PLAID_SECRET = os.getenv('PLAID_SECRET')
PLAID_ENV = os.getenv('PLAID_ENV', 'production')
PLAID_PRODUCTS = os.getenv('PLAID_PRODUCTS', 'transactions').split(',')
PLAID_COUNTRY_CODES = os.getenv('PLAID_COUNTRY_CODES', 'US').split(',')

"""
PLAID_ENV="sandbox"
PLAID_CLIENT_ID="676753d2491dca001bd2dc10"
PLAID_SECRET="d1449bffdc40adc52ac03d5d537c1d"
SECRET_KEY="3463328b3d3cf041ab3c746bc103488f996f9a980de1464d6a914bbb0f079159"
"""

host = Environment.Production if PLAID_ENV == 'production' else Environment.Sandbox

configuration = Configuration(
    host=host,
    api_key={
        'clientId': PLAID_CLIENT_ID,
        'secret': PLAID_SECRET,
        'plaidVersion': '2020-09-14',
    }
)

api_client = ApiClient(configuration)
client = plaid_api.PlaidApi(api_client)

print(f"Using Client ID: {PLAID_CLIENT_ID}")
print(f"Using Secret: {PLAID_SECRET[:4]}...")
print(f"Using Environment: {PLAID_ENV}")


# --- Safe, Reusable Functions ---
def get_access_token_for_user(user_id):
    """Safely get a user's access token from the database."""
    item = PlaidItem.query.filter_by(user_id=user_id).first()
    if item and item.decrypted_access_token:
        return item.decrypted_access_token
    logging.warning(f"No access token found for user_id={user_id}")
    return None


def get_accounts(access_token):
    try:
        request = AccountsGetRequest(access_token=access_token)
        response = client.accounts_get(request)
        return response.to_dict()
    except ApiException as e:
        logging.error(f"Plaid API error while fetching accounts: {e}")
        return None


def fetch_institution_name(access_token):
    try:
        item_request = ItemGetRequest(access_token=access_token)
        item_response = client.item_get(item_request).to_dict()
        institution_id = item_response['item'].get('institution_id')

        if not institution_id:
            return "Unknown Bank"

        institution_request = InstitutionsGetByIdRequest(
            institution_id=institution_id,
            country_codes=[CountryCode('US')]
        )
        institution_response = client.institutions_get_by_id(institution_request).to_dict()
        return institution_response["institution"]["name"]
    except ApiException as e:
        logging.error(f"Error fetching institution name: {e}")
        return "Unknown Bank"


def get_institution_logo_url(access_token):
    try:
        item_request = ItemGetRequest(access_token=access_token)
        item_response = client.item_get(item_request).to_dict()
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
    
def get_access_token_for_user(user_id):
    item = PlaidItem.query.filter_by(user_id=user_id).first()
    return item.decrypted_access_token if item else None


def get_user_token_for_user(user_id):
    item = PlaidItem.query.filter_by(user_id=user_id).first()
    return item.user_token if item and item.user_token else None
