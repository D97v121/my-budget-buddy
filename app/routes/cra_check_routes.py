import os
import time
import json
import base64
from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_login import current_user, login_required
from plaid.exceptions import ApiException
from app.plaid_helpers import client, get_user_token_for_user  # You need this helper
from app.models.plaid import PlaidItem  # If needed inside helper

cra_check = Blueprint("cra_check", __name__)

# Optional: Toggle CRA support via environment variable
CRA_ENABLED = os.getenv("FEATURE_CRA_ENABLED", "false").lower() == "true"

# Try to import Plaid CRA models (fail gracefully if unavailable)
try:
    from plaid.model import (
        CraCheckReportBaseReportGetRequest,
        CraCheckReportIncomeInsightsGetRequest,
        CraCheckReportPartnerInsightsGetRequest,
        CraCheckReportPDFGetRequest,
        CraPDFAddOns
    )
    CRA_MODELS_AVAILABLE = True
except ImportError:
    CRA_MODELS_AVAILABLE = False


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
    return {
        "error": {
            "status_code": e.status,
            "display_message": response.get("error_message"),
            "error_code": response.get("error_code"),
            "error_type": response.get("error_type")
        }
    }


@cra_check.route("/api/cra/get_base_report", methods=["GET"])
@login_required
def cra_check_report():
    if not CRA_ENABLED or not CRA_MODELS_AVAILABLE:
        return jsonify({"error": "CRA check not supported in this environment"}), 501

    try:
        user_token = get_user_token_for_user(current_user.id)
        if not user_token:
            return jsonify({"error": "User token not found"}), 400

        get_response = poll_with_retries(lambda: client.cra_check_report_base_report_get(
            CraCheckReportBaseReportGetRequest(user_token=user_token, item_ids=[])
        ))
        pdf_response = client.cra_check_report_pdf_get(
            CraCheckReportPDFGetRequest(user_token=user_token)
        )

        return jsonify({
            "report": get_response.to_dict().get("report"),
            "pdf": base64.b64encode(pdf_response.read()).decode("utf-8")
        })

    except ApiException as e:
        return jsonify(format_error(e))


@cra_check.route("/api/cra/get_income_insights", methods=["GET"])
@login_required
def cra_income_insights():
    if not CRA_ENABLED or not CRA_MODELS_AVAILABLE:
        return jsonify({"error": "CRA check not supported in this environment"}), 501

    try:
        user_token = get_user_token_for_user(current_user.id)
        if not user_token:
            return jsonify({"error": "User token not found"}), 400

        get_response = poll_with_retries(lambda: client.cra_check_report_income_insights_get(
            CraCheckReportIncomeInsightsGetRequest(user_token=user_token)
        ))
        pdf_response = client.cra_check_report_pdf_get(
            CraCheckReportPDFGetRequest(
                user_token=user_token,
                add_ons=[CraPDFAddOns("cra_income_insights")]
            )
        )

        return jsonify({
            "report": get_response.to_dict().get("report"),
            "pdf": base64.b64encode(pdf_response.read()).decode("utf-8")
        })

    except ApiException as e:
        return jsonify(format_error(e))


@cra_check.route("/api/cra/get_partner_insights", methods=["GET"])
@login_required
def cra_partner_insights():
    if not CRA_ENABLED or not CRA_MODELS_AVAILABLE:
        return jsonify({"error": "CRA check not supported in this environment"}), 501

    try:
        user_token = get_user_token_for_user(current_user.id)
        if not user_token:
            return jsonify({"error": "User token not found"}), 400

        response = poll_with_retries(lambda: client.cra_check_report_partner_insights_get(
            CraCheckReportPartnerInsightsGetRequest(user_token=user_token)
        ))
        return jsonify(response.to_dict())

    except ApiException as e:
        return jsonify(format_error(e))
