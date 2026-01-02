from flask import Blueprint, jsonify, request
import os
from plaid.model.item_remove_request import ItemRemoveRequest
from plaid.exceptions import ApiException
from app import db
from app.models.plaid import PlaidItem
from app.plaid_helpers import client
from app import csrf

admin_bp = Blueprint("admin_bp", __name__)

def _authorized():
    otp = os.getenv("PLAID_KILL_SWITCH_OTP")
    provided = request.headers.get("X-PLAID-OTP")

    # Require OTP to be set and correct
    if not otp or not provided or provided != otp:
        return False

    # Optional: restrict to your IP(s). Add if you want extra safety.
    # allowed = {"1.2.3.4"}  # your public IP
    # if request.remote_addr not in allowed:
    #     return False

    return True

@admin_bp.route("/admin/plaid/remove_all_items", methods=["POST"])
@csrf.exempt
def remove_all_plaid_items():
    if not _authorized():
        return jsonify({"error": "Not authorized"}), 403

    items = PlaidItem.query.all()
    results = []
    removed = 0
    failed = 0

    for item in items:
        token = item.decrypted_access_token
        masked = f"...{token[-4:]}" if token and len(token) >= 4 else "(missing)"

        try:
            client.item_remove(ItemRemoveRequest(access_token=token))
            db.session.delete(item)
            removed += 1
            results.append({"item_id": item.item_id, "token": masked, "status": "removed"})
        except ApiException as e:
            failed += 1
            results.append({"item_id": item.item_id, "token": masked, "status": "failed", "error": str(e)})
        except Exception as e:
            failed += 1
            results.append({"item_id": item.item_id, "token": masked, "status": "failed", "error": str(e)})

    db.session.commit()

    return jsonify({
        "removed": removed,
        "failed": failed,
        "total_seen": len(items),
        "results": results
    }), 200
