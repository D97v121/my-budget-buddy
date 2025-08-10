from flask import Blueprint, jsonify, session, request as flask_request, render_template, flash, redirect, url_for
from flask_login import login_required
from flask_login import login_required
from app.models import PlaidItem, Transaction
from app.plaid_helpers import fetch_institution_name, get_accounts, get_institution_logo_url
from app import db
from flask_login import current_user

dashboard_routes = Blueprint('dashboard_routes', __name__)

@dashboard_routes.route('/bank_accounts')
@login_required
def bank_accounts():
    user_id = current_user.id
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

@dashboard_routes.route('/delete_bank_account/<int:plaid_item_id>', methods=["POST"])
@login_required
def delete_bank_account(plaid_item_id):
    user_id = current_user.id

    # Find the Plaid item
    item = PlaidItem.query.filter_by(id=plaid_item_id, user_id=user_id).first_or_404()

    # Delete all related transactions
    deleted = Transaction.query.filter_by(item_id=item.item_id, user_id=user_id).delete()
    print(f"Deleted {deleted} transactions")
    # Delete the item itself
    db.session.delete(item)
    db.session.commit()

    flash("Bank account and all associated transactions have been deleted.", "success")
    return redirect(url_for("dashboard_routes.bank_accounts"))


@dashboard_routes.route('/accounts/<int:item_id>')
@login_required
def account_detail(item_id):
    user_id = current_user.id

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
