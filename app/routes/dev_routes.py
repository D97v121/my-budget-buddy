from flask import Blueprint, request, jsonify, session
from flask_login import login_required
import logging

from app import db
from app.models import Transaction, PlaidItem
from flask_login import current_user

dev_bp = Blueprint('dev', __name__)

@dev_bp.route('/delete_transactions', methods=['GET'])  # ← safer: POST only
@login_required
def delete_transactions():
    try:
        user_id = current_user.id
        if not user_id:
            logging.warning("Attempt to delete transactions without being logged in.")
            return jsonify({"error": "User not logged in"}), 401

        logging.info(f"User {user_id} is deleting all transactions.")

        # 1) Collect this user's transaction IDs
        tx_ids = db.session.scalars(
            db.select(Transaction.id).where(Transaction.user_id == user_id)
        ).all()

        if not tx_ids:
            logging.info("No transactions to delete.")
            return jsonify({"status": "success", "deleted_count": 0}), 200

        # 2) Delete association rows FIRST (prevents FK failures)
        from app.models.association_tables import transaction_tags
        db.session.execute(
            transaction_tags.delete().where(transaction_tags.c.transaction_id.in_(tx_ids))
        )

        # If you have other child tables referencing Transaction.id (e.g., splits, attachments),
        # delete them here too before deleting the parent rows.

        # 3) Delete the transactions themselves
        deleted = db.session.execute(
            db.delete(Transaction).where(Transaction.id.in_(tx_ids))
        ).rowcount

        db.session.commit()
        logging.info(f"Successfully deleted {deleted} transactions (and associations).")
        return jsonify({"status": "success", "deleted_count": deleted}), 200

    except Exception as e:
        logging.error(f"Error deleting transactions: {e}", exc_info=True)
        db.session.rollback()
        return jsonify({"error": "Failed to delete transactions"}), 500


    
@dev_bp.route('/delete_all_plaid_items', methods=['GET', 'POST'])
@login_required
def delete_all_plaid_items():
    try:
        user_id = current_user.id
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