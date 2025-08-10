from flask import Blueprint, request, jsonify, session
from flask_login import login_required
import logging

from app import db
from app.models import Transaction, PlaidItem
from flask_login import current_user

dev_bp = Blueprint('dev', __name__)

@dev_bp.route('/delete_transactions', methods=['GET', 'POST'])
@login_required
def delete_transactions():
    try:
        # Confirm the user is authenticated
        user_id = current_user.id
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