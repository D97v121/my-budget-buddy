import logging
from datetime import datetime, timedelta

from flask import current_app
from app import db  # Adjust if your db lives elsewhere
from app.models import Transaction, PlaidItem
from flask import jsonify, session
from flask_login import login_required
from apscheduler.schedulers.background import BackgroundScheduler
from app import app  # If you're using the Flask app instance directly
from app.models import User  # You referenced User in delete_user_data
from flask_login import current_user



def delete_old_data():
    """Delete transactions older than retention period"""
    with current_app.app_context():
        retention_period = 365  # ✅ Keep transactions for 1 year
        cutoff_date = datetime.utcnow() - timedelta(days=retention_period)

        # ✅ Delete old transactions
        deleted_transactions = Transaction.query.filter(Transaction.date < cutoff_date).delete()

        # ✅ Delete old PlaidItem entries for deleted users
        deleted_items = PlaidItem.query.filter(PlaidItem.created_at < cutoff_date).delete()

        db.session.commit()
        print(f"Deleted {deleted_transactions} transactions and {deleted_items} Plaid items")

scheduler = BackgroundScheduler()
scheduler.add_job(delete_old_data, 'interval', hours=24)
scheduler.start()

@app.route('/delete_user_data', methods=['POST'])
@login_required
def delete_user_data():
    """Delete all user data on request"""
    user_id = current_user.id

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