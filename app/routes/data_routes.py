from flask import Blueprint, render_template, request, session
from app import db
from app.models import Tags, TagColor, Transaction
from flask import jsonify
from flask_wtf.csrf import generate_csrf

data_bp = Blueprint('data', __name__)

@data_bp.route("/delete_data", methods=["GET", "POST"])
def delete_data():
    if request.method == "POST":
        category = request.form.get("category", "").lower()
        division_filter = request.form.get("division", "").lower()

        if not category:
            return render_template('delete_data.html', error="No category selected. Please choose a category.")

        try:
            if category == "tags":
                db.session.query(Tags).delete()
                db.session.query(TagColor).delete()
            elif category == "transactions":
                query = db.session.query(Transaction)
                if division_filter:
                    query = query.filter_by(division=division_filter)
                deleted_count = query.delete()
                if deleted_count == 0:
                    return render_template('delete_data.html', error=f"No transactions found for division: {division_filter}")
            else:
                return render_template('delete_data.html', error=f"Invalid category: {category}")

            db.session.commit()
            success_message = f"All data deleted successfully for category: {category}"
            if category == "transactions" and division_filter:
                success_message = f"Transactions with division '{division_filter}' deleted successfully."
            return render_template('delete_data.html', success=success_message)
        except Exception as e:
            db.session.rollback()
            return render_template('delete_data.html', error=f"Failed to delete {category}: {e}")
    return render_template('delete_data.html')

@data_bp.before_app_request
def refresh_session():
    session.permanent = True
    session.modified = True
