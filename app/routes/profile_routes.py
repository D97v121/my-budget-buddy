from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from flask_login import login_required
from decimal import Decimal
import logging
from app.models import User, PlaidItem
from app import db, csrf
from flask_login import current_user

profile_bp = Blueprint("profile", __name__)



@profile_bp.route("/profile_questions", methods=["GET", "POST"])
@csrf.exempt
def profile_questions():
    if request.method == "POST":
        try:
            user_id = current_user.id
            if not user_id:
                raise ValueError("User not logged in.")

            user = User.query.get(user_id)
            if not user:
                raise ValueError("User not found.")

            percentages = {
                "save": request.form.get("save_income_percentage"),
                "spend": request.form.get("spend_income_percentage"),
                "give": request.form.get("give_income_percentage"),
                "invest": request.form.get("invest_income_percentage"),
                "expense": request.form.get("expense_income_percentage"),
            }

            if not all(percentages.values()):
                raise ValueError("All percentages must be provided.")

            for key in percentages:
                percentages[key] = Decimal(percentages[key])

            if sum(percentages.values()) != Decimal(100):
                raise ValueError("Percentages must add up to 100.")

            user.savePercentage = percentages["save"]
            user.spendPercentage = percentages["spend"]
            user.givePercentage = percentages["give"]
            user.investPercentage = percentages["invest"]
            user.expensePercentage = percentages["expense"]

            db.session.commit()
            flash("Profile updated successfully.", "success")
            return redirect("/login")

        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")
            logging.debug(f"Error: {e}")
            return render_template("profile_questions.html")
    return render_template("profile_questions.html")


@profile_bp.route('/print_access_tokens', methods=['GET'])
@login_required
def print_access_tokens():
    user_id = current_user.id
    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    plaid_items = PlaidItem.query.filter_by(user_id=user_id).all()
    if plaid_items:
        tokens = [item.access_token for item in plaid_items]
        logging.debug(f"Access tokens for user {user_id}: {tokens}")
        return jsonify({"access_tokens": tokens})
    return jsonify({"message": "No access tokens found"})
