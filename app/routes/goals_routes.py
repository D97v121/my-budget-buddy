from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_required
from flask_wtf.csrf import generate_csrf
from datetime import datetime
from flask_login import current_user
from app import db
from app.models import Goal, Note #check this import

goals_bp = Blueprint("goals", __name__)

@goals_bp.route('/goals', methods=["GET", "POST"])
@login_required
def goals():
    user_id = current_user.id
    csrf_token = generate_csrf()

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_goal = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_goal)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_goals = Goal.query.filter_by(user_id=user_id).order_by(Goal.timestamp.desc()).all()

    return render_template('goals.html', goals=user_goals, csrf_token=csrf_token)

@goals_bp.route('/add_goal', methods=["POST"])
@login_required
def add_goal():
    content = request.form.get("content")
    if content:
        goal = Goal(user_id = current_user.id, content=content, timestamp=datetime.now())
        db.session.add(goal)
        db.session.commit()
    return redirect(url_for("goals"))

@goals_bp.route('/update_goal/<int:goal_id>', methods=["POST"])
@login_required
def update_goal(goal_id):
    content = request.form.get("content")
    goal = Goal.query.filter_by(id=goal_id, user_id = current_user.id).first()
    if goal:
        goal.content = content
        db.session.commit()
    return redirect(url_for("goals"))

@goals_bp.route('/delete_goal/<int:goal_id>', methods=["POST"])
@login_required
def delete_goal(goal_id):
    goal = Goal.query.filter_by(id=goal_id, user_id = current_user.id).first()
    if goal:
        db.session.delete(goal)
        db.session.commit()
    return redirect(url_for("goals"))