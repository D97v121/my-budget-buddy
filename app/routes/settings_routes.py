from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_login import login_required
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import generate_csrf
from flask_login import current_user
from app import db
from app.models import User, Tags, TagColor


settings_bp = Blueprint("settings", __name__)

@settings_bp.route('/Settings', methods=["GET", "POST"])
@login_required
def settings():
    return render_template('Settings.html')

@settings_bp.route('/settings/general')
@login_required
def settings_general():
    return render_template('settings/general.html')

@settings_bp.route('/settings/tags', methods=["GET", "POST"])
@login_required
def tags():
    user_id = current_user.id
    tags = Tags.query.filter_by(user_id=user_id).all()
    tag_colors = TagColor.query.filter_by(user_id=user_id).all()
    csrf_token = generate_csrf()

    if request.method == "POST":
        for tag in tags:
            tag_id = tag.id
            tag.color_id = request.form.get(f'color_{tag_id}')
            tag.name = request.form.get(f'tagName_{tag_id}')
            tag.status = f'tagStatus_{tag_id}' in request.form
        db.session.commit()

        if request.form.get('tagName_new'):
            new_tag = Tags(
                user_id=user_id,
                color_id=request.form.get('color_new'),
                name=request.form.get('tagName_new'),
                status='tagStatus_new' in request.form
            )
            db.session.add(new_tag)
            db.session.commit()

        return redirect(url_for('settings.tags'))

    return render_template("settings/tags.html", tags=tags, tag_colors=tag_colors, csrf_token=csrf_token)

@settings_bp.route('/delete_tags', methods=["POST"])
@login_required
def delete_tags():
    user_id = current_user.id
    tag_ids = [tag.id for tag in Tags.query.filter_by(user_id=user_id).all() if f"select_{tag.id}" in request.form]
    for tag_id in tag_ids:
        tag = Tags.query.filter_by(id=tag_id, user_id=user_id).first()
        if tag:
            db.session.delete(tag)
    db.session.commit()
    return redirect(url_for('settings.tags'))

@settings_bp.route('/add_tag', methods=['POST'])
@login_required
def add_tag():
    user_id = current_user.id

    new_tag_color = request.form.get('color_new')
    new_tag_name = request.form.get('tagName_new')

    if new_tag_name and new_tag_color:
        new_tag = Tags(
            user_id=user_id,
            color_id=new_tag_color,
            name=new_tag_name,
            status=True
        )
        db.session.add(new_tag)
        db.session.commit()

    return redirect(url_for('settings.tags'))

@settings_bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user_id = current_user.id
    user = User.query.filter_by(id=user_id).first()
    csrf_token = generate_csrf()
    error_message = None
    if request.method == "POST":
        form_id = request.form.get("form_id")

        # Handle Change Password Form
        if form_id == "change_password":
            old_password_input = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")

        # Ensure username exists and password is correct
        if not check_password_hash(user.hash, old_password_input):
            error_message = "Incorrect password"
            return render_template("settings/account.html", error_message=error_message)
        
        if new_password != confirmation:
            error_message = "Passwords must match"
            return render_template("settings/account.html", error_message=error_message)
        
        user.hash = generate_password_hash(new_password, method="pbkdf2:sha256")
        db.session.commit()
        flash("Password has been changed successfully!", "success")
        return redirect("account")
        
    else:
        return render_template("settings/account.html", csrf_token=csrf_token)