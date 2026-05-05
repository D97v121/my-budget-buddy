from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_required
from flask_wtf.csrf import generate_csrf
from datetime import datetime
from flask_login import current_user
from app import db
from app.models import Note

notes_bp = Blueprint("notes", __name__)

@notes_bp.route('/notes', methods=["GET", "POST"])
@login_required
def notes():
    user_id = current_user.id
    csrf_token=generate_csrf()

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_note = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_note)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_notes = Note.query.filter_by(user_id=user_id).order_by(Note.timestamp.desc()).all()

    return render_template('notes.html', notes=user_notes, csrf_token=csrf_token)

@notes_bp.route('/add_note', methods=["POST"])
@login_required
def add_note():
    content = request.form.get("content")
    user_id = current_user.id
    if content:
        note = Note(user_id=user_id, content=content, timestamp=datetime.now())
        db.session.add(note)
        db.session.commit()
    return redirect(url_for("notes"))

@notes_bp.route('/update_note/<int:note_id>', methods=["POST"])
@login_required
def update_note(note_id):
    content = request.form.get("content")
    user_id = current_user.id
    note = Note.query.filter_by(id=note_id, user_id=user_id).first()
    if note:
        note.content = content
        db.session.commit()
    return redirect(url_for("notes"))

@notes_bp.route('/delete_note/<int:note_id>', methods=["POST"])
@login_required
def delete_note(note_id):
    user_id = current_user.id
    note = Note.query.filter_by(id=note_id, user_id=user_id).first()
    if note:
        db.session.delete(note)
        db.session.commit()
    return redirect(url_for("notes"))