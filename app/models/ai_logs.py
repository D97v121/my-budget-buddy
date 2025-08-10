from app import db
from datetime import datetime

class AICategorizationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'))
    user_id = db.Column(db.Integer, nullable=False)  # 👈 New!
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ai_guess = db.Column(db.String(20))
    user_division = db.Column(db.String(20))
    accepted = db.Column(db.Boolean)
    # Tag-specific
    ai_tags_guess = db.Column(db.String(255))  # JSON string of AI-predicted tags
    user_tags = db.Column(db.String(255))      # JSON string of user-selected tags
    tags_accepted = db.Column(db.Boolean)      # Whether all AI tags were accepted