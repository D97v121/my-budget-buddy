from app import db
from flask_login import UserMixin
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False )
    hash = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    savePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    spendPercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    investPercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    expensePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    givePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)