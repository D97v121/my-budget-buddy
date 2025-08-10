from app import db

class Save(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120), nullable=False)
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Spend(Save): pass
class Give(Save): pass
class Invest(Save): pass
class Expense(Save): pass