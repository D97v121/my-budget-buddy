from app import db
class Money(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    save = db.Column(db.Numeric(precision=10, scale=2), default="0")
    spend  = db.Column(db.Numeric(precision=10, scale=2), default="0")
    give = db.Column(db.Numeric(precision=10, scale=2), default="0")
    invest = db.Column(db.Numeric(precision=10, scale=2), default="0")
    expense = db.Column(db.Numeric(precision=10, scale=2), default="0")