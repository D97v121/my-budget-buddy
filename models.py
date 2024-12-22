
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False )
    hash = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)

class Money(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    save = db.Column(db.Numeric(precision=10, scale=2), default="0")
    spend  = db.Column(db.Numeric(precision=10, scale=2), default="0")
    give = db.Column(db.Numeric(precision=10, scale=2), default="0")
    invest = db.Column(db.Numeric(precision=10, scale=2), default="0")
    expense = db.Column(db.Numeric(precision=10, scale=2), default="0")
    
class Save(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120), nullable=False)
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Spend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120), nullable=False)
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Give(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount =db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120), nullable=False)
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Invest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120))
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
    description = db.Column(db.String(200))
    root = db.Column(db.String(120))
    tag = db.Column(db.String(30))
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(50),  nullable=False, default="none")
    status = db.Column(db.Boolean, default=True)
    color_id = db.Column(db.Integer, db.ForeignKey('tag_color.id'))
    
class TagColor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    color_name = db.Column(db.String(50), nullable=False)
    color_hex = db.Column(db.String(7), nullable=False)
    
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
