from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import uuid
from cryptography.fernet import Fernet
import base64
import os
from cryptography.fernet import InvalidToken
from app.encryption_utils import encrypt_data, decrypt_data
from sqlalchemy import Column, DateTime
def generate_uuid():
    """Generate a UUID string."""
    return str(uuid.uuid4())

db = SQLAlchemy()

transaction_tags = db.Table(
    'transaction_tags',
    db.Column(
        'transaction_id',
        db.Integer,
        db.ForeignKey('transaction.id', ondelete="CASCADE"),
        primary_key=True
    ),
    db.Column(
        'tag_id',
        db.Integer,
        db.ForeignKey('tags.id', ondelete="CASCADE"),
        primary_key=True
    ),
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False )
    hash = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(120), nullable=False, unique=True)
    savePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    spendPercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    investPercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    expensePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)
    givePercentage = db.Column(db.Numeric(precision=10, scale=2), nullable=True)

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
    amount = db.Column(db.Numeric(precision=10, scale=2), nullable=False, default="0")
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
    transactions = db.relationship(
        'Transaction',
        secondary=transaction_tags,
        back_populates='tags'
    )
    __table_args__ = (
        db.UniqueConstraint('user_id', 'name', name='_user_tag_uc'),
    )

    
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

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class PlaidItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(255), nullable=False, server_default='')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    cursor = db.Column(db.String, nullable=True)
    institution_id = db.Column(db.String, nullable=True)  # Add this line
    institution_name = db.Column(db.String, nullable=True) 
    created_at = db.Column(DateTime, default=datetime.utcnow)


    # Relationship with User model
    user = db.relationship('User', backref=db.backref('plaid_items', lazy=True))

    # Securely store access_token as encrypted but allow decrypted access
    @property
    def decrypted_access_token(self):
        try:
            return decrypt_data(self.access_token)
        except InvalidToken:
            return self.access_token
        
    @decrypted_access_token.setter
    def decrypted_access_token(self, token):
        """Encrypt access_token before storing"""
        self.access_token = encrypt_data(token)  # ✅ Modify the column directly



class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Auto-increment ID for the database
    user_id = db.Column(db.Integer, nullable=False)  # Link transaction to the user
    transaction_id = db.Column(db.String, nullable=False, default=db.text(f"'{generate_uuid()}'"))  # Unique ID from Plaid
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())  # Transaction date
    name = db.Column(db.String, nullable=False, default="user transaction")  # Merchant or payee name
    category = db.Column(db.String, nullable=True, default="none")  # Plaid category for the transaction
    amount = db.Column(db.Float, nullable=False)  # Transaction amount
    bank_account = db.Column(db.String, nullable=True)
    account_id = db.Column(db.String, nullable=True)  # Linked bank account ID
    pending = db.Column(db.Boolean, default=False)  # Whether the transaction is pending
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp()) # Record creation timestamp
    bank_name = db.Column(db.String(100), nullable=True)
    division = db.Column(db.String, nullable=True, default="")  
    note = db.Column(db.String, nullable=True, default="")
    created_at = db.Column(DateTime, default=datetime.utcnow)
    item_id = db.Column(db.String(255), nullable=True)
    tags = db.relationship(
        'Tags',
        secondary=transaction_tags,
        back_populates='transactions')
    
    def __repr__(self):
        return f"<Transaction {self.name} - {self.amount}>"