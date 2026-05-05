from datetime import datetime
from sqlalchemy import text
from app import db
from sqlalchemy import DateTime
from app.models.association_tables import transaction_tags

def generate_uuid():
    import uuid
    return str(uuid.uuid4())

class Transaction(db.Model):
    __tablename__ = "transactions"
    id = db.Column(db.Integer, primary_key=True)  # Auto-increment ID for the database
    user_id = db.Column(db.Integer, nullable=False)  # Link transaction to the user
    transaction_id = db.Column(db.String, nullable=False, default=db.text(f"'{generate_uuid()}'"))  # Unique ID from Plaid
    date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())  # Transaction date
    name = db.Column(db.String, nullable=False, default="user transaction")  # Merchant or payee name
    plaid_category = db.Column(db.String, nullable=True, default="none")  # Plaid category for the transaction
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
    ai_division_guess = db.Column(db.String(20))
    ai_division_accepted = db.Column(db.Boolean, default=None) 
    tags = db.relationship(
        'Tags',
        secondary=transaction_tags,
        back_populates='transactions')
    
    def __repr__(self):
        return f"<Transaction {self.name} - {self.amount}>"