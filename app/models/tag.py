from app import db
from app.models.association_tables import transaction_tags


class Tags(db.Model):
    __tablename__ = 'tags'
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

