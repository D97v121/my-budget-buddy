from app import db

transaction_tags = db.Table(
    'transaction_tags',
    db.Column(
        'transaction_id',
        db.Integer,
        db.ForeignKey('transactions.id', ondelete="CASCADE"),
        primary_key=True
    ),
    db.Column(
        'tag_id',
        db.Integer,
        db.ForeignKey('tags.id', ondelete="CASCADE"),
        primary_key=True
    )
)
