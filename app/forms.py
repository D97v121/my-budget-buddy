from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=20, message="Username must be 3-20 characters long"),
        Regexp(r"^[a-zA-Z0-9_.-]+$", message="Username contains invalid characters")
    ])
    password = PasswordField("Password", validators=[
        DataRequired(message="Password is required"),
        Length(min=1, message="Password must be at least 8 characters long")
    ])
    submit = SubmitField("Login")

class TransactionForm(FlaskForm):
    amount = StringField("Amount", validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])