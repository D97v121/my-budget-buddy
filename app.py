import os
import re
import logging
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from decimal import Decimal, InvalidOperation
from helpers import apology, login_required, lookup, usd, calculateAllMoney, calculateCategory, dollar, graph_records, timestamp_editor, exit_usd, cycle_through_money_table, delete_record, initialize_money_record, populate_tags
from models import db, Give, Spend, Save, Invest, Money, Expense, User, Tags, TagColor, Note, Goal
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime 
from sqlalchemy.inspection import inspect
from collections import defaultdict
from flask_login import current_user
import locale

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters['timestamp_editor'] = timestamp_editor

# Configure session to use filesystem (instead of signed cookies)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///money.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False  # Optional, set if needed
Session(app)

db.init_app(app)
migrate = Migrate(app, db)

# Initialize SQLAlchemy
model_map = {
    "save": Save,
    "spend": Spend,
    "give": Give,
    "invest": Invest,
    "expense": Expense
}


# Create the database and tables
logging.basicConfig(level=logging.DEBUG)

# Create the database and tables
with app.app_context():
    db.create_all()
    print("Tables created successfully")

if __name__ == '__main__':
    app.run(debug=False)


@app.route('/delete_data', methods=["GET", "POST"])
def delete_data():
    if request.method == "POST":
        category = request.form.get("category").lower() 
        if category == "tags":
            db.session.query(Tags).delete()
            db.session.commit()
            db.session.query(TagColor).delete()
            db.session.commit()
            return render_template('delete_data.html')
        model = model_map[category]
        money_column = category
        print(f"Category: {category}")
        print(f"Model: {model}")
        print(f"Money Column: {money_column}")
        try:
            # Perform deletion
            db.session.query(model).delete()
            db.session.query(Money).update({money_column: 0})
            db.session.commit()
            return "All expenses deleted successfully."
        except Exception as e:
            db.session.rollback()
            return f"Failed to delete {category}: {e}"
    else:
        return render_template('delete_data.html')
    

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    error_message = None

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")

        # Query the user by username
        user = User.query.filter_by(username=username).first()

        # Ensure username exists and password is correct
        if user is None or not check_password_hash(user.hash, password):
            error_message = "Incorrect username or password"
            return render_template("login.html", error_message=error_message)

        # Remember which user has logged in
        session["user_id"] = user.id
            # Populate tags and tag colors for the new user
        
        # Redirect user to home page
        return redirect("/")
        
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")

give_goal = 1000
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        error_message = None

        if User.query.filter_by(username=username).first() is not None:
            username_error = "Username already taken"
            return render_template("register.html", username_error=username_error)
   
        # Create new user
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, username=username, hash=password_hash)

        try:
            logging.debug(f"name: { name } username: { username } password: { password }")
            db.session.add(new_user)
            db.session.commit()
            
            user_id = new_user.id
            session["user_id"] = user_id

            # Populate tags and tag colors for the new user
            populate_tags(db, user_id)

            return redirect(url_for("profile_questions"))
        
        except Exception as e:
            db.session.rollback()
            error_message = f"An error occurred: {e}"
            return render_template("register.html")

    else:
        return render_template("register.html")

@app.route('/profile_questions', methods=["GET", "POST"])
def profile_questions():
    if request.method == "POST":
        try:
            categories = ['save', 'spend', 'give', 'invest', 'expense']
            description = 'initial balance'
            root = 'external'

            for category in categories:
                balance_key = f'starting_{category}_balance'
                label = category
                tag = category.capitalize()
                money_str = request.form.get(balance_key)

                if money_str is None:
                    raise ValueError(f"Starting balance for {category} is missing.")

                try:
                    money = Decimal(money_str)
                except InvalidOperation:
                    raise ValueError(f"Invalid starting balance for {category}.")

                calculateCategory(db, model_map[label], label, money, description, root, tag)

            db.session.commit()

            flash("Profile updated successfully.", "success")
            logging.debug("Profile updated successfully")

            return redirect("/login")
        
        except Exception as e:
            db.session.rollback()
            flash(str(e), "danger")
            logging.debug("error")
            return render_template("profile_questions.html")
        
    else:
        return render_template("profile_questions.html")
        
    
@app.route('/', methods=["GET", "POST"])
@login_required
def index():
    user_id=session.get("user_id")
    logging.debug("Index route accessed")
    moneyTable = Money.query.filter_by(user_id=user_id).first()
    description = request.form.get("transaction_description")
    form_id = request.form.get('form_id')
    tag = request.form.get("tag")
    if request.method == "POST":
        if form_id == 'transactionForm':
            label = request.form.get("category").lower() 
            root = "external"
            logging.debug(f"Form submitted with category: {label}")
            try:
                if label in model_map:
                    money = Decimal(request.form.get("recordedTransaction"))
                    description = request.form.get("transaction_description")
                    calculateCategory(db, model_map[label], label, money, description, root, tag)
                else:
                    calculateAllMoney(db, Money, tag)
                db.session.commit()
                logging.debug("Transaction committed successfully")
                return redirect("/")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Transaction failed and rolled back: {e}")
                return f"Transaction failed and rolled back: {e}", 500
        elif form_id == "transferForm":
            to_label = request.form.get("toCategory").lower()
            from_label = request.form.get("fromCategory").lower()
            root = from_label
            try:
                if to_label in model_map and from_label in model_map:
                    money = Decimal(request.form.get("recordedTransaction"))
                    description = request.form.get("transaction_description")
                    calculateCategory(db, model_map[to_label], to_label, money, description, root, tag)
                    calculateCategory(db, model_map[from_label], from_label, -money, description, root="none", tag=tag)
                else:
                    calculateAllMoney(db, Money, tag)
                    money = Decimal(request.form.get("recordedTransaction"))
                    calculateCategory(db, model_map[from_label], from_label, -money, description, root, tag)
                db.session.commit()
                logging.debug("Transaction committed successfully")
                return redirect("/")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Transaction failed and rolled back: {e}")
                return f"Transaction failed and rolled back: {e}", 500
        else:
            print("error")

    left_in_spend = moneyTable.spend if moneyTable else 0
    spend_tag_color = Tags.query.filter_by(user_id=user_id, name='Spend').first()
    spending_color = spend_tag_color.color_id if spend_tag_color else '#BBA2C8'
    
    logging.debug(f"Spend tag color from DB: {spending_color}")


    expense_records = Expense.query.filter_by(user_id=user_id).all()
    tag_counter = defaultdict(float)
    for record in expense_records:
        tag_counter[record.tag] += float(record.amount)

    tags_list = Tags.query.filter_by(user_id=user_id, status=True).all()
    tag_color_map = {tag.name: tag.color_id for tag in tags_list if tag.name}

    tag_details = {}
    for tag, count in tag_counter.items():
        if tag in tag_color_map:
            tag_details[tag] = {
                'count': count,
                'color': tag_color_map.get(tag, '#FFFFFF')  # Default color if not in tag_color_map
            }

    colors = [details['color'] for details in tag_details.values()]
    counts = [details['count'] for details in tag_details.values()]
    tag_names = [tag if tag else 'none' for tag in tag_details.keys()]
    
    return render_template("index.html", moneyTable=moneyTable, left_in_spend=left_in_spend, description=description, tags_list=tags_list, colors=colors, counts=counts, tag_names=tag_names, spending_color=spending_color)


@app.route('/Tracking', methods=["GET", "POST"])
@login_required
def tracking():
    user_id=session.get("user_id")
    money_record = initialize_money_record(db)
    cycle_through_money_table(db, money_record)
    
    moneyTable = Money.query.filter_by(user_id=user_id).first()
    save = moneyTable.save if moneyTable else 0
    spend = moneyTable.spend if moneyTable else 0
    give = moneyTable.give if moneyTable else 0
    invest = moneyTable.invest if moneyTable else 0
    expense = moneyTable.expense if moneyTable else 0

    save_float, save_dates = graph_records(Save)
    spend_float, spend_dates = graph_records(Spend)
    give_float, give_dates = graph_records(Give)
    invest_float, invest_dates = graph_records(Invest)
    expense_float, expense_dates = graph_records(Expense)

    return render_template('Tracking.html',
                       save_data=save_float, save_dates=save_dates,
                       spend_data=spend_float, spend_dates=spend_dates,
                       give_data=give_float, give_dates=give_dates,
                       invest_data=invest_float, invest_dates=invest_dates,
                       expense_data=expense_float, expense_dates=expense_dates, save=dollar(save), spend=dollar(spend), give=dollar(give), invest=dollar(invest), expense=dollar(expense))


@app.route('/Settings', methods=["GET", "POST"])
@login_required
def settings():
    return render_template('Settings.html')

@app.route('/History', methods=["GET", "POST"])
@login_required
def history():
    user_id = session.get("user_id")
    tags_list = Tags.query.filter_by(user_id=user_id).all()

    category_records = {}
    for category, model in model_map.items():
        category_records[category] = model.query.filter_by(user_id=user_id).all()

 
    return render_template("history.html", category_records=category_records, tags_list=tags_list)

@app.route('/invest_history', methods=["GET", "POST"])
@login_required
def invest_history():
    invest_records = Invest.query.all()
    invest_records_data = []
    for record in invest_records:
        invest_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })
    return render_template("invest_history.html", invest_records_data=invest_records_data)

@app.route('/save_history', methods=["GET", "POST"])
@login_required
def save_history():
    save_records = Save.query.all()
    save_records_data = []
    for record in save_records:
        save_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })
    return render_template("save_history.html", save_records_data=save_records_data)


@app.route('/spend_history', methods=["GET", "POST"])
@login_required
def spend_history():
    spend_records = Spend.query.all()
    spend_records_data = []
    for record in spend_records:
        spend_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })
    return render_template("spend_history.html", spend_records_data=spend_records_data)


@app.route('/give_history', methods=["GET", "POST"])
@login_required
def give_history():
    give_records = Give.query.all()
    give_records_data = []
    for record in give_records:
        give_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })
    return render_template("give_history.html", give_records_data=give_records_data)

@app.route('/expense_history', methods=["GET", "POST"])
@login_required
def expense_history():
    expense_records = Expense.query.all()
    expense_records_data = []
    for record in expense_records:
        expense_records_data.append({
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })
    return render_template("expense_history.html", expense_records_data=expense_records_data)


@app.route('/update_record', methods=['POST'])
@login_required
def update_record():
    if request.method == "POST":
        tag = request.form.get('tag')
        category = request.form.get('category')
        record_id = request.form.get('record_id')
        amount = exit_usd(request.form.get('amount'))
        root = request.form.get('root')
        description = request.form.get('description')
        deleteBoolean = request.form.get('deleteBoolean')
        logging.debug(f"tag: {tag}")

        Model = model_map.get(category.lower())

        if deleteBoolean == "true":
            logging.debug(f"deleteBoolean is true")
            delete_record(db, record_id, Model)
            return redirect(url_for('history'))

        # Get the appropriate model based on category
        Model = model_map.get(category.lower())

        if not record_id:
            logging.debug(f"no record_id")
            return redirect(url_for('history'))

        if Model is None:
            logging.debug(f"model was none")
            return redirect(url_for('history'))

        record = Model.query.get_or_404(record_id)
        try:
            record.tag = tag
            record.amount = float(amount)
            record.root = root
            record.description = description
            db.session.commit()
    
        except Exception as e:
            db.session.rollback()

        return redirect(url_for('history'))

    return redirect(url_for('history'))

@app.route('/settings/general')
@login_required
def settings_general():
    return render_template('settings/general.html')

@app.route('/settings/tags', methods=["GET", "POST"])
@login_required
def tags():
    logging.debug(f"tags route called")
    user_id = session.get("user_id")
    tags = Tags.query.filter_by(user_id=user_id).all()
    tag_colors = TagColor.query.filter_by(user_id=user_id).all()

    if request.method == "POST":
        # Update existing tags
        for tag in tags:
            tag_id = tag.id
            tag.color_id = request.form.get(f'color_{tag_id}')
            tag.name = request.form.get(f'tagName_{tag_id}')
            tag_status_field = f'tagStatus_{tag_id}'
            tag.status = tag_status_field in request.form
            db.session.commit()
        
        # Add new tag if it exists in the form
        if request.form.get('tagName_new'):
            new_tag = Tags(
                user_id=user_id,
                color_id=request.form.get('color_new'),
                name=request.form.get('tagName_new'),
                status='tagStatus_new' in request.form
            )
            db.session.add(new_tag)
            db.session.commit()

        return redirect(url_for('tags'))

    return render_template("settings/tags.html", tags=tags, tag_colors=tag_colors)
    
@app.route('/delete_tags', methods=["POST"])
@login_required
def delete_tags():
    user_id = session.get("user_id")

    tag_select_data = []
    for tag in Tags.query.filter_by(user_id=user_id).all():
        if f"select_{tag.id}" in request.form:
            tag_select_data.append(tag.id)
    
    for tag_id in tag_select_data:
        tag = Tags.query.filter_by(id=tag_id, user_id=user_id).first()
        if tag:
            db.session.delete(tag)
            db.session.commit()
    return redirect(url_for('tags'))

@app.route('/add_tag', methods=['POST'])
@login_required
def add_tag():
    user_id = session.get("user_id")
    logging.debug(f"New tag being added for { user_id }")

    new_tag_color = request.form.get('color_new')
    new_tag_name = request.form.get('tagName_new')
    new_tag_status= request.form.get('select_new')

    if new_tag_name and new_tag_color:
        new_tag = Tags(
            user_id=user_id,
            color_id=new_tag_color,  # Assuming color_id is a valid color hex valueX
            name=new_tag_name,
            status=True  # Set default status to active, adjust as needed
        )
    db.session.add(new_tag)
    db.session.commit()
    logging.debug(f"New tag added: {new_tag_name} with color {new_tag_color}")

    return redirect(url_for('tags'))

@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    user_id = session.get("user_id")
    user = User.query.filter_by(id=user_id).first()
    error_message = None
    if request.method == "POST":
        form_id = request.form.get("form_id")

        # Handle Change Password Form
        if form_id == "change_password":
            old_password_input = request.form.get("old_password")
            new_password = request.form.get("new_password")
            confirmation = request.form.get("confirmation")

        # Ensure username exists and password is correct
        if not check_password_hash(user.hash, old_password_input):
            error_message = "Incorrect password"
            return render_template("settings/account.html", error_message=error_message)
        
        if new_password != confirmation:
            error_message = "Passwords must match"
            return render_template("settings/account.html", error_message=error_message)
        
        user.hash = generate_password_hash(new_password, method="pbkdf2:sha256")
        db.session.commit()
        flash("Password has been changed successfully!", "success")
        return redirect("account")
        
    else:
        return render_template("settings/account.html")

@app.route('/notes', methods=["GET", "POST"])
@login_required
def notes():
    user_id = session.get("user_id")

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_note = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_note)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_notes = Note.query.filter_by(user_id=user_id).order_by(Note.timestamp.desc()).all()

    return render_template('notes.html', notes=user_notes)

@app.route('/add_note', methods=["POST"])
@login_required
def add_note():
    content = request.form.get("content")
    if content:
        note = Note(user_id=session["user_id"], content=content, timestamp=datetime.now())
        db.session.add(note)
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/update_note/<int:note_id>', methods=["POST"])
@login_required
def update_note(note_id):
    content = request.form.get("content")
    note = Note.query.filter_by(id=note_id, user_id=session["user_id"]).first()
    if note:
        note.content = content
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/delete_note/<int:note_id>', methods=["POST"])
@login_required
def delete_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=session["user_id"]).first()
    if note:
        db.session.delete(note)
        db.session.commit()
    return redirect(url_for("notes"))

@app.route('/goals', methods=["GET", "POST"])
@login_required
def goals():
    user_id = session.get("user_id")

    # Handle form submission for adding a new note
    if request.method == "POST":
        content = request.form.get("content")
        if content:
            new_goal = Note(user_id=user_id, content=content, timestamp=datetime.now())
            db.session.add(new_goal)
            db.session.commit()
            return redirect(url_for("notes"))

    # Fetch all notes for the current user
    user_goals = Goal.query.filter_by(user_id=user_id).order_by(Goal.timestamp.desc()).all()

    return render_template('goals.html', goals=user_goals)

@app.route('/add_goal', methods=["POST"])
@login_required
def add_goal():
    content = request.form.get("content")
    if content:
        goal = Goal(user_id=session["user_id"], content=content, timestamp=datetime.now())
        db.session.add(goal)
        db.session.commit()
    return redirect(url_for("goals"))

@app.route('/update_goal/<int:goal_id>', methods=["POST"])
@login_required
def update_goal(goal_id):
    content = request.form.get("content")
    goal = Goal.query.filter_by(id=goal_id, user_id=session["user_id"]).first()
    if goal:
        goal.content = content
        db.session.commit()
    return redirect(url_for("goals"))

@app.route('/delete_goal/<int:goal_id>', methods=["POST"])
@login_required
def delete_goal(goal_id):
    goal = Goal.query.filter_by(id=goal_id, user_id=session["user_id"]).first()
    if goal:
        db.session.delete(goal)
        db.session.commit()
    return redirect(url_for("goals"))

@app.route('/verify')
def verify():
    user_id=session.get("user_id")
    # Query all records from each table
    saved_records = Save.query.filter_by(user_id=user_id).all()
    spend_records = Spend.query.filter_by(user_id=user_id).all()
    give_records = Give.query.filter_by(user_id=user_id).all()
    invest_records = Invest.query.filter_by(user_id=user_id).all()
    money_records = Money.query.filter_by(user_id=user_id).all()
    user_records = User.query.all()
    tags = Tags.query.filter_by(user_id=user_id).all()
    tag_color = TagColor.query.filter_by(user_id=user_id).all()

    user_data = []
    for record in user_records:
        user_data.append({
            "id": record.id,
            "name": record.name,
            "hash": record.hash,
            "username": record.username,
        })

    # Prepare data for each table
    save_data = []
    for record in saved_records:
        save_data.append({
            "id": record.id,
            "user_id": record.user_id,
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })

    spend_data = []
    for record in spend_records:
        spend_data.append({
            "id": record.id,
            "user_id": record.user_id,
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })

    give_data = []
    for record in give_records:
        give_data.append({
            "id": record.id,
            "user_id": record.user_id,
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })

    invest_data = []
    for record in invest_records:
        invest_data.append({
            "id": record.id,
            "user_id": record.user_id,
            "tag": record.tag,
            "amount": record.amount,
            "root": record.root,
            "description": record.description,
            "timestamp": record.timestamp
        })

    money_data = []
    for money_record in money_records:
        money_data.append({
            "id": money_record.id,
            "user_id": money_record.user_id,
            "save": money_record.save,
            "spend": money_record.spend,
            "give": money_record.give,
            "invest": money_record.invest
        })

    tag_data = []
    for tag in tags:
        tag_data.append({
            "name": tag.id,
            "status": tag.status,
            
        })

    tag_color_data = []
    for TagColorData in tag_color:
        tag_color_data.append({
            "color_name": TagColorData.color_name,
            "color_hex": TagColorData.color_hex,
        })
    # Render the template with all the data
    return render_template("verify.html", tags=tags, tag_color=tag_color, save_data=save_data, spend_data=spend_data, give_data=give_data, user_data=user_data, money_data=money_data, tag_data=tag_data, tag_color_data=tag_color_data)