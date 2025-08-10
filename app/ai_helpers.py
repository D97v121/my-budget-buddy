from app import db
from app.models.ai_logs import AICategorizationLog
from datetime import datetime
from openai import OpenAI
import logging
import os
import json 
from app.models import Tags
import json as pyjson

openai_api_key = OpenAI(
api_key=os.getenv("OPENAI_API_KEY"))


def predict_transaction_division(transaction):
    """
    Categorizes a transaction using prior user behavior if applicable,
    otherwise uses the OpenAI API to make a new prediction.
    """
    from app.models import AICategorizationLog, Transaction
    from sqlalchemy import func

    user_id = transaction.user_id
    name = transaction.name.lower()

    print(f"Categorizing transaction ID: {transaction.id} | Amount: {transaction.amount} | Bank: {transaction.bank_account}")

    # STEP 1: Check for a strong user preference override
    override = db.session.query(
        AICategorizationLog.user_division,
        func.count().label("count")
    ).join(Transaction, AICategorizationLog.transaction_id == Transaction.id)\
     .filter(
        AICategorizationLog.user_id == user_id,
        func.lower(Transaction.name).like(f"%{name[:10]}%"),  # Partial match on name
        AICategorizationLog.accepted == False,
        AICategorizationLog.ai_guess != AICategorizationLog.user_division
    ).group_by(AICategorizationLog.user_division)\
     .order_by(func.count().desc())\
     .first()

    if override and override.count >= 3:
        override_division = override.user_division.lower()
        print(f"User override used for '{transaction.name}': {override_division}")
        transaction.ai_division_guess = override_division
        return override_division

    # STEP 2: Use OpenAI if no user-based override
    direction = "INFLOW" if transaction.amount > 0 else "OUTFLOW"
    tag_names = [tag.name for tag in transaction.tags]
    transaction_text = f"Transaction: {transaction.name}, Amount: {transaction.amount}, Tags: {', '.join(tag_names)}, Division: {transaction.division}, Bank: {transaction.bank_account}, Direction: {direction}."
    print(f"Generated transaction text: {transaction_text}")

    completion = openai_api_key.chat.completions.create(
        model="gpt-4o-mini",
        store=True,
        messages=[{
            "role": "system",
            "content": (
                "You are an expert financial assistant. You will categorize bank transactions "
                "into one of exactly five divisions: Save, Spend, Give, Expense, or Invest. In order to do this you will take into account the transactions' name, division, amount, tags, bank and direction.\n\n"
                "Definitions:\n"
                "- Save: incoming money set aside for future use (e.g., savings transfers)\n"
                "- Invest: money allocated for returns (e.g., stock purchases, brokerage transfers)\n"
                "- Give: charitable or personal giving (e.g., donations, gifts to others)\n"
                "- Expense: recurring outgoing charges (don't assign this to a transaction unless you see a consistent monthly charge or it says 'subscription' in the name)\n"
                "- Spend: non-essential outgoing or discretionary purchases (e.g., restaurants, shopping). Incoming transactions can also be put in the spend division when small amounts of money are added to a user's account\n\n"
                "RULES:\n"
                "- Respond with only ONE WORD: Save, Spend, Give, Expense, or Invest.\n"
                "- Do NOT include any explanation or punctuation.\n"
                "- If unclear, make your best guess."
            )
        }, {
            "role": "user",
            "content": f"Categorize this transaction: {transaction_text}"
        }]
    )

    predicted_division = completion.choices[0].message.content.strip().lower()
    logging.warning(f"Received AI response: {predicted_division}")

    if predicted_division not in ["save", "spend", "give", "expense", "invest"]:
        logging.warning(f"Invalid division received: {predicted_division}. Defaulting to 'none'.")
        predicted_division = "none"

    transaction.ai_division_guess = predicted_division
    return predicted_division



def handle_user_division_edit(transaction, new_division):
    ai_guess = transaction.ai_division_guess

    if ai_guess:
        accepted = (ai_guess.lower() == new_division.lower())
        transaction.ai_division_accepted = accepted

        # Optional: Save a log for analytics
        log = AICategorizationLog(
            transaction_id=transaction.id,
            user_id=transaction.user_id,
            ai_guess=ai_guess,
            user_division=new_division,
            accepted=accepted,
            timestamp=datetime.utcnow()
        )
        db.session.add(log)

    transaction.division = new_division
    db.session.commit()


def predict_transaction_tags(transaction):
    """
    Predicts up to 5 tags for a transaction using prior user behavior if applicable,
    otherwise uses the OpenAI API to select from the user's existing tags.
    GPT will ONLY return tags from the allowed list. If none fit, it will return an empty list.
    Prevents assigning duplicate tags.
    """
    from app.models import AICategorizationLog, Transaction, Tags
    from sqlalchemy import func

    user_id = transaction.user_id
    name = transaction.name.lower()

    print(f"Predicting tags for transaction ID: {transaction.id} | Amount: {transaction.amount} | Bank: {transaction.bank_account}")

    # STEP 1: Check for a strong user preference override
    override = db.session.query(
        AICategorizationLog.user_tags,
        func.count().label("count")
    ).join(Transaction, AICategorizationLog.transaction_id == Transaction.id)\
    .filter(
        AICategorizationLog.user_id == user_id,
        func.lower(Transaction.name).like(f"%{name[:10]}%"),
        AICategorizationLog.user_tags.isnot(None)
    ).group_by(AICategorizationLog.user_tags)\
    .order_by(func.count().desc())\
    .first()

    if override and override.count >= 3:
        try:
            override_tags = json.loads(override.user_tags)
            print(f"User override used for '{transaction.name}': {override_tags}")
            return override_tags
        except Exception:
            pass

    # STEP 2: Get allowed tags for this user
    existing_user_tags = db.session.query(Tags.name).filter(Tags.user_id == user_id).all()
    allowed_tags = [t[0] for t in existing_user_tags]  # Preserve original case
    allowed_tags_str = ", ".join([f"'{t}'" for t in allowed_tags])

    # STEP 3: Build transaction context
    direction = "INFLOW" if transaction.amount > 0 else "OUTFLOW"
    existing_tags = [tag.name for tag in transaction.tags]
    transaction_text = (
        f"Transaction: {transaction.name}, Amount: {transaction.amount}, "
        f"Existing Tags: {', '.join(existing_tags) if existing_tags else 'none'}, "
        f"Division: {transaction.division}, Bank: {transaction.bank_account}, Direction: {direction}."
    )
    print(f"Generated transaction text for AI: {transaction_text}")

    # STEP 4: Ask GPT to select tags from the allowed list
    completion = openai_api_key.chat.completions.create(
        model="gpt-4o-mini",
        store=True,
        messages=[{
            "role": "system",
            "content": (
                "You are an expert financial assistant. You will assign up to 5 tags to a bank transaction. "
                "You can ONLY use tags from the provided list. If no tags are appropriate, return an empty list.\n\n"
                "RULES:\n"
                f"- Allowed tags: {allowed_tags_str}\n"
                "- Return ONLY a JSON array of strings (e.g., [\"groceries\", \"gas\"]).\n"
                "- No explanations or extra text.\n"
                "- Use between 0 and 5 tags. If none fit, return []."
            )
        }, {
            "role": "user",
            "content": f"Select appropriate tags for this transaction: {transaction_text}"
        }]
    )

    # STEP 5: Parse GPT response
    try:
        predicted_tags = json.loads(completion.choices[0].message.content.strip())
        if not isinstance(predicted_tags, list) or not all(isinstance(t, str) for t in predicted_tags):
            raise ValueError("Invalid format from AI")
        # Filter to only allowed tags
        predicted_tags = [t for t in predicted_tags if t in allowed_tags]
        # Prevent duplicates (remove tags already assigned)
        predicted_tags = [t for t in predicted_tags if t not in existing_tags]
    except Exception as e:
        logging.warning(f"Invalid tag response from AI: {completion.choices[0].message.content.strip()} | Error: {e}")
        predicted_tags = []

    log = AICategorizationLog(
        transaction_id=transaction.id,
        user_id=transaction.user_id,
        ai_tags_guess=pyjson.dumps(predicted_tags),  # Save as JSON string
        tags_accepted=None  # Will be updated later when user edits
    )
    db.session.add(log)
    db.session.commit()
    logging.warning(f"Predicted tags (final, no duplicates): {predicted_tags}")
    return predicted_tags[:5]

def handle_user_tag_edit(transaction, new_tags):
    """
    Handles user edits to tags, compares them to AI predictions, and logs the result.
    """
    from app.models import AICategorizationLog
    import json as pyjson

    # Find the latest AI log for this transaction
    log = AICategorizationLog.query.filter_by(transaction_id=transaction.id).order_by(AICategorizationLog.timestamp.desc()).first()
    ai_tags = pyjson.loads(log.ai_tags_guess) if log and log.ai_tags_guess else []

    # Determine acceptance (all AI tags present & no extra tags removed)
    accepted = set(ai_tags) == set(new_tags)

    # Update log
    if log:
        log.user_tags = pyjson.dumps(new_tags)
        log.tags_accepted = accepted
        db.session.add(log)

    # Apply tags to transaction
    transaction.tags.clear()
    for tag in new_tags:
        tag_obj = Tags.query.filter_by(user_id=transaction.user_id, name=tag).first()
        if tag_obj:
            transaction.tags.append(tag_obj)

    db.session.commit()



def clean_gpt_json(raw_output: str) -> str:
    """
    Cleans GPT output to extract valid JSON.
    Removes markdown fences (```json ... ```), leading/trailing text,
    and safely returns the JSON string.
    """
    cleaned = raw_output.strip()

    # Remove markdown code fences
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")  # remove all backticks
        # Remove leading "json" if present after stripping backticks
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    # Find the first { and last } to ensure valid JSON slice
    start_idx = cleaned.find("{")
    end_idx = cleaned.rfind("}")
    if start_idx != -1 and end_idx != -1:
        cleaned = cleaned[start_idx:end_idx + 1]

    return cleaned