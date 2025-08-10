from flask import Blueprint, request, jsonify, session
from flask_login import current_user
from app import db, csrf
from openai import OpenAI
import json
from datetime import date, datetime, timedelta
from sqlalchemy import func, text
from calendar import monthrange
from sqlalchemy import func
from app.models import Transaction, Tags, transaction_tags
import re

nlp_api = Blueprint('nlp_api', __name__)
client = OpenAI()
today = date.today()

CACHE_TTL = timedelta(minutes=15)  # refresh every 15 minutes

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

def get_user_financial_summary(user_id):
    from datetime import datetime, timedelta

    # Monthly spending trend (last 6 months)
    monthly_spending = db.session.query(
        func.strftime('%Y-%m', Transaction.date).label('month'),
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.amount < 0
    ).group_by('month').all()

    # Top categories (last 90 days) — only negative amounts
    cutoff_date = datetime.now() - timedelta(days=90)
    top_tags = (
        db.session.query(
            Tags.name.label('tag'),
            func.sum(Transaction.amount).label('total')
        )
        .join(transaction_tags, Tags.id == transaction_tags.c.tag_id)
        .join(Transaction, Transaction.id == transaction_tags.c.transaction_id)
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= cutoff_date,
            Transaction.amount < 0
        )
        .group_by(Tags.name)
        .order_by(func.sum(Transaction.amount))
        .limit(5)
        .all()
    )

    # Top names — only negative amounts
    top_names = db.session.query(
        Transaction.name,
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.user_id == user_id,
        Transaction.amount < 0
    ).group_by(Transaction.name).order_by(func.sum(Transaction.amount)).limit(5).all()

    division_totals = (
        db.session.query(
            Transaction.division,
            func.sum(Transaction.amount).label('total')
        )
        .filter(Transaction.user_id == user_id)
        .group_by(Transaction.division)
        .all()
    )


    return {
        "monthly_spending": [{"month": m, "total": float(t)} for m, t in monthly_spending],
        "top_tags": [{"tag": c, "total": float(t)} for c, t in top_tags],
        "top_names": [{"name": m, "total": float(t)} for m, t in top_names],
        "division_totals": [{"division": d, "total": float(t)} for d, t in division_totals],
    }

def parse_step_ref(ref: str, step_results):
    if isinstance(ref, (int, float)):
        return ref
    if isinstance(ref, str):
        digits = ''.join([c for c in ref if c.isdigit()])
        if digits.isdigit():
            idx = int(digits)
            if idx < len(step_results):
                return step_results[idx]
    raise ValueError(f"Invalid step reference: {ref}")

def calculate_projection(current_total, months_elapsed):
    """Estimate year-end projection based on current pace."""
    if months_elapsed == 0:
        return None
    avg_per_month = current_total / months_elapsed
    projection = avg_per_month * 12
    return round(projection, 2)

# --- Safety: Basic SQL sanitizer ---
def sanitize_sql(sql):
    sql_lower = sql.strip().lower()

    # Still block anything dangerous
    forbidden = ['insert', 'update', 'delete', 'drop', 'alter']
    if any(keyword in sql_lower for keyword in forbidden):
        raise ValueError("Unsafe SQL detected.")

    # Only allow SELECT statements
    if not sql_lower.startswith("select"):
        raise ValueError("Only SELECT queries are allowed.")

    # Block stacked queries (multiple statements)
    if sql_lower.count(';') > 1:
        raise ValueError("Multiple statements are not allowed.")
    # Remove trailing semicolon (optional)
    if sql_lower.endswith(';'):
        sql = sql.strip().rstrip(';')

    # Must reference at least the transactions table
    if "transactions" not in sql_lower:
        raise ValueError("Query must reference the transactions table.")

    return sql


def get_cached_query_result(sql):
    """Fetch a cached result if it's still valid."""
    cached = session.get(f"query_cache_{hash(sql)}")
    if cached and (datetime.now() - datetime.fromisoformat(cached["cached_at"])) < CACHE_TTL:
        return cached["result"]
    return None

def set_cached_query_result(sql, result):
    """Store a query result in cache."""
    session[f"query_cache_{hash(sql)}"] = {
        "cached_at": datetime.now().isoformat(),
        "result": result
    }

def execute_query(sql):
    """Executes a sanitized SQL query, with caching."""
    # Check cache first
    cached_result = get_cached_query_result(sql)
    if cached_result is not None:
        return cached_result

    # Sanitize and execute
    safe_sql = sanitize_sql(sql)
    result = db.session.execute(text(safe_sql)).fetchone()
    total = float(result[0]) if result and result[0] is not None else 0.0

    # Cache result
    set_cached_query_result(sql, total)
    return total


def fix_sql_for_sqlite(sql: str) -> str:
    """Fix common GPT mistakes to ensure valid SQLite syntax and correct filters."""
    fixed = sql.strip()

    # Case-insensitive matching
    fixed = fixed.replace("ILIKE", "LIKE").replace("ilike", "LIKE")
    if "LIKE" in fixed.upper() and "COLLATE NOCASE" not in fixed.upper():
        fixed = fixed.replace("LIKE", "LIKE COLLATE NOCASE")

    # Ensure DATE() around date fields
    fixed = fixed.replace("t.date", "DATE(t.date)")

    # Ensure negative spending for sums
    if "SUM" in fixed.upper() and "amount < 0" not in fixed:
        if "WHERE" in fixed.upper():
            fixed = fixed.replace("WHERE", "WHERE t.amount < 0 AND")
        else:
            fixed += " WHERE t.amount < 0"

    return fixed.rstrip(";")


ALLOWED_COLUMNS = {"amount", "date", "division", "name"}
ALLOWED_GROUP_BY = {"tags", "division", "name"}
ALLOWED_ORDER_BY = {"amount", "total", "date", "name"}

def build_dynamic_query(query_data, user_id):
    if query_data.get("sql"):
        sql = query_data["sql"].strip()

        # --- Step 1: Alias tables ---
        sql = re.sub(r'\bFROM\s+transactions\b', 'FROM transactions t', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bJOIN\s+transaction_tags\b', 'JOIN transaction_tags tt', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bJOIN\s+tags\b', 'JOIN tags tg', sql, flags=re.IGNORECASE)

        # --- Step 2: Rewrite all table-prefixed columns ---
        sql = re.sub(r'\btransactions\.', 't.', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\btransaction_tags\.', 'tt.', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\btags\.', 'tg.', sql, flags=re.IGNORECASE)

        # --- Step 3: Qualify unqualified columns ---
        sql = re.sub(r'\b(?<!\.)id\b', 't.id', sql)
        sql = re.sub(r'\b(?<!\.)user_id\b', 't.user_id', sql)
        sql = re.sub(r'\b(?<!\.)name\b', 't.name', sql)
        sql = re.sub(r'\b(?<!\.)date\b', 't.date', sql)
        sql = re.sub(r'\b(?<!\.)amount\b', 't.amount', sql)

        # --- Step 4: OR instead of AND for name + tags ---
        if "JOIN tags" in sql and "t.name LIKE" in sql and "tg.name LIKE" in sql:
            sql = re.sub(
                r"t\.name LIKE '[^']+' COLLATE NOCASE AND tg\.name LIKE '[^']+' COLLATE NOCASE",
                lambda m: m.group(0).replace("AND", "OR"),
                sql
            )

        # --- Step 5: Remove subqueries if JOINs exist ---
        sql = re.sub(r"AND t\.id IN \(SELECT .*?\)", "", sql, flags=re.DOTALL)

        # --- Step 6: Enforce user_id ---
        if "t.user_id" not in sql:
            if "WHERE" in sql.upper():
                sql += f" AND t.user_id = {user_id}"
            else:
                sql += f" WHERE t.user_id = {user_id}"

        print(f"[build_dynamic_query] Final GPT SQL: {sql}")
        return sql

    # (legacy filter-built query stays the same)


    # --- Case 2: Build dynamically from filters (legacy) ---
    operation = query_data.get("operation", "sum").lower()
    filters = query_data.get("filters", {})
    group_by = query_data.get("group_by")
    order_by = query_data.get("order_by")
    limit = query_data.get("limit")

    # SELECT
    select_clause = "SUM(t.amount)" if operation == "sum" else "COUNT(*)" if operation == "count" else "AVG(t.amount)"
    if group_by in ALLOWED_GROUP_BY:
        select_clause += f", {group_by}"

    sql = f"SELECT {select_clause} FROM transactions t"
    if filters.get("tags") or group_by == "tags":
        sql += " JOIN transaction_tags tt ON t.id = tt.transaction_id JOIN tags tg ON tg.id = tt.tag_id"

    # WHERE conditions
    conditions = [f"t.user_id = {user_id}"]
    if filters.get("date_range"):
        start = filters["date_range"].get("from")
        end = filters["date_range"].get("to")
        conditions.append(f"DATE(t.date) BETWEEN '{start}' AND '{end}'")
    if filters.get("division"):
        conditions.append(f"t.division LIKE '%{filters['division']}%' COLLATE NOCASE")
    if filters.get("tags") and filters.get("name"):
        conditions.append(f"(t.name LIKE '%{filters['name']}%' COLLATE NOCASE OR tg.name LIKE '%{filters['tags']}%' COLLATE NOCASE)")
    elif filters.get("tags"):
        conditions.append(f"tg.name LIKE '%{filters['tags']}%' COLLATE NOCASE")
    elif filters.get("name"):
        conditions.append(f"t.name LIKE '%{filters['name']}%' COLLATE NOCASE")
    if filters.get("amount"):
        conditions.append(f"t.amount {filters['amount']}")

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    if group_by in ALLOWED_GROUP_BY:
        sql += f" GROUP BY {group_by}"
    if order_by and any(col in order_by for col in ALLOWED_ORDER_BY):
        sql += f" ORDER BY {order_by}"
    if limit:
        sql += f" LIMIT {int(limit)}"

    print(f"[build_dynamic_query] Final Dynamic SQL: {sql}")
    return sql

def get_gpt_response(msgs, temp=0.3):
            resp = client.chat.completions.create(model="gpt-4o", messages=msgs, temperature=temp)
            return resp.choices[0].message.content.strip()

def parse_gpt_json_with_retries(messages, max_retries=3):
    """Try to get valid JSON from GPT with retries & stricter instructions."""
    for attempt in range(max_retries):
        gpt_output = get_gpt_response(messages, temp=0.1 if attempt > 0 else 0.3)
        print(f"GPT attempt {attempt+1} output: {gpt_output}")

        # Clean the response (strip code fences, etc.)
        cleaned_output = clean_gpt_json(gpt_output)
        print(f"Cleaned GPT output (attempt {attempt+1}): {cleaned_output}")

        # Check for obvious math expressions in numeric fields
        if re.search(r":\s*[\d\.]+\s*[\+\-\*/]", cleaned_output):
            print("Math detected in JSON. Forcing retry.")
            messages.append({
                "role": "system",
                "content": "Respond again with only valid JSON per the schema. No math expressions or inline calculations — pre-calculate all numbers."
            })
            continue

        # Try parsing
        try:
            parsed = json.loads(cleaned_output)
            return parsed
        except json.JSONDecodeError as e:
            print(f"JSON parse failed on attempt {attempt+1}: {e}")
            messages.append({
                "role": "system",
                "content": "Respond again with only valid JSON per the schema. No explanations. No comments. Only clean JSON."
            })

    raise ValueError("Failed to get valid JSON from GPT after multiple retries.")

@nlp_api.route('/api/nlp_query', methods=['POST'])
@csrf.exempt
def nlp_query():
    try:
        user_input = request.json.get('question')
        print(f"Received question: {user_input}")
        user_id = current_user.id
        print(f"Current user ID: {user_id}")
        chat_history = session.get("chat_history", [])
        print(f"Loaded chat history: {chat_history}")

        # Fetch financial summary for context
        try:
            financial_summary = get_user_financial_summary(user_id)
            print(f"Fetched financial summary: {financial_summary}")
        except Exception as e:
            print(f"ERROR fetching financial summary: {e}")
            return jsonify({"error": "Failed to fetch financial summary", "details": str(e)}), 500


        # --- SYSTEM PROMPT ---
        system_prompt = f"""
        You are a financial assistant for a personal finance app. 
        You have access to the user's transaction data and these tools:
        - run_sql_query(sql): Run safe SELECT queries on the transactions DB.
        - calculate_percentage(a, b): Compute simple percentages.
        - summarize_results(data): Summarize transaction lists in natural language.

        Database schema:
        Table: transactions
          - id, user_id, date, amount, division, name
        Table: tags
          - id, name
        Table: transaction_tags (mapping)

        Today's date: {today}.
        Precomputed user financial summary:
        {json.dumps(financial_summary, indent=2)}

        **RULES (CRITICAL):**
        - Always filter by user_id = {user_id}.
        - SQLite does NOT support ILIKE. Use `LIKE '%value%' COLLATE NOCASE`.
        - Spending (money out) = negative amounts. Deposits (money in) = positive amounts.
        - For "spending" questions, always filter `AND amount < 0`.
        - When presenting spending, **convert negatives to positive numbers** (e.g., -100 → "$100 spent").
        - If transactions include both positive and negative (refunds), set "needs_clarification" to true and ask:
          "Do you want only spending, only refunds, or the net total?"
        - If ambiguous, ask for clarification instead of assuming.
        - If the question involves trends or ongoing categories, provide a simple year-end projection based on current pace.
        - Never modify the database. Only SELECT queries.
        - Break complex questions into steps: interpret → plan → query → calculate → summarize.

        **OUTPUT FORMAT:** 
        Return ONLY valid JSON with this schema:
        {{
          "steps": [
            {{
              "action": "run_sql_query|calculate_percentage|summarize_results",
              "sql": "SQL query if applicable (if omitted, use operation + filters below)",
              "operation": "sum|count|avg|null",
              "filters": {{
              "name": "transaction name if merchant",
              "tags": "category or descriptive tag (e.g., 'coffee', 'groceries'). Always populate this for spending categories even if also providing a name.",
              "date_range": {{"from": "YYYY-MM-DD", "to": "YYYY-MM-DD"}},
              "division": "optional division",
              "amount": "> 0 or < 0"
              }},
              "group_by": "tags|division|name|null",
              "order_by": "amount DESC|total DESC|null",
              "limit": 5,
              "a": "reference to previous step result if applicable",
              "b": "reference to previous step result if applicable OR a single numeric literal. NEVER return math expressions — always pre-calculate before responding."

            }}
          ],
          "response_text": "Plain-language insight for the user.",
          "needs_clarification": false,
          "clarification_question": null,
          "projection": false
        }}
        """
        print("System prompt constructed.")

        # --- CALL GPT ---
        messages = [{"role": "system", "content": system_prompt}] + chat_history + [{"role": "user", "content": user_input}]
        print(f"Sending messages to GPT: {messages}")

        gpt_output = get_gpt_response(messages)
        print(f"Raw GPT output: {gpt_output}")
        cleaned_output = clean_gpt_json(gpt_output)
        print(f"Cleaned GPT output: {cleaned_output}")

        parsed = parse_gpt_json_with_retries(messages)
        print(f"Parsed GPT JSON: {parsed}")

        # --- Clarification if needed ---
        if parsed.get("needs_clarification"):
            print("Clarification needed:", parsed.get("clarification_question"))
            session["pending_clarification"] = {
                "original_question": user_input,
                "clarification_question": parsed.get("clarification_question")
            }
            return jsonify({
                "summary": "Clarification needed",
                "needs_clarification": True,
                "clarification_question": parsed.get("clarification_question")
            })

        # --- Execute GPT Steps ---
        step_results = []
        for idx, step in enumerate(parsed.get("steps", [])):
            print(f"Executing step {idx}: {step}")
            action = step.get("action")
            if action == "run_sql_query":
                safe_sql = build_dynamic_query(step, user_id)
                print(f"Executing SQL: {safe_sql}")
                result = db.session.execute(text(safe_sql)).fetchone()
                value = float(result[0]) if result and result[0] else 0.0
                print(f"SQL result: {value}")
                step_results.append(value)
            elif action == "calculate_percentage":
                a = parse_step_ref(step.get("a"), step_results)
                b = parse_step_ref(step.get("b"), step_results)
                value = round((a / b) * 100, 2) if b else 0.0
                print(f"Calculated percentage: {value}")
                step_results.append(value)
            elif action == "summarize_results":
                print(f"Summarizing results: {step_results[-1]}")
                step_results.append(step_results[-1])

        # --- Projection (if flagged) ---
        projection_text = None
        if parsed.get("projection"):
            print("Projection requested.")
            months_elapsed = today.month
            projected_total = calculate_projection(step_results[-1], months_elapsed)
            projection_text = f"If you continue at this pace, your projected total by year-end is approximately ${projected_total}."
            print(f"Projection calculated: {projection_text}")

        # --- Secondary GPT for final response ---
        reasoning_prompt = f"""
        User asked: {user_input}.
        Step results: {step_results}.
        Projection: {projection_text}.
        Provide a clear, friendly financial answer.
        """
        print(f"Reasoning prompt: {reasoning_prompt}")
        reasoning_response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a financial assistant summarizing query results for the user."},
                {"role": "user", "content": reasoning_prompt}
            ],
            temperature=0.3,
        )
        final_insight = reasoning_response.choices[0].message.content.strip()
        print(f"Final insight: {final_insight}")

        # Save history
        chat_history.append({"role": "user", "content": user_input})
        chat_history.append({"role": "assistant", "content": final_insight})
        session["chat_history"] = chat_history[-10:]
        print("Chat history updated.")

        return jsonify({
            "steps_executed": parsed.get("steps"),
            "step_results": step_results,
            "projection": projection_text,
            "insight": final_insight or parsed.get("response_text")
        })

    except Exception as e:
        import traceback
        print("UNHANDLED ERROR in /api/nlp_query:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


""""
@nlp_api.route('/api/nlp_query', methods=['POST'])
@csrf.exempt
def nlp_query():
    try:
        user_input = request.json.get('question')
        print(f"Received question: {user_input}")
        user_id = current_user.id
        print(f"Current user ID: {user_id}")

        # Conversation memory
        chat_history = session.get("chat_history", [])

        # Financial summary for context
        try:
            financial_summary = get_user_financial_summary(user_id)
            print(f"Financial summary fetched: {financial_summary}")
        except Exception as e:
            print("ERROR fetching financial summary:", e)
            return jsonify({"error": "Failed to fetch financial summary", "details": str(e)}), 500

        system_prompt = f
        You are a financial assistant with SQL access.
        Today's date is {today}.

        Here is a precomputed financial summary for this user:
        {json.dumps(financial_summary, indent=2)}


        **IMPORTANT:**
        - SQLite does NOT support ILIKE. Use `LIKE '%value%' COLLATE NOCASE` for case-insensitive matches.
        - When filtering by dates, wrap the column in `DATE()` (e.g., `DATE(t.date) BETWEEN '2025-07-01' AND '2025-07-31'`).
        - For "spending" questions, always filter `AND amount < 0`.
        - JOIN tags when filtering by categories, like this:
        ```sql
        SELECT SUM(t.amount)
        FROM transactions t
        JOIN transaction_tags tt ON t.id = tt.transaction_id
        JOIN tags tg ON tg.id = tt.tag_id
        WHERE tg.name LIKE '%coffee%' COLLATE NOCASE AND t.user_id = {user_id};


        Rules:
        - Always filter by user_id = {user_id}.
        - Only generate safe SELECT statements. Never modify the database.
        - For aggregation, use SUM, AVG, COUNT as needed.
        - You may use WHERE, GROUP BY, ORDER BY, and LIMIT clauses.
        - Return results for insight calculation, not raw dumps.
        - Break complex questions into multiple SQL queries if needed (step-by-step).
        - Use results from earlier steps to compute insights.
        - All spending (money going out) is stored as **negative numbers** in the database.
        - When presenting results to the user, **always convert spending amounts to positive numbers** (e.g., -100 → "You spent $100").
        - Do NOT treat negative values as errors when summing expenses.
        - If the question involves trends or ongoing categories, provide a simple year-end projection based on current pace.
        - Be specific (e.g., "At this pace, you’ll save $X by year-end").

        Spending rules:
        - When interpreting questions about "spending," assume the user usually means outgoing values (amount < 0), so ignore positive values when you are adding transactions.
        - However, if transactions include both positive and negative amounts (e.g., refunds, adjustments), ASK for clarification instead of assuming.
        - Example: "I see both refunds and charges for 'coffee.' Do you want me to report only what you spent, only what you received, or the net total?"
        - Whenever the interpretation could be ambiguous, set "needs_clarification" to true and provide a helpful clarification question. 
        - When interpreting questions about "spending," assume it means amount < 0. If uncertain (e.g., refunds involved), set needs_clarification to true and ask.
        - Be explicit in your clarifications: "Do you want only spending, only refunds, or the net total?"
        - If unsure, ask for clarification.

        Instead of writing SQL, produce a JSON intent describing the query:
        {{
          "operation": "sum|count|avg",
          "columns": ["amount"], 
          "filters": {{
            "name": {{ "transaction name" }}
            "date_range": {{"from": "YYYY-MM-DD", "to": "YYYY-MM-DD"}},
            "division": "optional division",
            "tags": "optional tag",
            "amount": "> 0 or < 0"
          }},
          "group_by": "tags|division|name|null",
          "order_by": "amount DESC|total DESC|null",
          "limit": 5,
          "response_text": "Friendly natural-language answer for the user. Always include this.",
          "needs_clarification": false,
          "clarification_question": null
        }}
        Return **only valid JSON**. Do not include commentary, markdown, or extra text.

         **CRITICAL FORMAT RULES**:
            - You must respond **only** with the JSON object matching the provided schema.
            - Never include explanations, commentary, or SQL inside code blocks.
            - Do not include markdown fences (```).
            - Your response must begin with '{{' and end with '}}' — no extra text.
            - If you cannot answer, still return a valid JSON object with null values.
        

        # Build GPT messages
        messages = [{"role": "system", "content": system_prompt}] + chat_history + [{"role": "user", "content": user_input}]

        # --- Call GPT (with retry) ---
        def get_gpt_response(msgs, temp=0.3):
            resp = client.chat.completions.create(model="gpt-4o", messages=msgs, temperature=temp)
            return resp.choices[0].message.content.strip()

        gpt_output = get_gpt_response(messages)
        print("Raw GPT output:", gpt_output)
        cleaned_output = clean_gpt_json(gpt_output)

        try:
            parsed = json.loads(cleaned_output)
        except json.JSONDecodeError:
            print("First parse failed. Retrying with strict instruction...")
            retry_messages = messages + [
                {"role": "system", "content": "Your last response was invalid. Respond again with **only valid JSON** per the schema. No explanations or extra text."}
            ]
            gpt_output = get_gpt_response(retry_messages, temp=0.1)
            print("Retry GPT output:", gpt_output)
            cleaned_output = clean_gpt_json(gpt_output)
            try:
                parsed = json.loads(cleaned_output)
            except json.JSONDecodeError:
                print("ERROR: Still invalid JSON from GPT.")
                return jsonify({"error": "Invalid GPT response", "raw": gpt_output}), 500

        query_data = parsed
        natural_response = parsed.get("response_text", "")
        if not natural_response:
            natural_response = "Here's what I found based on your question."

        # --- Clarification if needed ---
        if query_data.get("needs_clarification"):
            session["pending_clarification"] = {"original_question": user_input, "clarification_question": query_data.get("clarification_question")}
            return jsonify({
                "summary": "Clarification needed",
                "needs_clarification": True,
                "clarification_question": query_data.get("clarification_question")
            })

        # --- Build and Execute SQL ---
        safe_sql = build_dynamic_query(query_data, user_id)
        print(f"Final SQL executed: {safe_sql}")
        result = db.session.execute(text(safe_sql)).fetchone()
        total = float(result[0]) if result and result[0] is not None else 0.0

        # --- Projection ---
        projection_text = None
        if any(word in user_input.lower() for word in ["year", "projection", "at this pace"]):
            months_elapsed = today.month
            projected_total = calculate_projection(total, months_elapsed)
            if projected_total is not None:
                projection_text = f"If you continue at this pace, your projected total by year-end is approximately ${projected_total}."

        # --- Secondary GPT reasoning ---
        reasoning_prompt = f
        You planned this for the user's question: {user_input}.
        Query result: {total}.
        Projection: {projection_text}.
        Provide a clear, friendly answer.
        
        reasoning_response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a financial assistant generating a final explanation with projections."},
                {"role": "user", "content": reasoning_prompt}
            ],
            temperature=0.3,
        )
        final_insight = reasoning_response.choices[0].message.content.strip()


        # Save conversation
        chat_history.append({"role": "user", "content": user_input})
        chat_history.append({"role": "assistant", "content": final_insight})
        session["chat_history"] = chat_history[-10:]
        # --- Final return ---
        return jsonify({
            "summary": query_data.get("summary"),
            "executed_sql": safe_sql,
            "total": round(total, 2),
            "insight": final_insight or natural_response
        })

    except Exception as e:
        import traceback
        print("UNHANDLED ERROR in /api/nlp_query:", e)
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
"""

"""
@nlp_api.route('/api/nlp_query', methods=['POST'])
@csrf.exempt
def nlp_query():
    try:
        user_input = request.json.get('question')
        user_id = current_user.id
        chat_history = session.get("chat_history", [])

        # Precomputed context for GPT
        financial_summary = get_user_financial_summary(user_id)

        system_prompt = f
        You are a financial assistant for a personal finance app. 
        You have access to the user's transaction data and these tools:
        - run_sql_query(sql): Run safe SELECT queries on the transactions DB.
        - calculate_percentage(a, b): Compute simple percentages.
        - summarize_results(data): Summarize transaction lists in natural language.

        Database schema:
        Table: transactions
          - id, user_id, date, amount, division, name
        Table: tags
          - id, name
        Table: transaction_tags (mapping)

        Rules:
        - Always filter by user_id = {user_id}.
        - SQLite only supports LIKE with COLLATE NOCASE for case-insensitive search.
        - Spending (money out) = negative amounts. Deposits (money in) = positive.
        - Never modify the database.
        - If ambiguous (e.g., “spending” includes refunds), ask a clarifying question.
        - Break complex questions into **steps**: interpret → plan → query → calculate → summarize.

        Example tool call:
        {{
          "steps": [
            {{"action": "run_sql_query", "sql": "SELECT SUM(amount) FROM transactions WHERE division = 'Save' AND user_id = {user_id}"}},
            {{"action": "run_sql_query", "sql": "SELECT SUM(amount) FROM transactions WHERE user_id = {user_id}"}},
            {{"action": "calculate_percentage", "a": "step0_result", "b": "step1_result"}},
            {{"action": "summarize_results", "data": "step2_result"}}
          ],
          "response_text": "You have saved 25% of your total money."
        }}

        Always return JSON:
        {{
          "steps": [{{"action": "...", "sql": "...", "a": "...", "b": "..."}}],
          "response_text": "Plain-language insight for the user",
          "needs_clarification": false,
          "clarification_question": null
        }}
        

        # --- Call GPT ---
        messages = [{"role": "system", "content": system_prompt}] + chat_history + [{"role": "user", "content": user_input}]
        def get_gpt_response(msgs, temp=0.3):
            resp = client.chat.completions.create(model="gpt-4o", messages=msgs, temperature=temp)
            return resp.choices[0].message.content.strip()

        gpt_output = get_gpt_response(messages)
        cleaned_output = clean_gpt_json(gpt_output)

        try:
            parsed = json.loads(cleaned_output)
        except json.JSONDecodeError:
            # Retry once if bad JSON
            retry_messages = messages + [{"role": "system", "content": "Respond again with only valid JSON."}]
            gpt_output = get_gpt_response(retry_messages, temp=0.1)
            cleaned_output = clean_gpt_json(gpt_output)
            parsed = json.loads(cleaned_output)

        if parsed.get("needs_clarification"):
            session["pending_clarification"] = {
                "original_question": user_input,
                "clarification_question": parsed.get("clarification_question")
            }
            return jsonify({
                "summary": "Clarification needed",
                "needs_clarification": True,
                "clarification_question": parsed.get("clarification_question")
            })

        # --- Execute GPT Steps ---
        step_results = []
        for idx, step in enumerate(parsed.get("steps", [])):
            action = step.get("action")
            if action == "run_sql_query":
                safe_sql = build_dynamic_query(step, user_id)
                result = db.session.execute(text(safe_sql)).fetchone()
                step_results.append(float(result[0]) if result and result[0] else 0.0)
            elif action == "calculate_percentage":
                a = parse_step_ref(step.get("a"), step_results)
                b = parse_step_ref(step.get("b"), step_results)
                step_results.append(round((a / b) * 100, 2) if b else 0.0)
            elif action == "summarize_results":
                step_results.append(step_results[-1])  # Placeholder for now (later: use GPT to summarize)

        # --- Secondary GPT reasoning (turn numeric result into full answer) ---
        reasoning_prompt = f
        User asked: {user_input}.
        You produced steps: {json.dumps(parsed.get('steps', []))}.
        Final step results: {step_results}.
        Provide a clear, concise natural language answer.
        
        reasoning_response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a financial assistant summarizing the numeric results for the user."},
                {"role": "user", "content": reasoning_prompt}
            ],
            temperature=0.3,
        )
        final_insight = reasoning_response.choices[0].message.content.strip()

        # Save history
        chat_history.append({"role": "user", "content": user_input})
        chat_history.append({"role": "assistant", "content": final_insight})
        session["chat_history"] = chat_history[-10:]

        return jsonify({
            "steps_executed": parsed.get("steps"),
            "step_results": step_results,
            "insight": final_insight or parsed.get("response_text")
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
"""