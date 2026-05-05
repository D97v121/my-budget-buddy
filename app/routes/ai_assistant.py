"""
ai_assistant.py
---------------
A clean, function-calling-based AI financial assistant for My Budget Buddy.

Architecture:
  1. A library of safe, tested query functions (no model-generated SQL)
  2. An OpenAI tool registry that maps those functions to GPT-4o
  3. A single Flask route that runs the conversation loop

Drop this file into your app/routes/ directory and register the blueprint
in your app __init__.py the same way you registered nlp_api.
"""

from flask import Blueprint, request, jsonify, session
from flask_login import current_user, login_required
from app import db, csrf
from app.models import Transaction, Tags, transaction_tags
from openai import OpenAI
from sqlalchemy import func, text
from datetime import date, timedelta
from calendar import monthrange
from decimal import Decimal
import json

ai_assistant = Blueprint('ai_assistant', __name__)
client = OpenAI()
today = date.today()

# ---------------------------------------------------------------------------
# DIVISIONS
# The 5 valid division values your AI categorizer assigns.
# ---------------------------------------------------------------------------
VALID_DIVISIONS = {"save", "give", "spend", "invest", "expense"}


# ===========================================================================
# SECTION 1 — HELPER UTILITIES
# ===========================================================================

def _float(val) -> float:
    """Safely coerce any DB numeric value to float."""
    if val is None:
        return 0.0
    try:
        return float(Decimal(str(val)))
    except Exception:
        return 0.0


def _resolve_dates(period: str):
    """
    Convert a plain-English period string to (start_date, end_date) as
    date objects.  Returns (None, None) if the phrase is unrecognised.
    """
    p = (period or "").strip().lower()
    t = today

    def _fdom(d):
        return date(d.year, d.month, 1)

    def _ldom(d):
        _, dim = monthrange(d.year, d.month)
        return date(d.year, d.month, dim)

    def _quarter(d):
        q = (d.month - 1) // 3 + 1
        sm = 3 * (q - 1) + 1
        em = sm + 2
        _, ed = monthrange(d.year, em)
        return date(d.year, sm, 1), date(d.year, em, ed)

    if p in ("this month", "current month"):
        return _fdom(t), _ldom(t)
    if p == "last month":
        prev = _fdom(t) - timedelta(days=1)
        return _fdom(prev), prev
    if p in ("this quarter", "current quarter"):
        return _quarter(t)
    if p == "last quarter":
        qs, _ = _quarter(t)
        prev = qs - timedelta(days=1)
        return _quarter(prev)
    if p in ("this year", "current year"):
        return date(t.year, 1, 1), date(t.year, 12, 31)
    if p == "last year":
        return date(t.year - 1, 1, 1), date(t.year - 1, 12, 31)
    if p in ("ytd", "year to date"):
        return date(t.year, 1, 1), t
    if p in ("this week", "current week"):
        start = t - timedelta(days=t.weekday())
        return start, start + timedelta(days=6)
    if p == "last week":
        start = t - timedelta(days=t.weekday() + 7)
        return start, start + timedelta(days=6)
    if p == "last 30 days":
        return t - timedelta(days=30), t
    if p == "last 90 days":
        return t - timedelta(days=90), t
    if p == "last 6 months":
        return t - timedelta(days=183), t
    if p == "all time":
        return date(2000, 1, 1), t

    return None, None


def _base_query(user_id: int, start: date, end: date, divisions=None, spending_only=True):
    """
    Returns a SQLAlchemy query filtered by user, date range, and optionally
    division.  spending_only=True restricts to amount < 0 (money out).
    """
    q = db.session.query(Transaction).filter(
        Transaction.user_id == user_id,
        Transaction.date >= start,
        Transaction.date <= end,
    )
    if spending_only:
        q = q.filter(Transaction.amount < 0)
    if divisions:
        q = q.filter(Transaction.division.in_(divisions))
    return q


# ===========================================================================
# SECTION 2 — TOOL FUNCTIONS
# Each function returns a plain dict that is JSON-serialisable.
# The model never writes SQL.  These are the only functions that touch the DB.
# ===========================================================================

def get_spending_summary(user_id: int, period: str) -> dict:
    """
    Total spending (money out) and income (money in) for a period.
    Returns totals and transaction count.
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'. Try 'last month', 'this year', etc."}

    spend_total = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.user_id == user_id,
        Transaction.date >= start,
        Transaction.date <= end,
        Transaction.amount < 0,
    ).scalar()

    income_total = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.user_id == user_id,
        Transaction.date >= start,
        Transaction.date <= end,
        Transaction.amount > 0,
    ).scalar()

    tx_count = db.session.query(func.count(Transaction.id)).filter(
        Transaction.user_id == user_id,
        Transaction.date >= start,
        Transaction.date <= end,
    ).scalar()

    spend = abs(_float(spend_total))
    income = _float(income_total)

    return {
        "period": period,
        "start": str(start),
        "end": str(end),
        "total_spending": round(spend, 2),
        "total_income": round(income, 2),
        "net": round(income - spend, 2),
        "transaction_count": int(tx_count or 0),
    }


def get_spending_by_category(user_id: int, period: str, limit: int = 10) -> dict:
    """
    Break down spending by the 'division' field (save / give / spend /
    invest / expense).
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'."}

    rows = (
        db.session.query(
            Transaction.division,
            func.sum(Transaction.amount).label("total"),
            func.count(Transaction.id).label("count"),
        )
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= start,
            Transaction.date <= end,
            Transaction.amount < 0,
        )
        .group_by(Transaction.division)
        .order_by(func.sum(Transaction.amount))
        .limit(limit)
        .all()
    )

    categories = [
        {
            "division": r.division or "none",
            "total_spent": round(abs(_float(r.total)), 2),
            "transaction_count": int(r.count),
        }
        for r in rows
    ]

    return {
        "period": period,
        "start": str(start),
        "end": str(end),
        "categories": categories,
    }


def get_spending_by_tag(user_id: int, period: str, limit: int = 10) -> dict:
    """
    Break down spending by user-assigned tags.
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'."}

    rows = (
        db.session.query(
            Tags.name.label("tag"),
            func.sum(Transaction.amount).label("total"),
            func.count(Transaction.id).label("count"),
        )
        .join(transaction_tags, Tags.id == transaction_tags.c.tag_id)
        .join(Transaction, Transaction.id == transaction_tags.c.transaction_id)
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= start,
            Transaction.date <= end,
            Transaction.amount < 0,
        )
        .group_by(Tags.name)
        .order_by(func.sum(Transaction.amount))
        .limit(limit)
        .all()
    )

    tags = [
        {
            "tag": r.tag,
            "total_spent": round(abs(_float(r.total)), 2),
            "transaction_count": int(r.count),
        }
        for r in rows
    ]

    return {
        "period": period,
        "start": str(start),
        "end": str(end),
        "tags": tags,
    }


def get_top_merchants(user_id: int, period: str, limit: int = 10) -> dict:
    """
    Top merchants/payees by total spending.
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'."}

    rows = (
        db.session.query(
            Transaction.name.label("merchant"),
            func.sum(Transaction.amount).label("total"),
            func.count(Transaction.id).label("count"),
        )
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= start,
            Transaction.date <= end,
            Transaction.amount < 0,
        )
        .group_by(Transaction.name)
        .order_by(func.sum(Transaction.amount))
        .limit(limit)
        .all()
    )

    merchants = [
        {
            "merchant": r.merchant,
            "total_spent": round(abs(_float(r.total)), 2),
            "transaction_count": int(r.count),
        }
        for r in rows
    ]

    return {
        "period": period,
        "start": str(start),
        "end": str(end),
        "merchants": merchants,
    }


def compare_periods(user_id: int, period_a: str, period_b: str) -> dict:
    """
    Compare total spending between two periods and compute the % change.
    period_a is the baseline (older); period_b is the comparison (newer).
    """
    a = get_spending_summary(user_id, period_a)
    b = get_spending_summary(user_id, period_b)

    if "error" in a:
        return a
    if "error" in b:
        return b

    spend_a = a["total_spending"]
    spend_b = b["total_spending"]

    if spend_a == 0:
        pct_change = None
        direction = "no baseline"
    else:
        pct_change = round(((spend_b - spend_a) / spend_a) * 100, 1)
        direction = "up" if pct_change > 0 else "down" if pct_change < 0 else "flat"

    return {
        "period_a": {
            "label": period_a,
            "start": a["start"],
            "end": a["end"],
            "total_spending": spend_a,
            "total_income": a["total_income"],
        },
        "period_b": {
            "label": period_b,
            "start": b["start"],
            "end": b["end"],
            "total_spending": spend_b,
            "total_income": b["total_income"],
        },
        "spending_change_dollars": round(spend_b - spend_a, 2),
        "spending_change_percent": pct_change,
        "direction": direction,
    }


def get_monthly_trend(user_id: int, months: int = 6) -> dict:
    """
    Month-by-month spending and income for the last N months.
    """
    end = today
    start = date(today.year, today.month, 1) - timedelta(days=30 * (months - 1))
    start = date(start.year, start.month, 1)

    rows = (
        db.session.query(
            func.strftime('%Y-%m', Transaction.date).label("month"),
            func.sum(
                func.CASE(
                    (Transaction.amount < 0, Transaction.amount),
                    else_=0
                )
            ).label("spending"),
            func.sum(
                func.CASE(
                    (Transaction.amount > 0, Transaction.amount),
                    else_=0
                )
            ).label("income"),
        )
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= start,
            Transaction.date <= end,
        )
        .group_by("month")
        .order_by("month")
        .all()
    )

    trend = [
        {
            "month": r.month,
            "spending": round(abs(_float(r.spending)), 2),
            "income": round(_float(r.income), 2),
            "net": round(_float(r.income) - abs(_float(r.spending)), 2),
        }
        for r in rows
    ]

    return {
        "months_requested": months,
        "trend": trend,
    }


def get_division_summary(user_id: int, period: str) -> dict:
    """
    Summarise how much was allocated to each division (save / give /
    spend / invest / expense) for a period, including percentages.
    """
    result = get_spending_by_category(user_id, period, limit=10)
    if "error" in result:
        return result

    categories = result["categories"]
    grand_total = sum(c["total_spent"] for c in categories)

    for c in categories:
        c["percent_of_total"] = (
            round((c["total_spent"] / grand_total) * 100, 1) if grand_total else 0
        )

    return {
        "period": period,
        "start": result["start"],
        "end": result["end"],
        "grand_total_spent": round(grand_total, 2),
        "divisions": categories,
    }


def search_transactions(user_id: int, keyword: str, period: str = "last 90 days", limit: int = 20) -> dict:
    """
    Search transactions by merchant name (case-insensitive) within a period.
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'."}

    rows = (
        db.session.query(Transaction)
        .filter(
            Transaction.user_id == user_id,
            Transaction.date >= start,
            Transaction.date <= end,
            Transaction.name.ilike(f"%{keyword}%"),
        )
        .order_by(Transaction.date.desc())
        .limit(limit)
        .all()
    )

    transactions = [
        {
            "date": str(r.date),
            "merchant": r.name,
            "amount": _float(r.amount),
            "division": r.division,
        }
        for r in rows
    ]

    return {
        "keyword": keyword,
        "period": period,
        "transaction_count": len(transactions),
        "transactions": transactions,
    }


def get_largest_transactions(user_id: int, period: str, limit: int = 10, spending_only: bool = True) -> dict:
    """
    Return the largest individual transactions in a period.
    """
    start, end = _resolve_dates(period)
    if not start:
        return {"error": f"I don't recognise the period '{period}'."}

    q = db.session.query(Transaction).filter(
        Transaction.user_id == user_id,
        Transaction.date >= start,
        Transaction.date <= end,
    )
    if spending_only:
        q = q.filter(Transaction.amount < 0).order_by(Transaction.amount)
    else:
        q = q.order_by(Transaction.amount.desc())

    rows = q.limit(limit).all()

    transactions = [
        {
            "date": str(r.date),
            "merchant": r.name,
            "amount": abs(_float(r.amount)) if spending_only else _float(r.amount),
            "division": r.division,
        }
        for r in rows
    ]

    return {
        "period": period,
        "spending_only": spending_only,
        "transactions": transactions,
    }


# ===========================================================================
# SECTION 3 — TOOL REGISTRY
# This is what gets sent to the OpenAI API.  Each definition must match
# the function signature above exactly.
# ===========================================================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_spending_summary",
            "description": (
                "Get the total spending (money out), total income (money in), "
                "net cash flow, and transaction count for a time period. "
                "Use for general 'how much did I spend/earn' questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {
                        "type": "string",
                        "description": (
                            "A plain-English time period. Examples: 'last month', "
                            "'this year', 'last 30 days', 'ytd', 'last quarter', "
                            "'this week', 'last 6 months', 'all time'."
                        ),
                    }
                },
                "required": ["period"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_spending_by_category",
            "description": (
                "Break down spending by division/category. Divisions are: "
                "save, give, spend, invest, expense. Use when the user asks "
                "how their money is split across categories or divisions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {"type": "string", "description": "Plain-English time period."},
                    "limit": {
                        "type": "integer",
                        "description": "Max number of categories to return. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["period"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_spending_by_tag",
            "description": (
                "Break down spending by user-assigned tags. Use when the user "
                "asks about tags, labels, or custom categories they've applied."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {"type": "string", "description": "Plain-English time period."},
                    "limit": {
                        "type": "integer",
                        "description": "Max number of tags to return. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["period"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_top_merchants",
            "description": (
                "List the top merchants or payees by total spending. Use when "
                "the user asks where they spend the most or which stores/companies "
                "they use most."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {"type": "string", "description": "Plain-English time period."},
                    "limit": {
                        "type": "integer",
                        "description": "Number of merchants to return. Default 10.",
                        "default": 10,
                    },
                },
                "required": ["period"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_periods",
            "description": (
                "Compare spending between two time periods and calculate the "
                "percentage change. Use for 'this month vs last month', "
                "'Q1 vs Q2', 'this year vs last year' questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period_a": {
                        "type": "string",
                        "description": "The baseline/older period (e.g. 'last month').",
                    },
                    "period_b": {
                        "type": "string",
                        "description": "The comparison/newer period (e.g. 'this month').",
                    },
                },
                "required": ["period_a", "period_b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_monthly_trend",
            "description": (
                "Show month-by-month spending and income for the last N months. "
                "Use for trend questions like 'how has my spending changed over time'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "months": {
                        "type": "integer",
                        "description": "Number of months to look back. Default 6.",
                        "default": 6,
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_division_summary",
            "description": (
                "Show how spending is split across divisions (save, give, spend, "
                "invest, expense) with percentages. Use for 'how am I allocating "
                "my money' or 'what percent goes to savings' questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {"type": "string", "description": "Plain-English time period."},
                },
                "required": ["period"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_transactions",
            "description": (
                "Search transactions by merchant name keyword. Use when the user "
                "asks about a specific store, company, or payee (e.g. 'show me "
                "my Amazon purchases', 'how much did I spend at Starbucks')."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Merchant name or keyword to search for.",
                    },
                    "period": {
                        "type": "string",
                        "description": "Plain-English time period. Default 'last 90 days'.",
                        "default": "last 90 days",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max transactions to return. Default 20.",
                        "default": 20,
                    },
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_largest_transactions",
            "description": (
                "Return the largest individual transactions in a period. Use for "
                "'what were my biggest purchases' or 'largest expenses' questions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "period": {"type": "string", "description": "Plain-English time period."},
                    "limit": {
                        "type": "integer",
                        "description": "Number of transactions to return. Default 10.",
                        "default": 10,
                    },
                    "spending_only": {
                        "type": "boolean",
                        "description": "True for largest expenses, False to include income. Default True.",
                        "default": True,
                    },
                },
                "required": ["period"],
            },
        },
    },
]


# ===========================================================================
# SECTION 4 — TOOL DISPATCHER
# Maps tool name strings → actual Python function calls.
# ===========================================================================

def dispatch_tool(tool_name: str, args: dict, user_id: int) -> dict:
    """
    Call the right function based on what the model requested.
    user_id is always injected here — the model never controls it.
    """
    fns = {
        "get_spending_summary":     lambda a: get_spending_summary(user_id, a["period"]),
        "get_spending_by_category": lambda a: get_spending_by_category(user_id, a["period"], a.get("limit", 10)),
        "get_spending_by_tag":      lambda a: get_spending_by_tag(user_id, a["period"], a.get("limit", 10)),
        "get_top_merchants":        lambda a: get_top_merchants(user_id, a["period"], a.get("limit", 10)),
        "compare_periods":          lambda a: compare_periods(user_id, a["period_a"], a["period_b"]),
        "get_monthly_trend":        lambda a: get_monthly_trend(user_id, a.get("months", 6)),
        "get_division_summary":     lambda a: get_division_summary(user_id, a["period"]),
        "search_transactions":      lambda a: search_transactions(user_id, a["keyword"], a.get("period", "last 90 days"), a.get("limit", 20)),
        "get_largest_transactions": lambda a: get_largest_transactions(user_id, a["period"], a.get("limit", 10), a.get("spending_only", True)),
    }

    fn = fns.get(tool_name)
    if not fn:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        return fn(args)
    except Exception as e:
        return {"error": str(e)}


# ===========================================================================
# SECTION 5 — SYSTEM PROMPT
# Short, clear, no SQL templates.
# ===========================================================================

SYSTEM_PROMPT = f"""You are a friendly, knowledgeable financial assistant built into My Budget Buddy.

You have access to the user's real transaction data through a set of tools.
Use those tools to answer financial questions accurately.

Today's date: {today.isoformat()}

The app uses 5 spending divisions that an AI auto-assigns to each transaction:
- spend:   everyday living expenses (groceries, gas, dining, etc.)
- expense: fixed or irregular necessary expenses (rent, bills, insurance)
- save:    money moved to savings
- invest:  money invested
- give:    charitable giving, gifts, donations

Rules:
- Always use the tools to fetch real data. Never invent numbers.
- Spending = negative amounts (money out). Income = positive amounts (money in).
- Present dollar amounts as positive values with a $ sign.
- If you're not sure what period the user means, ask before calling a tool.
- If the user's question has nothing to do with finances, respond naturally and briefly without calling any tools.
- Keep answers friendly and conversational. Use plain English, not financial jargon.
- When presenting lists (top merchants, categories), use a short ranked format.
- If the data shows something notable (e.g. one category dominates), briefly call it out.
"""


# ===========================================================================
# SECTION 6 — FLASK ROUTE
# ===========================================================================

@ai_assistant.route('/api/chat', methods=['POST'])
@csrf.exempt
@login_required
def chat():
    """
    Main conversation endpoint.

    Request body:
        { "message": "How much did I spend last month?" }

    Response:
        {
            "reply": "You spent $1,234 last month...",
            "tools_used": ["get_spending_summary"],
            "tool_results": { ... }   // only in debug mode
        }
    """
    if not request.is_json:
        return jsonify({"error": "Expected JSON body"}), 400

    user_message = (request.json.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    user_id = current_user.id
    debug = request.json.get("debug", False)

    # Build message history (keep last 10 turns to stay within context)
    history = session.get("chat_history", [])
    history.append({"role": "user", "content": user_message})

    messages = [{"role": "system", "content": SYSTEM_PROMPT}] + history

    tools_used = []
    tool_results_log = {}

    # --- Agentic loop: let the model call tools until it's done ---
    MAX_TOOL_ROUNDS = 5  # safety cap to prevent runaway loops

    for _ in range(MAX_TOOL_ROUNDS):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.3,
                timeout=30,
            )
        except Exception as e:
            return jsonify({"error": "AI service unavailable", "details": str(e)}), 502

        choice = response.choices[0]
        assistant_message = choice.message

        # Add assistant turn to message list (may include tool_calls)
        messages.append(assistant_message)

        # If the model is done (no tool calls), we have our final reply
        if choice.finish_reason == "stop" or not assistant_message.tool_calls:
            final_reply = assistant_message.content or ""
            break

        # Process each tool call the model requested
        for tool_call in assistant_message.tool_calls:
            fn_name = tool_call.function.name
            fn_args = json.loads(tool_call.function.arguments)

            tools_used.append(fn_name)

            # Run the tool (user_id is injected here, never from the model)
            result = dispatch_tool(fn_name, fn_args, user_id)
            tool_results_log[fn_name] = result

            # Feed results back to the model
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result),
            })
    else:
        # Hit the loop cap — return whatever the last message was
        final_reply = "I ran into a problem processing that request. Could you try rephrasing?"

    # Save a trimmed history (last 10 user+assistant turns only)
    # Strip out tool call messages to keep history clean and small
    clean_history = [
        m for m in messages[1:]  # skip system prompt
        if isinstance(m, dict) and m.get("role") in ("user", "assistant")
        and isinstance(m.get("content"), str)
    ]
    session["chat_history"] = clean_history[-10:]

    response_payload = {
        "reply": final_reply,
        "tools_used": tools_used,
    }

    if debug:
        response_payload["tool_results"] = tool_results_log

    return jsonify(response_payload)


@ai_assistant.route('/api/chat/reset', methods=['POST'])
@csrf.exempt
@login_required
def reset_chat():
    """Clear the conversation history for the current user session."""
    session.pop("chat_history", None)
    return jsonify({"status": "ok", "message": "Conversation reset."})