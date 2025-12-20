from flask import Blueprint, request, jsonify, session
from flask_login import current_user, login_required
from app import db, csrf
from openai import OpenAI
import json
from datetime import date, datetime, timedelta
from datetime import date as _date
from sqlalchemy import func, text
import ast
from calendar import monthrange
from app.models import Transaction, Tags, transaction_tags
import re
from decimal import Decimal
import hashlib
from time import time, sleep   # CHANGED: add sleep for backoff
import random                  # NEW: jitter for backoff
from typing import List, Optional, Literal, Any  # NEW: typing for schema
from pydantic import BaseModel, Field, ValidationError, root_validator  # NEW: schema validation

nlp_api = Blueprint('nlp_api', __name__)
client = OpenAI()
today = date.today()

CACHE_TTL = timedelta(minutes=15)
_QUERY_CACHE = {}
USE_SEMANTIC_VIEWS = True  # NEW: set True when DBT views are live
EVAL_SUITE = [
    {"q": "How much did I spend last month?", "expect": "scalar"},
    {"q": "Top 3 categories this quarter", "expect": "table"},
    {"q": "Compare dining spend Q1 vs Q2", "expect": "table"},
    {"q": "What is my average weekend spend vs weekdays?", "expect": "table"},
]

# NEW: canonical view names (adjust to your dbt naming)
VIEWS = {
    "spend": "v_spend",                # transactions with amount < 0
    "income": "v_income",              # transactions with amount > 0
    "with_tags": "v_txn_with_tags",    # transactions joined to tags (one row per tag)
    "monthly": "v_txn_monthly",        # pre-aggregated per month (YYYY-MM)
}

def _try_view(view_name: str) -> Optional[str]:
    """Return view name if likely present; otherwise None. Lightweight, no metadata queries."""
    # We avoid information_schema checks to keep this minimal and portable.
    # We'll just optimistically use the name and catch errors when executing.
    return view_name if USE_SEMANTIC_VIEWS else None

def _cache_get(key: str):
    # CHANGED: simple TTL cache (swap with Redis later)
    now = time()
    val = _QUERY_CACHE.get(key)
    if not val:
        return None
    exp, result = val
    if now > exp:
        _QUERY_CACHE.pop(key, None)
        return None
    return result

def _cache_set(key: str, result):
    _QUERY_CACHE[key] = (time() + CACHE_TTL.total_seconds(), result)

def _sql_key(user_id: int, sql: str, params: dict | None) -> str:
    # CHANGED: stable hash over sql + params + user_id
    h = hashlib.sha256()
    h.update(str(user_id).encode())
    h.update(sql.encode())
    if params:
        # keep order stable
        for k in sorted(params):
            h.update(k.encode())
            h.update(str(params[k]).encode())
    return "query_cache_" + h.hexdigest()


def _dialect():
    # CHANGED: detect engine
    return (getattr(db.engine, "name", "") or "").lower()

def _ci_like(column_sql: str) -> str:
    # CHANGED: portable case-insensitive LIKE construction for literals
    if _dialect() == "sqlite":
        return f"{column_sql} LIKE :needle COLLATE NOCASE"
    else:
        return f"LOWER({column_sql}) LIKE LOWER(:needle)"

def _month_fmt(col):
    # CHANGED: month formatting by dialect
    if _dialect() == "sqlite":
        return func.strftime('%Y-%m', col)
    else:
        # Postgres/others
        return func.to_char(col, 'YYYY-MM')
# NEW: standardize output shaping
def shape_results(step_results, verifications, plan_assumptions=None, limitations=None):
    numbers = []
    tables = []

    for r in step_results:
        if isinstance(r, list):
            # table-ish
            tables.append(r)
        else:
            try:
                numbers.append(float(Decimal(str(r))))
            except Exception:
                pass

    return {
        "numbers": numbers,
        "tables": tables,
        "assumptions": plan_assumptions or [],
        "limitations": limitations or [],
        "verification": verifications,
    }


# CHANGED: get_user_financial_summary tries semantic views, else falls back transparently
def get_user_financial_summary(user_id):
    from datetime import datetime, timedelta
    six_months_ago = datetime.now() - timedelta(days=183)
    cutoff_date = datetime.now() - timedelta(days=90)

    monthly_rows = []
    try:
        monthly_view = _try_view(VIEWS["monthly"])
        if monthly_view:
            # Expect columns: month (YYYY-MM), total (sum of amount), user_id, and sign already applied in view for spend
            sql = f"SELECT month, SUM(total) AS total FROM {monthly_view} WHERE user_id = :uid AND total < 0 AND month >= :mcut GROUP BY month ORDER BY month"
            monthly_rows = db.session.execute(text(sql), {"uid": user_id, "mcut": six_months_ago.strftime("%Y-%m")}).mappings().all()
        else:
            raise RuntimeError("no monthly view")
    except Exception:
        # Fallback to base table logic
        monthly_rows = (
            db.session.query(
                _month_fmt(Transaction.date).label('month'),
                func.sum(Transaction.amount).label('total')
            )
            .filter(
                Transaction.user_id == user_id,
                Transaction.amount < 0,
                Transaction.date >= six_months_ago
            )
            .group_by('month')
            .order_by('month')
            .all()
        )
        monthly_rows = [{"month": m, "total": t} for m, t in monthly_rows]

    # top_tags
    top_tags_rows = []
    try:
        tags_view = _try_view(VIEWS["with_tags"])
        if tags_view:
            sql = f"""
                SELECT tag AS tag, SUM(amount) AS total
                FROM {tags_view}
                WHERE user_id = :uid AND date >= :cut AND amount < 0
                GROUP BY tag ORDER BY SUM(amount) ASC LIMIT 5
            """
            top_tags_rows = db.session.execute(text(sql), {"uid": user_id, "cut": cutoff_date}).mappings().all()
        else:
            raise RuntimeError("no tags view")
    except Exception:
        top_tags_rows = (
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
        top_tags_rows = [{"tag": r[0], "total": r[1]} for r in top_tags_rows]

    # top_names (by merchant)
    top_names_rows = (
        db.session.query(
            Transaction.name,
            func.sum(Transaction.amount).label('total')
        )
        .filter(
            Transaction.user_id == user_id,
            Transaction.amount < 0
        )
        .group_by(Transaction.name)
        .order_by(func.sum(Transaction.amount))
        .limit(5)
        .all()
    )
    top_names_rows = [{"name": r[0], "total": r[1]} for r in top_names_rows]

    division_totals_rows = (
        db.session.query(
            Transaction.division,
            func.sum(Transaction.amount).label('total')
        )
        .filter(Transaction.user_id == user_id)
        .group_by(Transaction.division)
        .all()
    )
    division_totals_rows = [{"division": r[0], "total": r[1]} for r in division_totals_rows]

    return {
        "monthly_spending": [{"month": r["month"], "total": float(Decimal(str(r["total"] or 0)))} for r in monthly_rows],
        "top_tags": [{"tag": r["tag"], "total": float(Decimal(str(r["total"] or 0)))} for r in top_tags_rows],
        "top_names": [{"name": r["name"], "total": float(Decimal(str(r["total"] or 0)))} for r in top_names_rows],
        "division_totals": [{"division": r["division"], "total": float(Decimal(str(r["total"] or 0)))} for r in division_totals_rows],
    }

def stats_describe(rows: Any, *, metric: Optional[str] = None, by: Optional[str] = None, k: Optional[int] = 5):
    """
    rows: either a scalar, or list[dict]
    metric: which numeric key to aggregate (defaults to first numeric column if not provided)
    by: optional grouping key (e.g., "tag", "merchant_name")
    k: top-k for the grouping
    Returns dict: {"count": int, "sum": float, "avg": float, "top": [{"key":..., "total":...}, ...]}
    """
    # Normalize to a list of dicts
    table: list[dict] = []
    if isinstance(rows, list):
        for r in rows:
            if isinstance(r, dict):
                table.append(r)
    elif rows is None:
        table = []
    else:
        # scalar → treat as a single row of {"value": scalar}
        table = [{"value": rows}]
        if metric is None:
            metric = "value"

    if not table:
        return {"count": 0, "sum": 0.0, "avg": 0.0, "top": []}

    # Pick a metric if not provided: first numeric-looking key
    if metric is None:
        for k0 in table[0].keys():
            v = table[0][k0]
            if isinstance(v, (int, float)):
                metric = k0
                break
        if metric is None:
            return {"count": len(table), "sum": 0.0, "avg": 0.0, "top": []}

    # Aggregate
    total = 0.0
    for r in table:
        v = r.get(metric)
        try:
            total += float(Decimal(str(v or 0)))
        except Exception:
            pass

    summary = {"count": len(table), "sum": round(total, 2), "avg": round(total / max(len(table), 1), 2)}

    # Top-k grouping
    if by:
        bucket: dict[str, float] = {}
        for r in table:
            key = str(r.get(by) or "Unknown")
            val = r.get(metric)
            try:
                bucket[key] = bucket.get(key, 0.0) + float(Decimal(str(val or 0)))
            except Exception:
                pass
        top = sorted(bucket.items(), key=lambda kv: kv[1], reverse=True)[: (k or 5)]
        summary["top"] = [{"key": kk, "total": round(vv, 2)} for kk, vv in top]
    else:
        summary["top"] = []

    return summary

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)
_ALLOWED_UNARY = (ast.UAdd, ast.USub)

def _eval_expr(node, names: dict):
    if isinstance(node, ast.Num):  # py<3.8
        return Decimal(str(node.n))
    if isinstance(node, ast.Constant):  # py3.8+
        if isinstance(node.value, (int, float)):
            return Decimal(str(node.value))
        raise ValueError("Only numeric constants allowed.")
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise ValueError(f"Unknown variable: {node.id}")
        return Decimal(str(names[node.id]))
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
        left = _eval_expr(node.left, names)
        right = _eval_expr(node.right, names)
        op = node.op
        if isinstance(op, ast.Add): return left + right
        if isinstance(op, ast.Sub): return left - right
        if isinstance(op, ast.Mult): return left * right
        if isinstance(op, ast.Div): return left / right if right != 0 else Decimal("0")
        if isinstance(op, ast.Mod): return left % right
        if isinstance(op, ast.Pow): return left ** right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _ALLOWED_UNARY):
        v = _eval_expr(node.operand, names)
        return v if isinstance(node.op, ast.UAdd) else -v
    raise ValueError("Unsupported expression syntax.")

def calc_evaluate(expression: str, inputs: dict) -> float:
    """
    Evaluate arithmetic like '(savings / income) * 100'
    inputs: dict of {name: number}, only these names may appear.
    """
    tree = ast.parse(expression, mode="eval")
    val = _eval_expr(tree.body, inputs or {})
    return float(val.quantize(Decimal("0.01")))


def run_evaluation(user_id: int) -> dict:
    reports = []
    for case in EVAL_SUITE:
        try:
            # Minimal: reuse planning prompt and execution path
            messages = [{"role": "system", "content": "Plan steps to answer the question. Return JSON matching the schema."},
                        {"role": "user", "content": case["q"]}]
            # In prod, use your full system prompt; here we keep it tiny for speed.
            # You can wire this to get_plan_with_validation(messages) too, but this keeps eval decoupled.

            # For simplicity, call through your live pipeline by posting to itself would be circular.
            # Instead, we mark as skipped and focus on reporting shape expectations.
            reports.append({"q": case["q"], "status": "skipped", "detail": "Hook into full pipeline for real eval"})
        except Exception as e:
            reports.append({"q": case["q"], "status": "error", "detail": str(e)})
    return {"cases": reports}

# NEW: simple verification attempt for aggregate SUM without GROUP BY
def verify_totals(sql: str, params: dict, user_id: int) -> dict:
    """
    If the query looks like a single SUM(amount) without GROUP BY,
    cross-check by summing category totals (tags) and compare.
    Returns {'status': 'ok'|'mismatch'|'skipped', 'delta': float, 'detail': str}
    """
    try:
        # Only attempt when SUM(...) present and no GROUP BY
        if "sum(" not in sql.lower() or "group by" in sql.lower():
            return {"status": "skipped", "delta": 0.0, "detail": "Not an aggregate or grouped query"}

        # Heuristic: reuse the same WHERE conditions, but compute sum by tag, then re-sum
        m = re.search(r"\bwhere\b(.*)", sql, flags=re.IGNORECASE | re.DOTALL)
        where_clause = m.group(1) if m else ""
        # Build a category-sum query over the semantic with_tags view if available
        base = _try_view(VIEWS["with_tags"]) or "transactions"
        tag_col = "tag" if base == VIEWS["with_tags"] else "tg.name"
        t_alias = "t"

        if base == "transactions":
            join = " JOIN transaction_tags tt ON t.id = tt.transaction_id JOIN tags tg ON tg.id = tt.tag_id "
        else:
            join = " "

        verify_sql = f"SELECT SUM(total_by_tag) AS recomputed FROM (SELECT {tag_col} AS tag, SUM({t_alias}.amount) AS total_by_tag FROM {base} {t_alias}{join} "
        if where_clause:
            verify_sql += f"WHERE {where_clause} "
        verify_sql += f"GROUP BY {tag_col}) x"

        # Normalize user_id param name across queries
        vparams = dict(params or {})
        if ":uid" in verify_sql and "uid" not in vparams and "user_id" in vparams:
            vparams["uid"] = vparams["user_id"]

        recomputed = execute_query(user_id, verify_sql, vparams)
        # get scalar
        if isinstance(recomputed, list):
            if not recomputed:
                return {"status": "skipped", "delta": 0.0, "detail": "No rows in verification"}
            recomputed_val = list(recomputed[0].values())[0]
        else:
            recomputed_val = recomputed

        original = execute_query(user_id, sql, params)
        if isinstance(original, list):
            if not original:
                orig_val = 0.0
            else:
                orig_val = list(original[0].values())[0]
        else:
            orig_val = original

        a = float(Decimal(str(orig_val or 0)))
        b = float(Decimal(str(recomputed_val or 0)))
        delta = abs(a - b)
        status = "ok" if delta < 0.01 else "mismatch"
        return {"status": status, "delta": round(delta, 4), "detail": "Cross-check via tag sum"}
    except Exception as e:
        return {"status": "skipped", "delta": 0.0, "detail": f"Verify error: {e}"}

# NEW: detect possible ambiguity if both positive and negative amounts are present and SQL lacks an amount sign filter
def detect_sign_ambiguity(sql: str, result) -> Optional[str]:
    s = sql.lower()
    if (" amount < 0" in s) or (" amount>0" in s) or (" amount > 0" in s) or (" amount>=0" in s) or (" amount <= 0" in s) or (" amount <=0" in s):
        return None  # explicit sign constraint present

    # Scan results for mix of signs
    vals = []
    if isinstance(result, list):
        for row in result:
            for k, v in row.items():
                if isinstance(v, (int, float)):
                    if k.lower() in ("amount", "total", "sum", "sum_amount", "total_by_tag"):
                        vals.append(float(v))
    else:
        # scalar
        try:
            vals.append(float(result))
        except Exception:
            pass

    has_pos = any(v > 0 for v in vals)
    has_neg = any(v < 0 for v in vals)
    if has_pos and has_neg:
        return "I see both deposits (positive) and spending (negative). Do you want only spending, only deposits/refunds, or the net total?"
    return None


def parse_step_ref(ref: str, step_results):
    if isinstance(ref, (int, float, Decimal)):
        return Decimal(str(ref))
    if isinstance(ref, str):
        digits = ''.join([c for c in ref if c.isdigit()])
        if digits.isdigit():
            idx = int(digits)
            if idx < len(step_results):
                return _coerce_to_number(step_results[idx])
    raise ValueError(f"Invalid step reference: {ref}")

def _coerce_to_number(val):
    # CHANGED: handle rows or numeric
    if isinstance(val, (int, float, Decimal)):
        return Decimal(str(val))
    if isinstance(val, list):
        # Expect list of dicts (rows). Use first row, first numeric column.
        if not val:
            return Decimal("0")
        row = val[0]
        if isinstance(row, dict):
            for v in row.values():
                try:
                    return Decimal(str(v))
                except Exception:
                    continue
    return Decimal("0")

def calculate_projection(current_total, months_elapsed):
    if months_elapsed == 0:
        return None
    avg_per_month = Decimal(str(current_total)) / Decimal(str(months_elapsed))
    projection = avg_per_month * Decimal("12")
    return round(float(projection), 2)  # serialize-friendly

# --- Safety: Basic SQL sanitizer ---
def sanitize_sql(sql):
    sql_lower = sql.strip().lower()
    forbidden = ['insert', 'update', 'delete', 'drop', 'alter']
    if any(keyword in sql_lower for keyword in forbidden):
        raise ValueError("Unsafe SQL detected.")
    if not sql_lower.startswith("select"):
        raise ValueError("Only SELECT queries are allowed.")
    if sql_lower.count(';') > 1:
        raise ValueError("Multiple statements are not allowed.")
    if sql_lower.endswith(';'):
        sql = sql.strip().rstrip(';')
    allowed_sources = ["transactions"]
    if USE_SEMANTIC_VIEWS:
        allowed_sources += [VIEWS["with_tags"], VIEWS["spend"], VIEWS["income"], VIEWS["monthly"]]

    if not any(src and src.lower() in sql_lower for src in allowed_sources):
        raise ValueError("Query must reference an allowed table or view.")

    return sql

def _first_day_of_month(d: _date) -> _date:
    return _date(d.year, d.month, 1)

def _last_day_of_month(d: _date) -> _date:
    # monthrange returns (weekday, days_in_month)
    _, dim = monthrange(d.year, d.month)
    return _date(d.year, d.month, dim)

def _quarter_of(d: _date):
    q = (d.month - 1) // 3 + 1
    start_month = 3 * (q - 1) + 1
    end_month = start_month + 2
    start = _date(d.year, start_month, 1)
    _, end_dim = monthrange(d.year, end_month)
    end = _date(d.year, end_month, end_dim)
    return q, start, end

def _quarter_bounds(year: int, q: int):
    start_month = 3 * (q - 1) + 1
    end_month = start_month + 2
    start = _date(year, start_month, 1)
    _, end_dim = monthrange(year, end_month)
    return start, _date(year, end_month, end_dim)

def _to_iso(d: _date) -> str:
    return d.isoformat()

def dates_resolve(phrase: str, today_d: Optional[_date] = None) -> dict:
    """
    Very small resolver for a few common phrases.
    Returns: {"start": "YYYY-MM-DD", "end": "YYYY-MM-DD", "grain": "..."}
    """
    if not today_d:
        today_d = _date.today()

    p = (phrase or "").strip().lower()

    # explicit quarters like "q2 2024"
    m = re.match(r"q([1-4])\s*(\d{4})", p)
    if m:
        q = int(m.group(1))
        yr = int(m.group(2))
        start, end = _quarter_bounds(yr, q)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "month"}

    # this/last month
    if p in ("this month", "current month"):
        start = _first_day_of_month(today_d)
        end = _last_day_of_month(today_d)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "day"}
    if p in ("last month",):
        first_this = _first_day_of_month(today_d)
        last_prev = first_this - timedelta(days=1)
        start_prev = _first_day_of_month(last_prev)
        return {"start": _to_iso(start_prev), "end": _to_iso(last_prev), "grain": "day"}

    # this/last quarter
    if p in ("this quarter", "current quarter"):
        _, q_start, q_end = _quarter_of(today_d)
        return {"start": _to_iso(q_start), "end": _to_iso(q_end), "grain": "month"}
    if p in ("last quarter",):
        # back up one day from the start of this quarter
        _, q_start, _ = _quarter_of(today_d)
        last_q_end = q_start - timedelta(days=1)
        q, q_start2, q_end2 = _quarter_of(last_q_end)
        return {"start": _to_iso(q_start2), "end": _to_iso(q_end2), "grain": "month"}

    # YTD / last year / this year
    if p in ("ytd", "year to date"):
        start = _date(today_d.year, 1, 1)
        return {"start": _to_iso(start), "end": _to_iso(today_d), "grain": "month"}
    if p in ("this year", "current year"):
        start = _date(today_d.year, 1, 1)
        end = _date(today_d.year, 12, 31)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "month"}
    if p in ("last year",):
        start = _date(today_d.year - 1, 1, 1)
        end = _date(today_d.year - 1, 12, 31)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "month"}

    # this/last week (simple ISO weeks: Monday..Sunday)
    if p in ("this week", "current week"):
        dow = today_d.weekday()  # 0=Mon
        start = today_d - timedelta(days=dow)
        end = start + timedelta(days=6)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "day"}
    if p in ("last week",):
        dow = today_d.weekday()
        this_start = today_d - timedelta(days=dow)
        last_start = this_start - timedelta(days=7)
        last_end = this_start - timedelta(days=1)
        return {"start": _to_iso(last_start), "end": _to_iso(last_end), "grain": "day"}

    # fallback: interpret as month name "september 2024" etc.
    m2 = re.match(r"(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)\s*(\d{4})", p)
    if m2:
        mm_map = {"jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,"jul":7,"aug":8,"sep":9,"sept":9,"oct":10,"nov":11,"dec":12}
        mm = mm_map[m2.group(1)]
        yy = int(m2.group(2))
        start = _date(yy, mm, 1)
        end = _last_day_of_month(start)
        return {"start": _to_iso(start), "end": _to_iso(end), "grain": "day"}

    # unknown → give back nothing (the planner can ask for clarification)
    return {"start": None, "end": None, "grain": None}

def execute_query(user_id: int, sql: str, params: dict | None = None):
    """Executes a sanitized, parameterized SQL query with caching and returns rows or scalar."""
    safe_sql = sanitize_sql(sql)
    key = _sql_key(user_id, safe_sql, params or {})
    cached = _cache_get(key)
    if cached is not None:
        return cached

    # Execute with bound params (prevents injection)
    res = db.session.execute(text(safe_sql), params or {})

    # IMPORTANT: get dict-like rows
    rows = res.mappings().all()

    if not rows:
        result = []  # or Decimal("0") if you *want* scalar for empty aggregates
    elif len(rows) == 1 and len(rows[0]) == 1:
        val = next(iter(rows[0].values()))
        # Normalize Decimal/None for JSON
        if isinstance(val, Decimal):
            result = float(val)
        else:
            result = 0 if val is None else val
    else:
        def coerce(row):
            out = {}
            for k, v in row.items():
                out[k] = float(v) if isinstance(v, Decimal) else v
            return out
        result = [coerce(r) for r in rows]

    _cache_set(key, result)
    return result

def fix_sql_for_sqlite(sql: str) -> str:
    """Fix common GPT mistakes to ensure valid SQLite syntax and correct filters."""
    fixed = sql.strip()
    fixed = fixed.replace("ILIKE", "LIKE").replace("ilike", "LIKE")
    if "LIKE" in fixed.upper() and "COLLATE NOCASE" not in fixed.upper():
        fixed = re.sub(r"\bLIKE\b", "LIKE COLLATE NOCASE", fixed, flags=re.IGNORECASE)
    fixed = fixed.replace("t.date", "DATE(t.date)")
    if "SUM" in fixed.upper() and "amount < 0" not in fixed:
        if re.search(r"\bWHERE\b", fixed, flags=re.IGNORECASE):
            fixed = re.sub(r"\bWHERE\b", "WHERE t.amount < 0 AND", fixed, flags=re.IGNORECASE)
        else:
            fixed += " WHERE t.amount < 0"
    return fixed.rstrip(";")

ALLOWED_COLUMNS = {"amount", "date", "division", "name"}
ALLOWED_GROUP_BY = {"tags", "division", "name"}
ALLOWED_ORDER_BY = {"amount", "total", "date", "name"}

def _prefer_semantic_views(sql: str) -> str:
    if not USE_SEMANTIC_VIEWS:
        return sql
    # If the query uses the base table + tag joins, swap to the flattened view
    if re.search(r'\bFROM\s+transactions\s+t\b', sql, flags=re.IGNORECASE):
        if _try_view(VIEWS["with_tags"]) and (
            re.search(r'\bJOIN\s+tags\b', sql, flags=re.IGNORECASE) or
            re.search(r'\bJOIN\s+transaction_tags\b', sql, flags=re.IGNORECASE)
        ):
            sql = re.sub(r'\bFROM\s+transactions\s+t\b',
                         f'FROM {VIEWS["with_tags"]} t',
                         sql, flags=re.IGNORECASE)
            # Remove now-redundant joins (the view already contains tags)
            sql = re.sub(r'\bJOIN\s+transaction_tags\b.*?(?=JOIN|\bWHERE\b|$)', '',
                         sql, flags=re.IGNORECASE | re.DOTALL)
            sql = re.sub(r'\bJOIN\s+tags\b.*?(?=JOIN|\bWHERE\b|$)', '',
                         sql, flags=re.IGNORECASE | re.DOTALL)
    return sql

def build_dynamic_query(query_data, user_id):
    """
    Returns (sql, params) for safe execution.
    """
    params = {"user_id": user_id}

    if query_data.get("sql"):
        sql = query_data["sql"].strip()

        # Table alias normalizations remain (they're not user-injected literals)
        sql = re.sub(r'\bFROM\s+transactions\b', 'FROM transactions t', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bJOIN\s+transaction_tags\b', 'JOIN transaction_tags tt', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bJOIN\s+tags\b', 'JOIN tags tg', sql, flags=re.IGNORECASE)

        sql = re.sub(r'\btransactions\.', 't.', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\btransaction_tags\.', 'tt.', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\btags\.', 'tg.', sql, flags=re.IGNORECASE)

        sql = re.sub(r'\b(?<!\.)id\b', 't.id', sql)
        sql = re.sub(r'\b(?<!\.)user_id\b', 't.user_id', sql)
        sql = re.sub(r'\b(?<!\.)name\b', 't.name', sql)
        sql = re.sub(r'\b(?<!\.)date\b', 't.date', sql)
        sql = re.sub(r'\b(?<!\.)amount\b', 't.amount', sql)

        # Enforce user_id via parameter (no string interpolation)
        if re.search(r"\bt\.user_id\b", sql, flags=re.IGNORECASE):
            # Replace literal comparisons to parameter if present
            sql = re.sub(r"t\.user_id\s*=\s*\d+", "t.user_id = :user_id", sql, flags=re.IGNORECASE)
        else:
            sql += " WHERE t.user_id = :user_id"

        # CHANGED: apply SQLite fixes only when needed
        if _dialect() == "sqlite":
            sql = fix_sql_for_sqlite(sql)

        sql = _prefer_semantic_views(sql)  # NEW
        return sql, params

    # --- Legacy filter-built path: parameterized everywhere ---
    operation = query_data.get("operation", "sum").lower()
    filters = query_data.get("filters", {}) or {}
    group_by = query_data.get("group_by")
    order_by = query_data.get("order_by")
    limit = query_data.get("limit")

    select_clause = "SUM(t.amount)" if operation == "sum" else "COUNT(*)" if operation == "count" else "AVG(t.amount)"
    if group_by in ALLOWED_GROUP_BY:
        select_clause += f", {group_by}"

    sql = "SELECT " + select_clause + " FROM transactions t"
    if filters.get("tags") or group_by == "tags":
        sql += " JOIN transaction_tags tt ON t.id = tt.transaction_id JOIN tags tg ON tg.id = tt.tag_id"

    conditions = ["t.user_id = :user_id"]

    if filters.get("date_range"):
        start = filters["date_range"].get("from")
        end = filters["date_range"].get("to")
        if start and end:
            conditions.append("DATE(t.date) BETWEEN :start AND :end")
            params["start"] = start
            params["end"] = end

    if filters.get("division"):
        conditions.append(_ci_like("t.division"))
        params["needle"] = f"%{filters['division']}%"

    if filters.get("tags") and filters.get("name"):
        # OR name/tags; use separate needles to avoid clashes
        conditions.append(f"({_ci_like('t.name')} OR " + _ci_like("tg.name") + ")")
        params["needle"] = f"%{filters['name']}%"
        params["needle2"] = f"%{filters['tags']}%"
        # Adjust the second placeholder name in the compiled SQL
        # (SQLAlchemy binds by name; to keep both, rename below)
        conditions[-1] = conditions[-1].replace(":needle)", ":needle) OR " + _ci_like("tg.name").replace(":needle", ":needle2") + ")")
    elif filters.get("tags"):
        conditions.append(_ci_like("tg.name"))
        params["needle"] = f"%{filters['tags']}%"
    elif filters.get("name"):
        conditions.append(_ci_like("t.name"))
        params["needle"] = f"%{filters['name']}%"

    if filters.get("amount"):
        # Expect something like '> 0' or '< 0'
        amt_op = filters['amount'].strip()
        if amt_op in ("> 0", "< 0", ">= 0", "<= 0"):
            conditions.append(f"t.amount {amt_op}")
        else:
            raise ValueError("Invalid amount filter operator")

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    if group_by in ALLOWED_GROUP_BY:
        sql += f" GROUP BY {group_by}"
    if order_by and any(col in order_by for col in ALLOWED_ORDER_BY):
        sql += f" ORDER BY {order_by}"
    if limit:
        sql += " LIMIT :limit"
        params["limit"] = int(limit)

    sql = _prefer_semantic_views(sql)  
    print(f"[build_dynamic_query] Final Dynamic SQL: {sql} | params={params}")
    return sql, params

ActionType = Literal[
    "run_sql_query",
    "calculate_percentage",
    "summarize_results",
    "stats_describe",     # NEW
    "dates_resolve",      # NEW
    "calc_evaluate"       # NEW
]

class Step(BaseModel):
    action: ActionType

    # Existing optional fields used by run_sql_query path
    sql: Optional[str] = None
    operation: Optional[Literal["sum", "count", "avg", "null"]] = None
    filters: Optional[dict] = None
    group_by: Optional[Literal["tags", "division", "name", "null"]] = None
    order_by: Optional[str] = None
    limit: Optional[int] = None

    # Cross-step referencing for calculations
    a: Optional[Any] = None
    b: Optional[Any] = None

    # NEW: tool-specific options
    # stats_describe
    by: Optional[str] = None          # e.g., "tag" or "merchant_name"
    metric: Optional[str] = None      # which numeric field to aggregate (e.g., "spend", "amount", "total")
    k: Optional[int] = None           # top-k

    # dates_resolve
    phrase: Optional[str] = None      # e.g., "last month", "Q2 2024"
    grain: Optional[Literal["day", "week", "month", "quarter", "year"]] = None

    # calc_evaluate
    expression: Optional[str] = None  # e.g., "(savings / income) * 100"
    inputs: Optional[dict] = None     # { "savings": 1234, "income": 5678 }

    # The model sometimes nests things under args; we normalize later
    args: Optional[dict] = None
class Plan(BaseModel):
    steps: List[Step] = Field(default_factory=list)
    response_text: Optional[str] = None
    needs_clarification: bool = False
    clarification_question: Optional[str] = None
    projection: bool = False

# =========================
# CHANGED: robust OpenAI call
# - Structured JSON (response_format)
# - Retries with exponential backoff + jitter
# - Timeout on request
# =========================

def _openai_chat_json(messages, *, temperature=0.3, max_tries=4, base_delay=0.5, timeout_s=20) -> dict:
    """
    Calls OpenAI with JSON-mode and retries on transient failures.
    Returns a parsed dict (already JSON by API contract).
    """
    last_err = None
    for attempt in range(1, max_tries + 1):
        try:
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                temperature=temperature,
                response_format={"type": "json_object"},  # CHANGED: structured output
                timeout=timeout_s,                        # CHANGED: request timeout
            )
            content = resp.choices[0].message.content
            # In JSON-mode, content is guaranteed to be a single JSON object string
            return json.loads(content)
        except Exception as e:
            last_err = e
            if attempt == max_tries:
                break
            # Exponential backoff with jitter
            delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.25)
            sleep(delay)
    # Bubble up with context
    raise RuntimeError(f"OpenAI JSON call failed after {max_tries} attempts: {last_err}")

# =========================
# CHANGED: parse & validate with schema
# =========================

def get_plan_with_validation(messages) -> Plan:
    """
    Get a model plan with structured JSON and validate it.
    If validation fails, we ask the model once more to fix shape.
    """
    try:
        raw = _openai_chat_json(messages, temperature=0.2)
        return Plan(**raw)  # validate
    except ValidationError as ve:
        # Ask the model to reformat exactly to schema
        fix_messages = messages + [{
            "role": "system",
            "content": (
                "The previous response did not match the required JSON schema. "
                "Respond again with ONLY a JSON object matching this shape:\n"
                "{"
                "  'steps': [{'action': 'run_sql_query|calculate_percentage|summarize_results',"
                "             'sql': 'optional', 'operation':'sum|count|avg|null',"
                "             'filters': {}, 'group_by':'tags|division|name|null',"
                "             'order_by':'optional', 'limit': 5, 'a': any, 'b': any}],"
                "  'response_text': 'string or null',"
                "  'needs_clarification': boolean,"
                "  'clarification_question': 'string or null',"
                "  'projection': boolean"
                "}"
            )
        }]
        raw = _openai_chat_json(fix_messages, temperature=0.0)
        return Plan(**raw)  # may raise ValidationError → let it propagate

# =========================
# CHANGED: small helper to normalize steps (strings → objects)
# =========================

def _normalize_steps(plan: Plan) -> List[Step]:
    norm = []
    for idx, st in enumerate(plan.steps):
        # Pydantic already made them Step, but the model might have put args inside st.args
        if st.args:
            # pull through common fields from args if missing
            if st.a is None and "a" in st.args: st.a = st.args["a"]
            if st.b is None and "b" in st.args: st.b = st.args["b"]
            if st.sql is None and "sql" in st.args: st.sql = st.args["sql"]
            if st.limit is None and "limit" in st.args: st.limit = st.args["limit"]
            if st.filters is None and "filters" in st.args: st.filters = st.args["filters"]
            if st.operation is None and "operation" in st.args: st.operation = st.args["operation"]
            if st.group_by is None and "group_by" in st.args: st.group_by = st.args["group_by"]
            if st.order_by is None and "order_by" in st.args: st.order_by = st.args["order_by"]
        norm.append(st)
    return norm


@nlp_api.route('/api/nlp_query', methods=['POST'])
@csrf.exempt
@login_required
def nlp_query():
    try:
        if not request.is_json:
            return jsonify({"error": "Expected JSON body"}), 400

        user_input = request.json.get('question')
        user_id = current_user.id
        chat_history = session.get("chat_history", [])

        # Financial summary for context
        try:
            financial_summary = get_user_financial_summary(user_id)
        except Exception as e:
            return jsonify({"error": "Failed to fetch financial summary", "details": str(e)}), 500

        system_prompt = f"""
        You are a financial assistant for a personal finance app. 
        You have access to the user's transaction data and these tools:
        - run_sql_query(sql): Run safe SELECT queries on the transactions DB.
        - calculate_percentage(a, b): Compute simple percentages.
        - summarize_results(data): Summarize transaction lists in natural language.
        - stats_describe(rows, by=?, metric=?, k=?): Given a table from sql.run, compute count/sum/avg and optionally a top-k breakdown by a column.
        - dates_resolve(phrase): Convert natural phrases ("last month", "Q2 2024", "YTD") into {"start","end","grain"}.
        - calc_evaluate(expression, inputs): Safely compute arithmetic like "(a / b) * 100" using provided named inputs.


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
        - SQLite does NOT support ILIKE. Use `LIKE '%value%' COLLATE NOCASE` (or LOWER(x) LIKE LOWER for other DBs).
        - Spending (money out) = negative amounts. Deposits (money in) = positive amounts.
        - For "spending" questions, always filter `AND amount < 0`.
        - Convert negative spending to positive values when presenting.
        - If both positive and negative exist, set needs_clarification and ask which to report.
        - Never modify the database. Only SELECT queries.
        - Break complex questions into steps: interpret → plan → query → calculate → summarize.

        **OUTPUT FORMAT (MUST be a single JSON object):** 
        {{
          "steps": [{{"action":"run_sql_query|calculate_percentage|summarize_results","sql":"optional","operation":"sum|count|avg|null","filters":{{}},"group_by":"tags|division|name|null","order_by":"optional","limit":5,"a":null,"b":null}}],
          "response_text": "string or null",
          "needs_clarification": false,
          "clarification_question": null,
          "projection": false
        }}

        TEMPLATES & PATTERNS (use these shapes exactly; adjust WHERE only):

            General notes
            - Prefer semantic views when available:
            - Spending rows (positive magnitude): v_spend (column: spend, plus month, tag, merchant_name, division)
            - Income rows: v_income (column: income)
            - With tags (one row per tag): v_txn_with_tags (columns: amount [signed], tag, month, merchant_name)
            - Monthly rollups: v_txn_monthly (columns: spend, income, net_spend by user_id, month)
            - Always filter by user_id = :user_id.
            - For date windows, use DATE(ts_utc) or month key as appropriate, and always parameterize (:start, :end, :n, etc.).

            Top-N by category (spend)
            SQL:
            SELECT tag AS category, SUM(spend) AS total
            FROM v_spend
            WHERE user_id = :user_id
            AND DATE(ts_utc) BETWEEN :start AND :end
            GROUP BY tag
            ORDER BY SUM(spend) DESC
            LIMIT :n;

            Top-N by merchant (spend)
            SQL:
            SELECT merchant_name, SUM(spend) AS total
            FROM v_spend
            WHERE user_id = :user_id
            AND DATE(ts_utc) BETWEEN :start AND :end
            GROUP BY merchant_name
            ORDER BY SUM(spend) DESC
            LIMIT :n;

            Total spend / income / net over a period
            SQL (spend):
            SELECT SUM(spend) AS total
            FROM v_spend
            WHERE user_id = :user_id
            AND DATE(ts_utc) BETWEEN :start AND :end;

            SQL (income):
            SELECT SUM(income) AS total
            FROM v_income
            WHERE user_id = :user_id
            AND DATE(ts_utc) BETWEEN :start AND :end;

            SQL (net, monthly rollup then sum):
            SELECT SUM(net_spend) AS total
            FROM v_txn_monthly
            WHERE user_id = :user_id
            AND month BETWEEN :mstart AND :mend;

            Month-over-month (MoM) comparison (two queries + % change)
            1) Resolve two windows (previous month vs current month).
            2) Query each period’s total spend from v_spend (see “Total spend”).
            3) Calculate percentage change.

            Quarter-over-quarter (QoQ) or Year-over-year (YoY) comparison
            Same as MoM but with quarter or year windows.

            Category share of spend (composition)
            SQL:
            SELECT tag AS category, SUM(spend) AS total
            FROM v_spend
            WHERE user_id = :user_id
            AND DATE(ts_utc) BETWEEN :start AND :end
            GROUP BY tag
            ORDER BY total DESC;

            Recurring merchants (heuristic)
            Definition: merchant appears in ≥ :m_count distinct months in window, with at least :min_tx transactions overall.
            SQL:
            WITH m AS (
            SELECT merchant_name,
                    COUNT(*) AS tx_count,
                    COUNT(DISTINCT strftime('%Y-%m', ts_utc)) AS active_months,
                    SUM(spend) AS total_spend
            FROM v_spend
            WHERE user_id = :user_id
                AND DATE(ts_utc) BETWEEN :start AND :end
            GROUP BY merchant_name
            )
            SELECT merchant_name, tx_count, active_months, total_spend
            FROM m
            WHERE active_months >= :m_count AND tx_count >= :min_tx
            ORDER BY total_spend DESC
            LIMIT :n;

            Period breakdown (trend)
            SQL:
            SELECT month, SUM(spend) AS total
            FROM v_spend
            WHERE user_id = :user_id
            AND month BETWEEN :mstart AND :mend
            GROUP BY month
            ORDER BY month;

            Division or tag filters (case-insensitive)
            - division: AND LOWER(division) LIKE LOWER(:needle)
            - tag: AND LOWER(tag) LIKE LOWER(:needle)

            IMPORTANT:
            - Use the minimal columns required for the task.
            - Do not emit SELECT *.
            - Keep LIMITs small (e.g., 5–20) unless the question asks for full detail.
            - For comparisons, produce two queries and then a calc step: calculate_percentage or calc_evaluate.

        ---
        PLANNING PLAYBOOK (multi-step):
        - When the user asks for a comparison (e.g., “this month vs last month”), do:
        1) dates_resolve("this month"), dates_resolve("last month")
        2) run_sql_query for each window (v_spend or v_income)
        3) calc_evaluate("(this / last - 1) * 100", {"this": x, "last": y}) or calculate_percentage
        4) summarize_results

        - When the user asks for “top categories/vendors”:
        1) dates_resolve("<phrase>")
        2) run_sql_query using the Top-N template
        3) stats_describe on the result (by=category or merchant_name)
        4) summarize_results

        - When the user asks for “recurring”:
        1) dates_resolve("<phrase>" or default to YTD)
        2) run_sql_query using Recurring merchants template with :m_count (e.g., 2) and :min_tx (e.g., 3)
        3) summarize_results

        - If the request is ambiguous (spend vs income vs net, or dates unclear), set needs_clarification and ask a direct question.
        ---

        """

        messages = [{"role": "system", "content": system_prompt}] + chat_history + [{"role": "user", "content": user_input}]

        # CHANGED: get structured JSON + validate
        try:
            plan = get_plan_with_validation(messages)
        except (RuntimeError, ValidationError) as e:
            return jsonify({"error": "Model planning failed", "details": str(e)}), 502

        if plan.needs_clarification:
            session["pending_clarification"] = {
                "original_question": user_input,
                "clarification_question": plan.clarification_question
            }
            return jsonify({
                "summary": "Clarification needed",
                "needs_clarification": True,
                "clarification_question": plan.clarification_question
            })

        # === Execute steps with verification + ambiguity detection ===
        steps = _normalize_steps(plan)
        step_results = []
        verifications = []
        assumptions = []
        limitations = []

        for idx, step in enumerate(steps):
            if step.action == "run_sql_query":
                sql, params = build_dynamic_query(step.dict(), user_id)
                result = execute_query(user_id, sql, params)
                step_results.append(result)

                # Verification loop
                verifications.append({"step": idx, **verify_totals(sql, params, user_id)})

                # Ambiguity detector (sign mixing if no explicit sign filter)
                clarq = detect_sign_ambiguity(sql, result)
                if clarq:
                    limitations.append("Result may mix spending and deposits; interpretation could be ambiguous.")
                    session["pending_clarification"] = {
                        "original_question": user_input,
                        "clarification_question": clarq
                    }

            elif step.action == "calculate_percentage":
                a = parse_step_ref(step.a, step_results)
                b = parse_step_ref(step.b, step_results)
                A = Decimal(str(a or 0))
                B = Decimal(str(b or 0))
                val = Decimal("0") if B == 0 else (A / B) * Decimal("100")
                step_results.append(float(val.quantize(Decimal("0.01"))))

            elif step.action == "stats_describe":
                # source can be a previous step index or attach rows directly in step.args.rows
                rows_source = step.a if step.a is not None else (step.args or {}).get("rows")
                rows = parse_step_ref(rows_source, step_results) if isinstance(rows_source, (str, int)) else rows_source
                desc = stats_describe(rows, metric=step.metric, by=step.by, k=step.k or 5)
                step_results.append(desc)

            elif step.action == "dates_resolve":
                phrase = step.phrase or (step.args or {}).get("phrase") or ""
                resolved = dates_resolve(phrase, today)
                step_results.append(resolved)

            elif step.action == "calc_evaluate":
                expression = step.expression or (step.args or {}).get("expression") or ""
                inputs = step.inputs or (step.args or {}).get("inputs") or {}
                val = calc_evaluate(expression, inputs)
                step_results.append(val)


            elif step.action == "summarize_results":
                step_results.append(step_results[-1] if step_results else None)

        # Projection (unchanged)
        projection_text = None
        if plan.projection:
            months_elapsed = today.month
            projected_total = calculate_projection(_coerce_to_number(step_results[-1]), months_elapsed)
            if projected_total is not None:
                projection_text = f"If you continue at this pace, your projected total by year-end is approximately ${projected_total}."

        # Shape results for consistent API + better prompting
        shaped = shape_results(step_results, verifications, assumptions, limitations)

        # Optional evaluation harness
        if request.json.get("eval"):
            shaped["evaluation"] = run_evaluation(user_id)

        # Final narrative (use shaped results)
        reasoning_prompt = f"""
        User asked: {user_input}.
        Key numbers: {shaped.get('numbers')}.
        Tables (first row samples): {[t[:1] for t in shaped.get('tables', [])]}.
        Projection: {projection_text}.
        Known limitations: {shaped.get('limitations')}.
        Provide a clear, friendly financial answer grounded in the numbers.
        """
        try:
            final_json = _openai_chat_json(
                [
                    {"role": "system", "content": "You are a financial assistant summarizing query results for the user. Respond as JSON: {\"insight\": string}."},
                    {"role": "user", "content": reasoning_prompt}
                ],
                temperature=0.3,
                timeout_s=20
            )
            final_insight = final_json.get("insight") or plan.response_text or ""
        except Exception:
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a financial assistant summarizing query results for the user."},
                    {"role": "user", "content": reasoning_prompt}
                ],
                temperature=0.3,
                timeout=20
            )
            final_insight = resp.choices[0].message.content.strip()

        # Save small chat history server-side
        chat_history.append({"role": "user", "content": user_input})
        chat_history.append({"role": "assistant", "content": final_insight})
        session["chat_history"] = chat_history[-10:]

        return jsonify({
            "steps_executed": [s.dict() for s in steps],
            "results": shaped,                                # <-- shaped output
            "projection": projection_text,
            "insight": final_insight or plan.response_text,
            "needs_clarification": bool(session.get("pending_clarification")),
            "clarification_question": session.get("pending_clarification", {}).get("clarification_question"),
        })
    except Exception as e: 
        import traceback 
        traceback.print_exc() 
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500