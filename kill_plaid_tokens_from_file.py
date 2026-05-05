import os
import csv
import time
from datetime import datetime
from typing import List, Tuple, Dict, Optional

from plaid.model.item_remove_request import ItemRemoveRequest
from plaid.exceptions import ApiException

from app import create_app
from app.plaid_helpers import client

# --- CONFIG ---
TOKENS_FILE = os.getenv("PLAID_TOKENS_FILE", "/tmp/plaid_tokens.csv")  # path to CSV from SendSafely
RESULTS_FILE = os.getenv("PLAID_RESULTS_FILE", "/tmp/removal_results.csv")
SLEEP_SECONDS = float(os.getenv("PLAID_RATE_LIMIT_SLEEP", "0.2"))      # gentle pacing
REQUIRE_CONFIRM = os.getenv("PLAID_REQUIRE_CONFIRM", "true").lower() in ("1", "true", "yes")
# --------------

def mask(t: str, keep: int = 6) -> str:
    if not t:
        return "(missing)"
    return f"...{t[-keep:]}" if len(t) >= keep else "(short)"

def find_access_token_column(fieldnames: List[str]) -> Optional[str]:
    if not fieldnames:
        return None
    # exact match case-insensitive
    for h in fieldnames:
        if h.strip().lower() == "access_token":
            return h
    # fallback: contains access_token
    for h in fieldnames:
        if "access_token" in h.strip().lower():
            return h
    return None

def read_tokens_from_csv(path: str) -> Tuple[List[str], str]:
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        token_col = find_access_token_column(reader.fieldnames or [])
        if not token_col:
            raise SystemExit(
                f"Could not find an access_token column in CSV headers: {reader.fieldnames}"
            )

        tokens: List[str] = []
        for row in reader:
            raw = (row.get(token_col) or "").strip()
            if raw:
                tokens.append(raw)

    # Deduplicate while preserving order
    seen = set()
    unique_tokens = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique_tokens.append(t)

    return unique_tokens, token_col

def write_results_csv(path: str, rows: List[Dict[str, str]]) -> None:
    fieldnames = [
        "timestamp",
        "access_token_last6",
        "status",
        "removed",
        "error_type",
        "error_code",
        "error_message",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        if not os.path.exists(TOKENS_FILE):
            raise SystemExit(
                f"Missing {TOKENS_FILE}. Set PLAID_TOKENS_FILE to your CSV path or put it there."
            )

        tokens, token_col = read_tokens_from_csv(TOKENS_FILE)

        print(f"CSV: {TOKENS_FILE}")
        print(f"Detected token column: {token_col}")
        print(f"Found {len(tokens)} unique tokens")

        if REQUIRE_CONFIRM:
            confirm = input(
                f"\nThis will PERMANENTLY remove {len(tokens)} Plaid Items in PRODUCTION.\n"
                f"Type REMOVE to proceed: "
            ).strip()
            if confirm != "REMOVE":
                raise SystemExit("Aborted.")

        removed = 0
        failed = 0
        results: List[Dict[str, str]] = []

        for idx, t in enumerate(tokens, start=1):
            ts = datetime.utcnow().isoformat() + "Z"
            try:
                resp = client.item_remove(ItemRemoveRequest(access_token=t))
                # resp.removed is typically True
                removed += 1
                print(f"[{idx}/{len(tokens)}] Removed token={mask(t)} removed={getattr(resp, 'removed', None)}")

                results.append(
                    {
                        "timestamp": ts,
                        "access_token_last6": t[-6:] if len(t) >= 6 else t,
                        "status": "removed",
                        "removed": str(getattr(resp, "removed", True)).lower(),
                        "error_type": "",
                        "error_code": "",
                        "error_message": "",
                    }
                )

            except ApiException as e:
                failed += 1
                # Plaid SDK ApiException often has .body with JSON error details
                error_type = ""
                error_code = ""
                error_message = str(e)

                try:
                    body = getattr(e, "body", None)
                    if body and isinstance(body, dict):
                        error_type = body.get("error_type", "") or ""
                        error_code = body.get("error_code", "") or ""
                        error_message = body.get("error_message", "") or error_message
                except Exception:
                    pass

                print(f"[{idx}/{len(tokens)}] FAILED token={mask(t)} plaid_error={error_message}")

                results.append(
                    {
                        "timestamp": ts,
                        "access_token_last6": t[-6:] if len(t) >= 6 else t,
                        "status": "failed",
                        "removed": "false",
                        "error_type": error_type,
                        "error_code": error_code,
                        "error_message": error_message,
                    }
                )

            except Exception as e:
                failed += 1
                msg = str(e)
                print(f"[{idx}/{len(tokens)}] FAILED token={mask(t)} error={msg}")

                results.append(
                    {
                        "timestamp": ts,
                        "access_token_last6": t[-6:] if len(t) >= 6 else t,
                        "status": "failed",
                        "removed": "false",
                        "error_type": "",
                        "error_code": "",
                        "error_message": msg,
                    }
                )

            time.sleep(SLEEP_SECONDS)

        write_results_csv(RESULTS_FILE, results)

        print(f"\nDone. removed={removed} failed={failed}")
        print(f"Results written to: {RESULTS_FILE}")
