from app import create_app, db
from app.models.plaid import PlaidItem
from plaid.model.item_remove_request import ItemRemoveRequest
from plaid.exceptions import ApiException
from app.plaid_helpers import client

app = create_app()

with app.app_context():
    items = PlaidItem.query.all()
    print(f"Found {len(items)} Plaid items in DB")

    removed = 0
    failed = 0

    for item in items:
        token = item.decrypted_access_token
        masked = f"...{token[-4:]}" if token and len(token) >= 4 else "(missing)"

        try:
            client.item_remove(ItemRemoveRequest(access_token=token))
            db.session.delete(item)
            removed += 1
            print(f"Removed item_id={item.item_id} token={masked}")
        except ApiException as e:
            failed += 1
            print(f"FAILED item_id={item.item_id} token={masked} err={e}")
        except Exception as e:
            failed += 1
            print(f"FAILED item_id={item.item_id} token={masked} err={e}")

    db.session.commit()
    print(f"Done. removed={removed} failed={failed}")
