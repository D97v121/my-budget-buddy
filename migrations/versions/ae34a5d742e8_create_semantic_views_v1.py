from alembic import op

# revision identifiers, used by Alembic.
revision = "semantic_views_v1"
down_revision = "2b72c209fab9"
branch_labels = None
depends_on = None


CREATE_V_TXN_WITH_TAGS = """
CREATE OR REPLACE VIEW v_txn_with_tags AS
WITH base AS (
  SELECT
    t.id            AS txn_id,
    t.user_id       AS user_id,
    t.amount        AS amount,
    t.date          AS ts_utc,
    t.name          AS merchant_name,
    t.division      AS division,
    tg.name         AS tag,
    0               AS is_transfer
  FROM transactions t
  LEFT JOIN transaction_tags tt ON t.id = tt.transaction_id
  LEFT JOIN tags tg ON tg.id = tt.tag_id
)
SELECT
  *,
  ts_utc                                          AS ts_local,
  date_trunc('month', ts_utc)                     AS month_start,
  to_char(ts_utc, 'YYYY-MM')                      AS month
FROM base
"""

CREATE_V_SPEND = """
CREATE OR REPLACE VIEW v_spend AS
SELECT
  txn_id,
  user_id,
  ABS(amount)      AS spend,
  amount           AS amount_raw,
  ts_utc, ts_local, month_start, month,
  merchant_name, division, tag,
  is_transfer
FROM v_txn_with_tags
WHERE amount < 0 AND is_transfer = 0
"""

CREATE_V_INCOME = """
CREATE OR REPLACE VIEW v_income AS
SELECT
  txn_id,
  user_id,
  amount           AS income,
  ts_utc, ts_local, month_start, month,
  merchant_name, division, tag,
  is_transfer
FROM v_txn_with_tags
WHERE amount > 0 AND is_transfer = 0
"""

CREATE_V_TXN_MONTHLY = """
CREATE OR REPLACE VIEW v_txn_monthly AS
WITH staged AS (
  SELECT user_id, month, amount
  FROM v_txn_with_tags
  WHERE is_transfer = 0
)
SELECT
  user_id,
  month,
  SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END) AS spend,
  SUM(CASE WHEN amount > 0 THEN amount      ELSE 0 END) AS income,
  SUM(CASE WHEN amount < 0 THEN -ABS(amount) ELSE amount END) AS net_spend
FROM staged
GROUP BY user_id, month
"""


def upgrade():
    op.execute(CREATE_V_TXN_WITH_TAGS)
    op.execute(CREATE_V_SPEND)
    op.execute(CREATE_V_INCOME)
    op.execute(CREATE_V_TXN_MONTHLY)


def downgrade():
    op.execute("DROP VIEW IF EXISTS v_txn_monthly")
    op.execute("DROP VIEW IF EXISTS v_income")
    op.execute("DROP VIEW IF EXISTS v_spend")
    op.execute("DROP VIEW IF EXISTS v_txn_with_tags")