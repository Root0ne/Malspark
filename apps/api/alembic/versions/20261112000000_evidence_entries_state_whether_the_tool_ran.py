"""Evidence entries state whether the call's tool ran.

``evidence_entries`` gains ``ran``, the field ``malspark.schemas.evidence.LedgerEntry``
carries for a call that was served without running (false) and for one that ran
and whose answer an earlier entry holds (true): a nullable boolean. The run
summary counts the two apart from the calls that ran once.

The column is nullable and has no default. A row written before this revision,
or for an entry that states nothing, holds none and reads as absent; the ledger
chain's digest seals it whenever it holds anything but NULL (false included),
so every stored digest and chain value stays what it was.

One added nullable column with no default: Postgres changes the catalogue and
rewrites no row, so the only cost is the ACCESS EXCLUSIVE lock, bounded by
``LOCK_TIMEOUT``.

The downgrade drops the column and what it stated; the entry's other fields are
unchanged.

Revision ID: 20261112000000
Revises: 20261107000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261112000000"
down_revision = "20261107000000"
branch_labels = None
depends_on = None

# How long the ALTER waits for its lock before the migration fails instead, so
# a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"

COLUMN = "ran"


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("evidence_entries")}


def upgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if COLUMN not in _columns():
        op.add_column("evidence_entries", sa.Column(COLUMN, sa.Boolean(), nullable=True))


def downgrade() -> None:
    if _is_postgres():
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    if COLUMN in _columns():
        op.drop_column("evidence_entries", COLUMN)
