"""Whether a call's tool ran is stored on the entry's row, served back and sealed.

``ran`` (T-659) is false on an entry filed with no tool run and true on one that
ran and whose answer an earlier entry holds; an entry that states nothing holds
none. It goes into the row ``_evidence_row`` builds, comes out of the reader as
the entry carried it, and is sealed whenever stated, false included, so a ledger
sealed before the column existed still verifies.

The revision is run on a bare SQLite table and never imports the application.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from importlib import util
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.models.evidence import EvidenceEntry
from app.schemas.evidence import EvidenceEntryResponse
from app.services import ledger_chain
from app.worker.analysis_worker import _evidence_row
from malspark.schemas.evidence import LedgerEntry

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261112000000_evidence_entries_state_whether_the_tool_ran.py"
)
_WRITTEN = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)


def _entry(seq: int, **extra: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": f"ev_{seq:04d}",
        "tool": "decompile_function",
        "agent": "static",
        "args": {"address": "0x401000"},
        "output": "int main(void) { return 0; }",
        "started_at": 1_700_000_000.0 + seq,
        "duration_ms": 12,
        "seq": seq,
    }
    fields.update(extra)
    return LedgerEntry(**fields).model_dump(mode="json")


def _served(row: Any) -> dict[str, Any]:
    row.id = uuid.uuid4()
    return json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())


def test_a_stated_value_is_kept_and_served_false_included() -> None:
    for value in (False, True):
        row = _evidence_row(_entry(1, ran=value), job_id=uuid.uuid4(), written_at=_WRITTEN)
        assert row.ran is value
        served = _served(row)
        assert served["ran"] is value
        back = LedgerEntry.model_validate({**served, "id": served["entry_id"]})
        assert back.ran is value


def test_an_entry_that_states_nothing_stores_none_and_serves_none() -> None:
    row = _evidence_row(_entry(1), job_id=uuid.uuid4(), written_at=_WRITTEN)
    assert row.ran is None
    assert "ran" not in _served(row)


def test_it_is_sealed_when_stated_and_not_when_absent() -> None:
    job = uuid.uuid4()
    plain = _evidence_row(_entry(1), job_id=job, written_at=_WRITTEN)
    refused = _evidence_row(_entry(1, ran=False), job_id=job, written_at=_WRITTEN)
    ran = _evidence_row(_entry(1, ran=True), job_id=job, written_at=_WRITTEN)
    assert "ran" not in ledger_chain.entry_fields(plain)
    assert ledger_chain.entry_fields(refused)["ran"] is False
    digests = {ledger_chain.entry_digest(r) for r in (plain, refused, ran)}
    assert len(digests) == 3
    assert "ran" in {c.name for c in EvidenceEntry.__table__.columns}


def _load() -> Any:
    spec = util.spec_from_file_location("evidence_state_whether_the_tool_ran", _REV)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_single_head() -> None:
    mod = _load()
    assert mod.revision == "20261112000000"
    assert mod.down_revision == "20261107000000"


def test_an_older_row_holds_none_and_the_downgrade_takes_it_away() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            row = conn.execute(sa.text("SELECT ran FROM evidence_entries"))
            assert tuple(row.one()) == (None,)
            mod.upgrade()
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert "ran" not in columns
