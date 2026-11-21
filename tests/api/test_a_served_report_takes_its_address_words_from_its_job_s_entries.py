"""A stored report's address rows take the publish rule's words from the job's network entries.

A report stored before an address row recorded what the publish rule read in the
flow rows to it is served with those words read from the job's stored network
entries (``ReportService.served_document``); its decisions stay the stored ones
and nothing stored changes. Where the entries cannot be read, the document is
served as stored, and the row says what is true without them.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.report_service import ReportService
from malspark.reporting.builder import ioc_table
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from malspark.reporting.renderers.stix_renderer import FLOW_NOT_PLACED

ADDRESS = "93.184.216.34"
FLOWS = {"tcp": [{"dst": ADDRESS, "dport": 443, "procid": 47, "pid": 2780}]}


def _stored() -> dict[str, Any]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        network=NetworkIOCs(ips=[NetworkIP(address=ADDRESS, source="sandbox")]),
    )
    return json.loads(report.model_dump_json())


def _entry_row() -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        entry_id="ev_0001",
        stage="analysis",
        agent="dynamic",
        server=None,
        tool="sandbox_network",
        ok=True,
        error=None,
        remediation=None,
        duration_ms=1,
        waited_ms=0,
        seq=1,
        args={},
        args_repaired=False,
        args_raw=None,
        model=None,
        output=json.dumps(FLOWS),
        structured=FLOWS,
        function_ranges=None,
        truncated=False,
        chars_dropped=0,
        repeated_of=None,
        symbol=None,
        started_at=None,
    )


def _answer(document: dict[str, Any]) -> str:
    (row,) = [r for r in ioc_table(MalwareReport.model_validate(document)) if r.value == ADDRESS]
    return str(row.published)


@pytest.mark.asyncio
async def test_the_words_come_from_the_job_s_entries_and_the_decision_stays() -> None:
    found = MagicMock()
    found.scalars.return_value.all.return_value = [_entry_row()]
    db = MagicMock()
    db.execute = AsyncMock(return_value=found)
    stored = _stored()
    report = SimpleNamespace(malware_report=stored, job_id=uuid.uuid4())

    served = await ReportService(db).served_document(report)

    assert FLOW_NOT_PLACED in _answer(stored)
    assert "did not place the process a flow to it names by id (procid 47 pid 2780)" in _answer(
        served
    )
    assert _answer(served).startswith("no:") and _answer(stored).startswith("no:")
    assert "flow_reading" not in stored["network"]["ips"][0]


@pytest.mark.asyncio
async def test_with_no_entry_at_hand_the_document_is_served_as_stored() -> None:
    db = MagicMock()
    db.execute = AsyncMock(side_effect=RuntimeError("no store"))
    stored = _stored()
    report = SimpleNamespace(malware_report=stored, job_id=uuid.uuid4())

    assert await ReportService(db).served_document(report) is stored
    assert FLOW_NOT_PLACED in _answer(stored)
