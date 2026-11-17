"""Every sandbox entry of the pack answers, for a report of each reader the repository has.

Listing a view among the pack's entries says nothing about its answer: a
read that raised is recorded as an entry with an error, and the pack still
lists it. For a report read by each registered reader, every entry the pack
records of the sandbox's views and channels answered: it ran, and its answer
is no error. Synthetic reports only; nothing is run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from malspark.providers.sandbox.readers import report_reader_ids, required_reader
from malspark.schemas.sandbox_document import sandbox_document

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"
CAPE_FAMILY = ("cape2", "cuckoo", "mock")


def _document(reader: str) -> tuple[dict[str, Any], tuple[str, ...]]:
    if reader in CAPE_FAMILY:
        raw = json.loads((FIXTURES / "cape2_synthetic.json").read_text(encoding="utf-8"))
        raw["channels"] = {"linux.systemd": [{"unit": "x.service"}]}
        report = required_reader(reader).read(raw, provider="lab")
        return sandbox_document(report), ("lab", reader)
    if reader == "triage":
        from tests.unit.providers.test_the_dropped_files_view_keeps_each_row_s_path_origin_kind_and_writer import (  # noqa: E501
            TASKS,
            WRITTEN,
            _report,
        )

        return sandbox_document(_report(WRITTEN)), TASKS
    if reader == "generic":
        from malspark.core.config import RestMappingConfig

        mapping = RestMappingConfig(
            processes="$.procs[*]",
            dropped_files="$.files[*]",
            field_names={"processes.pid": "id", "processes.name": "image"},
        )
        payload = {"procs": [{"id": 4, "image": "a.exe"}], "files": [{"name": "x.bin"}]}
        report = required_reader(reader).read(payload, provider="lab", mapping=mapping)
        return sandbox_document(report), ("lab", reader)
    report = required_reader(reader).read({"blob": {"k": 1}}, provider="lab")
    return sandbox_document(report), ("lab", reader)


def test_every_registered_reader_is_covered() -> None:
    assert set(report_reader_ids()) == {*CAPE_FAMILY, "triage", "generic", "unread"}


@pytest.mark.parametrize("reader", sorted(report_reader_ids()))
def test_every_sandbox_entry_of_the_pack_answered(reader: str, tmp_path: Path) -> None:
    from tests.unit.pipeline.test_triage_pack import _pack, _write
    from tests.unit.tools.test_binary import _pe

    document, normalised_by = _document(reader)
    path = _write(tmp_path, "s.exe", _pe())
    result = _pack(path, "pe", sandbox_report=document, sandbox_normalised_by=normalised_by)
    sandbox = [e for e in result.entries if e.tool.startswith("sandbox_")]

    assert sandbox, "the pack read none of the sandbox's views"
    failed = {
        e.tool: e.error or (e.structured or {}).get("error")
        for e in sandbox
        if not e.ok or (isinstance(e.structured, dict) and e.structured.get("error"))
    }
    assert failed == {}
