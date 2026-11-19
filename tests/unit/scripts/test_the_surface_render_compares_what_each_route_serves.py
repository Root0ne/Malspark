"""Two refs are compared by what each route serves: its status, every header and its body.

A repository of the test's own holds this checkout's platform; its second
commit changes, each in one place, what the application serves and nothing a
renderer prints: the response class of the Markdown route, the error the STIX
route answers for a report with no bundle, the default of the rule download's
``include``, the values the IOC route's ``include`` accepts, the status the
MITRE route answers with, and the statement the call map reads the ledger
with. Each is a difference, and the comparison ends with the differences
status whether or not surfaces both refs lack alike are accepted.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import (
    commit_edits,
    platform_repository,
    stored_run,
)

REPORTS = "apps/api/app/api/v1/reports.py"
JOBS = "apps/api/app/api/v1/jobs.py"
EDITS: tuple[tuple[str, str, str], ...] = (
    (
        REPORTS,
        '@router.get("/{report_id}/markdown", response_class=PlainTextResponse)',
        '@router.get("/{report_id}/markdown", response_class=HTMLResponse)',
    ),
    (
        REPORTS,
        'detail="Report not found or STIX bundle not available",',
        'detail="The STIX bundle is gone",',
    ),
    (
        REPORTS,
        'default="printed",\n        pattern="^(printed|all)$",',
        'default="all",\n        pattern="^(printed|all)$",',
    ),
    (
        REPORTS,
        'pattern="^(published|unpublished|all)$",',
        'pattern="^(published|unpublished)$",',
    ),
    (
        REPORTS,
        '@router.get("/{report_id}/mitre")',
        '@router.get("/{report_id}/mitre", status_code=203)',
    ),
    (
        JOBS,
        ".order_by(EvidenceEntry.seq)\n    )\n    orm_rows",
        ".order_by(EvidenceEntry.seq.desc()).limit(1)\n    )\n    orm_rows",
    ),
)
BASE = 0x2470000
GATE, CHECK = BASE + 0x5A10, BASE + 0x5A38


def _lifted(entry_id: str, seq: int, address: int, body: str) -> dict[str, Any]:
    """A ledger row of a routine read as a listing, as the evidence page serves it."""
    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ledger:{entry_id}")),
        "entry_id": entry_id,
        "seq": seq,
        "stage": "analysis",
        "agent": "reader_one",
        "server": None,
        "tool": "lift_routine",
        "ok": True,
        "error": None,
        "duration_ms": 1,
        "args": {"address": hex(address)},
        "output": f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n",
        "structured": None,
        "truncated": False,
        "facts": {"v": 1, "kind": "decompile", "reader": "listing"},
        "created_at": f"2026-01-01T00:00:{seq:02d}Z",
    }


def _run(at: Path) -> Path:
    """The tiny run, its report row holding a STIX column with no bundle, its ledger two
    routines that call each other."""
    run = stored_run(at)
    byjob = json.loads((run / "report-byjob.json").read_text(encoding="utf-8"))
    byjob["stix_bundle"] = None
    (run / "report-byjob.json").write_text(json.dumps(byjob), encoding="utf-8")
    ledger = json.loads((run / "evidence.json").read_text(encoding="utf-8"))
    ledger["items"] += [
        _lifted("ev_0005", 5, GATE, f"  if (FUN_{CHECK:x}(a) == 0) return 0;"),
        _lifted("ev_0006", 6, CHECK, "  return a;"),
    ]
    (run / "evidence.json").write_text(json.dumps(ledger), encoding="utf-8")
    return run


@pytest.fixture(scope="module")
def compared(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    at = tmp_path_factory.mktemp("served")
    repo, first = platform_repository(at)
    second = commit_edits(repo, EDITS)
    run = _run(at)
    out = at / "diff.json"
    argv = [str(run), "--repo", str(repo), "--work", str(at / "work"), "--mode", "serve"]
    argv += ["--compare", first, second, "--json", str(out), "--quiet"]
    plain = rs.main(argv)
    accepted = rs.main([*argv, "--accept-not-compared"])
    [diff] = json.loads(out.read_text(encoding="utf-8"))["runs"]
    return {"plain": plain, "accepted": accepted, "diff": diff}


def _served(compared: dict[str, Any], key: str) -> dict[str, Any]:
    found = [
        c
        for c in compared["diff"]["changes"]
        if c["surface"] == rs.HTTP_SURFACE and c["key"] == key
    ]
    assert len(found) == 1, (key, [c["key"] for c in compared["diff"]["changes"]])
    return found[0]


@pytest.mark.slow
def test_a_route_served_with_another_response_class_is_a_difference(
    compared: dict[str, Any],
) -> None:
    change = _served(compared, "GET /reports/{id}/markdown header content-type")
    assert change["old"].startswith("text/plain") and change["new"].startswith("text/html")


@pytest.mark.slow
def test_an_error_both_refs_answer_differently_is_a_difference_even_when_absence_is_accepted(
    compared: dict[str, Any],
) -> None:
    change = _served(compared, "GET /reports/{id}/stix body")
    assert "STIX bundle not available" in change["old"]
    assert "The STIX bundle is gone" in change["new"]
    assert compared["plain"] == compared["accepted"] == rs.EXIT_UNEXPECTED


@pytest.mark.slow
def test_a_changed_query_default_is_a_difference(compared: dict[str, Any]) -> None:
    _served(compared, "GET /reports/{id}/signatures/yara body")
    changed = {c["group"] for c in compared["diff"]["changes"] if c["surface"] == "rules.download"}
    assert "yara default" in changed
    assert "yara printed" not in changed and "yara all" not in changed


@pytest.mark.slow
def test_a_variant_the_request_validation_refuses_is_a_difference(
    compared: dict[str, Any],
) -> None:
    change = _served(compared, "GET /reports/{id}/iocs?include=all status")
    assert (change["old"], change["new"]) == ("200", "422")


@pytest.mark.slow
def test_a_changed_status_is_a_difference(compared: dict[str, Any]) -> None:
    change = _served(compared, "GET /reports/{id}/mitre status")
    assert (change["old"], change["new"]) == ("200", "203")


@pytest.mark.slow
def test_the_rows_a_changed_ledger_statement_selects_are_a_difference(
    compared: dict[str, Any],
) -> None:
    changed = [c for c in compared["diff"]["changes"] if c["surface"] == "call_map"]
    assert any(hex(GATE) in str(c["key"]) and c["change"] == "removed" for c in changed)
