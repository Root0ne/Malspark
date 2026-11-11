"""The replay reader rebuilds the judge's checked-technique list from a stored run's files.

``scripts/replay/checked_techniques.py`` reads the analysts' final claims, the
stored Findings table, the judge's bundle and the ledger, and lists each id an
agent checked or a tool's declared answer named that nothing carries. A run
built here pins the reading; the stored benchmark runs, where present, pin the
lists the scoping measured.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import checked_techniques as reader
from scripts.replay.output import terminal_text

ROOT = Path(__file__).resolve().parents[3]
RUNS = Path(".superpowers") / "sdd" / "mandate-2026-09-17" / "benchmark" / "deepseek"


def _write(run: Path, name: str, value: Any) -> None:
    (run / name).write_text(json.dumps(value), encoding="utf-8")


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "built"
    run.mkdir()
    _write(
        run,
        "evidence.json",
        {
            "items": [
                {
                    "id": "ev_0001",
                    "entry_id": "ev_0001",
                    "agent": "analyst_a",
                    "tool": "any_tool",
                    "args": {"ids": ["T1041", "T1082", "T1083"]},
                    "output": '{"invalid": []}',
                },
                {
                    "id": "ev_0002",
                    "entry_id": "ev_0002",
                    "agent": "analyst_a",
                    "tool": "other_tool",
                    "args": {"path": "x"},
                    "output": "beacon\x1b[31m",
                },
            ]
        },
    )
    _write(
        run,
        "report-byjob.json",
        {
            "agent_findings": [
                {
                    "agent_name": "analyst_a",
                    "domain": "analyst_a",
                    "claims": [
                        {
                            "claim": "host facts are read",
                            "evidence_ref": "[ev_0002]",
                            "confidence": 0.7,
                            "technique_id": "T1082",
                        }
                    ],
                }
            ]
        },
    )
    _write(
        run,
        "report.json",
        {
            "sections": [
                {
                    "key": "findings",
                    "rows": [["analyst_a", "listing", "T1083", "0.5", "ev_0002"]],
                }
            ]
        },
    )
    _write(run, "stix-judge.json", {"bundle": {"type": "bundle", "id": "b", "objects": []}})
    return run


def test_a_built_run_lists_the_id_nothing_carries(tmp_path: Path, capsys: Any) -> None:
    run = _run(tmp_path)

    read = reader.read_run(run)

    assert [row["id"] for row in read["checked"]] == ["T1041"]
    assert read["checked"][0]["seen"] == [
        {"agent": "analyst_a", "entry": "ev_0001", "place": "arguments"}
    ]
    assert read["checked"][0]["claim_entries"] == {"analyst_a": ["ev_0002"]}
    # The finding's id is asked as a finding, and named apart.
    assert read["carried_by_a_finding"] == ["T1083"]
    assert reader.main([str(run)]) == 0
    out = capsys.readouterr().out
    assert "built: 1 checked technique(s): T1041" in out
    assert "analyst_a: ev_0001 (arguments); its final claims cite 1 entry" in out


def test_the_reader_writes_the_readings_as_json(tmp_path: Path) -> None:
    run = _run(tmp_path)
    out = tmp_path / "out.json"

    assert reader.main([str(run), "--json", str(out)]) == 0

    assert [row["id"] for row in json.loads(out.read_text())[0]["checked"]] == ["T1041"]


def test_stored_text_reaches_the_terminal_escaped() -> None:
    assert terminal_text("a\x1b[31mb‮c\r\nd") == "a\\x1b[31mb\\u202ec d"
    assert terminal_text("x" * 10, limit=5) == "xxxx…"
    assert terminal_text(None) == ""


def _stored_runs() -> Path | None:
    for base in (ROOT, *(p for p in ROOT.parents if (p / ".claude" / "worktrees").is_dir())):
        if (base / RUNS / "haiku13" / "evidence.json").is_file():
            return base / RUNS
    return None


# The scoping's B.1 lists (validated or looked-up ids on no final claim) per run,
# less the ids a stored finding carries, which the question asks as findings.
_STORED = {
    "hk14-ref-haiku": (11, ()),
    "haiku13": (6, ("T1055",)),
    "haiku12": (6, ()),
    "haiku11": (16, ()),
    "haiku10": (4, ()),
    "haiku8": (8, ("T1055", "T1135")),
}


def test_the_stored_runs_give_the_scoping_s_lists() -> None:
    runs = _stored_runs()
    if runs is None:
        pytest.skip("the stored benchmark runs are not on this machine")
    read = {name: reader.read_run(runs / name) for name in _STORED}
    for name, (count, on_findings) in _STORED.items():
        assert len(read[name]["checked"]) == count, name
        assert tuple(read[name]["carried_by_a_finding"]) == on_findings, name
    (t1041,) = [row for row in read["haiku13"]["checked"] if row["id"] == "T1041"]
    assert t1041["seen"] == [{"agent": "triage", "entry": "ev_0038", "place": "arguments"}]
    assert "T1083" in [row["id"] for row in read["haiku11"]["checked"]]
