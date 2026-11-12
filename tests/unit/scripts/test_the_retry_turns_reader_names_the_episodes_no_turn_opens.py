"""The replay reader lists a stored run's retry episodes and the ones the turn rule would not open.

``scripts/replay/retry_turns.py`` reads the run's events: each analyst's batch
of findings shown, the retry calls that batch cost, and the follow-on batches
that ask what the retry left out. An episode whose findings are the describe
check's alone is one the rule opens no turn for. A run built here pins the
reading; the stored benchmark runs, where present, pin the measured totals.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import retry_turns as reader

ROOT = Path(__file__).resolve().parents[3]
RUNS = Path(".superpowers") / "sdd" / "mandate-2026-09-17" / "benchmark" / "deepseek"
DESCRIBE = "attck.claim_does_not_describe"


def _events(*rows: tuple[str, str, str, str]) -> list[dict[str, Any]]:
    """``(type, agent, code or call, path or price)`` rows, numbered in order."""
    out: list[dict[str, Any]] = []
    for seq, (kind, agent, what, extra) in enumerate(rows, start=1):
        if kind == "F":
            payload: dict[str, Any] = {
                "seq": seq,
                "agent": agent,
                "code": what,
                "path": extra,
                "state": "retried",
            }
            out.append({"seq": seq, "type": "validation_feedback", "payload": payload})
        elif kind == "R":
            payload = {"seq": seq, "agent": agent, "code": what, "path": "", "state": "resolved"}
            out.append({"seq": seq, "type": "validation_feedback", "payload": payload})
        else:
            payload = {"seq": seq, "agent": agent, "call": what, "priced_usd": float(extra)}
            out.append({"seq": seq, "type": "model_usage", "payload": payload})
    # Stored out of order: the reader orders by seq.
    return list(reversed(out))


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "built"
    run.mkdir()
    events = _events(
        # analyst_a: the describe check alone, its retry, its drops question.
        ("U", "analyst_a", "tool loop turn", "0.5"),
        ("F", "analyst_a", DESCRIBE, "analyst_a.claims[1]"),
        ("F", "analyst_a", DESCRIBE, "analyst_a.claims[2].T1105"),
        # analyst_b, interleaved: the describe check beside a finding with no path.
        ("U", "analyst_b", "tool loop turn", "0.5"),
        ("F", "analyst_b", "isr.technique_line_unread", ""),
        ("F", "analyst_b", DESCRIBE, "analyst_b.claims[0]"),
        ("U", "analyst_a", "validation retry", "0.25"),
        ("U", "analyst_a", "validation retry", "0.125"),
        ("F", "analyst_a", "isr.retry_dropped", ""),
        ("U", "analyst_b", "validation retry", "1.0"),
        ("U", "analyst_a", "kept-retry drops question", "0.0625"),
        ("R", "analyst_a", "isr.retry_dropped", ""),
        # The judge is shown a finding; no analyst retry call follows it.
        ("F", "judge", "verdict.unknown", ""),
        ("U", "judge", "verdict", "2.0"),
        # analyst_a again, a later round. A retry call after another call, with no
        # batch of its own stored, joins no episode.
        ("U", "analyst_a", "tool loop turn", "0.5"),
        ("U", "analyst_a", "validation retry", "0.75"),
        # Then another finding alone.
        ("F", "analyst_a", "isr.empty_evidence", "analyst_a.claims[4]"),
        ("U", "analyst_a", "validation retry", "0.5"),
    )
    (run / "events.json").write_text(json.dumps(events), encoding="utf-8")
    return run


def test_a_built_run_names_the_episode_the_rule_does_not_open(tmp_path: Path, capsys: Any) -> None:
    run = _run(tmp_path)
    read = reader.read_run(run)

    rows = read["episodes"]
    assert [(r["agent"], r["opens_a_turn"], r["calls"]) for r in rows] == [
        ("analyst_a", False, 3),
        ("analyst_b", True, 1),
        ("analyst_a", True, 1),
    ]
    first = rows[0]
    assert first["codes"] == {DESCRIBE: 2}
    assert first["follow_ons"] == ["isr.retry_dropped"]
    assert first["usd"] == pytest.approx(0.4375)
    assert first["call_names"] == {"validation retry": 2, "kept-retry drops question": 1}
    # A finding with no path still opens the turn the describe finding joins.
    assert rows[1]["describe_beside_another"] is True
    assert rows[2]["describe_beside_another"] is False
    summed = reader.totals(rows)
    assert summed["not_opened"] == {"episodes": 1, "calls": 3, "usd": 0.44, "unpriced": 0}
    assert summed["opened"]["episodes"] == 3

    assert reader.main([str(run)]) == 0
    out = capsys.readouterr().out
    assert "opened no turn by the rule: 1 episode(s), 3 call(s), 0.44 USD" in out
    assert f" - analyst_a at seq 2: {DESCRIBE} x2; follow-ons isr.retry_dropped" in out


def test_a_run_with_no_events_says_so(tmp_path: Path, capsys: Any) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    assert reader.read_run(empty) == {"run": "empty", "events": False, "episodes": []}
    assert reader.main([str(empty)]) == 0
    assert "empty: no events.json is stored" in capsys.readouterr().out


def test_the_reader_writes_the_readings_as_json(tmp_path: Path) -> None:
    run = _run(tmp_path)
    out = tmp_path / "out.json"

    assert reader.main([str(run), "--json", str(out)]) == 0

    assert len(json.loads(out.read_text())[0]["episodes"]) == 3


def _stored_runs() -> Path | None:
    for base in (ROOT, *(p for p in ROOT.parents if (p / ".claude" / "worktrees").is_dir())):
        if (base / RUNS / "haiku13" / "events.json").is_file():
            return base / RUNS
    return None


# Per run: (episodes opened, episodes the rule does not open, their calls).
_STORED = {
    "hk14-ref-haiku": (12, 4, 12),
    "haiku13": (11, 3, 6),
    "haiku12": (19, 3, 9),
    "haiku11": (20, 3, 6),
    "haiku10": (12, 2, 5),
    "haiku8": (20, 4, 11),
}


def test_the_stored_runs_give_the_measured_episodes() -> None:
    runs = _stored_runs()
    if runs is None:
        pytest.skip("the stored benchmark runs are not on this machine")
    every: list[dict[str, Any]] = []
    for name, (opened, alone, calls) in _STORED.items():
        rows = reader.read_run(runs / name)["episodes"]
        summed = reader.totals(rows)
        assert summed["opened"]["episodes"] == opened, name
        assert (summed["not_opened"]["episodes"], summed["not_opened"]["calls"]) == (
            alone,
            calls,
        ), name
        every.extend(rows)
    summed = reader.totals(every)
    assert summed["not_opened"] == {"episodes": 19, "calls": 49, "usd": 3.25, "unpriced": 0}
