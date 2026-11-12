"""Read a stored run's analyst retry episodes and the ones the turn rule would not open.

Over one or more stored runs, each a directory in the benchmark's layout::

    python -m scripts.replay.retry_turns <run dir> [<run dir> ...]

reads the run's events (``events.json``) and lists every analyst validation
retry episode the run opened: the batch of findings an analyst was shown
(``validation_feedback`` lines in the ``retried`` state, in the order the run
emitted them), and the model calls that batch cost, by the platform's own call
names: the retry and its tool-loop turns, the whole answer asked after a retry
not merged, and the kept-retry drops question. A batch that only asks what the
retry left out (``isr.retry_dropped``, ``isr.retry_restated_few``) is that
episode's follow-on, never an episode of its own. Each episode's findings are
then put to the platform's turn rule (``validation.describe_stands_alone``):
an episode whose findings are the describe check's alone would open no turn,
and its calls and priced USD (each call's ``priced_usd`` as the run's usage
events stored it) are what the rule would not spend. Episodes where the
describe check sits beside another finding are counted apart: they are opened
as before.

A batch shown to the judge or the report composer is followed by no analyst
retry call and makes no episode. Stored text is printed through
``scripts.replay.output.terminal_safe``, each value on its own.

Read-only over the runs: nothing is written beside them, no network is reached,
no credential is read. ``--json PATH`` also writes the readings to ``PATH``.
This reads what the run spent; it does not replay any answer.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _events(run: Path) -> list[dict[str, Any]] | None:
    path = run / "events.json"
    if not path.is_file():
        return None
    rows = json.loads(path.read_bytes())
    events = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def _seq(row: dict[str, Any]) -> int:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        try:
            return int(row.get("seq") if row.get("seq") is not None else payload.get("seq") or 0)
        except (TypeError, ValueError):
            return 0

    return sorted(events, key=_seq)


def episodes(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every analyst retry episode of a run's events, in the order each began. One pass.

    Per agent: consecutive ``retried`` lines are one batch; a batch of
    follow-on codes alone joins the agent's open episode; any other batch
    opens a new one. The agent's retry calls join its open episode, and any
    other call of the agent closes it. An episode no retry call followed is
    left out.
    """
    from malspark.core.token_ledger import (
        RETRY_DROPS_QUESTION_CALL,
        VALIDATION_RETRY_CALL,
        WHOLE_ANSWER_RETRY_CALL,
    )
    from malspark.pipeline.validation import RETRY_DROPPED_CODE, RETRY_RESTATED_FEW_CODE

    retry_calls = {VALIDATION_RETRY_CALL, WHOLE_ANSWER_RETRY_CALL, RETRY_DROPS_QUESTION_CALL}
    follow_ons = {RETRY_DROPPED_CODE, RETRY_RESTATED_FEW_CODE}
    found: list[dict[str, Any]] = []
    open_episode: dict[str, dict[str, Any] | None] = {}
    batch: dict[str, dict[str, Any]] = {}
    in_batch: dict[str, bool] = {}
    for event in events:
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        agent = str(payload.get("agent") or "")
        if event.get("type") == "validation_feedback":
            if payload.get("state") != "retried":
                continue
            if not in_batch.get(agent):
                batch[agent] = {"findings": [], "episode": None}
            in_batch[agent] = True
            held = batch[agent]
            held["findings"].append(
                (str(payload.get("code") or ""), str(payload.get("path") or ""))
            )
            codes = {code for code, _path in held["findings"]}
            current = open_episode.get(agent)
            if codes <= follow_ons and current is not None:
                if held["episode"] is not current:
                    held["episode"] = current
                    current["follow_on_batches"].append(held["findings"])
            elif held["episode"] is None or held["episode"]["calls"]:
                episode = {
                    "agent": agent,
                    "seq": payload.get("seq")
                    if payload.get("seq") is not None
                    else event.get("seq"),
                    "findings": held["findings"],
                    "follow_on_batches": [],
                    "calls": [],
                }
                held["episode"] = episode
                open_episode[agent] = episode
                found.append(episode)
        elif event.get("type") == "model_usage":
            in_batch[agent] = False
            call = str(payload.get("call") or "")
            current = open_episode.get(agent)
            if call in retry_calls:
                if current is not None:
                    current["calls"].append(payload)
            else:
                open_episode[agent] = None
    return [episode for episode in found if episode["calls"]]


def _usd(calls: list[dict[str, Any]]) -> tuple[float, int]:
    """The priced USD of ``calls``, and how many of them carry no price."""
    total, unpriced = 0.0, 0
    for call in calls:
        try:
            total += float(call["priced_usd"])
        except (KeyError, TypeError, ValueError):
            unpriced += 1
    return total, unpriced


def read_run(run: Path) -> dict[str, Any]:
    """One stored run's retry episodes, each with what the turn rule decides for it."""
    from malspark.pipeline.validation import (
        CLAIM_DOES_NOT_DESCRIBE_CODE,
        Violation,
        describe_stands_alone,
    )

    events = _events(run)
    if events is None:
        return {"run": run.name, "events": False, "episodes": []}
    rows: list[dict[str, Any]] = []
    for episode in episodes(events):
        findings = episode["findings"]
        shown = [Violation(code=code, message="", path=path) for code, path in findings]
        usd, unpriced = _usd(episode["calls"])
        codes = Counter(code for code, _path in findings)
        alone = describe_stands_alone(shown)
        rows.append(
            {
                "agent": episode["agent"],
                "seq": episode["seq"],
                "codes": dict(sorted(codes.items())),
                "follow_ons": sorted(
                    {code for held in episode["follow_on_batches"] for code, _path in held}
                ),
                "calls": len(episode["calls"]),
                "call_names": dict(Counter(str(c.get("call") or "") for c in episode["calls"])),
                "usd": round(usd, 6),
                "unpriced": unpriced,
                "opens_a_turn": not alone,
                "describe_beside_another": not alone and CLAIM_DOES_NOT_DESCRIBE_CODE in codes,
            }
        )
    return {"run": run.name, "events": True, "episodes": rows}


def totals(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Episodes, calls and USD: all opened, the ones the rule opens no turn for, and the mixed."""

    def _sum(chosen: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "episodes": len(chosen),
            "calls": sum(row["calls"] for row in chosen),
            "usd": round(sum(row["usd"] for row in chosen), 2),
            "unpriced": sum(row["unpriced"] for row in chosen),
        }

    return {
        "opened": _sum(rows),
        "not_opened": _sum([row for row in rows if not row["opens_a_turn"]]),
        "describe_beside_another": _sum([row for row in rows if row["describe_beside_another"]]),
    }


def _line(name: str, counted: dict[str, Any]) -> str:
    unpriced = f" ({counted['unpriced']} unpriced)" if counted["unpriced"] else ""
    return (
        f"{name}: {counted['episodes']} episode(s), {counted['calls']} call(s), "
        f"{counted['usd']:.2f} USD{unpriced}"
    )


def _print(read: dict[str, Any]) -> None:
    from scripts.replay.output import terminal_safe as safe

    if not read["events"]:
        print(f"== {safe(read['run'])}: no events.json is stored")
        return
    summed = totals(read["episodes"])
    print(f"== {safe(read['run'])}")
    print(f"   {_line('opened', summed['opened'])}")
    print(f"   {_line('opened no turn by the rule', summed['not_opened'])}")
    print(
        f"   {_line('describe beside another finding (opened)', summed['describe_beside_another'])}"
    )
    for row in read["episodes"]:
        if row["opens_a_turn"]:
            continue
        codes = ", ".join(f"{safe(code)} x{count}" for code, count in row["codes"].items())
        follow = (
            f"; follow-ons {', '.join(safe(c) for c in row['follow_ons'])}"
            if row["follow_ons"]
            else ""
        )
        print(
            f" - {safe(row['agent'])} at seq {safe(row['seq'])}: {codes}{follow}; "
            f"{row['calls']} call(s), {row['usd']:.2f} USD"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.replay.retry_turns",
        description=(__doc__ or "").split("\n", 1)[0],
    )
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, default=None, help="write the readings here too")
    args = parser.parse_args(argv)
    found = []
    for run in args.runs:
        read = read_run(run)
        _print(read)
        found.append(read)
    if len(found) > 1:
        every = [row for read in found for row in read["episodes"]]
        summed = totals(every)
        print(f"== {len(found)} runs")
        for key, name in (
            ("opened", "opened"),
            ("not_opened", "opened no turn by the rule"),
            ("describe_beside_another", "describe beside another finding (opened)"),
        ):
            print(f"   {_line(name, summed[key])}")
    if args.json is not None:
        from scripts.replay.output import write_json

        write_json(args.json, found, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
