"""A replay rebuilds a record-only run's validation block naming its mode (T-672).

The replay installs the stored snapshot's ``validation.*`` values, so the
platform's own ``validation_metrics`` reads ``validation.feedback`` as the run
had it. A run in ``record_only`` is named so in the rebuilt block; one in the
default, or one whose snapshot predates the setting, carries no such key.
Whether a finding was asked is read from the stored events, as before.
"""

from __future__ import annotations

from pathlib import Path

from scripts.replay import rules
from scripts.replay.guard import replay_environment
from scripts.replay.stored import StoredRun

from malspark.pipeline.validation import Violation


def _run(snapshot: dict[str, object]) -> rules._Run:
    stored = StoredRun(name="r", root=Path("."), run_summary={"settings_snapshot": snapshot})
    run = rules._Run(stored=stored, show_text=False)
    run.in_force_found = {"static": [Violation("attck.unknown_id", "no such id", asked=False)]}
    return run


def test_a_record_only_snapshot_is_named_in_the_rebuilt_block() -> None:
    snapshot = {"validation.feedback": "record_only"}
    with replay_environment(snapshot):
        block = rules._replayed_validation(_run(snapshot))
    assert block["feedback"] == "record_only"
    (row,) = block["unresolved"]
    assert row["asked"] == "false"


def test_a_default_or_older_snapshot_carries_no_key() -> None:
    for snapshot in ({}, {"validation.feedback": "feed_back"}):
        with replay_environment(snapshot):
            block = rules._replayed_validation(_run(snapshot))
        assert "feedback" not in block, snapshot
