"""A run in the default ``validation.feedback`` reads as it did before the mode existed (T-672).

The stub pipeline of the record-only test (an analyst whose one finding is
corrected in its validation turn, a judge whose ungrounded indicator is
corrected in its retry) builds its run summary in ``feed_back``; and
``validation_metrics`` builds a validation block of every kind of row. Each is
compared, byte for byte, with the fixture captured from the tree before the
mode was added, with only what changes from run to run masked: the clock, the
elapsed time and the id a mock prints. A default run that gained a key, lost
one or reworded a row fails here.

Every sentence, value and id here is made up for the test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from malspark.pipeline.validation import Violation, validation_metrics
from tests.unit.pipeline.test_a_record_only_run_records_its_findings_and_its_mode import _run

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
# The values a run gives differently every time it runs.
VOLATILE = frozenset({"elapsed_seconds", "timestamp"})
MOCK_ID = re.compile(r"id='\d+'")


def _masked(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "<masked>" if key in VOLATILE or "duration" in key else _masked(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_masked(item) for item in value]
    if isinstance(value, str):
        return MOCK_ID.sub("id='<masked>'", value)
    return value


def _text(value: Any) -> str:
    """``value`` as its fixture stores it: JSON as the summary is stored, masked."""
    stored = json.loads(json.dumps(value, default=str))
    return json.dumps(_masked(stored), sort_keys=True, indent=1) + "\n"


def test_the_stub_run_summary_is_the_one_before_the_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    summary, analyst_calls, judge_calls = _run("feed_back", monkeypatch)

    assert (analyst_calls, judge_calls) == (1, 2)
    expected = (FIXTURES / "default_run_summary_before_feedback_mode.json").read_text("utf-8")
    assert _text(summary) == expected


def test_the_validation_block_is_the_one_before_the_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    from malspark.core.settings_overrides import build_settings

    built = build_settings({})
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)

    metrics = validation_metrics(
        3,
        [
            ("static", Violation("attck.unknown_id", "no such id", "static.claims[0]")),
            (
                "static",
                Violation(
                    "attck.claim_does_not_describe",
                    "shares no term",
                    "static.claims[1]",
                    asked=False,
                    subject="T1003",
                ),
            ),
            ("judge", Violation("stix.ungrounded_indicator", "never seen", advisory=True)),
            ("judge", Violation("stix.indicator_unattributed_flow", "kept", answered=True)),
            ("composer:x", Violation("report.citation_wrong_entry", "not in ev_0105")),
        ],
        fed_back={"attck.unknown_id": 1, "isr.empty_evidence": 2},
        not_run=["attck.unknown_id"],
        unparsed_answers=[{"agent": "static", "answer": "prose"}],
    )

    expected = (FIXTURES / "default_validation_block_before_feedback_mode.json").read_text("utf-8")
    assert _text(metrics) == expected
