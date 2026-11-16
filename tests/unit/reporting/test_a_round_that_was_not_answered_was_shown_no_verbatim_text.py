"""A round that failed or was not asked was shown no verbatim text, and a count's error is said.

The round's record holds the verbatim texts it was shown, and the finished report's render
counts those it prints outside that set. Where the call failed or the question was not asked,
the model read none of them: the set is empty, so every printed verbatim text counts as
unseen. An error while counting is a recorded degradation reason (T-613). Every address,
entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from malspark.reporting.section_agreement import (
    VERBATIM_SHOWN,
    VERBATIM_UNSEEN,
    ask_section_agreement,
    record_verbatim_unseen,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

# The verbatim texts report_of's analyst render prints.
_PRINTED = 6


class _Broken:
    def __init__(self) -> None:
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        raise RuntimeError("down")


def _counted(summary: dict[str, Any]) -> Any:
    report = report_of()
    report.run_summary = {**(report.run_summary or {}), "section_agreement": summary}
    record_verbatim_unseen(report)
    return report


def test_a_failed_call_was_shown_none_and_counts_every_printed_text_unseen() -> None:
    done = asyncio.run(ask_section_agreement(_Broken(), report_of(), citable_ids=["ev_0103"]))

    assert done.summary[VERBATIM_SHOWN] == {}
    report = _counted(done.summary)
    assert report.run_summary["section_agreement"][VERBATIM_UNSEEN] == _PRINTED


def test_a_question_not_asked_was_shown_none() -> None:
    for reporter in (None, _Broken()):
        report = report_of()
        # No source of any kind: the question is not asked.
        assert report.technical_analysis is not None
        report.technical_analysis.string_resolution = None
        done = asyncio.run(ask_section_agreement(reporter, report, citable_ids=["ev_0103"]))

        assert done.summary == {VERBATIM_SHOWN: {}}


def test_an_error_while_counting_is_a_recorded_degradation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import malspark.reporting.renderers.analyst as analyst

    def _fails(_report: Any) -> list[Any]:
        raise ValueError("no render")

    monkeypatch.setattr(analyst, "verbatim_texts", _fails)
    report = _counted({VERBATIM_SHOWN: {}})

    assert VERBATIM_UNSEEN not in report.run_summary["section_agreement"]
    assert report.degradation_reasons == [
        "The verbatim texts the analyst report prints were not counted against those the "
        "section agreement question was shown (ValueError)."
    ]
