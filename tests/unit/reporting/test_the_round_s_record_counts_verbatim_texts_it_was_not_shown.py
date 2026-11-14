"""The round's record names the verbatim texts it was shown; the final render counts the rest.

The agreement round reads the analyst report's verbatim texts before its own rewrites, the
limitations recorded and the indicator table rebuilt, so the finished report can print one the
round never saw. The round's record in the run summary holds which texts it was shown, and
the finished report's render counts those it prints outside that set; nothing printed changes
(T-613). A render error while the texts are read is a recorded degradation reason. Every
address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from malspark.reporting.models import CapabilityCell
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.section_agreement import (
    VERBATIM_SHOWN,
    VERBATIM_UNSEEN,
    ask_section_agreement,
    record_verbatim_unseen,
    text_digest,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)


class _Reporter:
    def __init__(self) -> None:
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        return AIMessage(content=json.dumps({"sentences": []}))


def _asked() -> Any:
    report = report_of()
    done = asyncio.run(ask_section_agreement(_Reporter(), report, citable_ids=["ev_0103"]))
    report.run_summary = {**(report.run_summary or {}), "section_agreement": done.summary}
    return report, done


def test_the_record_holds_each_verbatim_text_shown() -> None:
    _report, done = _asked()

    shown = done.summary[VERBATIM_SHOWN]
    assert set(shown) == {
        "judge.business_impact",
        "attack_note.T1055",
        "attack_claim.T1622",
        "attack_note.T1622",
        "attack_claim.T1057",
        "statements.T1057.1",
    }
    assert shown["attack_claim.T1622"] == text_digest(
        "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
    )


def test_the_final_render_counts_none_where_it_prints_what_was_shown() -> None:
    report, _done = _asked()
    before = MarkdownRenderer(layout=ANALYST).render(report)

    record_verbatim_unseen(report)

    assert report.run_summary["section_agreement"][VERBATIM_UNSEEN] == 0
    assert MarkdownRenderer(layout=ANALYST).render(report) == before


def test_a_text_printed_after_the_round_is_counted() -> None:
    report, _done = _asked()
    report.capability_matrix.append(
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            evidence=["Routine 0x5d40 decodes its strings with XOR 0x5a [ev_0106]."],
        )
    )

    record_verbatim_unseen(report)

    assert report.run_summary["section_agreement"][VERBATIM_UNSEEN] == 1


def test_a_run_whose_round_recorded_no_set_is_left_as_it_is() -> None:
    report = report_of()
    record_verbatim_unseen(report)

    assert "section_agreement" not in (report.run_summary or {})


def test_a_render_error_while_reading_the_texts_is_a_degradation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import malspark.reporting.renderers.analyst as analyst

    def _fails(_report: Any) -> list[Any]:
        raise ValueError("no render")

    monkeypatch.setattr(analyst, "verbatim_texts", _fails)
    reporter = _Reporter()
    asyncio.run(ask_section_agreement(reporter, report_of(), citable_ids=["ev_0103"]))

    assert (
        "The section agreement question was shown none of the texts the analyst report prints "
        "in their writer's own words: they were not read (ValueError)."
    ) in reporter.degradations
