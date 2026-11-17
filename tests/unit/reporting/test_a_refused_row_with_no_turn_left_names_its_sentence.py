"""A row the agreement round refused on its last turn leaves the sentence it was about.

The round asks once more about each refused row; a refusal of the retry's answer has no turn
left. Its record kept the code and the refusal's words, which name the row by its number in
an answer the run does not store, so the sentence the model raised was lost without a trace.
Now such a record names the passage and the sentence, and says that no turn was left (T-717).
Every name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import Violation
from malspark.reporting.section_agreement import (
    UNKNOWN_SOURCE_CODE,
    _no_turn_left,
    ask_section_agreement,
)
from tests.unit.reporting.test_a_section_sentence_is_asked_against_the_judge_s_decision import (
    OTHER,
    report_of,
)

SUMMARY = "The sample formats a host name for a request."


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [json.dumps(a) for a in answers]
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _refused() -> dict[str, Any]:
    return {
        "sentences": [
            {
                "passage": "executive_summary",
                "sentence": SUMMARY,
                "sources": ["nowhere.1"],
                "decision": "keep",
                "rewrite": "",
                "reason": "",
                "quote": "",
            }
        ]
    }


def test_the_last_turn_s_refusal_names_its_sentence_and_says_no_turn_was_left() -> None:
    report = report_of(OTHER)
    report.executive_summary = SUMMARY
    done = asyncio.run(ask_section_agreement(_Reporter(_refused(), _refused()), report))

    rows = [r for r in done.tally.unresolved if r["code"] == UNKNOWN_SOURCE_CODE]
    assert len(rows) == 1
    assert "No turn was left to answer this refusal" in rows[0]["message"]
    assert f"the row's sentence of executive_summary: {SUMMARY!r}" in rows[0]["message"]


def test_a_refusal_the_retry_answered_leaves_no_such_record() -> None:
    report = report_of(OTHER)
    report.executive_summary = SUMMARY
    done = asyncio.run(ask_section_agreement(_Reporter(_refused(), {"sentences": []}), report))

    assert not any("No turn was left" in r["message"] for r in done.tally.unresolved)


def test_a_section_5_passage_and_the_judge_s_decision_alone_are_not_asked() -> None:
    # The judge's decision starts no question of its own: the round is asked where it was
    # before the decision was shown (T-717).
    reporter = _Reporter({"sentences": []})
    asked: list[Any] = []
    real = reporter.ask

    async def _ask(turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        asked.append(turns)
        return await real(turns, call=call, what=what)

    reporter.ask = _ask  # type: ignore[method-assign]
    asyncio.run(ask_section_agreement(reporter, report_of(OTHER)))
    assert asked == []


def test_a_record_already_saying_so_or_naming_no_row_is_left_as_it_was() -> None:
    row = _refused()["sentences"][0]
    said = Violation(code=UNKNOWN_SOURCE_CODE, message="Refused.", path="sentences.0.sources")
    once = _no_turn_left([said], {"sentences": [row]})
    assert once[0].message.count("No turn was left") == 1
    assert _no_turn_left(once, {"sentences": [row]}) == once
    # A path past the answer's rows, or no row path at all, names no sentence.
    past = Violation(code=UNKNOWN_SOURCE_CODE, message="Refused.", path="sentences.3.sources")
    held = Violation(code=UNKNOWN_SOURCE_CODE, message="Refused.", path="held.summary")
    assert _no_turn_left([past, held], {"sentences": [row]}) == [past, held]
