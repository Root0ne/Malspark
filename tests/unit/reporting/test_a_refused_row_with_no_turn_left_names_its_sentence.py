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

from malspark.reporting.section_agreement import UNKNOWN_SOURCE_CODE, ask_section_agreement
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
