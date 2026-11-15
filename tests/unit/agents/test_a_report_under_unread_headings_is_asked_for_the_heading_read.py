"""A last message whose claims open under headings the reader does not read is told the one read.

A revision answer wrote every claim with its EVIDENCE, CONFIDENCE and TECHNIQUE
lines under headings the claim grammar does not read (``**C1 [UNCHANGED]
Identity.**``, ``**R1. ...**``). The one nudge the loop is sent said only
"Return your final ISR now", the answer that followed had the same headings,
and the revision was not made: its corrections and concessions were lost.

The nudge stays one turn. When the last message writes claim field lines, its
words state the heading the platform reads (``CLAIM <n>: <sentence>``), from
the same constants the heading rule is checked against; when it writes none,
the nudge is the one sent before. The log line that says a nudge is sent says
which one.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from malspark.agents.base_agent import (
    FINAL_ANSWER_HEADING_NUDGE,
    FINAL_ANSWER_NUDGE,
    BaseAnalyst,
    answer_is_isr,
    final_answer_nudge,
    read_claim_blocks,
)
from malspark.agents.claim_headings import (
    CLAIM_HEAD_RE,
    CLAIM_HEADING_EXAMPLE,
    CLAIM_HEADING_FORM,
    heading_number,
    heading_sentence,
    writes_claim_fields,
)

# Claims written whole under open labels the grammar does not read.
_UNREAD_HEADINGS = (
    "**C1 [UNCHANGED] Identity.** The sample is an unsigned 64-bit DLL.\n"
    "- EVIDENCE: ev_0003, ev_0004\n"
    "- CONFIDENCE: 0.95\n"
    "- TECHNIQUE: none\n\n"
    "**C2 [REVISED] Imports.** The import table holds five names.\n"
    "- EVIDENCE: ev_0004\n"
    "- CONFIDENCE: 0.90\n"
    "- TECHNIQUE: none\n"
)

_INTENTION = "Let me search for more specific strings related to malware indicators:"

_REPORT = (
    "CLAIM 1: The sample resolves its imports at runtime\n"
    "EVIDENCE: ev_0003 LoadLibraryA / GetProcAddress pair\n"
    "CONFIDENCE: 0.7\n"
    "TECHNIQUE: T1027\n"
)

# Two claims read and a third written whole under a heading ended by a dot
# with no note; then the same three claims under headings that are read.
_READ_IN_PART = (
    "CLAIM 1 (kept). Routine 0x1400 decodes the string table.\n"
    "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\nTECHNIQUE: T1140\n\n"
    "CLAIM 2 (revised). Routine 0x1800 downloads a file.\n"
    "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.85\nTECHNIQUE: T1105\n\n"
    "CLAIM 3. Routine 0x2000 opens a mutex.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n"
)
_READ_WHOLE = _READ_IN_PART.replace("CLAIM 3. ", "CLAIM 3: ")
# The same, with a DISPUTES section after the claims.
_DISPUTE = "\nDISPUTES:\n- Static claim 7 is wrong: [ev_0019] shows no stack string.\n"
_READ_IN_PART_DISPUTING = _READ_IN_PART + _DISPUTE
_READ_WHOLE_DISPUTING = _READ_WHOLE + _DISPUTE
# Three claims numbered as the report's, none of them its claims, and no DISPUTES.
_UNRELATED = (
    "CLAIM 1: The sample is a DLL.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.5\n"
    "CLAIM 2: The sample is packed.\nEVIDENCE: [ev_0004]\nCONFIDENCE: 0.5\n"
    "CLAIM 3: The sample beacons.\nEVIDENCE: [ev_0005]\nCONFIDENCE: 0.5\n"
)


class _FakeLLM:
    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.seen.append(list(messages))
        return AIMessage(content=self._answers.pop(0) if self._answers else "")


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.heading_nudge")
        self.llm = llm
        self.token_ledger = None
        self._answer_unstructured = False

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _conversation(last: str) -> list[Any]:
    return [
        SystemMessage(content="You are a static analyst."),
        HumanMessage(content="Revise your answer."),
        AIMessage(content=last),
    ]


class TestTheHeadingTheNudgeStatesIsTheOneRead:
    def test_the_example_is_read_as_claim_one_with_its_sentence(self) -> None:
        heading = CLAIM_HEAD_RE.match(CLAIM_HEADING_EXAMPLE)

        assert heading is not None
        assert heading_number(heading) == "1"
        assert heading_sentence(CLAIM_HEADING_EXAMPLE, heading).strip()

    def test_the_example_writes_a_placeholder_and_no_claim(self) -> None:
        heading = CLAIM_HEAD_RE.match(CLAIM_HEADING_EXAMPLE)

        assert heading is not None
        assert re.fullmatch(r"<[^<>]+>", heading_sentence(CLAIM_HEADING_EXAMPLE, heading).strip())

    @pytest.mark.parametrize("number", ["1", "7", "42"])
    def test_the_form_with_a_number_is_read(self, number: str) -> None:
        line = CLAIM_HEADING_FORM.replace("<n>", number)
        heading = CLAIM_HEAD_RE.match(line)

        assert heading is not None
        assert heading_number(heading) == number
        assert heading_sentence(line, heading) == "<sentence>"

    def test_the_nudge_quotes_both(self) -> None:
        assert CLAIM_HEADING_FORM in FINAL_ANSWER_HEADING_NUDGE
        assert CLAIM_HEADING_EXAMPLE in FINAL_ANSWER_HEADING_NUDGE
        assert "headings the platform does not read" in FINAL_ANSWER_HEADING_NUDGE
        # The turn invokes the model with no tool bound, as the plain nudge says.
        assert "No tool can be called in this turn." in FINAL_ANSWER_HEADING_NUDGE

    def test_an_answer_written_in_the_stated_form_is_a_report(self) -> None:
        claims = read_claim_blocks(
            CLAIM_HEADING_EXAMPLE + "\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\n"
        ).claims

        assert answer_is_isr(CLAIM_HEADING_EXAMPLE)
        assert [c.number for c in claims] == ["1"]


class TestWhichNudgeIsChosen:
    @pytest.mark.parametrize(
        "text",
        [
            _UNREAD_HEADINGS,
            "**R1. The sample is a DLL.**\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9",
            "U1 capa PEB access.\n**CONFIDENCE**: 0.8",
        ],
        ids=["bulleted-fields", "plain-fields", "emphasised-label"],
    )
    def test_field_lines_under_unread_headings_get_the_heading_nudge(self, text: str) -> None:
        assert not answer_is_isr(text)
        assert writes_claim_fields(text)
        assert final_answer_nudge(text) == FINAL_ANSWER_HEADING_NUDGE

    @pytest.mark.parametrize(
        "text",
        [
            _INTENTION,
            "",
            "Evidence suggests the loader decodes its strings first.",
            "The confidence of the triage reading is low; the technique is not shown.",
        ],
        ids=["intention", "empty", "prose-opening-with-a-label-word", "prose-naming-labels"],
    )
    def test_a_message_with_no_field_line_gets_the_nudge_as_before(self, text: str) -> None:
        assert not writes_claim_fields(text)
        assert final_answer_nudge(text) == FINAL_ANSWER_NUDGE


class TestTheOneTurn:
    def _settle(self, last: str, answers: list[str]) -> tuple[_FakeLLM, _Analyst, str]:
        llm = _FakeLLM(answers)
        analyst = _Analyst(llm)
        kept = analyst._settle_final_answer(last, _conversation(last), 60, 1.0, 40)
        return llm, analyst, kept

    def test_unread_headings_are_asked_once_with_the_heading_stated(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="test.heading_nudge"):
            llm, analyst, kept = self._settle(_UNREAD_HEADINGS, [_REPORT])

        assert kept == _REPORT
        assert analyst._answer_unstructured is False
        assert len(llm.seen) == 1
        sent = llm.seen[0]
        assert isinstance(sent[-1], HumanMessage)
        assert sent[-1].content == FINAL_ANSWER_HEADING_NUDGE
        assert [m.content for m in sent[:3]] == [m.content for m in _conversation(_UNREAD_HEADINGS)]
        assert "stating the claim heading the platform reads" in caplog.text

    def test_an_intention_is_asked_once_with_the_nudge_as_before(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="test.heading_nudge"):
            llm, _analyst, kept = self._settle(_INTENTION, [_REPORT])

        assert kept == _REPORT
        assert len(llm.seen) == 1
        assert llm.seen[0][-1].content == FINAL_ANSWER_NUDGE
        assert "asking once for one." in caplog.text
        assert "claim heading" not in caplog.text

    def test_a_partly_read_answer_is_asked_once_with_the_heading_stated(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="test.heading_nudge"):
            llm, analyst, kept = self._settle(_READ_IN_PART, [_READ_WHOLE])

        assert answer_is_isr(_READ_IN_PART)
        assert final_answer_nudge(_READ_IN_PART) == FINAL_ANSWER_HEADING_NUDGE
        assert len(llm.seen) == 1
        # The turn's words open the question; the run state may follow them.
        assert llm.seen[0][-1].content.startswith(FINAL_ANSWER_HEADING_NUDGE)
        assert kept == _READ_WHOLE
        assert analyst._answer_unstructured is False
        assert "stating the claim heading the platform reads" in caplog.text

    @pytest.mark.parametrize(
        "answer",
        [
            _REPORT,
            _READ_IN_PART,
            _READ_WHOLE.replace("CLAIM 2 (revised). ", "CLAIM 2. "),
            "",
            _INTENTION,
        ],
        ids=["fewer-claims", "read-in-part-again", "another-claim-unread", "empty", "intention"],
    )
    def test_a_partly_read_answer_stands_when_the_reply_reads_no_better(self, answer: str) -> None:
        llm, analyst, kept = self._settle(_READ_IN_PART, [answer])

        assert len(llm.seen) == 1
        assert kept == _READ_IN_PART
        assert analyst._answer_unstructured is False

    def test_a_reply_that_loses_the_disputes_section_leaves_the_report_standing(self) -> None:
        llm, analyst, kept = self._settle(_READ_IN_PART_DISPUTING, [_UNRELATED])

        assert len(llm.seen) == 1
        assert kept == _READ_IN_PART_DISPUTING
        assert analyst._answer_unstructured is False

    @pytest.mark.parametrize(
        ("written", "instead"),
        [("CLAIM 2 (revised). ", "CLAIM 4 (revised). "), ("CLAIM 3: ", "CLAIM 4: ")],
        ids=["a-number-read", "a-number-begun"],
    )
    def test_a_reply_that_drops_a_claim_number_leaves_the_report_standing(
        self, written: str, instead: str
    ) -> None:
        dropped = _READ_WHOLE.replace(written, instead)
        llm, _analyst, kept = self._settle(_READ_IN_PART, [dropped])

        assert len(llm.seen) == 1
        assert kept == _READ_IN_PART

    def test_a_number_written_only_under_the_reply_s_disputes_is_not_among_its_claims(
        self,
    ) -> None:
        reply = _READ_WHOLE.replace("CLAIM 2 (revised). ", "CLAIM 4 (revised). ") + (
            "\nDISPUTES:\n- CLAIM 2: the static analyst's reading of the download.\n"
        )
        llm, _analyst, kept = self._settle(_READ_IN_PART, [reply])

        assert len(llm.seen) == 1
        assert kept == _READ_IN_PART

    def test_a_reply_beginning_fewer_claims_leaves_the_report_standing(self) -> None:
        # Two claims with no number read, a third begun; the reply writes the
        # third alone.
        report = (
            "CLAIM: Routine 0x1400 decodes the string table.\n"
            "EVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n\n"
            "CLAIM: Routine 0x1800 downloads a file.\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.85\n\n"
            "CLAIM 3. Routine 0x2000 opens a mutex.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
        )
        reply = "CLAIM 3: Routine 0x2000 opens a mutex.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\n"
        llm, _analyst, kept = self._settle(report, [reply])

        assert len(llm.seen) == 1
        assert kept == report

    def test_a_reply_that_keeps_every_number_and_the_disputes_replaces_the_report(self) -> None:
        llm, _analyst, kept = self._settle(_READ_IN_PART_DISPUTING, [_READ_WHOLE_DISPUTING])

        assert len(llm.seen) == 1
        assert kept == _READ_WHOLE_DISPUTING

    def test_a_line_begun_under_the_disputes_section_is_not_asked(self) -> None:
        text = _READ_WHOLE + (
            "\nDISPUTES:\nCLAIM 3. The static reading is wrong.\nEVIDENCE: [ev_0019]\n"
        )
        llm, analyst, kept = self._settle(text, [_REPORT])

        assert llm.seen == []
        assert kept == text
        assert analyst._answer_unstructured is False

    def test_an_answer_read_whole_is_not_asked(self) -> None:
        llm, analyst, kept = self._settle(_READ_WHOLE, [_REPORT])

        assert llm.seen == []
        assert kept == _READ_WHOLE
        assert analyst._answer_unstructured is False

    def test_a_second_unread_answer_is_not_asked_again(self) -> None:
        llm, analyst, kept = self._settle(_UNREAD_HEADINGS, [_UNREAD_HEADINGS])

        assert len(llm.seen) == 1
        assert kept == _UNREAD_HEADINGS
        assert analyst._answer_unstructured is True
