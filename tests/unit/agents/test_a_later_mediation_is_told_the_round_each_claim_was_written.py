"""From a later mediation on, each claim's line states the round its text was last written.

The fact is read from what the merge records: a claim a revision neither wrote
again nor withdrew is unchanged since the round before the first revision that
carried it (``ClaimEvidence.carried_since_round``); a claim kept beside the
additions of a validation retry stood in force before the retry's round; any
other claim was written in its answer's revision round. A claim whose text an
earlier mediation already read says so on its line ("written in round N",
"unchanged since round N"); a claim written in the last revision round carries
no note. Every other surface renders the summary as before.

The carried-or-new question (``LINE_MARK_RULE``) asks, for a line marked
[new] on a claim with such a note, what is new on it. It is a question: the
block reader reads the mark as before, and no line is dropped or re-marked.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

from scripts.replay import remerge_revisions

from malspark.agents.judge_agent import JudgeAgent, mediation_reports_text
from malspark.pipeline.debate_facts import (
    LINE_MARK_RULE,
    UNCHANGED_CLAIM_QUESTION,
    read_line_mark,
    round_facts_text,
)
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, written_round_note


def _claim(text: str, **extra: Any) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref="[ev_0011]", confidence=0.7, **extra)


def _isr(round_: int, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims), revision_round=round_)


class TestTheNote:
    def test_a_claim_of_an_older_answer_was_written_in_its_round(self) -> None:
        assert written_round_note(_claim("a"), 0, 1) == "written in round 0"

    def test_a_carried_claim_is_unchanged_since_the_round_before_its_first_carry(self) -> None:
        carried = _claim("a", carried_since_round=2)

        assert written_round_note(carried, 3, 3) == "unchanged since round 1"

    def test_a_claim_written_in_the_last_round_carries_none(self) -> None:
        assert written_round_note(_claim("a"), 2, 2) == ""

    def test_a_claim_kept_beside_a_retry_s_additions_stood_before_its_round(self) -> None:
        kept = _claim("a")

        assert written_round_note(kept, 2, 2, retried=True) == "unchanged since round 1"
        added = _claim("b", added_by_retry_in_round=2)
        assert written_round_note(added, 2, 2, retried=True) == ""


class TestTheSummary:
    def test_each_claim_an_earlier_mediation_read_says_its_round(self) -> None:
        isr = _isr(2, _claim("Old claim.", carried_since_round=2), _claim("New claim."))

        summary = isr.to_text_summary(last_round=2)

        old, new = (line for line in summary.splitlines() if line.startswith("  Claim "))
        assert old.endswith("(unchanged since round 1) | Confidence: 0.70")
        assert "round" not in new.split(" | Evidence: ")[1]

    def test_an_answer_not_revised_in_the_last_round_is_written_in_its_own(self) -> None:
        summary = _isr(0, _claim("Claim.")).to_text_summary(last_round=1)

        assert "(written in round 0) | Confidence" in summary

    def test_a_retry_s_answer_tells_its_kept_claims_apart(self) -> None:
        isr = _isr(2, _claim("Kept."), _claim("Added.", added_by_retry_in_round=2))

        kept, added = (
            line for line in isr.to_text_summary(last_round=2).splitlines() if "Claim " in line
        )
        assert "(unchanged since round 1)" in kept
        assert "since round" not in added and "written in round" not in added

    def test_every_other_surface_renders_as_before(self) -> None:
        isr = _isr(0, _claim("Claim.", carried_since_round=1))

        assert isr.to_text_summary() == isr.to_text_summary(last_round=None)
        assert "since round" not in isr.to_text_summary()


class TestTheMediationReports:
    def test_a_report_that_is_the_summary_shows_the_notes_once(self) -> None:
        isr = _isr(0, _claim("Claim."))
        isr.note_rendered_summary(isr.to_text_summary())
        reports = {"static": isr.to_text_summary()}

        text = mediation_reports_text(reports, {"static": isr}, last_round=1)

        assert text.count("Claim 1: Claim.") == 1
        assert "(written in round 0)" in text

    def test_a_report_equal_to_the_summary_with_no_record_shows_them_once(self) -> None:
        isr = _isr(0, _claim("Claim."))
        reports = {"static": isr.to_text_summary()}

        text = mediation_reports_text(reports, {"static": isr}, last_round=1)

        assert text.count("Claim 1: Claim.") == 1
        assert "(written in round 0)" in text

    def test_a_first_mediation_shows_the_reports_as_before(self) -> None:
        isr = _isr(0, _claim("Claim."))
        reports = {"static": isr.to_text_summary()}

        assert mediation_reports_text(reports, {"static": isr}) == mediation_reports_text(
            reports, {"static": isr}, last_round=None
        )
        assert "written in round" not in mediation_reports_text(reports, {"static": isr})


def _question(**extra: Any) -> str:
    seen: list[str] = []
    judge = JudgeAgent.__new__(JudgeAgent)
    judge.logger = MagicMock()
    judge.tools = []
    judge.token_ledger = None
    judge.truncation_ledger = None
    judge._config = None
    judge.evidence_counter = None
    judge._evidence_entries = []
    judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]

    class _Model:
        async def ainvoke(self, messages: Any, **_k: Any) -> Any:
            seen.append(str(getattr(messages[1], "content", messages[1])))
            return MagicMock(content="CONTRADICTIONS: NONE\nagreement_confidence: 0.9")

    judge.llm = _Model()
    isrs = {"static": _isr(0, _claim("Claim.")), "dynamic": _isr(1, _claim("Other."))}
    with (
        patch.object(JudgeAgent, "_question_room", return_value=None),
        patch.object(JudgeAgent, "_context_budget", return_value=None),
        patch.object(JudgeAgent, "_built_cap_tokens", return_value=0),
    ):
        asyncio.run(
            judge.mediate(
                reports={n: isr.to_text_summary() for n, isr in isrs.items()},
                history=[],
                isr_reports=isrs,
                reputation_asked=True,
                **extra,
            )
        )
    return seen[0]


class TestTheMediation:
    def test_a_later_mediation_shows_the_round_of_each_claim_read_before(self) -> None:
        question = _question(last_revision_round=1)

        assert "Claim 1: Claim. | Evidence: [ev_0011] (written in round 0)" in question
        assert "Claim 1: Other. | Evidence: [ev_0011] | Confidence" in question

    def test_a_first_mediation_shows_no_round(self) -> None:
        question = _question()

        assert "written in round" not in question and "since round" not in question


class TestTheQuestion:
    def test_the_mark_rule_asks_what_is_new_on_an_unchanged_claim(self) -> None:
        assert LINE_MARK_RULE.endswith(UNCHANGED_CLAIM_QUESTION)
        said = UNCHANGED_CLAIM_QUESTION
        assert "'written in round N'" in said and "'unchanged since round N'" in said
        assert "[new]" in said and "what" in said.lower() and "?" in said

    def test_the_round_s_record_ends_on_it(self) -> None:
        record = {"lines": [{"line": "x", "named": ["static"]}], "filed": {}}

        assert round_facts_text(record).endswith(UNCHANGED_CLAIM_QUESTION)

    def test_a_new_line_on_an_unchanged_claim_is_read_as_new(self) -> None:
        line = (
            "[analysts: STATIC] [new] STATIC claim 1 (unchanged since round 0) contradicts "
            "ev_0011, which no mediation read before. [blocking: read ev_0011]"
        )

        assert read_line_mark(line) == "new"


class TestTheReplayReader:
    def test_a_logged_summary_s_round_note_is_no_part_of_the_evidence(self) -> None:
        body = (
            "[STATIC ANALYST — round 2]\nDomain: static | Mean confidence: 0.70\n"
            "  Claim 1: Old. | Evidence: [ev_0011] (carried forward: the round-2 revision "
            "neither wrote it again nor withdrew it) (unchanged since round 1) | Confidence: 0.70\n"
            "  Claim 2: Kept. | Evidence: [ev_0012] (written in round 0) | Confidence: 0.60\n"
        )

        claims, carried = remerge_revisions._claims_of(body)

        assert [c.evidence_ref for c in claims] == ["[ev_0011]", "[ev_0012]"]
        assert carried == [True, False]
