"""The report stage's rounds in both ``validation.feedback`` modes (T-672).

The composer, the narrative, the question round and the section agreement each
send one correction turn for a finding in ``feed_back``. In ``record_only`` no
turn is sent, every finding is recorded as not asked, and the text stands as
written; what code does with it after the round is unchanged (a refused word
prints as not determinable, a held sentence no answer passes for is left out).
An answer outside its schema is asked again in both modes.

Every value, entry and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.pipeline.validation import CITATION_WRONG_ENTRY_CODE
from malspark.reporting.question_round import (
    NEGATIVE_WITHOUT_COVERAGE_CODE,
    SCHEMA_CODE,
    answer_questions,
)
from malspark.reporting.section_agreement import DROPPED_CODE
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    _ask,
    _row,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _report as _agreement_report,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _Reporter as _AgreementReporter,
)
from tests.unit.reporting.test_a_kept_wrong_citation_is_marked_with_its_holder import (
    KEYWORD,
    _invoke,
    _narrative,
    _summary,
)
from tests.unit.reporting.test_a_question_asked_of_the_run_is_answered import (
    LEDGER,
    QUESTIONS,
    _reply,
)
from tests.unit.reporting.test_a_question_asked_of_the_run_is_answered import (
    _report as _question_report,
)
from tests.unit.reporting.test_a_question_asked_of_the_run_is_answered import (
    _Reporter as _QuestionReporter,
)

WRONG = f"It stops on `{KEYWORD}` [ev_0105]."
FIXED = f"It stops on `{KEYWORD}` [ev_0107]."


def _settings(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


@pytest.fixture(params=["feed_back", "record_only"])
def mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    built = _settings(request.param)
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)
    return str(request.param)


class TestTheComposer:
    def test_a_wrong_citation_is_asked_only_in_feed_back(self, mode: str) -> None:
        first = json.dumps({"body": WRONG, "evidence_refs": []})
        llm, report = _invoke(first, json.dumps({"body": FIXED, "evidence_refs": []}))

        if mode == "feed_back":
            assert len(llm.sent) == 2
            assert report.flagged_statements == []
            return
        assert len(llm.sent) == 1
        (row,) = report.flagged_statements
        # The sentence as written, recorded and not asked.
        assert (row.sentence, row.code, row.asked) == (WRONG, CITATION_WRONG_ENTRY_CODE, False)

    def test_an_answer_outside_the_schema_is_asked_again_in_both_modes(self, mode: str) -> None:
        llm, report = _invoke("not json at all", json.dumps({"body": FIXED, "evidence_refs": []}))

        assert len(llm.sent) == 2
        assert report.flagged_statements == []


def _retry_rows(mode: str) -> dict[str, list[dict[str, str]]]:
    """The composer's and the narrative's rows for a citation an off-schema answer wrote.

    The first answer breaks its schema and cites the wrong entry; the retry,
    asked about the schema alone in ``record_only``, cites it again. The
    citation was in the first answer, so it did not first appear in a retry.
    """
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    from langchain_core.messages import HumanMessage

    from malspark.reporting.composer import ReportComposer
    from malspark.reporting.narrative_agent import NarrativeAgent
    from tests.unit.reporting.test_a_kept_wrong_citation_is_marked_with_its_holder import (
        _ProseOut,
        _RawLLM,
        _report,
        _texts,
    )

    citable = ["ev_0102", "ev_0105", "ev_0107", "ev_0109"]
    comp = ReportComposer(
        llm=_RawLLM(  # type: ignore[arg-type]
            json.dumps({"body": WRONG, "evidence_refs": 5}),
            json.dumps({"body": WRONG, "evidence_refs": []}),
        ),
        per_section_timeout=5,
    )
    comp._report = _report()
    comp._entries = _texts()
    comp._citable = citable
    with patch(
        "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
    ):
        asyncio.run(comp._invoke([HumanMessage(content="write it")], _ProseOut, section="x"))

    off_schema = json.loads(_summary(WRONG))
    off_schema["defensive_recommendations"] = 5
    llm = MagicMock()
    structured = MagicMock()
    structured.ainvoke = AsyncMock(side_effect=Exception("no schema"))
    llm.with_structured_output.return_value = structured
    llm.ainvoke = AsyncMock(
        side_effect=[MagicMock(content=json.dumps(off_schema)), MagicMock(content=_summary(WRONG))]
    )
    narrative = NarrativeAgent(llm=llm)
    asyncio.run(narrative.generate(_report(), citable_ids=citable, evidence=_texts()))
    return {
        "composer": comp.validation_tally.unresolved,
        "narrative": narrative.validation_tally.unresolved,
    }


def test_no_finding_is_said_to_be_only_in_a_retry_that_was_not_asked_for_it(mode: str) -> None:
    for stage, rows in _retry_rows(mode).items():
        (row,) = [r for r in rows if r["code"] == CITATION_WRONG_ENTRY_CODE]
        assert "first appeared in the answer to" not in row["message"], stage
        if mode == "record_only":
            assert row["asked"] == "false", stage
        else:
            assert "asked" not in row, stage


class TestTheComposerStructuredPath:
    def test_an_unpublished_value_is_asked_only_in_feed_back(self, mode: str) -> None:
        from malspark.pipeline.validation import UNPUBLISHED_VALUE_CODE
        from tests.unit.reporting.test_a_structured_section_is_asked_about_an_unpublished_value import (  # noqa: E501
            _invoke as _structured,
        )
        from tests.unit.reporting.test_an_unpublished_value_in_prose_carries_its_state import (
            PUBLISHED,
            REFUSED,
            _body,
        )

        wrong = json.dumps(_body(f"It uses {REFUSED} as C2."))
        right = json.dumps(_body(f"It uses {PUBLISHED} as C2."))

        result, llm, report = _structured(wrong, right)

        if mode == "feed_back":
            assert len(llm.sent) == 2
            assert result is not None and PUBLISHED in result.body
            assert report.flagged_statements == []
            return
        assert len(llm.sent) == 1
        # The section as written, the value marked where it stands, not asked.
        assert result is not None and REFUSED in result.body
        (row,) = report.flagged_statements
        assert (row.code, row.asked) == (UNPUBLISHED_VALUE_CODE, False)


class TestTheNarrative:
    def test_a_wrong_citation_is_asked_only_in_feed_back(self, mode: str) -> None:
        kept = f"Its parser halts on `{KEYWORD}` [ev_0105]."

        report = _narrative(_summary(WRONG), _summary(kept))

        asked = {row.sentence: row.asked for row in report.flagged_statements}
        if mode == "feed_back":
            assert asked == {kept: True}
        else:
            # The first answer stands; the retry's was never asked for.
            assert asked == {WRONG: False}


class TestTheQuestionRound:
    @pytest.mark.asyncio
    async def test_a_refused_word_is_asked_only_in_feed_back(self, mode: str) -> None:
        refused = {"answers": [_reply(1, "limited_negative")]}
        reporter = _QuestionReporter(refused, refused)

        result = await answer_questions(reporter, _question_report(), QUESTIONS[:1], ledger=LEDGER)

        (answer,) = result.answers
        # Printed as not determinable in both: what code does after the round.
        assert (answer.outcome, answer.answered) == ("not_determinable", "limited_negative")
        (row,) = result.tally.unresolved
        assert row["code"] == NEGATIVE_WITHOUT_COVERAGE_CODE
        if mode == "feed_back":
            assert len(reporter.turns) == 2
            assert result.tally.retries == 1
            assert "asked" not in row
        else:
            assert len(reporter.turns) == 1
            assert result.tally.retries == 0
            assert row["asked"] == "false"

    @pytest.mark.asyncio
    async def test_an_answer_off_its_schema_is_asked_again_in_both_modes(self, mode: str) -> None:
        reporter = _QuestionReporter(
            {"answers": [{"question": 1, "outcome": "certain", "answer": "x"}]},
            {"answers": [_reply(1, "out_of_scope")]},
        )

        result = await answer_questions(reporter, _question_report(), QUESTIONS[:1], ledger=LEDGER)

        assert len(reporter.turns) == 2
        assert result.tally.by_code.get(SCHEMA_CODE) == 1
        assert [a.outcome for a in result.answers] == ["out_of_scope"]


class TestTheSectionAgreement:
    def test_a_refused_answer_is_asked_only_in_feed_back_and_its_end_is_unchanged(
        self, mode: str
    ) -> None:
        first = "The gate reads a host mode [ev_0107]."
        report = _agreement_report(first, background=f"{first} {_UNKNOWN}")
        kept = _row(_UNKNOWN, "keep", [], reason="no source states it")
        keep = {**kept, "passage": "introduction"}
        reporter = _AgreementReporter({"sentences": [keep]}, {"sentences": [keep]})

        done = _ask(report, reporter)

        # The held sentence no answer passes for is left out in both modes.
        assert report.intro_background == first
        assert done.summary["dropped"] == 1
        assert [r["subject"] for r in done.tally.unresolved if r["code"] == DROPPED_CODE] == [
            "introduction"
        ]
        refusals = [r for r in done.tally.unresolved if r["code"] != DROPPED_CODE]
        assert refusals
        if mode == "feed_back":
            assert len(reporter.asked) == 2
            assert done.tally.retries == 1
            assert all("asked" not in r for r in refusals)
        else:
            assert len(reporter.asked) == 1
            assert done.tally.retries == 0
            assert all(r["asked"] == "false" for r in refusals)
