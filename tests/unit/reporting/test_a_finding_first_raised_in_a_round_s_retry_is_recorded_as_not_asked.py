"""A finding the agreement round or the question round first raised in its retry is not asked.

Each report round asks its model once more about its first answer's findings. A finding the
retry's answer raised for the first time had no turn left: the composer and the narrative
record such a finding as not asked (``validation.raised_only_in_retry``), but the agreement
round and the question round recorded it as asked, as if the model had been told and left it.

Both rounds now record it through the same function, as not asked and saying why. A finding
the retry was asked about and that still stands stays asked. The agreement round names a
row's finding by the sentence the row answers, not by the row's number, as the retry's rows
stand in another order (T-719). Every value here is made up.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.question_round import (
    ESTABLISHED_UNGROUNDED_CODE,
    NEGATIVE_WITHOUT_COVERAGE_CODE,
    answer_questions,
)
from malspark.reporting.section_agreement import UNKNOWN_PASSAGE_CODE
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _ask,
    _report,
    _Reporter,
    _row,
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

FIRST = "The gate reads a host mode [ev_0107]."
SECOND = "It waits for a reply [ev_0107]."


def _rows(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"sentences": list(rows)}


def _elsewhere(passage: str, sentence: str) -> dict[str, Any]:
    return {**_row(sentence, "keep", [], reason="no source speaks of it"), "passage": passage}


def _kept() -> dict[str, Any]:
    return _row(FIRST, "keep", [], reason="no source speaks of it")


def _records(result: Any, code: str) -> list[dict[str, str]]:
    return [row for row in result.tally.unresolved if row["code"] == code]


def test_agreement_round_records_a_finding_first_raised_in_its_retry_as_not_asked() -> None:
    reporter = _Reporter(
        _rows(_elsewhere("nowhere", FIRST)),
        # The retry fixes the row asked about and raises a new one, on another passage.
        _rows(_kept(), _elsewhere("elsewhere", SECOND)),
    )
    result = _ask(_report(f"{FIRST} {SECOND}"), reporter)
    (record,) = _records(result, UNKNOWN_PASSAGE_CODE)
    assert record["asked"] == "false"
    assert (
        "first appeared in the answer to the agreement question's one retry" in (record["message"])
    )


def test_agreement_round_keeps_a_finding_its_retry_was_asked_about_as_asked() -> None:
    reporter = _Reporter(
        _rows(_elsewhere("nowhere", FIRST)),
        # The same refused row again, now second: the same finding, under another number.
        _rows(_kept(), _elsewhere("nowhere", FIRST)),
    )
    result = _ask(_report(f"{FIRST} {SECOND}"), reporter)
    (record,) = _records(result, UNKNOWN_PASSAGE_CODE)
    assert "asked" not in record


@pytest.mark.asyncio
async def test_question_round_records_a_finding_first_raised_in_its_retry_as_not_asked() -> None:
    reporter = _QuestionReporter(
        {
            "answers": [
                _reply(1, "established", evidence_ids=["ev_0002"]),
                _reply(2, "out_of_scope"),
            ]
        },
        # The retry fixes the answer asked about and raises a new finding on the other.
        {
            "answers": [
                _reply(1, "established", evidence_ids=["ev_0001"]),
                _reply(2, "limited_negative"),
            ]
        },
    )
    result = await answer_questions(reporter, _question_report(), QUESTIONS, ledger=LEDGER)
    assert result.tally.by_code[ESTABLISHED_UNGROUNDED_CODE] == 1
    (record,) = [r for r in result.tally.unresolved if r["code"] == NEGATIVE_WITHOUT_COVERAGE_CODE]
    assert record["asked"] == "false"
    assert "first appeared in the answer to the question round's one retry" in record["message"]


@pytest.mark.asyncio
async def test_question_round_keeps_a_finding_its_retry_was_asked_about_as_asked() -> None:
    refused = {"answers": [_reply(1, "limited_negative")]}
    reporter = _QuestionReporter(refused, refused)
    result = await answer_questions(reporter, _question_report(), QUESTIONS[:1], ledger=LEDGER)
    (record,) = result.tally.unresolved
    assert record["code"] == NEGATIVE_WITHOUT_COVERAGE_CODE
    assert "asked" not in record


@pytest.mark.parametrize("order", ["whole then apart", "apart then whole"])
def test_a_finding_on_a_sentence_asked_in_any_row_shape_stays_asked(order: str) -> None:
    from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (  # noqa: E501
        _UNKNOWN,
    )

    first = "The analysis covers one file."
    text = f"{first} {_UNKNOWN}"

    def keep(sentence: str) -> dict[str, Any]:
        return _row(sentence, "keep", [], reason="none")

    whole, apart = _rows(keep(text)), _rows(keep(first), keep(_UNKNOWN))
    answers = (whole, apart) if order == "whole then apart" else (apart, whole)
    result = _ask(_report(text), _Reporter(*answers))
    records = [r for r in result.tally.unresolved if r["code"] != "agreement.held_unlisted"]
    assert records
    # The keep of the held sentence was refused in the first answer and again in the retry,
    # whichever shape each answer gave its rows: asked, both times.
    assert all("asked" not in r for r in records), records


@pytest.fixture
def record_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.unit.pipeline.test_record_only_findings_open_no_turn import settings_with

    built = settings_with("record_only")
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)


def test_in_record_only_the_agreement_round_leaves_the_loop_s_marks(record_only: None) -> None:
    # The retry asks only about the answer that could not be read; the finding of the answer
    # read after it is marked not asked by the loop, without the retry's own words.
    reporter = _Reporter("not an answer", _rows(_elsewhere("nowhere", FIRST)))
    result = _ask(_report(f"{FIRST} {SECOND}"), reporter)
    (record,) = _records(result, UNKNOWN_PASSAGE_CODE)
    assert record["asked"] == "false"
    assert "first appeared in the answer" not in record["message"]


@pytest.mark.asyncio
async def test_in_record_only_the_question_round_leaves_the_loop_s_marks(
    record_only: None,
) -> None:
    reporter = _QuestionReporter("not an answer", {"answers": [_reply(1, "limited_negative")]})
    result = await answer_questions(reporter, _question_report(), QUESTIONS[:1], ledger=LEDGER)
    (record,) = [r for r in result.tally.unresolved if r["code"] == NEGATIVE_WITHOUT_COVERAGE_CODE]
    assert record["asked"] == "false"
    assert "first appeared in the answer" not in record["message"]
