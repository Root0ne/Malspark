"""A sentence printed in its writer's own words that the round lists is kept or left out.

A text the analyst report prints as an analyst or the judge wrote it is never rewritten: a
rewrite would not be the writer's words. Listed, a sentence of it is kept on a quote of a
source that passes the keep checks, or left out of the analyst report: dropped on its reason,
or kept on no passing quote, or answered with a rewrite, which is refused and no keep. A
sentence left out is recorded naming its passage, under the round's own code for a sentence
left out, and as a flagged statement the renderers read; the passage's text, and so the
bundle, keeps it whole. A sentence no row lists stands as written, with no record (T-613).
Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from malspark.reporting.models import MalwareReport
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    KEEP_UNQUOTED_CODE,
    UNKNOWN_PASSAGE_CODE,
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    apply_rows,
    ask_section_agreement,
    passages_of,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    CLAIM,
    IMPACT,
    STATEMENT,
    report_of,
)

_CLAIM_SENTENCE = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
_QUOTE = "Routine 0x5b20 reads the BeingDebugged byte and returns -1 when it is set"
_SECOND = "It compares each name with HOST_MODE [ev_0102]."


def _row(passage: str, sentence: str, decision: str, **said: Any) -> dict[str, Any]:
    return {"passage": passage, "sentence": sentence, "decision": decision, **said}


def _answer(report: MalwareReport, *rows: dict[str, Any]) -> tuple[dict[str, int], list[Any]]:
    return apply_rows({"sentences": list(rows)}, passages_of(report))


def _refusals(report: MalwareReport, row: dict[str, Any]) -> list[Any]:
    """The refusals of ``row`` alone: the limitations paragraph's own sentences are asked
    about too, every one of them held."""
    found = agreement_violations({"sentences": [row]}, passages_of(report))
    return [v for v in found if v.path.startswith("sentences.")]


def _left(report: MalwareReport) -> list[tuple[str, str, str]]:
    return [(row.code, row.label, row.sentence) for row in report.flagged_statements]


def _as_written(report: MalwareReport) -> None:
    cells = {cell.technique_id: cell for cell in report.capability_matrix}
    assert cells["T1057"].statements == [STATEMENT]
    assert cells["T1622"].evidence == [CLAIM]
    assert report.severity is not None and report.severity.business_impact == IMPACT


def test_a_keep_on_a_quote_that_passes_prints_it_and_is_counted() -> None:
    report = report_of()
    counts, found = _answer(
        report,
        _row(
            "attack_claim.T1622",
            _CLAIM_SENTENCE,
            "keep",
            sources=["string_resolution"],
            quote=_QUOTE,
        ),
    )

    assert counts["kept"] == 1 and counts["dropped"] == 0 and counts["listed"] == 0
    assert found == []
    assert _left(report) == []
    _as_written(report)


def test_a_keep_on_no_passing_quote_leaves_it_out_and_records_it() -> None:
    report = report_of()
    row = _row(
        "attack_claim.T1622",
        _CLAIM_SENTENCE,
        "keep",
        sources=["string_resolution"],
        quote="Routine 0x5b20 returns zero when the byte is set",
    )
    asked = _refusals(report, row)
    counts, found = _answer(report, row)

    assert [v.code for v in asked] == [KEEP_UNQUOTED_CODE]
    assert asked[0].message.endswith(
        'keep it naming the source you read and found agreeing, with "quote": its words that '
        'state the same thing, copied exactly, or drop it with "reason". If no answer for it '
        "passes the checks, it is left out of the report, and the bundle prints it whole."
    )
    assert "rewrite" not in asked[0].message.split(" but ", 1)[1]
    assert counts["dropped"] == 1 and counts["kept"] == 0
    assert [(v.code, v.subject) for v in found] == [(DROPPED_CODE, "attack_claim.T1622")]
    assert found[0].message.startswith(
        "The agreement question leaves a sentence of ATT&CK table, the claim sentence printed "
        "for T1622 (attack_claim.T1622) out of the analyst report, which the bundle prints "
        "whole (its last answer, a keep, was refused; an analyst's own words, printed as "
        f"written: {KEEP_UNQUOTED_CODE}): "
    )
    assert _left(report) == [(DROPPED_CODE, "attack_claim.T1622", _CLAIM_SENTENCE)]
    _as_written(report)


def test_a_drop_leaves_the_one_sentence_out_and_the_text_stays_whole() -> None:
    report = report_of()
    counts, found = _answer(
        report,
        _row("statements.T1057.1", _SECOND, "drop", reason="Section 5 names no such compare."),
    )

    assert counts["dropped"] == 1
    assert [(v.code, v.subject) for v in found] == [(DROPPED_CODE, "statements.T1057.1")]
    assert "its reason: Section 5 names no such compare." in found[0].message
    assert _left(report) == [(DROPPED_CODE, "statements.T1057.1", _SECOND)]
    _as_written(report)


def test_a_rewrite_is_refused_offering_a_keep_or_a_drop_and_is_no_keep() -> None:
    report = report_of()
    row = _row(
        "judge.business_impact",
        "It reaches 0x5c30 first.",
        "rewrite",
        sources=["string_resolution"],
        rewrite="It reaches 0x5b20 first [ev_0103].",
    )
    asked = _refusals(report, row)
    counts, found = _answer(report, row)

    assert [v.code for v in asked] == [UNKNOWN_PASSAGE_CODE]
    assert asked[0].message == (
        "row 1: judge.business_impact prints the judge's own words, printed as written and is "
        'never rewritten: keep it naming the source you read and found agreeing, with "quote": '
        'its words that state the same thing, copied exactly, or drop it with "reason". If no '
        "answer for it passes the checks, it is left out of the report, and the bundle prints "
        "it whole."
    )
    assert counts["rewritten"] == 0 and counts["dropped"] == 1
    assert [(v.code, v.subject) for v in found] == [(DROPPED_CODE, "judge.business_impact")]
    assert _left(report) == [(DROPPED_CODE, "judge.business_impact", "It reaches 0x5c30 first.")]
    _as_written(report)


def test_a_keep_naming_no_source_is_refused_and_leaves_it_out() -> None:
    report = report_of()
    row = _row("statements.T1057.1", _SECOND, "keep", reason="No source speaks of it.")
    asked = _refusals(report, row)
    counts, found = _answer(report, row)

    assert [v.code for v in asked] == [UNKNOWN_SOURCE_CODE]
    assert asked[0].message.startswith(
        "row 1 names no source. Name the ids of the sources you read for the sentence of "
        "statements.T1057.1, or, leaving it out, give the reason."
    )
    assert counts["dropped"] == 1
    assert _left(report) == [(DROPPED_CODE, "statements.T1057.1", _SECOND)]


def test_a_sentence_no_row_lists_stands_with_no_record() -> None:
    report = report_of()
    counts, found = _answer(report)

    assert counts["dropped"] == 0
    assert not [v for v in found if v.subject.startswith(("statements.", "attack_", "judge."))]
    assert _left(report) == []
    _as_written(report)


class _Reporter:
    """The reporter's model, answering each turn with the next answer given."""

    def __init__(self, *answers: dict[str, Any]) -> None:
        self.answers = [json.dumps(answer) for answer in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def test_a_rewrite_the_retry_leaves_unanswered_is_still_no_keep() -> None:
    report = report_of()
    limitations = "The second stage was not observed [ev_0105]."
    kept = _row("limitations", limitations, "keep", reason="No source speaks of it.")
    rewritten = _row(
        "judge.business_impact",
        "It reaches 0x5c30 first.",
        "rewrite",
        sources=["string_resolution"],
        rewrite="It reaches 0x5b20 first [ev_0103].",
    )
    reporter = _Reporter({"sentences": [rewritten, kept]}, {"sentences": [kept]})
    done = asyncio.run(ask_section_agreement(reporter, report, citable_ids=["ev_0103"]))

    # The retry was asked, answered the other sentence alone, and the refused rewrite stayed
    # the sentence's last answer: no keep, so it is left out.
    assert len(reporter.asked) == 2
    assert done.summary["dropped"] == 1 and done.summary["rewritten"] == 0
    assert _left(report) == [(DROPPED_CODE, "judge.business_impact", "It reaches 0x5c30 first.")]
    _as_written(report)
