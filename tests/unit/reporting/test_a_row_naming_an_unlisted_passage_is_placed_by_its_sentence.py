"""A row naming a passage no list writes is placed by the sentence it copies.

A row whose passage id is not one the question lists was refused, and the sentence it copied
counted as not answered: the form of the answer decided the sentence's end. Now such a row is
placed by its sentence, where that sentence stands whole in exactly one passage a row may
answer; it is then checked and ended as any row naming that passage, and recorded as placed
by its text (``PLACED_BY_SENTENCE_CODE``). A sentence standing in two passages, or in none,
is refused as before (T-736). Every address, entry and name here is a neutral synthetic
value.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import MalwareReport
from malspark.reporting.section_agreement import (
    PLACED_BY_SENTENCE_CODE,
    UNKNOWN_PASSAGE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    rewrites_violations,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    CALLED,
    _ask,
    _ledger,
    _report,
    _Reporter,
    _row,
)

# Stands in the introduction and in the limitations.
FIRST = "The gate reads a host mode [ev_0107]."
_PLAIN = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."


def _background() -> MalwareReport:
    return _report(FIRST, background=f"{FIRST} {_UNKNOWN}")


def _applied(payload: dict[str, Any]) -> tuple[MalwareReport, dict[str, int], list[Any], list[Any]]:
    report = _background()
    ledger = _ledger()
    passages = passages_of(report, entries=ledger)
    found = [
        (v.code, v.path)
        for v in [
            *agreement_violations(payload, passages, [str(e.id) for e in ledger]),
            *rewrites_violations(
                payload, [str(e.id) for e in ledger], None, EntryTexts.from_ledger(ledger), passages
            ),
        ]
    ]
    counts, records = apply_rows(
        payload,
        passages,
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    return report, counts, records, found


_ROWS = {
    "a rewrite": _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN),
    "a drop": _row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise"),
    "a refused keep": _row(_UNKNOWN, "keep", [], reason="no source states it"),
}


@pytest.mark.parametrize("named", ["held.introduction", "[nowhere.1]", "intro"])
@pytest.mark.parametrize("row", list(_ROWS.values()), ids=list(_ROWS))
def test_a_row_whose_sentence_stands_in_one_passage_ends_as_that_passage_s_row(
    row: dict[str, Any], named: str
) -> None:
    twin, twin_counts, twin_records, twin_found = _applied(
        {"sentences": [{**row, "passage": "introduction"}]}
    )
    report, counts, records, found = _applied({"sentences": [{**row, "passage": named}]})
    assert UNKNOWN_PASSAGE_CODE not in {code for code, _at in found}
    assert found == twin_found
    assert counts == twin_counts
    assert report.model_dump() == twin.model_dump()
    # Its ends are the twin's; one record more says how it was placed.
    placed = [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]
    assert [v for v in records if v.code != PLACED_BY_SENTENCE_CODE] == twin_records
    assert [(v.path, v.answered) for v in placed] == [("sentences.0", True)]
    assert placed[0].message == (
        f"The agreement question places row 1, which names the passage {named!r}, not one "
        "the question lists, by the sentence it copies, which stands whole in introduction "
        f"alone: {_UNKNOWN!r}."
    )


def test_a_sentence_standing_in_two_passages_or_in_none_is_refused_as_before() -> None:
    for sentence in (FIRST, "The gate writes nothing at all."):
        row = {**_row(sentence, "keep", ["ledger.1"]), "passage": "held.introduction"}
        _report_, counts, records, found = _applied({"sentences": [row]})
        assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
        assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]
        assert counts["sentences"] == 1 and counts["rewritten"] == 0


def test_the_round_places_a_row_of_either_answer_and_asks_nothing_of_its_form() -> None:
    rewrite = {
        **_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN),
        "passage": "held.introduction",
    }
    keep = {**_row(FIRST, "keep", ["ledger.1"]), "passage": "limitations"}
    # Placed in the first answer: no refusal of its passage, and the rewrite stands.
    report = _background()
    reporter = _Reporter({"sentences": [keep, rewrite]}, {"sentences": [keep, rewrite]})
    done = _ask(report, reporter)
    assert UNKNOWN_PASSAGE_CODE not in done.tally.by_code
    assert report.intro_background == f"{FIRST} {_PLAIN}"
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved].count(PLACED_BY_SENTENCE_CODE) == 1
    # Placed in the retry's answer, the first answer giving none.
    report = _background()
    done = _ask(report, _Reporter({"sentences": [keep]}, {"sentences": [rewrite]}))
    assert UNKNOWN_PASSAGE_CODE not in done.tally.by_code
    assert report.intro_background == f"{FIRST} {_PLAIN}"


def test_a_model_s_own_key_of_the_same_name_places_nothing() -> None:
    from malspark.reporting.section_agreement import _PLACED_FROM

    row = {**_row(FIRST, "keep", ["ledger.1"]), "passage": "limitations", _PLACED_FROM: "x"}
    report = _background()
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}))
    assert PLACED_BY_SENTENCE_CODE not in done.tally.by_code
