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


def test_a_listed_passage_written_in_square_brackets_is_named_not_placed() -> None:
    row = {**_row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise")}
    _report_, _counts, records, found = _applied(
        {"sentences": [{**row, "passage": "[introduction]"}]}
    )
    assert UNKNOWN_PASSAGE_CODE not in {code for code, _at in found}
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]


def test_a_passage_shown_as_a_source_only_takes_no_placed_row() -> None:
    import dataclasses

    report = _background()
    passages = [
        dataclasses.replace(p, source_only=True) if p.id == "introduction" else p
        for p in passages_of(report, entries=_ledger())
    ]
    row = {**_row(_UNKNOWN, "drop", [], reason="x"), "passage": "held.introduction"}
    found = [(v.code, v.path) for v in agreement_violations({"sentences": [row]}, passages)]
    assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
    _counts, records = apply_rows({"sentences": [row]}, passages)
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]


def test_a_question_that_got_no_answer_records_no_placement() -> None:
    row = {**_row(_UNKNOWN, "drop", [], reason="x"), "passage": "held.introduction"}
    counts, records = apply_rows(
        {"sentences": [row]}, passages_of(_background(), entries=_ledger()), asked=False
    )
    assert counts["sentences"] == 0
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]


def test_a_row_placed_in_the_first_answer_and_named_in_the_retry_answers_once() -> None:
    placed = {
        **_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN),
        "passage": "held.introduction",
    }
    named = {**placed, "passage": "introduction"}
    # A refused keep of the limitations' sentence opens the retry.
    refused = {**_row(FIRST, "keep", ["nowhere.1"]), "passage": "limitations"}
    report = _background()
    done = _ask(
        report, _Reporter({"sentences": [refused, placed]}, {"sentences": [refused, named]})
    )
    assert done.tally.retries == 1
    # The retry's row and the first answer's placed row answer one sentence: one row.
    assert done.summary["sentences"] == 2 and done.summary["not_applied"] == 0
    assert report.intro_background == f"{FIRST} {_PLAIN}"


def test_a_row_placed_in_the_first_answer_stands_where_the_retry_leaves_it_out() -> None:
    placed = {
        **_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN),
        "passage": "held.introduction",
    }
    refused = {**_row(FIRST, "keep", ["nowhere.1"]), "passage": "limitations"}
    report = _background()
    # The retry answers only the row it was asked about: the placed row is the first
    # answer's sound row, kept as any is.
    done = _ask(report, _Reporter({"sentences": [refused, placed]}, {"sentences": [refused]}))
    assert done.tally.retries == 1
    assert report.intro_background == f"{FIRST} {_PLAIN}"
    assert done.summary["rewritten"] == 1


@pytest.mark.parametrize(
    "limitations",
    [FIRST, "The gate writes no file [ev_0107]."],
    ids=["once in another passage", "in no other passage"],
)
def test_a_sentence_one_passage_writes_twice_places_no_row(limitations: str) -> None:
    # The introduction writes the sentence twice: it holds it, though not once, so no one
    # passage holds it exactly once and the row is refused, every passage as written.
    background = f"{FIRST} {FIRST}"
    row = {
        **_row(FIRST, "drop", [], reason="the lines shown say otherwise"),
        "passage": "held.introduction",
    }
    report = _report(limitations, background=background)
    ledger = _ledger()
    passages = passages_of(report, entries=ledger)
    found = [
        (v.code, v.path)
        for v in agreement_violations({"sentences": [row]}, passages, [str(e.id) for e in ledger])
    ]
    assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
    _counts, records = apply_rows({"sentences": [row]}, passages)
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]
    report = _report(limitations, background=background)
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}))
    assert PLACED_BY_SENTENCE_CODE not in done.tally.by_code
    assert report.intro_background == background
    assert report.technical_analysis.analyst_limitations.body == limitations


@pytest.mark.parametrize(
    "bad",
    [
        {"decision": "drop", "reason": ""},
        {"decision": ["drop"], "reason": "the lines shown say otherwise"},
        {"decision": "rewrite", "rewrite": "  "},
    ],
    ids=["a drop with no reason", "a decision the schema has not", "a rewrite with no words"],
)
def test_a_row_the_schema_refuses_is_neither_placed_nor_recorded(bad: dict[str, Any]) -> None:
    row = {**_row(_UNKNOWN, "drop", []), **bad, "passage": "held.introduction"}
    _report_, counts, records, _found = _applied({"sentences": [row]})
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]
    assert counts["sentences"] == 0
    report = _background()
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}))
    assert PLACED_BY_SENTENCE_CODE not in done.tally.by_code
    # The sentence ends as one no row answered.
    unanswered = _background()
    _ask(unanswered, _Reporter({"sentences": []}, {"sentences": []}))
    assert report.model_dump() == unanswered.model_dump()


def test_a_passage_holding_the_sentence_twice_by_its_words_places_no_row() -> None:
    # The second copy differs only in its white space: the same sentence by its words, so
    # the passage holds it twice, and the row is refused though one copy stands exactly.
    background = f"{FIRST} {FIRST.replace(' ', '  ', 1)}"
    row = {
        **_row(FIRST, "drop", [], reason="the lines shown say otherwise"),
        "passage": "held.introduction",
    }
    passages = passages_of(_report("The gate writes no file [ev_0107].", background=background))
    found = [(v.code, v.path) for v in agreement_violations({"sentences": [row]}, passages)]
    assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
    _counts, records = apply_rows({"sentences": [row]}, passages)
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]


def test_a_copy_one_passage_holds_only_by_its_words_places_no_row() -> None:
    # The row's copy differs from the passage's sentence in its white space: the passage holds
    # it by its words, but no row naming that passage answers it, so none is placed there.
    row = {
        **_row(_UNKNOWN.replace(" ", "  ", 1), "drop", [], reason="x"),
        "passage": "held.introduction",
    }
    _report_, _counts, records, found = _applied({"sentences": [row]})
    assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]


# A copy of several sentences: each sentence of it is asked where the row is placed.
_T = "The sample writes no file to disk [ev_0107]."
_X = "It also stops [ev_0107]."


def _unplaced_ends(limitations: str, background: str, copy: str) -> None:
    row = {**_row(copy, "drop", [], reason="the lines shown say otherwise"), "passage": "held.x"}
    report = _report(limitations, background=background)
    passages = passages_of(report, entries=_ledger())
    found = [(v.code, v.path) for v in agreement_violations({"sentences": [row]}, passages)]
    assert (UNKNOWN_PASSAGE_CODE, "sentences.0.passage") in found
    _counts, records = apply_rows({"sentences": [row]}, passages)
    assert not [v for v in records if v.code == PLACED_BY_SENTENCE_CODE]
    assert report.intro_background == background
    assert report.technical_analysis.analyst_limitations.body == limitations


def test_a_copy_of_several_sentences_another_passage_holds_one_of_places_no_row() -> None:
    # The limitations are the whole copy; the introduction holds its sentences inside a longer
    # text: two passages hold a sentence of the copy, and every passage stands as written.
    _unplaced_ends(f"{FIRST} {_T}", f"{FIRST} {_T} {_X}", f"{FIRST} {_T}")


def test_a_copy_of_several_sentences_one_of_which_its_passage_holds_twice_places_no_row() -> None:
    _unplaced_ends(f"{FIRST} {_T} {FIRST}", _X, f"{FIRST} {_T} {FIRST}")


@pytest.mark.parametrize("background", [_X, f"{FIRST} {_T} {_X}"], ids=["placed", "refused"])
def test_a_whole_copy_and_its_sentences_one_by_one_end_alike_under_placement(
    background: str,
) -> None:
    def ended(sentences: list[str]) -> tuple[Any, ...]:
        report = _report(f"{FIRST} {_T}", background=background)
        rows = [
            {**_row(s, "drop", [], reason="the lines shown say otherwise"), "passage": "held.x"}
            for s in sentences
        ]
        done = _ask(report, _Reporter({"sentences": rows}, {"sentences": rows}))
        # The ends and the codes that say how each sentence ended; a refused row is counted
        # once per row, so the codes are compared as a set.
        return (
            report.model_dump(),
            done.summary["dropped"],
            {r["code"] for r in done.tally.unresolved if r["code"] != PLACED_BY_SENTENCE_CODE},
        )

    assert ended([f"{FIRST} {_T}"]) == ended([FIRST, _T])


@pytest.mark.parametrize("named", ["introduction", "held.introduction"])
def test_a_key_a_row_writes_is_never_the_round_s_own_mark_wherever_the_rows_enter(
    named: str,
) -> None:
    # The round's mark of a placed row, written by a row itself under any key a JSON answer
    # can hold, is read past by every check and by the ends: the row is the same row.
    row = {**_row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise"), "passage": named}
    marked = {**row, "\x00placed_from": "nowhere.1"}
    plain, plain_counts, plain_records, plain_found = _applied({"sentences": [row]})
    report, counts, records, found = _applied({"sentences": [marked]})
    assert found == plain_found
    assert counts == plain_counts
    assert [(v.code, v.message) for v in records] == [(v.code, v.message) for v in plain_records]
    assert report.model_dump() == plain.model_dump()
