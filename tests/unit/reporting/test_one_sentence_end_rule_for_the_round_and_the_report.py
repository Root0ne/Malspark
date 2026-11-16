"""One rule says where a sentence ends, for the agreement round and the analyst report (T-719).

The agreement round cut a passage into sentences at any period a space followed. A table
cell reading "... names present, e.g. NAME_A and NAME_B); details not established" was two
sentences to it: the model's answer for the cell, copied whole, stood in neither, was
refused, and each fragment, unanswered, was left out, so the cell printed "-". The analyst
report read a period after "e.g." as no sentence's end, so the two disagreed.

One module now holds the rule (``reporting.sentence_ends``), and both read it: a period
ends no sentence where it closes a run of single letters with periods, sits inside a
number, or a lower-case word follows it, or a digit after a word of one to five letters.
Where the rule cannot tell, the sentence is the longer one. And an answer whose copied
text is the whole field is found, however many sentences the field holds. Every value
here is made up.
"""

from __future__ import annotations

import itertools
import random
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import C2Channel, MalwareReport
from malspark.reporting.renderers.analyst import _ends_sentence, _stands_whole
from malspark.reporting.section_agreement import (
    SENTENCE_NOT_FOUND_CODE,
    _sentence_units,
    agreement_violations,
    apply_rows,
    passages_of,
    whole_code_absences,
)
from malspark.reporting.sentence_ends import ends_sentence, pieces
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _ledger,
    _report,
    _row,
)

CELL = (
    "TLS transport encryption (handshake message names present, e.g. CLIENT_HELLO and "
    "SERVER_KEY_EXCHANGE); algorithm details not established"
)
TWO = "Not established. A key of 16 bytes is read [ev_0107]."
CELL_ID = "communications.1.encryption"


def _units(text: str) -> list[str]:
    starts, _ends = _sentence_units(text)
    return [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]


def _cell(text: str) -> MalwareReport:
    report = _report("The gate reads a host mode [ev_0107].")
    report.c2_channels = [C2Channel(name="TLS channel", encryption=text)]
    return report


def _answered(report: MalwareReport, rows: list[dict[str, Any]]) -> tuple[dict[str, int], list]:
    ledger = _ledger()
    passages = passages_of(report, entries=ledger)
    citable = [str(e.id) for e in ledger]
    entries = EntryTexts.from_ledger(ledger)
    found = agreement_violations({"sentences": rows}, passages, citable, None, entries)
    counts, records = apply_rows({"sentences": rows}, passages, citable=citable, entries=entries)
    return counts, [*found, *records]


def _beside() -> dict[str, Any]:
    return _row("The gate reads a host mode [ev_0107].", "keep", [], reason="no source says")


# -- the rule ----------------------------------------------------------------------------


def test_a_cell_with_e_g_is_one_sentence_to_the_agreement_round() -> None:
    assert _units(CELL) == [CELL]


def test_a_whole_cell_answer_with_an_abbreviation_is_found() -> None:
    report = _cell(CELL)
    said = "no source speaks of the algorithm"
    keep = {**_row(CELL, "keep", [], reason=said), "passage": CELL_ID}
    counts, found = _answered(report, [keep, _beside()])
    assert SENTENCE_NOT_FOUND_CODE not in {v.code for v in found}
    assert report.c2_channels[0].encryption == CELL
    assert counts["dropped"] == 0


@pytest.mark.parametrize(
    "text",
    [
        "The block is one of approx. half the records.",
        "Strings, files, keys, etc. were read.",
        "The table is shown in Fig. 3 of the bundle.",
        "The loader v. 7 reads it.",
        "It reads the key, i.e. the run key.",
        "The size is 1.5 MB in all.",
        "It names U.S. Hosts in the list.",
    ],
)
def test_an_abbreviation_before_a_lower_case_word_ends_no_sentence(text: str) -> None:
    assert _units(text) == [text]


@pytest.mark.parametrize(
    ("text", "units"),
    [
        ("It reads keys. Then it waits.", ["It reads keys.", "Then it waits."]),
        ("It runs Mon. Then it waits.", ["It runs Mon.", "Then it waits."]),
        # A word of six letters or more before a digit: the period ends the sentence.
        ("It waited. 3 hosts answered.", ["It waited.", "3 hosts answered."]),
        ("It stops! then waits.", ["It stops!", "then waits."]),
        ("Is it read? 2 are.", ["Is it read?", "2 are."]),
        ('It says "done." Then it exits.', ['It says "done."', "Then it exits."]),
        ("It ends.\nnext line.", ["It ends.", "next line."]),
    ],
)
def test_a_period_before_a_capital_after_a_full_word_still_ends_a_sentence(
    text: str, units: list[str]
) -> None:
    assert _units(text) == units


def test_an_answer_whose_copied_text_is_the_whole_field_is_found() -> None:
    assert len(_units(TWO)) == 2
    report = _cell(TWO)
    keep = {**_row(TWO, "keep", [], reason="no source speaks of the key"), "passage": CELL_ID}
    counts, found = _answered(report, [keep, _beside()])
    assert SENTENCE_NOT_FOUND_CODE not in {v.code for v in found}
    # Each sentence of the field is answered by the one row: none is left out unanswered.
    assert report.c2_channels[0].encryption == TWO
    assert counts["dropped"] == 0


def test_a_whole_field_drop_leaves_the_whole_field_out() -> None:
    report = _cell(TWO)
    drop = {**_row(TWO, "drop", [], reason="no source states it"), "passage": CELL_ID}
    counts, found = _answered(report, [drop, _beside()])
    assert SENTENCE_NOT_FOUND_CODE not in {v.code for v in found}
    assert report.c2_channels[0].encryption == ""


def test_a_run_of_sentences_short_of_the_whole_field_is_still_not_found() -> None:
    three = f"{TWO} It is reused."
    report = _cell(three)
    keep = {**_row(TWO, "keep", [], reason="no source speaks of it"), "passage": CELL_ID}
    _counts, found = _answered(report, [keep, _beside()])
    assert SENTENCE_NOT_FOUND_CODE in {v.code for v in found}


# -- the two callers read alike ----------------------------------------------------------

_TOKENS = (
    "Word",
    "word",
    "e.g.",
    "i.e.",
    "Fig.",
    "approx.",
    "etc.",
    "v.",
    "3",
    "1.5",
    "end.",
    "End.",
    "it!",
    "so?",
    '"quoted."',
    "(aside.)",
    "**bold.**",
    "_em._",
    "U.S.",
    "x",
)


def _corpus() -> list[str]:
    texts = [" ".join(words) for words in itertools.product(_TOKENS, repeat=3)]
    rng = random.Random(719)
    texts += [" ".join(rng.choice(_TOKENS) for _ in range(rng.randint(4, 12))) for _ in range(3000)]
    return texts


def _round_ends(text: str) -> set[int]:
    """Each place a sentence of the round's cut ends, the end of the text aside."""
    _starts, ends = _sentence_units(text)
    return {end for end in ends if text[end:].strip()}


def _report_ends(text: str) -> set[int]:
    """Each place the analyst renderer reads a sentence's end, closing marks read past."""
    out: set[int] = set()
    for at in range(len(text)):
        if _ends_sentence(text, at):
            end = at + 1
            while end < len(text) and text[end] in "\"'’”)]*_":
                end += 1
            if text[end:].strip():
                out.add(end)
    return out


def test_renderer_and_round_split_alike() -> None:
    for text in _corpus():
        assert _round_ends(text) == _report_ends(text), text
        starts, _ends = _sentence_units(text)
        for said, places in starts.items():
            for start in places:
                assert _stands_whole(text, start, start + len(said)), (text, said)


def test_both_callers_read_the_one_rule() -> None:
    text = "It reads e.g. Keys. Then approx. 3 more. Done."
    assert [at for at in range(len(text)) if _ends_sentence(text, at)] == [
        at for at in range(len(text)) if ends_sentence(text, at)
    ]


def test_a_joined_sentence_is_held_where_a_part_of_it_would_be() -> None:
    # A sentence opening on a lower-case word is joined to the one before it; the absence
    # the first states is still asked about, though the second names an address.
    absent = "A further 96 decodings are not referenced by code and were not shown [ev_0021]."
    named = "tooling matched an XOR loop at 0x401000 [ev_0008]."
    text = f"It decodes texts. {absent} {named}"
    assert _units(text) == ["It decodes texts.", f"{absent} {named}"]
    assert pieces(f"{absent} {named}") == [absent, named]
    assert whole_code_absences(absent, unsettled=True) == (absent,)
    assert whole_code_absences(text, unsettled=True) == (f"{absent} {named}",)
    assert whole_code_absences(named, unsettled=True) == ()
