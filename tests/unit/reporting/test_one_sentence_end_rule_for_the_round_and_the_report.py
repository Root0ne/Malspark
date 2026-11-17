"""One rule says where a sentence ends, for the agreement round and the analyst report (T-719).

The agreement round cut a passage into sentences at any period a space followed. A table
cell reading "... names present, e.g. NAME_A and NAME_B); details not established" was two
sentences to it: the model's answer for the cell, copied whole, stood in neither, was
refused, and each fragment, unanswered, was left out, so the cell printed "-". The analyst
report read a period after "e.g." as no sentence's end, so the two disagreed.

One module now holds the rule (``reporting.sentence_ends``), and both read it: a period
ends no sentence where it closes a run of two or more single letters each followed by a
period, or sits inside a number. Nothing else joins: where the rule cannot tell, the cut is
the one it always was, so a sentence opening on a lower-case word or a number after a short
word still follows a sentence's end. And a keep or a drop whose copied text is the whole
field is found, however many sentences the field holds. Every value here is made up.
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
        "It reads the key, i.e. the run key.",
        "It reads the key, e.g. The run key.",
        "The size is 1.5 MB in all.",
        "It names U.S. Hosts in the list.",
    ],
)
def test_a_run_of_single_letters_or_a_number_ends_no_sentence(text: str) -> None:
    assert _units(text) == [text]


@pytest.mark.parametrize(
    ("text", "units"),
    [
        # What the rule cannot tell from a sentence's end is cut as it always was.
        ("The block is approx. half.", ["The block is approx.", "half."]),
        ("Keys, etc. were read.", ["Keys, etc.", "were read."]),
        ("It is in Fig. 3 here.", ["It is in Fig.", "3 here."]),
        ("It names a host. capa reads it.", ["It names a host.", "capa reads it."]),
        ("It is a loop. 4. It ends.", ["It is a loop.", "4.", "It ends."]),
        # A single letter alone is no run.
        ("It is plan A. Then B.", ["It is plan A.", "Then B."]),
    ],
)
def test_what_the_rule_cannot_tell_is_cut_as_before(text: str, units: list[str]) -> None:
    assert _units(text) == units


@pytest.mark.parametrize(
    ("text", "units"),
    [
        ("It reads keys. Then it waits.", ["It reads keys.", "Then it waits."]),
        ("It runs Mon. Then it waits.", ["It runs Mon.", "Then it waits."]),
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


def test_a_rewrite_copying_a_whole_field_of_two_sentences_is_still_not_found() -> None:
    # One text would stand in place of two sentences: the rewrite is asked again, and the
    # field stands as written.
    report = _cell(TWO)
    rewrite = {
        **_row(TWO, "rewrite", ["string_resolution"], rewrite="RC4 keys [ev_0107]."),
        "passage": CELL_ID,
    }
    _counts, found = _answered(report, [rewrite, _beside()])
    assert SENTENCE_NOT_FOUND_CODE in {v.code for v in found}
    assert report.c2_channels[0].encryption in (TWO, "")
    assert "RC4 keys" not in report.c2_channels[0].encryption


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
    "4.",
    "A.",
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
    text = "It reads e.g. Keys. Then approx. 3 more. U.S. hosts. Done."
    assert [at for at in range(len(text)) if _ends_sentence(text, at)] == [
        at for at in range(len(text)) if ends_sentence(text, at)
    ]


def test_a_joined_sentence_is_held_where_a_part_of_it_would_be() -> None:
    # A run of single letters joins what follows it; the absence the first part states is
    # still asked about, though the second names an address.
    absent = "A further 96 decodings are not referenced by code and were not shown, i.e."
    named = "XOR loops at 0x401000 [ev_0008]."
    text = f"It decodes texts. {absent} {named}"
    assert _units(text) == ["It decodes texts.", f"{absent} {named}"]
    assert pieces(f"{absent} {named}") == [absent, named]
    assert whole_code_absences(absent, unsettled=True) == (absent,)
    assert whole_code_absences(text, unsettled=True) == (f"{absent} {named}",)
    assert whole_code_absences(named, unsettled=True) == ()


def test_a_word_with_a_digit_or_a_line_break_still_follows_an_end() -> None:
    assert _units("It reads keys. ev_0060 shows the call.") == [
        "It reads keys.",
        "ev_0060 shows the call.",
    ]
    text = "It reads keys, e.g.\nthe run key."
    assert ends_sentence(text, text.index("e.g.") + 3)


def test_a_whole_field_answer_is_refused_for_what_any_of_its_sentences_is() -> None:
    from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (  # noqa: E501
        _UNKNOWN,
    )

    first = "The gate reads a host mode [ev_0107]."
    report = _report(f"{first} {_UNKNOWN}")
    alone = _answered(report, [_row(_UNKNOWN, "keep", [], reason="no source states it")])[1]
    whole = _answered(
        _report(f"{first} {_UNKNOWN}"),
        [_row(f"{first} {_UNKNOWN}", "keep", [], reason="no source states it")],
    )[1]
    refusals = {v.code for v in alone if v.path.startswith("sentences.0")}
    assert refusals
    assert refusals <= {v.code for v in whole if v.path.startswith("sentences.0")}
    assert SENTENCE_NOT_FOUND_CODE not in {v.code for v in whole}


def test_a_refused_whole_field_answer_leaves_out_only_the_sentence_it_ends_on() -> None:
    from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (  # noqa: E501
        _UNKNOWN,
    )

    body = "Routine 0x5a10 reads a host mode through a slot [ev_0107]."
    report = _report("The gate reads a host mode [ev_0107].")
    report.intro_background = f"{body} {_UNKNOWN}"
    keep = {
        **_row(f"{body} {_UNKNOWN}", "keep", [], reason="no source states it"),
        "passage": "introduction",
    }
    counts, found = _answered(report, [keep])
    assert "agreement.keep_unquoted" in {v.code for v in found}
    # The held sentence the refused keep ends on is left out; the other stands, as it
    # would where the same keep answered each sentence apart.
    assert report.intro_background == body
    assert counts["dropped"] == 1


def test_a_whole_field_answer_lists_every_sentence_of_it() -> None:
    report = _cell(TWO)
    keep = {**_row(TWO, "keep", [], reason="no source speaks of the key"), "passage": CELL_ID}
    _counts, found = _answered(report, [keep, _beside()])
    assert "agreement.held_unlisted" not in {v.code for v in found}
