"""The sentence under a shortened answer says only what the entry reading reads (T-776).

It is said where the reading finds the shortener's map in the entry's own
answer (``schemas.entry_reading``), whatever else it reads of the entry (a
failed answer or a repeat may hold one), of the first three rows of the map
with something left out, as the map orders and records them: a row counting
rows left out in rows, any other in characters, the ``others`` row so too.
Never of a row it records nothing left out of or a count that is no count,
and never raising. Every tool name and path here is a neutral synthetic
value.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.reporting.ledger_report import build_sections, shortened_sentence
from malspark.schemas.entry_reading import CHARACTERS, ELEMENTS, entry_reading
from malspark.schemas.evidence import LedgerEntry

PREFIX = "This answer was shortened to fit the analyst's budget: "


def _entry(answer: dict[str, Any], **kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0012",
        tool="list_texts",
        agent="reader_one",
        args={},
        output=json.dumps(answer),
        **kw,
    )


ANSWER = {
    "rows": [{"text": "a"}, {"text": "b"}],
    "blob": "x" * 10,
    "note": "y" * 5,
    "tail": "z" * 3,
    "shortened": {
        "/rows": {"kept": 2, "omitted": 221},
        "/blob": {"kept_chars": 10, "omitted_chars": 990},
        "/note": {"kept_chars": 5, "omitted_chars": 95},
        "/tail": {"kept_chars": 3, "omitted_chars": 7},
    },
    "truncated": True,
}


def test_the_reading_names_the_map_s_paths_in_its_order() -> None:
    read = entry_reading(_entry(ANSWER, truncated=True))
    assert read.shortened_rows == (
        ("/rows", 221, ELEMENTS),
        ("/blob", 990, CHARACTERS),
        ("/note", 95, CHARACTERS),
        ("/tail", 7, CHARACTERS),
    )


def test_a_shortened_answer_names_the_first_three_paths_the_map_names() -> None:
    assert shortened_sentence(_entry(ANSWER, truncated=True)) == (
        PREFIX + "/rows (221 rows not shown), /blob (990 characters not shown), "
        "/note (95 characters not shown)."
    )


def test_the_section_carries_the_sentence() -> None:
    sections = build_sections([_entry(ANSWER, truncated=True)])
    assert any(PREFIX in section.text for section in sections)


def test_a_failed_answer_holding_the_map_is_said_shortened() -> None:
    assert shortened_sentence(_entry(ANSWER, truncated=True, ok=False)).startswith(
        PREFIX + "/rows (221 rows not shown)"
    )


def test_a_repeat_holding_the_map_is_said_shortened() -> None:
    said = shortened_sentence(_entry(ANSWER, structured=ANSWER, repeated_of="ev_0001"))
    assert said.startswith(PREFIX + "/rows (221 rows not shown)")


def test_a_map_of_the_others_row_alone_says_its_rows() -> None:
    answer = {"rows": [1], "shortened": {"others": {"paths": 3, "omitted": 4, "omitted_chars": 9}}}
    assert shortened_sentence(_entry(answer)) == PREFIX + "others (4 rows not shown)."


def test_a_row_counting_rows_and_characters_is_said_in_rows() -> None:
    answer = {"a": [1], "shortened": {"/a": {"omitted": 3, "omitted_chars": 10}}}
    assert shortened_sentence(_entry(answer)) == PREFIX + "/a (3 rows not shown)."


def test_a_map_recording_nothing_left_out_says_nothing() -> None:
    zero = {"a": "x", "shortened": {"/a": {"kept_chars": 1, "omitted_chars": 0}}}
    truth = {"a": "x", "shortened": {"/a": {"kept_chars": 1, "omitted_chars": True}}}
    others = {"a": "x", "shortened": {"others": {"paths": 3, "omitted": 0, "omitted_chars": 9}}}
    for answer in (zero, truth, others):
        assert shortened_sentence(_entry(answer)) == ""


def test_the_others_row_counting_no_rows_is_not_said() -> None:
    answer = {
        "blob": "x" * 10,
        "shortened": {
            "others": {"paths": 40, "omitted": 0, "omitted_chars": 400},
            "/blob": {"kept_chars": 10, "omitted_chars": 990},
        },
        "truncated": True,
    }
    assert shortened_sentence(_entry(answer, truncated=True)) == (
        PREFIX + "/blob (990 characters not shown)."
    )


def test_a_count_that_is_no_count_never_raises_and_names_nothing() -> None:
    answer = {
        "blob": "x" * 10,
        "note": "y" * 5,
        "shortened": {
            "/blob": {"kept_chars": "ten", "omitted_chars": "many"},
            "/note": {"kept_chars": 5, "omitted_chars": 95},
        },
        "truncated": True,
    }
    assert shortened_sentence(_entry(answer, truncated=True)) == (
        PREFIX + "/note (95 characters not shown)."
    )


def test_an_answer_not_shortened_says_nothing() -> None:
    assert shortened_sentence(_entry({"rows": [1, 2]})) == ""


def test_an_answer_nested_past_the_decoder_says_nothing_and_never_raises() -> None:
    deep = LedgerEntry(
        id="ev_0013", tool="list_texts", agent="reader_one", args={}, output="[" * 50_000
    )
    assert shortened_sentence(deep) == ""
