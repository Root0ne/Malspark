"""A refusal of the agreement round that says what to do is never cut before it says it.

The round bounds each finding it passes on to fit a finding row. A finding whose message is
the platform's words around values each bounded where they were written, ending on what to
do (``Violation.instructs``), is passed whole: the entries it names and the instruction stand
in the refusal however long the value it quotes, and the value itself stays bounded. Every
entry and value here is a neutral synthetic one.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest

import malspark.reporting.section_agreement as agreement
from malspark.pipeline.events import FINDING_VALUE_LIMIT
from malspark.pipeline.validation import (
    CITATION_WRONG_ENTRY_CODE,
    WRONG_ENTRY_ENDS,
    EntryTexts,
    wrong_entry_citations,
)
from malspark.reporting.section_agreement import passages_of, rewrites_violations
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting.test_every_refusal_offers_only_the_ends_that_pass import (
    SUBJECTS,
    _ledger,
    _others,
    _report_of,
    _row,
)

_HOLDER = "ev_0120"
_CITED = "ev_0107"


def _value(length: int) -> str:
    """A value of ``length`` characters, written as words."""
    words = ("gate", "host", "mode", "table", "reply", "word")
    out: list[str] = []
    while len(" ".join(out)) < length:
        out.append(f"{words[len(out) % len(words)]}{len(out)}")
    return " ".join(out)[:length].strip()


def _refusals(value: str) -> list[Any]:
    subject = SUBJECTS["limitations"]
    ledger = [
        *_ledger(),
        LedgerEntry(id=_HOLDER, tool="strings", output=f"{value}\nother text\n"),
    ]
    passages = passages_of(_report_of(subject), entries=ledger)
    row = _row(
        subject,
        "rewrite",
        ["string_resolution"],
        rewrite=f"The gate reads `{value}` [{_CITED}].",
    )
    payload = {"sentences": [row, *_others(subject, passages)]}
    citable = [str(entry.id) for entry in ledger]
    return rewrites_violations(payload, citable, None, EntryTexts.from_ledger(ledger), passages)


def _recorded(value: str) -> list[Any]:
    """The same finding raised by a record whose whole value is ``value``.

    A sentence's quoted value is read up to 300 characters; a record's value field is read
    whole, so a value of any length reaches the message through it. The round is handed that
    finding as one its rewrite checks raised.
    """
    subject = SUBJECTS["limitations"]
    ledger = [
        *_ledger(),
        LedgerEntry(id=_HOLDER, tool="strings", output=f"{value}\nother text\n"),
    ]
    entries = EntryTexts.from_ledger(ledger)
    raised = wrong_entry_citations(
        {"items": [{"key": "Reply", "value": value, "evidence_refs": [_CITED]}]}, entries
    )
    passages = passages_of(_report_of(subject), entries=ledger)
    row = _row(
        subject, "rewrite", ["string_resolution"], rewrite=f"The gate reads a reply [{_CITED}]."
    )
    payload = {"sentences": [row, *_others(subject, passages)]}
    citable = [str(entry.id) for entry in ledger]
    with patch.object(agreement, "_rewrite_violations", return_value=raised):
        return rewrites_violations(payload, citable, None, entries, passages)


def _wrong_entry(found: list[Any]) -> Any:
    (one,) = [v for v in found if v.code == CITATION_WRONG_ENTRY_CODE]
    return one


@pytest.mark.parametrize("length", [10, 200])
def test_a_sentence_s_value_leaves_the_entries_and_the_instruction_whole(length: int) -> None:
    found = _wrong_entry(_refusals(_value(length)))

    assert found.message.startswith("row 1: ")
    assert f"in the answer of {_CITED} (lift_routine), which the sentence cites" in found.message
    assert f"it was found whole in {_HOLDER} (strings)." in found.message
    assert found.message.endswith(WRONG_ENTRY_ENDS)


@pytest.mark.parametrize("length", [10, 200, 5000])
def test_a_value_of_any_length_leaves_the_entries_and_the_instruction_whole(length: int) -> None:
    value = _value(length)
    assert len(value) >= length - 1

    found = _wrong_entry(_recorded(value))

    assert found.message.startswith("row 1: ")
    assert f"in the answer of {_CITED} (lift_routine), which its record cites" in found.message
    assert f"it was found whole in {_HOLDER} (strings)." in found.message
    assert found.message.endswith(WRONG_ENTRY_ENDS)


def test_the_value_it_quotes_stays_bounded() -> None:
    value = _value(5000)

    found = _wrong_entry(_recorded(value))

    assert value not in found.message
    quoted = found.message.removeprefix("row 1: ").split(" was not found as a whole value")[0]
    assert len(quoted) <= FINDING_VALUE_LIMIT + 1


def test_a_finding_that_says_nothing_to_do_is_still_bounded() -> None:
    value = _value(5000)
    raised = [
        replace(v, instructs=False)
        for v in wrong_entry_citations(
            {"items": [{"key": "Reply", "value": value, "evidence_refs": [_CITED]}]},
            EntryTexts.from_ledger(
                [*_ledger(), LedgerEntry(id=_HOLDER, tool="strings", output=f"{value}\n")]
            ),
        )
    ]
    subject = SUBJECTS["limitations"]
    passages = passages_of(_report_of(subject), entries=_ledger())
    row = _row(
        subject, "rewrite", ["string_resolution"], rewrite=f"The gate reads a reply [{_CITED}]."
    )
    payload = {"sentences": [row, *_others(subject, passages)]}
    with patch.object(agreement, "_rewrite_violations", return_value=raised):
        found = _wrong_entry(
            rewrites_violations(
                payload,
                [str(entry.id) for entry in _ledger()],
                None,
                EntryTexts.from_ledger(_ledger()),
                passages,
            )
        )

    assert len(found.message) <= len("row 1: ") + FINDING_VALUE_LIMIT + 1
