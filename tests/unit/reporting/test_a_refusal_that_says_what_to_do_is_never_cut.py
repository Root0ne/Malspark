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
from malspark.pipeline import events
from malspark.pipeline.events import FINDING_VALUE_LIMIT, safe_finding_value
from malspark.pipeline.validation import (
    ABSENCE_CONTRADICTS_LEDGER_CODE,
    CITATION_NOT_EVIDENCE_CODE,
    CITATION_WRONG_ENTRY_CODE,
    ENTRY_CONTENTS_MISSTATED_CODE,
    WRONG_ENTRY_ENDS,
    EntryTexts,
    Violation,
    citation_violations,
    ledger_absence_contradictions,
    misstated_entry_contents,
    wrong_entry_citations,
)
from malspark.reporting.section_agreement import (
    agreement_violations,
    passages_of,
    rewrites_violations,
)
from malspark.schemas.evidence import LedgerEntry
from tests.credential_shapes import prefixed_key
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


def _through_the_round(raised: list[Violation], ledger: list[Any]) -> list[Any]:
    """The round's refusals of a rewrite whose checks raised ``raised``."""
    subject = SUBJECTS["limitations"]
    passages = passages_of(_report_of(subject), entries=ledger)
    row = _row(
        subject, "rewrite", ["string_resolution"], rewrite=f"The gate reads a reply [{_CITED}]."
    )
    payload = {"sentences": [row, *_others(subject, passages)]}
    citable = [str(entry.id) for entry in ledger]
    with patch.object(agreement, "_rewrite_violations", return_value=raised):
        return rewrites_violations(payload, citable, None, EntryTexts.from_ledger(ledger), passages)


def _wrong_entry(found: list[Any]) -> Any:
    (one,) = [v for v in found if v.code == CITATION_WRONG_ENTRY_CODE]
    return one


def _one(found: list[Any], code: str) -> Any:
    (one,) = [v for v in found if v.code == code]
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


# A tool name longer than the stored runs' longest, and eight holders and twelve cited entries
# of it: more than one finding names, so each list ends on how many more there are.
_LONG_TOOL = "extract_iocs_with_context_long_name"
_CITED_TOOL = "extract_iocs_with_context"
_HOLDERS = [f"ev_{20 + n:04d}" for n in range(8)]
_MANY_CITED = [f"ev_{40 + n:04d}" for n in range(12)]


def _long_lists(value: str, tools: dict[str, str] | None = None) -> tuple[Any, list[Any]]:
    tools = tools or {}
    ledger = [
        *_ledger(),
        *(
            LedgerEntry(id=ref, tool=tools.get(ref, _LONG_TOOL), output=f"{value}\nother text\n")
            for ref in _HOLDERS
        ),
        *(
            LedgerEntry(id=ref, tool=_CITED_TOOL, output="a reply of no note\n")
            for ref in _MANY_CITED
        ),
    ]
    raised = wrong_entry_citations(
        {"items": [{"key": "Reply", "value": value, "evidence_refs": _MANY_CITED}]},
        EntryTexts.from_ledger(ledger),
    )
    return _wrong_entry(_through_the_round(raised, ledger)), ledger


@pytest.mark.parametrize("length", [10, 5000])
def test_long_id_lists_are_bounded_by_count_and_every_id_shown_stands_whole(length: int) -> None:
    value = _value(length)

    found, _ledger_used = _long_lists(value)

    holders = ", ".join(f"{ref} ({_LONG_TOOL})" for ref in _HOLDERS[:6])
    assert f"it was found whole in {holders} and 2 more." in found.message
    cited = ", ".join(f"{ref} ({_CITED_TOOL})" for ref in _MANY_CITED[:6])
    assert f"in the answers of {cited} and 6 more, which its record cites" in found.message
    for unshown in (*_HOLDERS[6:], *_MANY_CITED[6:]):
        assert unshown not in found.message
    assert found.message.endswith(WRONG_ENTRY_ENDS)
    assert value not in found.message or length <= FINDING_VALUE_LIMIT
    quoted = found.message.removeprefix("row 1: ").split(" was not found as a whole value")[0]
    assert len(quoted) <= FINDING_VALUE_LIMIT + 1


@pytest.fixture
def configured_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """A credential-shaped value registered as the worker registers a job's settings."""
    key = prefixed_key("ghs_")
    monkeypatch.setattr(events, "_SECRET_SCOPES", {})
    monkeypatch.setattr(events, "_SHORT_SECRETS", {})
    monkeypatch.setattr(events, "_FAILED_SCOPES", set())
    monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
    events.remember_secret_values([key], scope="job")
    return key


def test_a_credential_in_a_tool_name_of_a_long_list_is_still_masked(configured_key: str) -> None:
    found, _ledger_used = _long_lists(_value(10), {_HOLDERS[1]: configured_key})

    assert configured_key not in found.message
    assert f"{_HOLDERS[1]} (" in found.message
    assert f"{_HOLDERS[0]} ({_LONG_TOOL})" in found.message
    assert found.message.endswith(WRONG_ENTRY_ENDS)


def test_a_credential_in_an_id_position_is_still_masked(configured_key: str) -> None:
    entries = EntryTexts(tools={configured_key: _LONG_TOOL, "ev_0020": configured_key})

    for ref in (configured_key, "ev_0020"):
        assert configured_key not in safe_finding_value(entries.named_whole(ref), whole=True)


def _long_record(length: int, said: str) -> list[dict[str, Any]]:
    """A record whose value field carries ``said`` with a long run of words inside it."""
    return [{"key": "Reply", "value": said.format(words=_value(length))}]


@pytest.mark.parametrize("length", [10, 5000])
def test_an_id_the_answer_was_not_shown_stands_whole_beside_a_long_value(length: int) -> None:
    ledger = _ledger()
    records = _long_record(length, "{words} as ev_0999 reads it")
    raised = citation_violations(
        {"items": [{**records[0], "evidence_refs": [_CITED]}]},
        [str(entry.id) for entry in ledger],
        records=True,
    )

    found = _one(_through_the_round(raised, ledger), CITATION_NOT_EVIDENCE_CODE)

    assert found.message.startswith("row 1: ev_0999 is not an entry this answer was shown. ")
    assert found.message.endswith("— or leave that id out.")
    assert len(found.message) <= 600


@pytest.mark.parametrize("length", [10, 5000])
def test_a_misstated_entry_stands_whole_beside_a_long_value(length: int) -> None:
    ledger = _ledger()
    said = "Entry ev_0107 is empty, {words} [ev_0107]."
    raised = misstated_entry_contents(
        {"items": _long_record(length, said)}, EntryTexts.from_ledger(ledger)
    )

    found = _one(_through_the_round(raised, ledger), ENTRY_CONTENTS_MISSTATED_CODE)

    assert found.message.startswith("row 1: The text says ev_0107 (lift_routine) holds nothing (")
    assert "ev_0107 (lift_routine) holds 8 values in this run." in found.message
    assert found.message.endswith(
        "State what the entry holds, or cite the entry the statement is about."
    )
    assert len(found.message) <= 600


@pytest.mark.parametrize("length", [10, 5000])
def test_an_absence_the_ledger_contradicts_stands_whole_beside_a_long_value(length: int) -> None:
    ledger = _ledger()
    said = "Routine 0x5a10 was not read, {words} [ev_0107]."
    raised = ledger_absence_contradictions(
        {"items": _long_record(length, said)}, EntryTexts.from_ledger(ledger)
    )

    found = _one(_through_the_round(raised, ledger), ABSENCE_CONTRADICTS_LEDGER_CODE)

    assert found.message.startswith("row 1: The text says 0x5a10 was not read (")
    assert "ev_0107 (lift_routine) holds it in this run." in found.message
    assert found.message.endswith("State what that entry shows, or say exactly what is absent.")
    assert len(found.message) <= 600


@pytest.mark.parametrize("length", [10, 5000])
def test_a_refusal_built_on_a_row_answer_is_passed_whole(length: int) -> None:
    value = _value(length)
    subject = SUBJECTS["limitations"]
    ledger = [
        *_ledger(),
        *(LedgerEntry(id=ref, tool=_LONG_TOOL, output=f"{value}\n") for ref in _HOLDERS),
        *(
            LedgerEntry(id=ref, tool=_CITED_TOOL, output="a reply of no note\n")
            for ref in _MANY_CITED
        ),
    ]
    entries = EntryTexts.from_ledger(ledger)
    raised = wrong_entry_citations(
        {"items": [{"key": "Reply", "value": value, "evidence_refs": _MANY_CITED}]}, entries
    )
    passages = [
        replace(p, check=lambda _text: raised) if p.id == subject.pid else p
        for p in passages_of(_report_of(subject), entries=ledger)
    ]
    row = _row(
        subject, "rewrite", ["string_resolution"], rewrite=f"The gate reads a reply [{_CITED}]."
    )
    payload = {"sentences": [row, *_others(subject, passages)]}

    found = _wrong_entry(
        agreement_violations(payload, passages, [str(e.id) for e in ledger], None, entries)
    )

    assert found.message.startswith(f"row 1: the rewrite of {subject.pid}: ")
    holders = ", ".join(f"{ref} ({_LONG_TOOL})" for ref in _HOLDERS[:6])
    assert f"it was found whole in {holders} and 2 more." in found.message
    assert found.message.endswith(WRONG_ENTRY_ENDS)
    assert len(found.message) <= 2 * FINDING_VALUE_LIMIT + 1200
