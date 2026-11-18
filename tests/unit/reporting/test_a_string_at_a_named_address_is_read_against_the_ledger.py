"""A sentence naming an address at which a strings row of the ledger starts is shown that row.

A strings row states a file offset; the file's own section table places it at an offset
from the image base (``evidence_roots.placed_texts``). Where a sentence of a writable
passage writes an address at which such a row starts, the round is shown a ``ledger.N``
fact stating that the ledger holds a string there, its text and the entries holding it. A
negated sentence is held on it, so "the text behind that address was not recovered" is no
longer kept on a reason while the fact answers it. Nothing is shown for a row in a section
its file marks as code (bytes of code a strings pass read as printable), for a row whose
tool declares no file offset, or where no section table places the offset. Every address,
entry and text here is a neutral synthetic value.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from malspark.analysis.evidence_roots import placed_texts
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    FACT,
    KEEP_UNQUOTED_CODE,
    agreement_violations,
    passages_of,
)
from malspark.schemas.evidence import LedgerEntry
from tests.unit.analysis.test_corroboration_counts_evidence_roots import BASE, SECTIONS

# The fixture's section table, each section marked as its parser writes it.
_MARKED = [
    {**SECTIONS[0], "characteristics": "EXECUTE|READ|CODE"},
    {**SECTIONS[1], "characteristics": "READ|WRITE|INITIALIZED_DATA"},
]
_LAYOUT = {"v": 1, "kind": "format_info", "reader": "pe_header"}
_STRINGS = {
    "v": 1,
    "kind": "strings",
    "rows": "/strings/*",
    "places": {"offset": "/offset"},
    "values": {"text": "/text"},
}
# File offset 0x4410 lies in .data (raw 0x4400, offset 0x5000): offset 0x5010.
DATA_AT = BASE + 0x5010
# File offset 0x500 lies in .text (raw 0x400, offset 0x1000): offset 0x1100.
CODE_AT = BASE + 0x1100

DENIED = f"The module name behind {DATA_AT:#x} was not recovered as text."
STATED = f"The loader passes the name at {DATA_AT:#x} to the module loader."
FACT_TEXT = (
    'the ledger holds a string at offset 0x5010: "netapi.dll" (ev_0003), its row read at '
    "file offset 0x4410 in section .data"
)


def _ledger(
    sections: list[dict[str, Any]] | None = None,
    strings: dict[str, Any] | None = None,
    layout: bool = True,
) -> list[LedgerEntry]:
    rows = {
        "strings": [{"offset": 0x4410, "text": "netapi.dll"}, {"offset": 0x500, "text": "AVSH"}]
    }
    image = {"image_base": hex(BASE), "sections": _MARKED if sections is None else sections}
    return [
        *(
            [LedgerEntry(id="ev_0002", tool="image_facts", structured=image, facts=_LAYOUT)]
            if layout
            else []
        ),
        LedgerEntry(
            id="ev_0003",
            tool="text_runs",
            structured=rows,
            facts=_STRINGS if strings is None else strings,
        ),
    ]


def _report(body: str = "", limitations: str = "") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            string_resolution=TechnicalSubsection(
                title="API and String Resolution",
                body=f"Routine 0x2200 resolves its imports by name [ev_0003]. {body}".strip(),
                evidence_refs=["ev_0003"],
            ),
            **(
                {"analyst_limitations": TechnicalSubsection(title="Limitations", body=limitations)}
                if limitations
                else {}
            ),
        ),
    )


def _string_facts(passages: list[Any]) -> list[Any]:
    return [p for p in passages if p.kind == FACT and "holds a string at" in p.text]


def test_a_text_row_is_placed_through_the_file_s_section_table() -> None:
    _layouts, placed = placed_texts(_ledger())
    assert [(p.file, hex(p.rva), hex(p.offset), p.section, p.text, p.entry) for p in placed] == [
        ("", "0x5010", "0x4410", ".data", "netapi.dll", "ev_0003")
    ]


def test_a_denial_naming_the_address_is_held_on_the_fact() -> None:
    passages = passages_of(_report(DENIED), entries=_ledger())
    by_id = {p.id: p for p in passages}
    (fact,) = _string_facts(passages)
    assert fact.text == FACT_TEXT
    assert fact.cites == frozenset({"ev_0003"})
    assert fact.speaks_to == (DENIED,)
    assert {DATA_AT, 0x5010} <= fact.addresses
    passage = by_id["string_resolution"]
    assert dict(passage.ledger_named) == {DENIED: (fact.id,)}
    assert DENIED in passage.absences and DENIED in passage.held


def test_a_sentence_denying_nothing_is_shown_the_fact_and_not_held() -> None:
    passages = passages_of(_report(STATED), entries=_ledger())
    (fact,) = _string_facts(passages)
    assert fact.speaks_to == (STATED,)
    assert dict(next(p for p in passages if p.id == "string_resolution").ledger_named) == {}


def test_no_fact_for_a_row_in_a_section_marked_as_code() -> None:
    sentence = f"The text behind {CODE_AT:#x} was not recovered."
    assert _string_facts(passages_of(_report(sentence), entries=_ledger())) == []
    # Marked by its flag bits as well as by their names.
    as_bits = [{**_MARKED[0], "characteristics": 0x60000020}, _MARKED[1]]
    assert [p.section for p in placed_texts(_ledger(sections=as_bits))[1]] == [".data"]
    unmarked = [dict(SECTIONS[0]), _MARKED[1]]
    assert [p.section for p in placed_texts(_ledger(sections=unmarked))[1]] == [".data", ".text"]


def test_no_fact_where_the_offset_is_undeclared_or_no_section_table_places_it() -> None:
    undeclared = {k: v for k, v in _STRINGS.items() if k != "places"}
    by_rva = {**_STRINGS, "places": {"rva": "/offset"}}
    for ledger in (
        _ledger(strings=undeclared),
        _ledger(strings=by_rva),
        _ledger(layout=False),
        _ledger(sections=[]),
    ):
        assert placed_texts(ledger)[1] == []
        assert _string_facts(passages_of(_report(DENIED), entries=ledger)) == []


def _keep(passage: str, sentence: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "sources": [],
        "decision": "keep",
        "rewrite": "",
        "reason": "no source speaks of it",
        "quote": "",
    }


def test_a_keep_on_the_reason_is_refused_where_the_fact_speaks_of_the_absence() -> None:
    for report, passage in (
        (_report(DENIED), "string_resolution"),
        (_report("", DENIED), "limitations"),
    ):
        keep = {"sentences": [_keep(passage, DENIED)]}
        spoken = agreement_violations(keep, passages_of(report, entries=_ledger()))
        assert KEEP_UNQUOTED_CODE in {v.code for v in spoken}, passage
        # Without the row the keep on the reason stands, as before.
        silent = agreement_violations(keep, passages_of(report, entries=_ledger(layout=False)))
        assert KEEP_UNQUOTED_CODE not in {v.code for v in silent}, passage


def test_a_file_offset_the_sentence_states_is_placed_as_a_file_offset() -> None:
    # File offset 0x4410 is placed at offset 0x5010, where the row starts.
    denied = "The module name at file offset 0x4410 was not recovered as text."
    passages = passages_of(_report(denied), entries=_ledger())
    (fact,) = _string_facts(passages)
    assert fact.text == FACT_TEXT
    assert dict(next(p for p in passages if p.id == "string_resolution").ledger_named) == {
        denied: (fact.id,)
    }


def test_a_file_offset_is_never_read_as_an_offset_from_the_image_base() -> None:
    # 0x5010 as a file offset lies elsewhere in .data, where no row starts; the row
    # at offset 0x5010 from the image base is not that place.
    for sentence in (
        "The text at file offset 0x5010 was not recovered.",
        # A file offset no section of the file holds names no row.
        "The text at file offset 0x9f000 was not recovered.",
    ):
        assert _string_facts(passages_of(_report(sentence), entries=_ledger())) == [], sentence


def test_a_string_fact_is_labelled_by_what_it_is() -> None:
    (fact,) = _string_facts(passages_of(_report(STATED), entries=_ledger()))
    assert fact.label == "what the run's answers hold at an address a sentence names"


def test_a_held_denial_keeps_its_fact_within_the_budget(monkeypatch: Any) -> None:
    from malspark.reporting import section_agreement

    # A second row in .data: file offset 0x4420 is placed at offset 0x5020.
    ledger = _ledger()
    ledger[1] = ledger[1].model_copy(
        update={
            "structured": {
                "strings": [
                    {"offset": 0x4410, "text": "netapi.dll"},
                    {"offset": 0x4420, "text": "samlib.dll"},
                ]
            }
        }
    )
    stated = f"The loader passes the name at {BASE + 0x5020:#x} to the module loader."
    # Room for one fact: the sentence denying nothing comes first and is shown only.
    monkeypatch.setattr(section_agreement, "_NAMES_PER_QUESTION", len(FACT_TEXT) + 10)
    passages = passages_of(_report(f"{stated} {DENIED}"), entries=ledger)
    (fact,) = _string_facts(passages)
    assert fact.text == FACT_TEXT
    assert dict(next(p for p in passages if p.id == "string_resolution").ledger_named) == {
        DENIED: (fact.id,)
    }
