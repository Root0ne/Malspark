"""A sentence calling the text at a data address not decoded is read against the ledger (T-652).

haiku13's section 5 said "The texts at 0xf9a0, 0xf9b0 and 0xf9d8 are not decoded
in the analysed sample's string recovery" while a listing showed routine 0x33ac
passing those three addresses to the decoder, and the function index tied 0x33ac
to a decoded format text no sentence quoted. The round read texts by their value
only, never by where they are stored, so the sentence was not held.

A negated clause writing a word a text is held under that names a data address a
routine's listing names after a declared data label, where no decoded row holds
a text at it, now holds the sentence on a ``ledger.N`` fact stating only what the
ledger holds: which routine passes which addresses to which routine, the texts the
index ties to it, and that no decoded row holds a text there. A routine's own
address is no data address, and an address a decoded row holds a text at holds
nothing. Every address, entry and text here is a neutral synthetic value.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from malspark.reporting.agreement_facts import ledger_facts
from malspark.reporting.ledger_entities import RunNames, TextHeld, hold_data, run_names
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    _NAMES_PER_QUESTION,
    _hold_listed_data,
    _text_at_fact,
    name_readings,
    passages_of,
)
from malspark.schemas.evidence import LedgerEntry

BASE = 0x2470000
ROUTINE, DECODER, HELPER = BASE + 0x33AC, BASE + 0xAE78, BASE + 0x6100
STORED = (BASE + 0xF9A0, BASE + 0xF9B0, BASE + 0xF9D8)
DECODED = BASE + 0xF988
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_INDEX = {"v": 1, "kind": "function_index", "reader": "function_table"}
_BLOBS = {
    "v": 1,
    "kind": "decoded_strings",
    "rows": "/results/*",
    "places": {"rva": "/rva"},
    "values": {"text": "/text"},
}

DENIED = (
    "The texts at 0xf9a0, 0xf9b0 and 0xf9d8 are not decoded in the analysed sample's string "
    "recovery, so their values are not stated here."
)
FACT = (
    "the routine at offset 0x33ac names the data at offsets 0xf9a0, 0xf9b0, 0xf9d8, each on a "
    "line that calls the routine at offset 0xae78 (ev_0086); the function index (ev_0025) ties "
    "to that routine the "
    'texts "%s %s" (ev_0019), "Updater" (ev_0021); no decoded row holds a text at offsets '
    "0xf9a0, 0xf9b0, 0xf9d8 (ev_0021)"
)


def _index(base: int | None = BASE) -> LedgerEntry:
    rows = [
        {
            "function": hex(ROUTINE),
            "callees": [hex(DECODER), hex(HELPER)],
            "decoded_strings": [
                {"text": "%s %s", "sources": ["ev_0019"]},
                {"text": "Updater", "sources": ["ev_0021"]},
            ],
        },
        {"function": hex(DECODER), "callees": []},
        {"function": hex(HELPER), "callees": []},
    ]
    data: dict[str, Any] = {"rows": rows, "other_callees": {}, "resolved_slots": {}}
    if base is not None:
        data["image_base"] = hex(base)
    return LedgerEntry(
        id="ev_0025", tool="routine_table", args={}, output=json.dumps(data), facts=_INDEX
    )


def _ledger(
    decoded: tuple[int, ...] = (DECODED,),
    base: int | None = BASE,
    other_base: int | None = None,
    text: str = "Updater",
) -> list[LedgerEntry]:
    body = "\n".join(
        [
            f"  FUN_{DECODER:x}((int *)&DAT_{DECODED:x},buf);",
            *(f"  FUN_{DECODER:x}((int *)&DAT_{at:x},buf);" for at in STORED),
            # A routine's own address under a data label is no datum.
            f"  FUN_{HELPER:x}(&DAT_{HELPER:x});",
            "  return 0;",
        ]
    )
    blobs = {"results": [{"rva": hex(at - BASE), "text": text} for at in decoded]}
    other = (
        [LedgerEntry(id="ev_0001", tool="image_facts", output=json.dumps(image), structured=image)]
        if other_base is not None and (image := {"image_base": hex(other_base)})
        else []
    )
    return [
        *other,
        LedgerEntry(id="ev_0019", tool="emulate_strings", output="{}"),
        LedgerEntry(
            id="ev_0021",
            tool="decode_blobs",
            output=json.dumps(blobs),
            structured=blobs,
            facts=_BLOBS,
        ),
        _index(base),
        LedgerEntry(
            id="ev_0086",
            tool="lift_routine",
            args={"address": hex(ROUTINE)},
            output=f"int FUN_{ROUTINE:x}(void)\n{{\n{body}\n}}\n",
            facts=_DECOMPILE,
        ),
    ]


def _report(sentence: str = DENIED) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            persistence_detail=TechnicalSubsection(
                title="Persistence",
                body=f"Routine 0x33ac installs the copy [ev_0086]. {sentence}",
                evidence_refs=["ev_0086"],
            ),
        ),
    )


def _by_id(sentence: str = DENIED, **kw: Any) -> dict[str, Any]:
    return {p.id: p for p in passages_of(_report(sentence), entries=_ledger(**kw))}


def _names(**kw: Any) -> RunNames:
    """The run's names with the data its listings name, as the round reads them."""
    ledger = _ledger(**kw)
    found = ledger_facts(ledger)
    names = run_names(ledger, found.image_bases)
    _hold_listed_data(names, found, {e.id: e for e in ledger})
    return names


def test_the_texts_at_data_addresses_a_routine_passes_are_held_on_a_fact() -> None:
    by_id = _by_id()
    passage = by_id["persistence_detail"]
    assert dict(passage.ledger_named) == {DENIED: ("ledger.1",)}
    assert DENIED in passage.absences and DENIED in passage.held
    fact = by_id["ledger.1"]
    assert fact.text == FACT
    assert fact.cites == {"ev_0019", "ev_0021", "ev_0025", "ev_0086"}
    assert fact.speaks_to == (DENIED,)
    assert fact.row_values == ("0xf9a0", "0xf9b0", "0xf9d8")


def test_the_reading_names_the_addresses_as_the_sentence_writes_them() -> None:
    (reading,) = name_readings(DENIED, "", _names())
    assert (reading.kind, reading.shown) == ("data", "0xf9a0, 0xf9b0, 0xf9d8")


def test_a_routine_address_is_no_data_address() -> None:
    names = _names()
    assert names.routine_at(HELPER) and HELPER not in names.data_at
    # haiku10's "command strings decoded in routine 0x2200 are not shown to execute".
    for sentence in (
        "The command strings decoded in routine 0x33ac are not shown to execute.",
        "The text at 0x6100 is not decoded.",
    ):
        assert name_readings(sentence, "", names) == []


def test_nothing_is_held_where_a_decoded_row_holds_a_text_at_the_address() -> None:
    assert name_readings("The text at 0xf988 is not decoded.", "", _names()) == []
    every = (DECODED, *STORED)
    assert name_readings(DENIED, "", _names(decoded=every)) == []
    assert dict(_by_id(decoded=every)["persistence_detail"].ledger_named) == {}


def test_a_denial_writing_no_word_a_text_is_held_under_holds_nothing() -> None:
    assert name_readings("The flag at 0xf9a0 is not set.", "", _names()) == []


def test_the_fact_stays_within_the_name_fact_budget_and_names_six_addresses_at_most() -> None:
    names = RunNames(bases=(BASE,), rows=frozenset({ROUTINE}), index_entry="ev_0025")
    stored = [BASE + 0x20000 + 16 * i for i in range(40)]
    listing = "\n".join(f"  FUN_{DECODER:x}(&DAT_{at:x});" for at in stored)
    hold_data(names, ROUTINE, listing, ("ev_0086",), ("DAT_",))
    sentence = "The texts at " + ", ".join(hex(at - BASE) for at in stored) + " are not decoded."
    (reading,) = name_readings(sentence, "", names)
    fact = _text_at_fact(reading.key, names)
    assert fact is not None
    assert len(fact.values) == 6
    assert fact.text.count(" and 34 more") == 2
    assert len(fact.text) < _NAMES_PER_QUESTION // 40


def test_a_line_naming_a_datum_and_a_routine_is_said_as_that_never_as_passing() -> None:
    names = RunNames(
        bases=(BASE,),
        rows=frozenset({ROUTINE, DECODER}),
        callees={ROUTINE: (DECODER,)},
        index_entry="ev_0025",
    )
    stored = BASE + 0xF9A0
    hold_data(names, ROUTINE, f"  DAT_{stored:x} = FUN_{DECODER:x}(buf);", ("ev_0086",), ("DAT_",))
    (reading,) = name_readings("The text at 0xf9a0 is not decoded.", "", names)
    fact = _text_at_fact(reading.key, names)
    assert fact is not None
    assert fact.text == (
        "the routine at offset 0x33ac names the data at offset 0xf9a0 on a line that calls the "
        "routine at offset 0xae78 (ev_0086); the function index (ev_0025) ties no text to that "
        "routine; no decoded row holds a text at offset 0xf9a0"
    )


def test_only_the_index_s_callees_are_said_called() -> None:
    names = RunNames(bases=(BASE,), rows=frozenset({ROUTINE}), callees={ROUTINE: ()})
    other = BASE + 0x7700
    hold_data(names, ROUTINE, f"  FUN_{other:x}(&DAT_{BASE + 0xF9A0:x});", ("ev_0086",), ("DAT_",))
    assert names.refs_of[ROUTINE].addresses == {BASE + 0xF9A0: {}}


def test_a_routine_the_index_lists_only_as_called_is_no_data_address() -> None:
    called = BASE + 0x7700
    names = RunNames(bases=(BASE,), rows=frozenset({ROUTINE}), called=frozenset({called}))
    hold_data(names, ROUTINE, f"  FUN_x(&DAT_{called:x});", ("ev_0086",), ("DAT_",))
    assert names.routine_at(called) and called not in names.data_at


def test_a_decoded_row_with_no_text_holds_no_text() -> None:
    names = _names(decoded=STORED, text="  ")
    assert not any(names.decoded(at) for at in STORED)
    (reading,) = name_readings(DENIED, "", names)
    assert reading.kind == "data"


def test_the_texts_past_the_cap_are_counted() -> None:
    names = RunNames(bases=(BASE,), rows=frozenset({ROUTINE}), index_entry="ev_0025")
    for i in range(8):
        key = f"text{i}"
        names.texts[key] = TextHeld(text=key, routines={ROUTINE: None})
        names.texts_of.setdefault(ROUTINE, []).append(key)
    hold_data(names, ROUTINE, f"  FUN_x(&DAT_{BASE + 0xF9A0:x});", ("ev_0086",), ("DAT_",))
    (reading,) = name_readings("The text at 0xf9a0 is not decoded.", "", names)
    fact = _text_at_fact(reading.key, names)
    assert fact is not None
    assert '"text5" and 2 more; no decoded row' in fact.text


def test_a_decoded_row_s_offset_and_a_listing_s_address_are_one_place_with_one_base() -> None:
    # One base: the row's offset and the listing's virtual address are one spelling.
    assert name_readings(DENIED, "", _names(decoded=STORED)) == []
    assert _names(decoded=STORED).decoded(STORED[0])


def test_with_no_base_or_two_bases_nothing_is_said_of_where_no_row_holds_a_text() -> None:
    # With no base the row's offset and the listing's address cannot be told one place, so a
    # sentence denying texts the rows do hold is not held on "no decoded row holds a text".
    written = "The texts at " + ", ".join(hex(at) for at in STORED) + " are not decoded."
    for kw in ({"base": None}, {"other_base": 0x10000000}):
        names = _names(decoded=STORED, **kw)
        assert len(names.bases) != 1, kw
        assert STORED[0] in names.data_at, kw
        for sentence in (DENIED, written):
            assert name_readings(sentence, "", names) == [], (kw, sentence)
        names = _names(**kw)
        assert name_readings(written, "", names) == [], kw
    # With no decoded answer at all there is nothing to reconcile: a sentence writing the
    # listing's own addresses is held.
    names = _names(base=None)
    names.decoded_entries.clear()
    names.decoded_at.clear()
    assert [r.kind for r in name_readings(written, "", names)] == ["data"]
