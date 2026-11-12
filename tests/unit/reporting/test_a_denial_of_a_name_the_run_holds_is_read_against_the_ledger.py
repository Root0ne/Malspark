"""A sentence denying something of a name the run holds is read against the ledger.

The limitations said the target of two process calls in a routine "were not
established" while the routine's listing passed the current process id to the
call, said "the decompiler produced no function" at two addresses a later
decompile listed, and called the export that starts the loader not
established beside the export table and its callees; section 5 said resolved
names were not shown being called while the function index listed one of them
called through a slot (T-600). The round was shown none of these facts, so a
keep "on no source" stood. Now a negated sentence naming an API, an export or
a decoded text the run holds is held to what the ledger holds of it, keyed by
the run's own names: the routines calling an API with their call lines and
slots named, the export's address, callees and listing, the routines a text is
tied to. Code decides none of these sentences from their words: each is the
model's to answer, with the fact shown. A limitations sentence naming a failed
call a later call redid, by an address it asked for and its tool or kind, or
citing it, and citing no call that redid it, is held to the failed calls, and
a keep of it must cite a call that redid it. Every address, entry and name here
is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from functools import partial
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.agreement_facts import ledger_facts
from malspark.reporting.ledger_entities import (
    RELATION_KEYS,
    ApiCall,
    ApiHeld,
    ExportHeld,
    RunNames,
    TextHeld,
    run_names,
)
from malspark.reporting.limitation_facts import FailedCall
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    ABSENCE_KEPT_CODE,
    DROPPED_CODE,
    FACT,
    FAILURE_REDONE_CODE,
    HELD_UNLISTED_CODE,
    KEEP_UNQUOTED_CODE,
    QUALIFIED_CODE,
    REWRITE_DROPS_CITATION_CODE,
    REWRITE_UNGROUNDED_CODE,
    UNKNOWN_SOURCE_CODE,
    _failure_redone_check,
    _redo_choices,
    _stale_calls,
    _uncited,
    agreement_violations,
    ask_section_agreement,
    held_limitation_sentences,
    name_readings,
    passages_of,
    prompt_text,
    redone_calls_named,
    relation_of,
    repeats_sentence,
)
from malspark.schemas.evidence import LedgerEntry

BASE = 0x2470000
GATE, HELPER, ENTRY, LOADER = BASE + 0x5A10, BASE + 0x6100, BASE + 0x7700, BASE + 0x7720
SLOT, OTHER_SLOT = BASE + 0xB90, BASE + 0xC38
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_INDEX = {"v": 1, "kind": "function_index", "reader": "function_table"}

CALLED = "QueryHostMode"
RESOLVED_ONLY = "EmitTraceLine"
TEXT = "quietmode"


def _lifted(entry_id: str, address: int, body: str, **kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n",
        facts=_DECOMPILE,
        **kw,
    )


def _index() -> LedgerEntry:
    rows = [
        {
            "function": hex(GATE),
            "offset": hex(GATE - BASE),
            "callees": [],
            "slot_calls": [{"name": CALLED, "slot": hex(SLOT), "sources": ["ev_0102"]}],
            "decoded_strings": [{"text": TEXT, "sources": ["ev_0103"]}],
        },
        {
            "function": hex(HELPER),
            "offset": hex(HELPER - BASE),
            "callees": [],
            "resolved": [{"name": RESOLVED_ONLY, "sources": ["ev_0102"]}],
        },
        {
            "function": hex(ENTRY),
            "offset": hex(ENTRY - BASE),
            "callees": [hex(LOADER)],
        },
        {
            "function": hex(LOADER),
            "offset": hex(LOADER - BASE),
            "callees": [hex(GATE)],
        },
    ]
    data = {
        "image_base": hex(BASE),
        "rows": rows,
        "other_callees": {},
        "resolved_slots": {hex(SLOT): CALLED, hex(OTHER_SLOT): "ReadSelfToken"},
    }
    return LedgerEntry(
        id="ev_0109", tool="routine_table", args={}, output=json.dumps(data), facts=_INDEX
    )


def _ledger() -> list[LedgerEntry]:
    body = "\n".join(
        [
            "  int mode;",
            f"  int self = (*_DAT_{OTHER_SLOT:x})();",
            f"  (*_DAT_{SLOT:x})(self,&mode);",
            "  if (mode == 0) { return -1; }",
            "  return 0;",
        ]
    )
    return [
        LedgerEntry(
            id="ev_0101",
            tool="lift_routine",
            args={"address": hex(GATE)},
            ok=False,
            error="no function there",
            facts=_DECOMPILE,
        ),
        LedgerEntry(id="ev_0102", tool="name_hashes", output="{}"),
        LedgerEntry(id="ev_0103", tool="decode_blobs", output="{}"),
        LedgerEntry(
            id="ev_0104",
            tool="file_header",
            structured={"export_rows": [{"rva": hex(ENTRY - BASE), "name": "begin"}]},
        ),
        _lifted("ev_0107", GATE, body),
        _index(),
    ]


def _names() -> Any:
    ledger = _ledger()
    return run_names(ledger, ledger_facts(ledger).image_bases)


def _held(sentence: str, previous: str = "", names: Any = None) -> set[str]:
    """The names a sentence is held on: each a question for the model, never decided."""
    return {r.shown for r in name_readings(sentence, previous, names or _names())}


def test_the_run_s_names_are_read_off_its_answers_by_their_keys() -> None:
    names = _names()
    held = names.api(CALLED)
    assert held is not None
    assert [(c.routine, c.slot) for c in held.calls] == [(GATE, SLOT)]
    assert names.api(RESOLVED_ONLY) is not None and not names.api(RESOLVED_ONLY).calls
    assert names.exports["begin"].address == ENTRY
    assert names.callees[ENTRY] == (LOADER,)
    assert names.slots[OTHER_SLOT] == "ReadSelfToken"
    assert set(names.texts) == {TEXT}


@pytest.mark.parametrize(
    "sentence",
    [
        # What the index states, and what it holds nothing of: both the model's to read.
        f"No routine calls {CALLED}.",
        f"{CALLED} is not called.",
        f"{CALLED} is unresolved.",
        f"Routine 0x5a10 does not call {CALLED}.",
        f"Routine 0x6100 does not call {CALLED}.",
        f"{CALLED} is never called with a remote handle.",
        f"The decryption routine does not call {CALLED}.",
        f"{CALLED} is not used to test for a debugger.",
        # The subject is the rest of the sentence: the clause stating the absence is bare.
        f"The target of the {CALLED} call in 0x5a10, and whether a write follows, "
        "were not established [ev_0109].",
    ],
)
def test_a_denial_of_an_api_the_run_holds_is_held_and_never_decided(sentence: str) -> None:
    (reading,) = name_readings(sentence, "", _names())
    assert (reading.kind, reading.shown, reading.back) == ("api", CALLED, False)
    assert not hasattr(reading, "verdict")


def test_a_denial_of_an_api_the_index_lists_no_call_to_is_held_too() -> None:
    assert _held(f"No routine calls {RESOLVED_ONLY}.") == {RESOLVED_ONLY}


def test_a_name_beside_a_denial_of_something_else_is_not_held() -> None:
    assert _held(f"Emulating 0x5a10 against the {CALLED} value returned no match.") == set()
    assert _held(f"Routine 0x5a10 calls {CALLED}.") == set()


def test_a_denial_of_what_a_run_saw_names_nothing() -> None:
    assert _held(f"{CALLED} was not observed being called in the sandbox.") == set()


def test_a_sentence_pointing_back_is_held_on_the_names_before_it() -> None:
    previous = f"Routine 0x6100 resolves {RESOLVED_ONLY} and {CALLED} by hash."
    sentence = "These names are shown only as resolved; the code does not show them being called."
    readings = name_readings(sentence, previous, _names())
    assert {(r.shown, r.back) for r in readings} == {(RESOLVED_ONLY, True), (CALLED, True)}
    # A sentence naming an address of its own is about it, never the sentence before.
    assert name_readings("Their bytes at 0x5a10 were not read.", previous, _names()) == []


_DENIALS = (
    f"`{CALLED}` is not called.",
    f"No routine calls {CALLED}.",
    f"{CALLED} is never called by any routine.",
    f"No call to {CALLED} is shown.",
)


@pytest.mark.parametrize("sentence", _DENIALS)
@pytest.mark.parametrize("citation", ["[ev_0109]", "[ev_0107][ev_0109]", "(ev_0109)"])
@pytest.mark.parametrize("where", ["start", "after its second word", "middle", "end"])
def test_a_denial_citing_an_entry_anywhere_is_held_on_the_same_names(
    sentence: str, citation: str, where: str
) -> None:
    if where == "after its second word":
        words = sentence.split(" ")
        cited = " ".join([*words[:2], citation, *words[2:]])
    else:
        cited = _cited(sentence, citation, where)
    assert _held(sentence) == {CALLED}
    readings = name_readings(cited, "", _names())
    assert {r.shown for r in readings} == {CALLED}
    # The reading keeps the sentence as written: it is what the model is shown.
    assert {r.sentence for r in readings} == {cited}


@pytest.mark.parametrize("where", ["start", "middle", "end"])
def test_a_sentence_pointing_back_citing_an_entry_is_held_on_the_names_before_it(
    where: str,
) -> None:
    previous = f"Routine 0x6100 resolves {RESOLVED_ONLY} [ev_0107] and {CALLED} by hash."
    sentence = _cited(
        "These names are shown only as resolved; the code does not show them being called.",
        "[ev_0109]",
        where,
    )
    readings = name_readings(sentence, previous, _names())
    assert {(r.shown, r.back) for r in readings} == {(RESOLVED_ONLY, True), (CALLED, True)}


def test_the_export_table_is_named_by_its_word_only_as_what_is_denied() -> None:
    assert _held("Which export the loader calls is not established.") == {"begin"}
    assert _held("The hash set was not reproduced against the export tables of 27 DLLs.") == set()
    # The export table writes "begin": a "Begin" key is none of its names.
    assert _held("No 'Begin' key path appears in the strings read.") == set()


@pytest.mark.parametrize(
    "sentence",
    [
        f"No call to {CALLED}, {RESOLVED_ONLY} or `connect` is shown.",
        f"{CALLED} and {RESOLVED_ONLY} are not called.",
        f"The code calls neither {CALLED} nor {RESOLVED_ONLY}.",
    ],
)
def test_a_sentence_held_on_one_name_is_held_on_every_name_it_writes(sentence: str) -> None:
    assert _held(sentence) == {CALLED, RESOLVED_ONLY}


def test_a_quoted_text_the_run_holds_is_held() -> None:
    assert _held(f"No '{TEXT}' text is decoded.") == {TEXT}
    assert _held(f"No '{TEXT}' text appears in the decoded strings.") == {TEXT}
    # A text the run holds none of is no name of the run's: the sentence is not held.
    assert _held("No 'loudmode' text appears in the decoded strings.") == set()


def _report(limitations: str, background: str = "") -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        intro_background=background,
        technical_analysis=TechnicalAnalysis(
            string_resolution=TechnicalSubsection(
                title="API and String Resolution",
                body="Routine 0x5a10 reads a host mode through a slot [ev_0107].",
                evidence_refs=["ev_0107"],
            ),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
    )


def test_the_round_is_shown_the_call_lines_with_their_slots_named() -> None:
    sentence = (
        f"The target of the {CALLED} call in 0x5a10, and whether a write follows, "
        "were not established [ev_0109]."
    )
    passages = passages_of(_report(sentence), entries=_ledger())
    (fact,) = [p for p in passages if p.kind == FACT and p.id.startswith("ledger.")]
    assert fact.cites == frozenset({"ev_0102", "ev_0107", "ev_0109"})
    assert f"(*_DAT_{SLOT:x})(self,&mode);  /* {SLOT:x} = {CALLED} */" in fact.text
    assert f"/* {OTHER_SLOT:x} = ReadSelfToken */" in fact.text
    assert fact.speaks_to == (sentence,)
    limitations = next(p for p in passages if p.id == "limitations")
    assert dict(limitations.ledger_named) == {sentence: (fact.id,)}
    text = prompt_text(passages)
    assert f"[{fact.id}] what the run's answers hold of a name" in text


def test_the_export_s_fact_names_its_callees_and_theirs() -> None:
    sentence = "Which export the loader calls is not established."
    passages = passages_of(_report(sentence), entries=_ledger())
    (fact,) = [p for p in passages if p.id.startswith("ledger.")]
    assert fact.text.startswith('the export table (ev_0104) names "begin" at offset 0x7700')
    assert "lists it calling offset 0x7720 (which calls offset 0x5a10)" in fact.text


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _keep(passage: str, sentence: str, sources: list[str], reason: str = "") -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "sources": sources,
        "decision": "keep",
        "rewrite": "",
        "reason": reason,
        "quote": "",
    }


def _ask(report: MalwareReport, reporter: _Reporter) -> Any:
    ledger = _ledger()
    return asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )


def test_a_closing_sentence_denying_what_the_ledger_states_is_shown_its_fact() -> None:
    first = "The gate reads a host mode [ev_0107]."
    denied = f"No routine calls {CALLED} [ev_0109]."
    passages = passages_of(_report(f"{first} {denied}"), entries=_ledger())
    fact = next(p for p in passages if p.id.startswith("ledger."))
    assert f'"{denied}" ({fact.id})' in prompt_text(passages)
    # The model answers it: a rewrite on the fact, or a drop with its reason, stands.
    rows = [
        {
            "passage": "limitations",
            "sentence": denied,
            "sources": [fact.id],
            "decision": "rewrite",
            "rewrite": f"Routine 0x5a10 calls {CALLED} through a slot [ev_0107][ev_0109].",
        },
        {**_keep("limitations", denied, [], "the ledger says otherwise"), "decision": "drop"},
    ]
    for row in rows:
        found = agreement_violations({"sentences": [row]}, passages)
        assert [v for v in found if v.path.startswith("sentences.0")] == [], row


def test_a_body_sentence_denying_what_the_ledger_states_is_left_as_the_model_answers() -> None:
    denied = f"No routine calls {CALLED}."
    report = _report("The gate reads a host mode [ev_0107].", background=denied)
    done = _ask(report, _Reporter({"sentences": []}, {"sentences": []}))
    # Held and shown its fact; no row answered it in either turn: code writes nothing in its
    # place and leaves it out, recorded (T-600).
    assert report.intro_background == ""
    assert QUALIFIED_CODE not in {r["code"] for r in done.tally.unresolved}
    assert [r["code"] for r in done.tally.unresolved if r["code"] == DROPPED_CODE] == [DROPPED_CODE]


def test_a_rewrite_still_denying_the_ledger_s_fact_is_not_refused_for_its_words() -> None:
    denied = f"No routine calls {CALLED}."
    passages = passages_of(
        _report("The gate reads a host mode [ev_0107].", denied), entries=_ledger()
    )
    fact = next(p for p in passages if p.id.startswith("ledger."))
    still = {
        "passage": "introduction",
        "sentence": denied,
        "sources": [fact.id],
        "decision": "rewrite",
        "rewrite": f"{CALLED} is not called [ev_0109].",
    }
    found = agreement_violations({"sentences": [still]}, passages)
    assert [v for v in found if v.path.startswith("sentences.0")] == []


def test_a_closing_keep_on_no_source_is_refused_where_a_ledger_fact_speaks_of_it() -> None:
    sentence = (
        f"The target of the {CALLED} call in 0x5a10, and whether a write follows, "
        "were not established [ev_0109]."
    )
    passages = passages_of(_report(sentence), entries=_ledger())
    keep = {"sentences": [_keep("limitations", sentence, [], "no source speaks of it")]}
    assert KEEP_UNQUOTED_CODE in {v.code for v in agreement_violations(keep, passages)}


# ---------------------------------------------------------------------------
# A limitations sentence is held to a failed call a later call redid by the entities it
# names: an address the call asked for with the call's tool or kind, or the call's own
# entry; never by what else it says. A keep must then cite a call that redid it.
# ---------------------------------------------------------------------------

_REDONE = FailedCall(
    entry="ev_0201",
    tool="lift_routine",
    error="no function there",
    asked=(0x2200,),
    redone_by=("ev_0202",),
    lists_code=True,
    kind="decompile",
)
_REDONE_AT_TWO = [
    _REDONE,
    FailedCall(
        entry="ev_0203",
        tool="lift_routine",
        error="no function there",
        asked=(0x1030,),
        redone_by=("ev_0204",),
        lists_code=True,
        kind="decompile",
    ),
]


@pytest.mark.parametrize(
    "sentence",
    [
        # True of the redo's content, and still held: a keep must cite the redo.
        "The decompile of 0x2200 shows no network call.",
        "The decompiled code at 0x2200 does not reference any registry key.",
        "The decompilation of 0x2200 contains no loop.",
        "0x2200, decompiled later, shows no network call.",
        "The network-call search in the decompile of 0x2200 found nothing.",
        "The decompile of 0x2200 calls nothing.",
        # Said of the call's own output.
        "The decompiler produced no function at 0x2200.",
        "The decompiler produced no other function at 0x2200.",
        "Apart from a thunk, the decompiler produced no function at 0x2200.",
        "Lift_routine returned nothing for 0x2200.",
        "The decompiler produced no function at 0x2200, and its bytes were read.",
    ],
)
def test_a_negated_sentence_naming_a_redone_call_by_address_and_kind_is_held(
    sentence: str,
) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == [sentence]
    assert redone_calls_named(sentence, [_REDONE], ()) == [_REDONE]


@pytest.mark.parametrize(
    "sentence",
    [
        "The decompiler produced no function at 0x2200 or 0x1030 [ev_0109].",
        "The function boundaries of 0x2200 and 0x1030 are not confirmed, because the "
        "decompiler produced no function at either address [ev_0109].",
        "The decompiler produced no function at 0x2200 and other 0x1030.",
    ],
)
def test_a_sentence_naming_two_redone_calls_is_held_to_both(sentence: str) -> None:
    assert held_limitation_sentences(sentence, _REDONE_AT_TWO, [], ()) == [sentence]
    assert redone_calls_named(sentence, _REDONE_AT_TWO, ()) == _REDONE_AT_TWO


@pytest.mark.parametrize(
    "sentence",
    [
        # The address alone, or the kind at another address: no redone call is named.
        "The routine at 0x2200 shows no network call.",
        "No network call is made at 0x2200.",
        "The decompiler produced no function at 0x3300.",
        "The decompile of 0x3300 shows no network call.",
        # Not negated.
        "The decompile of 0x2200 shows a network call.",
        # Citing the call that redid it.
        "The decompile of 0x2200 shows no network call [ev_0202].",
        "The decompiler produced no function at 0x2200 [ev_0201][ev_0202].",
    ],
)
def test_a_sentence_naming_no_redone_call_or_citing_its_redo_is_not_held(sentence: str) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == []


def test_a_negated_sentence_citing_a_redone_call_and_not_its_redo_is_held() -> None:
    cited = "The analysis did not stop [ev_0201]."
    assert held_limitation_sentences(cited, [_REDONE], [], ()) == [cited]
    assert redone_calls_named(cited, [_REDONE], ()) == [_REDONE]


def test_a_sentence_citing_one_redo_is_held_to_the_other_call_only() -> None:
    sentence = "The decompiler produced no function at 0x2200 or 0x1030 [ev_0202]."
    assert redone_calls_named(sentence, _REDONE_AT_TWO, ()) == [_REDONE_AT_TWO[1]]


def test_an_uncited_keep_is_refused_naming_the_redo_to_cite() -> None:
    check = _failure_redone_check([_REDONE], [], (), {})
    for sentence in (
        "The decompiler produced no function at 0x2200.",
        "The decompile of 0x2200 shows no network call.",
    ):
        (found,) = check(sentence, [], "")
        assert found.code == FAILURE_REDONE_CODE
        assert found.message == (
            "it names a call that failed and a later call redid (ev_0201 by ev_0202) and "
            "cites none of the calls that redid it. Rewrite it in your own words on what "
            "ev_0202 answered, citing it, or drop it; the same words with a citation added "
            "are a keep."
        )
        # Citing the call that redid it passes this check; the same words are still a keep.
        assert check(sentence.rstrip(".") + " [ev_0202].", [], "") == []


def test_a_keep_naming_two_redone_calls_is_told_to_cite_a_redo_of_each() -> None:
    redone_twice = FailedCall(
        entry="ev_0203",
        tool="lift_routine",
        error="no function there",
        asked=(0x1030,),
        redone_by=("ev_0204", "ev_0205"),
        lists_code=True,
        kind="decompile",
    )
    check = _failure_redone_check([_REDONE, redone_twice], [], (), {})
    sentence = "The decompiler produced no function at 0x2200 or 0x1030."
    (found,) = check(sentence, [], "")
    assert "on what ev_0202 and ev_0204 or ev_0205 answered, citing each, or drop" in (
        found.message
    )
    # One redo of each call passes; the redo of one call alone does not.
    assert check(sentence.rstrip(".") + " [ev_0202][ev_0205].", [], "") == []
    assert check(sentence.rstrip(".") + " [ev_0202].", [], "") != []


_OTHER_KINDS = [
    *_REDONE_AT_TWO,
    FailedCall(
        entry="ev_0205",
        tool="list_asm",
        error="bad",
        asked=(0x5000,),
        redone_by=("ev_0206",),
        lists_code=True,
        kind="disassemble",
    ),
    FailedCall(
        entry="ev_0207",
        tool="run_emulator",
        error="bad",
        asked=(0x6000,),
        redone_by=("ev_0208",),
        lists_code=False,
        kind="emulate",
    ),
]


@pytest.mark.parametrize(
    ("sentence", "said", "redos"),
    [
        # A kind word names no call of its kind the sentence does not name by its address.
        ("The decompile of 0x2200 shows no network call.", "ev_0201 by ev_0202", "ev_0202"),
        ("0x2200 does not call 0x5000, as the disassembly shows.", "ev_0205 by ev_0206", "ev_0206"),
        (
            "The function boundaries of 0x2200 and 0x1030 are not confirmed, because the "
            "decompiler produced no function at either address [ev_0109].",
            "ev_0201 by ev_0202; ev_0203 by ev_0204",
            "ev_0202 and ev_0204",
        ),
    ],
)
def test_a_keep_is_asked_for_exactly_the_redos_the_round_names(
    sentence: str, said: str, redos: str
) -> None:
    named = redone_calls_named(sentence, _OTHER_KINDS, ())
    assert " and ".join(_redo_choices(named)) == redos
    (found,) = _failure_redone_check(_OTHER_KINDS, [], (), {})(sentence, [], "")
    assert f"redid ({said}) and cites" in found.message
    assert f"on what {redos} answered" in found.message


def test_a_sentence_saying_a_call_failed_keeps_its_finding() -> None:
    check = _failure_redone_check([_REDONE], [], (), {})
    (found,) = check("The decompile of 0x2200 failed.", [], "")
    # Said of a keep and of a rewrite alike, and offering no keep: one is refused.
    assert found.message == (
        "it says a call failed or a reading could not be made, while a later call redid it "
        "(ev_0201 by ev_0202). Rewrite it citing ev_0202 and saying what it answered, or "
        "drop it."
    )


_TRUE = "The decompile of 0x5a10 shows no network call."


def _row(sentence: str, decision: str, sources: list[str], **said: str) -> dict[str, Any]:
    return {
        "passage": "limitations",
        "sentence": sentence,
        "sources": sources,
        "decision": decision,
        "rewrite": "",
        "reason": "",
        "quote": "",
        **said,
    }


def test_the_round_is_shown_the_redo_to_cite_and_refuses_an_uncited_keep() -> None:
    passages = passages_of(_report(_TRUE), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert limitations.redone_named == ((_TRUE, ("ev_0107",)),)
    text = prompt_text(passages)
    assert (
        "- [inv.1] tool call that failed, and whether a later call redid it (cites ev_0101, "
        'ev_0107): ev_0101 ("lift_routine") failed: "no function there"; the later call ev_0107 '
        "answered for every address it asked (offset 0x5a10), so it did not fail for good"
    ) in text
    assert (
        "  [limitations] each of these names a call that failed and a later call redid, and "
        "cites none of the calls that redid it: a keep of it as written is refused, and the "
        "same words with a citation added are a keep; rewrite it in your own words on what the "
        f"call named here answered, citing it, {_DENIAL}, or drop it; if no answer for it passes "
        f'the checks, it is left out of the report: "{_TRUE}" (cite ev_0107)'
    ) in text
    ends = f"{_ONE_REDO_ENDS} {_LEFT_OUT}"
    keep = {"sentences": [_keep("limitations", _TRUE, [], "no source speaks of it")]}
    refused = agreement_violations(keep, passages)
    assert {v.code for v in refused} == {FAILURE_REDONE_CODE, KEEP_UNQUOTED_CODE}
    assert [v.message for v in refused if v.code == FAILURE_REDONE_CODE] == [
        "row 1: limitations keeps the sentence, but it names a call that failed and a later "
        "call redid (ev_0101 by ev_0107) and cites none of the calls that redid it. R" + ends[1:]
    ]
    # Every refusal says what to do, and offers no source to quote.
    assert all(v.message.endswith(ends[1:]) and "quot" not in v.message for v in refused)


def test_a_sentence_held_to_a_redone_call_ends_as_the_round_is_told() -> None:
    passages = passages_of(_report(_TRUE), entries=_ledger())
    # The same words with the citation added are a keep, and refused, saying what to do.
    same = _row(_TRUE, "rewrite", ["inv.1"], rewrite=_TRUE.rstrip(".") + " [ev_0107].")
    (refused,) = agreement_violations({"sentences": [same]}, passages)
    assert refused.code == KEEP_UNQUOTED_CODE
    assert "into the same words, which keeps it" in refused.message
    assert refused.message.endswith(f"{_ONE_REDO_ENDS} {_LEFT_OUT}")
    # A rewrite in its own words on what the redo answered, citing it, and a drop stand
    # whole: no finding of any kind.
    for row in (
        _row(
            _TRUE,
            "rewrite",
            ["inv.1"],
            rewrite="The later decompile of 0x5a10 contains no network call [ev_0107].",
        ),
        _row(_TRUE, "drop", [], reason="a later call redid the call it names"),
    ):
        assert agreement_violations({"sentences": [row]}, passages) == [], row


_UNKNOWN = f"The runtime result of `{CALLED}` is not known."


def test_a_closing_sentence_held_on_a_name_ends_as_the_round_is_told() -> None:
    passages = passages_of(_report(_UNKNOWN), entries=_ledger())
    (fact,) = [p for p in passages if p.id.startswith("ledger.")]
    assert (
        "  [limitations] each of these denies something and names what a ledger.N fact shows "
        "(an API's call lines, an export, a decoded text); a keep of it as written is refused, "
        "and the same words with a citation added are a keep; rewrite it in your own words on "
        "the lines shown, citing the entry they come from, saying what the lines show and what "
        f"stays unknown, {_DENIAL}, or drop it; if no answer for it passes the checks, it is left "
        f'out of the report: "{_UNKNOWN}" ({fact.id})'
    ) in prompt_text(passages)
    ends = f"{_NAME_ENDS} {_LEFT_OUT}"
    # A keep in any form, and the same words with a citation added, are refused, each
    # told what to do and offered no source to quote.
    for row in (
        _row(_UNKNOWN, "keep", [], reason="no source states it"),
        _row(_UNKNOWN, "keep", [fact.id], reason="the fact shows the call, not its result"),
        _row(_UNKNOWN, "keep", [fact.id], quote=f"(*_DAT_{SLOT:x})(self,&mode);"),
        _row(_UNKNOWN, "rewrite", [fact.id], rewrite=_UNKNOWN.rstrip(".") + " [ev_0109]."),
    ):
        found = agreement_violations({"sentences": [row]}, passages)
        assert [v.code for v in found] == [KEEP_UNQUOTED_CODE], row
        assert found[0].message.endswith(ends), row
    # A rewrite in its own words on the lines shown, citing their entry, and a drop stand
    # whole: no finding of any kind.
    for row in (
        _row(
            _UNKNOWN,
            "rewrite",
            [fact.id],
            rewrite=(
                f"Routine 0x5a10 calls `{CALLED}` [ev_0107], but what it returns at run time "
                "is not recorded [ev_0107]."
            ),
        ),
        _row(_UNKNOWN, "drop", [], reason="the lines shown do not state its result"),
    ):
        assert agreement_violations({"sentences": [row]}, passages) == [], row


def _cited(sentence: str, citation: str, where: str) -> str:
    """The sentence in the same words with ``citation`` at its end, after its third word,
    or before it."""
    if where == "end":
        return f"{sentence.rstrip('.')} {citation}."
    if where == "middle":
        words = sentence.split(" ")
        return " ".join([*words[:3], citation, *words[3:]])
    return f"{citation} {sentence}"


@pytest.mark.parametrize("sentence", [_UNKNOWN, _TRUE])
@pytest.mark.parametrize(
    "citation", ["[ev_0109]", "[ev_0107][ev_0109]", "[ev_0107, ev_0109]", "(ev_0107)"]
)
@pytest.mark.parametrize("where", ["end", "middle", "start"])
def test_the_same_words_citing_an_entry_anywhere_are_the_same_words(
    sentence: str, citation: str, where: str
) -> None:
    assert repeats_sentence(sentence, _cited(sentence, citation, where))
    # Several citations, each where it stands.
    words = sentence.split(" ")
    several = " ".join(["[ev_0107]", *words[:2], citation, *words[2:-1], f"{citation} {words[-1]}"])
    assert repeats_sentence(sentence, several)
    # An entry id cuts no clause: a rewrite in other words is still none.
    assert not repeats_sentence(sentence, f"Routine 0x5a10 [ev_0107] reads a host mode {citation}.")


@pytest.mark.parametrize(
    ("sentence", "uncited"),
    [
        (f"{CALLED}[ev_0109]is not called.", f"{CALLED} is not called."),
        (
            f"No routine calls {CALLED}[ev_0109]and none reads it.",
            f"No routine calls {CALLED} and none reads it.",
        ),
        (f"No call to {CALLED}(ev_0109, ev_0107)is shown.", f"No call to {CALLED} is shown."),
        (f"{CALLED}[ev_0109] is not called.", f"{CALLED} is not called."),
        (f"No call to `{CALLED}` [ev_0109].", f"No call to `{CALLED}`."),
    ],
)
def test_a_citation_written_between_two_words_parts_them(sentence: str, uncited: str) -> None:
    assert _uncited(sentence) == uncited
    # Held on the name it writes, and the same words as the sentence without the citation.
    assert _held(sentence) == {CALLED}
    assert repeats_sentence(uncited, sentence)


@pytest.mark.parametrize("where", ["start", "middle", "after its address", "end"])
def test_a_rewrite_restating_a_contradicted_absence_is_refused_wherever_it_cites(
    where: str,
) -> None:
    passages = passages_of(_report(_TRUE), entries=_ledger())

    def codes(rewrite: str) -> list[str]:
        row = _row(_TRUE, "rewrite", ["listed.1"], rewrite=rewrite)
        return [v.code for v in agreement_violations({"sentences": [row]}, passages)]

    at_end = codes(_cited(_TRUE, "[ev_0107]", "end"))
    assert ABSENCE_KEPT_CODE in at_end
    if where == "after its address":
        rewrite = "The decompile of 0x5a10 [ev_0107] shows no network call."
    else:
        rewrite = _cited(_TRUE, "[ev_0107]", where)
    assert codes(rewrite) == at_end


_TWO = "The decompile of 0x5a10 and 0x6100 shows no network call."
_SAYS_FAILED = "The decompile of 0x5a10 failed [ev_0101]."


def _ledger_two() -> list[LedgerEntry]:
    """The ledger with a second failed decompile, of the helper, redone."""
    return [
        *_ledger(),
        LedgerEntry(
            id="ev_0111",
            tool="lift_routine",
            args={"address": hex(HELPER)},
            ok=False,
            error="no function there",
            facts=_DECOMPILE,
        ),
        _lifted("ev_0112", HELPER, "  return 0;"),
    ]


# How each held sentence's rewrite carries its denials: each followed at once by an entry
# shown for that sentence.
_DENIAL = "each denial in it followed at once by the entry it rests on, one shown for it"
_NAME_ENDS = (
    "it names what ledger.1 holds lines on: a keep of it as written is refused, and the "
    "same words with a citation added are a keep; rewrite it in your own words on the lines "
    "shown, citing the entry they come from, saying what the lines show and what stays "
    f"unknown, {_DENIAL}, or drop it."
)
_BODY_ENDS = (
    'it names what ledger.1 holds lines on: keep it naming that fact, with "quote": words '
    "inside one of its rows that name what the sentence names, copied exactly; or rewrite it "
    f"in your own words on the lines shown, citing an entry the fact cites, {_DENIAL}; or "
    "drop it."
)
_ONE_REDO_ENDS = (
    f"rewrite it in your own words on what ev_0107 answered, citing it, {_DENIAL}, or drop it; "
    "the same words with a citation added are a keep."
)
_TWO_REDO_ENDS = (
    f"rewrite it in your own words on what ev_0107 and ev_0112 answered, citing each, {_DENIAL}, "
    "or drop it; the same words with a citation added are a keep."
)
_FAILED_ENDS = f"ewrite it citing ev_0107 and saying what it answered, {_DENIAL}, or drop it."
# What every refusal of an answer for a held sentence ends with: a refused last answer leaves
# it out, in a closing passage and in the body alike.
_LEFT_OUT = "If no answer for it passes the checks, it is left out of the report."
_LEAVING = "or, leaving it out, give the reason."
_SLOT_ROW = f"(*_DAT_{SLOT:x})(self,&mode);  /* {SLOT:x} = {CALLED} */"
_FAILED_ROW = 'ev_0101 ("lift_routine") failed: "no function there"'

# Each held path: the report, the ledger, the passage, the sentence, the sources a row
# names, the citation the text asks for, a quote, and a rewrite in other words citing it.
_PATHS: dict[str, tuple[Any, ...]] = {
    "closing held on a name": (
        partial(_report, _UNKNOWN),
        _ledger,
        "limitations",
        _UNKNOWN,
        ["ledger.1"],
        "[ev_0109]",
        _SLOT_ROW,
        f"Routine 0x5a10 calls `{CALLED}` [ev_0107], but what it returns at run time is not "
        "recorded [ev_0107].",
    ),
    "body held on a name": (
        partial(_report, "", background=_UNKNOWN),
        _ledger,
        "introduction",
        _UNKNOWN,
        ["ledger.1"],
        "[ev_0109]",
        _SLOT_ROW,
        f"Routine 0x5a10 calls `{CALLED}` [ev_0107], but what it returns at run time is not "
        "recorded [ev_0107].",
    ),
    "held to one redone call": (
        partial(_report, _TRUE),
        _ledger,
        "limitations",
        _TRUE,
        ["inv.1"],
        "[ev_0107]",
        _FAILED_ROW,
        "The later decompile of 0x5a10 contains no network call [ev_0107].",
    ),
    "held to two redone calls": (
        partial(_report, _TWO),
        _ledger_two,
        "limitations",
        _TWO,
        ["inv.1", "inv.2"],
        "[ev_0107][ev_0112]",
        _FAILED_ROW,
        "The later decompiles of 0x5a10 and 0x6100 contain no network call [ev_0107][ev_0112].",
    ),
    "says a call failed": (
        partial(_report, _SAYS_FAILED),
        _ledger,
        "limitations",
        _SAYS_FAILED,
        ["inv.1"],
        "[ev_0107]",
        _FAILED_ROW,
        "The first decompile of 0x5a10 failed [ev_0101]; a later call [ev_0107] lifted it and "
        "shows a host-mode check.",
    ),
}

_SAME = ("same words cited at the end", "same words cited mid-sentence", "same words cited first")

# The rows each held path is answered with beyond those every path is: rewrites citing
# none of the calls that redid the calls the sentence is held to, or only some of them.
_OWN_ROWS: dict[str, dict[str, dict[str, Any]]] = {
    "body held on a name": {
        "same words cited, quoting a row": _row(
            _UNKNOWN,
            "rewrite",
            ["ledger.1"],
            rewrite=_cited(_UNKNOWN, "[ev_0109]", "end"),
            quote=CALLED,
        ),
    },
    "held to one redone call": {
        "rewrite citing the failed call only": _row(
            _TRUE,
            "rewrite",
            ["inv.1"],
            rewrite="Routine 0x5a10 holds a host-mode check and returns [ev_0101].",
        ),
    },
    "held to two redone calls": {
        "rewrite citing the failed calls only": _row(
            _TWO,
            "rewrite",
            ["inv.1", "inv.2"],
            rewrite=(
                "Routines 0x5a10 [ev_0101] and 0x6100 [ev_0111] hold only a host-mode read and "
                "a return."
            ),
        ),
        "rewrite citing the redo of one of the two": _row(
            _TWO,
            "rewrite",
            ["inv.1", "inv.2"],
            rewrite="The later decompile of 0x5a10 contains no network call [ev_0107].",
        ),
    },
    "says a call failed": {
        "rewrite no longer saying it failed": _row(
            _SAYS_FAILED,
            "rewrite",
            ["inv.1"],
            rewrite="Routine 0x5a10 holds a host-mode check and returns [ev_0101].",
        ),
        "rewrite denying instead": _row(
            _SAYS_FAILED,
            "rewrite",
            ["inv.1"],
            rewrite="Routine 0x5a10 holds no network call [ev_0101].",
        ),
    },
}


def _no_source(where: str, *, leaving: bool) -> str:
    return (
        f"row 1 names no source. Name the ids of the sources you read for the sentence of "
        f"{where}" + (", or, leaving it out, give the reason." if leaving else ".")
    )


# A keep naming no source of a closing sentence no keep passes for: asked only for a drop's
# reason, never for sources.
_NO_SOURCE_KEPT = "row 1 names no source; leaving it out, give the reason."


def _kept(where: str, sentence: str, why: str, ends: str) -> str:
    return f"row 1: {where} keeps {sentence!r} {why}: {ends}"


def _same_words(where: str, sentence: str, sources: str, why: str, ends: str) -> str:
    return (
        f"row 1: {where} rewrites {sentence!r} into the same words, which keeps it, on "
        f"{sources}, but the best sentence of those sources {why}: {ends}"
    )


def _same_kept(where: str, sentence: str, sources: str, why: str, ends: str) -> str:
    return (
        f"row 1: {where} rewrites {sentence!r} into the same words, which keeps it, on "
        f"{sources}, but its quote {why}: {ends}"
    )


_HELD_REDONE = "it names a call that failed and a later call redid: a keep of it as written is "
_KEEP_REDONE = (
    "row 1: limitations keeps the sentence, but it names a call that failed and a later call "
)
_KEEP_FAILED = (
    "row 1: limitations keeps the sentence, but it says a call failed or a reading could not be "
    "made, while a later call redid it (ev_0101 by ev_0107). R" + _FAILED_ENDS
)
_REWRITE_HELD = (
    "row 1: the rewrite of limitations: it replaces a sentence held to a call that failed and a "
    "later call redid "
)
_UNQUOTED_ROW = (
    "quotes the rows of an entry, which state no absence, while the sentence states one: "
)
_FEW = "shares too few of the words the sentence denies something of"


def _expected() -> dict[str, dict[str, list[tuple[str, str]]]]:
    """What each row answering a held sentence draws, the whole row: each finding's code and
    its whole message. A row with none stands."""
    name = _NAME_ENDS
    named = "naming no source, but ledger.1 speaks of what it names"
    one = f"{_HELD_REDONE}refused; {_ONE_REDO_ENDS}"
    two = f"{_HELD_REDONE}refused; {_TWO_REDO_ENDS}"
    failed = "it says a call failed that a later call redid: a keep of it as written is refused; r"
    keep_one = (
        f"{_KEEP_REDONE}redid (ev_0101 by ev_0107) and cites none of the calls that redid it. "
        f"R{_ONE_REDO_ENDS[1:]}"
    )
    keep_two = (
        f"{_KEEP_REDONE}redid (ev_0101 by ev_0107; ev_0111 by ev_0112) and cites none of the "
        f"calls that redid it. R{_TWO_REDO_ENDS[1:]}"
    )
    one_rows = "naming no source, but answered.1, inv.1 speaks of what it names"
    two_rows = "naming no source, but answered.1, answered.2, inv.1, 1 more speaks of what it names"
    return {
        "closing held on a name": {
            "keep": [
                (UNKNOWN_SOURCE_CODE, _NO_SOURCE_KEPT),
                (KEEP_UNQUOTED_CODE, _kept("limitations", _UNKNOWN, named, name)),
            ],
            "keep on a reason": [(KEEP_UNQUOTED_CODE, _kept("limitations", _UNKNOWN, named, name))],
            "keep quoting": [
                (
                    KEEP_UNQUOTED_CODE,
                    _kept(
                        "limitations",
                        _UNKNOWN,
                        f"on ledger.1, but its quote {_UNQUOTED_ROW}rewrite it on them, or drop it",
                        name,
                    ),
                )
            ],
            **dict.fromkeys(
                _SAME,
                [
                    (
                        KEEP_UNQUOTED_CODE,
                        _same_words(
                            "limitations",
                            _UNKNOWN,
                            "ledger.1",
                            "quotes no single row of the entry holding a value the sentence names",
                            name,
                        ),
                    )
                ],
            ),
            "reworded rewrite citing": [],
            "drop": [],
        },
        "body held on a name": {
            "keep": [
                (UNKNOWN_SOURCE_CODE, _no_source("introduction", leaving=True)),
                (KEEP_UNQUOTED_CODE, _kept("introduction", _UNKNOWN, named, _BODY_ENDS)),
            ],
            "keep on a reason": [
                (KEEP_UNQUOTED_CODE, _kept("introduction", _UNKNOWN, named, _BODY_ENDS))
            ],
            # A body keep quoting the fact's row that names what the sentence names stands.
            "keep quoting": [],
            # The same words with a citation added, wherever it stands, are a keep: its quote
            # is read as a keep's (T-600).
            **dict.fromkeys(
                _SAME,
                [
                    (
                        KEEP_UNQUOTED_CODE,
                        # It gives no quote, and is told so (T-600).
                        f"row 1: introduction rewrites {_UNKNOWN!r} into the same words, which "
                        "keeps it, on ledger.1, but gives no quote; quote at least 12 characters "
                        f"of the source's words: {_BODY_ENDS}",
                    )
                ],
            ),
            "same words cited, quoting a row": [],
            "reworded rewrite citing": [],
            # A held body sentence is left out where no answer for it passes: a drop of it,
            # with its reason, is an answer (T-600).
            "drop": [],
        },
        "held to one redone call": {
            "keep": [
                (UNKNOWN_SOURCE_CODE, _NO_SOURCE_KEPT),
                (KEEP_UNQUOTED_CODE, _kept("limitations", _TRUE, one_rows, one)),
                (FAILURE_REDONE_CODE, keep_one),
            ],
            "keep on a reason": [
                (KEEP_UNQUOTED_CODE, _kept("limitations", _TRUE, one_rows, one)),
                (FAILURE_REDONE_CODE, keep_one),
            ],
            "keep quoting": [
                (
                    KEEP_UNQUOTED_CODE,
                    _kept("limitations", _TRUE, f"on inv.1, but its quote {_FEW}", one),
                ),
                (FAILURE_REDONE_CODE, keep_one),
            ],
            **dict.fromkeys(
                _SAME,
                [(KEEP_UNQUOTED_CODE, _same_words("limitations", _TRUE, "inv.1", _FEW, one))],
            ),
            "reworded rewrite citing": [],
            "drop": [],
            # A rewrite citing none of the calls that redid the call its sentence is held to
            # is told what a keep of it is told, whatever it says.
            "rewrite citing the failed call only": [
                (
                    FAILURE_REDONE_CODE,
                    f"{_REWRITE_HELD}(ev_0101 by ev_0107) and cites none of the calls that redid "
                    f"it. R{_ONE_REDO_ENDS[1:]}",
                )
            ],
        },
        "held to two redone calls": {
            "keep": [
                (UNKNOWN_SOURCE_CODE, _NO_SOURCE_KEPT),
                (KEEP_UNQUOTED_CODE, _kept("limitations", _TWO, two_rows, two)),
                (FAILURE_REDONE_CODE, keep_two),
            ],
            "keep on a reason": [
                (KEEP_UNQUOTED_CODE, _kept("limitations", _TWO, two_rows, two)),
                (FAILURE_REDONE_CODE, keep_two),
            ],
            "keep quoting": [
                (
                    KEEP_UNQUOTED_CODE,
                    _kept("limitations", _TWO, f"on inv.1, but its quote {_FEW}", two),
                ),
                (FAILURE_REDONE_CODE, keep_two),
            ],
            **dict.fromkeys(
                _SAME,
                [
                    (
                        KEEP_UNQUOTED_CODE,
                        _same_words("limitations", _TWO, "inv.1, inv.2", _FEW, two),
                    )
                ],
            ),
            "reworded rewrite citing": [],
            "drop": [],
            # In the number of the calls it cites no redo of.
            "rewrite citing the failed calls only": [
                (
                    FAILURE_REDONE_CODE,
                    "row 1: the rewrite of limitations: it replaces a sentence held to calls that "
                    "failed and later calls redid (ev_0101 by ev_0107; ev_0111 by ev_0112) and "
                    f"cites none of the calls that redid them. R{_TWO_REDO_ENDS[1:]}",
                )
            ],
            # Citing a call that redid one of the two, it names the other and the ends of both.
            "rewrite citing the redo of one of the two": [
                (
                    FAILURE_REDONE_CODE,
                    f"{_REWRITE_HELD}(ev_0111 by ev_0112) and cites none of the calls that redid "
                    f"it. R{_TWO_REDO_ENDS[1:]}",
                )
            ],
        },
        "says a call failed": {
            "keep": [
                (UNKNOWN_SOURCE_CODE, _NO_SOURCE_KEPT),
                (
                    KEEP_UNQUOTED_CODE,
                    _kept("limitations", _SAYS_FAILED, one_rows, failed + _FAILED_ENDS),
                ),
                (FAILURE_REDONE_CODE, _KEEP_FAILED),
            ],
            "keep on a reason": [
                (
                    KEEP_UNQUOTED_CODE,
                    _kept("limitations", _SAYS_FAILED, one_rows, failed + _FAILED_ENDS),
                ),
                (FAILURE_REDONE_CODE, _KEEP_FAILED),
            ],
            "keep quoting": [(FAILURE_REDONE_CODE, _KEEP_FAILED)],
            # Citing the call that redid it is what the check asks: it stands.
            **dict.fromkeys(_SAME, []),
            "reworded rewrite citing": [],
            "drop": [],
            "rewrite no longer saying it failed": [
                (
                    FAILURE_REDONE_CODE,
                    f"{_REWRITE_HELD}(ev_0101 by ev_0107) and cites none of the calls that "
                    f"redid it. R{_FAILED_ENDS}",
                )
            ],
            # Its denial cites the failed call, which is not among the entries shown for it.
            "rewrite denying instead": [
                (
                    REWRITE_UNGROUNDED_CODE,
                    "row 1: the rewrite of limitations denies something in 'Routine 0x5a10 holds "
                    "no network call' and no entry shown for the sentence follows that denial at "
                    "once: in a rewrite of this sentence each denial is followed at once by the "
                    "entry it rests on, cited in square brackets, one of ev_0107.",
                ),
                (
                    FAILURE_REDONE_CODE,
                    f"{_REWRITE_HELD}(ev_0101 by ev_0107) and cites none of the calls that "
                    f"redid it. R{_FAILED_ENDS}",
                ),
            ],
        },
    }


_EXPECTED = _expected()


@pytest.mark.parametrize(
    ("path", "action"),
    [(path, action) for path, rows in _EXPECTED.items() for action in rows],
)
def test_every_answer_to_a_held_sentence_draws_what_the_round_is_told(
    path: str, action: str
) -> None:
    report, ledger, pid, sentence, sources, citation, quote, reworded = _PATHS[path]
    passages = passages_of(report(), entries=ledger())
    rows = {
        "keep": _row(sentence, "keep", []),
        "keep on a reason": _row(sentence, "keep", [], reason="no source states it"),
        "keep quoting": _row(sentence, "keep", sources[:1], quote=quote),
        _SAME[0]: _row(sentence, "rewrite", sources, rewrite=_cited(sentence, citation, "end")),
        _SAME[1]: _row(sentence, "rewrite", sources, rewrite=_cited(sentence, citation, "middle")),
        _SAME[2]: _row(sentence, "rewrite", sources, rewrite=_cited(sentence, citation, "start")),
        "reworded rewrite citing": _row(sentence, "rewrite", sources, rewrite=reworded),
        "drop": _row(sentence, "drop", [], reason="the lines shown say otherwise"),
        **_OWN_ROWS.get(path, {}),
    }
    found = agreement_violations({"sentences": [{**rows[action], "passage": pid}]}, passages)
    # Each refusal ends saying what becomes of the sentence if its last answer is refused.
    assert [(v.code, v.message) for v in found] == [
        (code, f"{message} {_LEFT_OUT}") for code, message in _EXPECTED[path][action]
    ]
    # No finding on a held sentence offers a keep where a keep is refused.
    if pid == "limitations":
        assert all("keep the sentence" not in v.message for v in found)


@pytest.mark.parametrize(
    ("path", "line"),
    [
        (
            "body held on a name",
            "  [introduction] each of these denies something and names what a ledger.N fact "
            "shows (an API's call lines, an export, a decoded text); keep it naming that fact, "
            'with "quote": words inside one of its rows that name what the sentence names, '
            "copied exactly; or rewrite it in your own words on the lines shown, citing an entry "
            f"the fact cites, {_DENIAL}; or drop it; if no answer for it passes the checks, it is "
            f'left out of the report: "{_UNKNOWN}" (ledger.1)',
        ),
        (
            "held to one redone call",
            "  [limitations] each of these names a call that failed and a later call redid, and "
            "cites none of the calls that redid it: a keep of it as written is refused, and the "
            "same words with a citation added are a keep; rewrite it in your own words on what "
            f"the call named here answered, citing it, {_DENIAL}, or drop it; if no answer for it "
            f'passes the checks, it is left out of the report: "{_TRUE}" (cite ev_0107)',
        ),
        (
            "held to two redone calls",
            "  [limitations] each of these names a call that failed and a later call redid, and "
            "cites none of the calls that redid it: a keep of it as written is refused, and the "
            "same words with a citation added are a keep; rewrite it in your own words on what "
            f"the calls named here answered, citing each, {_DENIAL}, or drop it; if no answer for "
            f'it passes the checks, it is left out of the report: "{_TWO}" (cite ev_0107 and '
            "ev_0112)",
        ),
    ],
)
def test_the_round_is_told_what_stands_for_each_held_sentence(path: str, line: str) -> None:
    report, ledger, *_rest = _PATHS[path]
    assert line in prompt_text(passages_of(report(), entries=ledger())).splitlines()


@pytest.mark.parametrize(
    ("path", "ends"),
    [
        ("closing held on a name", _NAME_ENDS),
        (
            "held to one redone call",
            "it names a call that failed and a later call redid: a keep of it as written is "
            "refused; " + _ONE_REDO_ENDS,
        ),
        (
            "says a call failed",
            "it says a call failed that a later call redid: a keep of it "
            "as written is refused; r" + _FAILED_ENDS,
        ),
        ("body held on a name", _BODY_ENDS),
    ],
)
def test_a_held_sentence_no_row_lists_is_told_its_own_ends(path: str, ends: str) -> None:
    report, ledger, *_rest = _PATHS[path]
    found = agreement_violations({"sentences": []}, passages_of(report(), entries=ledger()))
    (unlisted,) = [v for v in found if v.code == HELD_UNLISTED_CODE]
    assert unlisted.message.endswith(
        f"List it: {ends} {_LEFT_OUT} Answer with every row again, this one included."
    )


@pytest.mark.parametrize(
    ("sentence", "ledger", "sources", "rewrite", "said", "ends"),
    [
        (
            _TRUE,
            _ledger,
            ["inv.1"],
            "Routine 0x5a10 as first lifted [ev_0101] holds no network call at all.",
            "a call that failed and a later call redid (ev_0101 by ev_0107) and cites none of the "
            "calls that redid it",
            _ONE_REDO_ENDS,
        ),
        (
            _TWO,
            _ledger_two,
            ["inv.1", "inv.2"],
            "Routines 0x5a10 [ev_0101] and 0x6100 [ev_0111] as first lifted hold no network call.",
            "calls that failed and later calls redid (ev_0101 by ev_0107; ev_0111 by ev_0112) and "
            "cites none of the calls that redid them",
            _TWO_REDO_ENDS,
        ),
    ],
)
def test_a_rewrite_s_failure_finding_is_never_cut(
    sentence: str, ledger: Any, sources: list[str], rewrite: str, said: str, ends: str
) -> None:
    passages = passages_of(_report(sentence), entries=ledger())
    row = _row(sentence, "rewrite", sources, rewrite=rewrite)
    (finding,) = [
        v
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.code == FAILURE_REDONE_CODE
    ]
    # In the number of its calls, and whole, the end it is left out on included.
    assert finding.message == (
        f"row 1: the rewrite of limitations: it replaces a sentence held to {said}. "
        f"R{ends[1:]} {_LEFT_OUT}"
    )
    assert len(finding.message) > 200


def test_a_rewrite_adding_a_redone_failure_is_told_what_stands_in_its_passage() -> None:
    report = _report(_TRUE, background="The gate reads a host mode [ev_0109].")
    assert report.technical_analysis is not None
    report.technical_analysis.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The gate reads a host mode [ev_0109]."
    )
    passages = passages_of(report, entries=_ledger())
    sentence = "The gate reads a host mode [ev_0109]."
    added = _row(
        sentence,
        "rewrite",
        ["inv.1"],
        rewrite="The gate reads a host mode [ev_0109]; the decompiler failed on it [ev_0101].",
    )
    for pid, ends, stands in (
        # The body: the sentence is kept, and a keep naming its source stands.
        (
            "introduction",
            "Cite ev_0107 and say what it answered, or keep the sentence.",
            _row(
                sentence,
                "keep",
                ["string_resolution"],
                quote="Routine 0x5a10 reads a host mode through a slot",
            ),
        ),
        # A closing sentence no gate holds: the keep that passes for it, as in the body.
        (
            "conclusion",
            "Cite ev_0107 and say what it answered, or keep the sentence.",
            _row(
                sentence,
                "keep",
                ["string_resolution"],
                quote="Routine 0x5a10 reads a host mode through a slot",
            ),
        ),
    ):
        found = [
            v
            for v in agreement_violations({"sentences": [{**added, "passage": pid}]}, passages)
            if v.path.startswith("sentences.")
        ]
        assert [(v.code, v.message.endswith(ends)) for v in found] == [
            (FAILURE_REDONE_CODE, True)
        ], found
        kept = agreement_violations({"sentences": [{**stands, "passage": pid}]}, passages)
        assert [v for v in kept if v.path.startswith("sentences.")] == [], kept


def test_a_rewrite_dropping_a_cited_id_of_a_held_sentence_is_told_to_drop_it() -> None:
    passages = passages_of(_report(_SAYS_FAILED), entries=_ledger())
    row = _row(
        _SAYS_FAILED,
        "rewrite",
        ["inv.1"],
        rewrite="The decompile of 0x5a10 [ev_0107] shows a host-mode check.",
    )
    (found,) = agreement_violations({"sentences": [row]}, passages)
    assert found.code == REWRITE_DROPS_CITATION_CODE
    assert found.message.endswith(f"Keep every id the sentence cites, or drop it. {_LEFT_OUT}")


_UNKNOWN_CITED = f"The runtime result of `{CALLED}` is not known [ev_0109]."
_BODY_KEEP = (
    'or keep it naming ledger.1, with "quote": words inside one of its rows that name what the '
    f"sentence names, copied exactly, or drop it. {_LEFT_OUT}"
)


def test_a_refused_rewrite_of_a_body_sentence_held_on_a_name_is_offered_the_keep_that_passes() -> (
    None
):
    passages = passages_of(_report(_TWO, background=_UNKNOWN_CITED), entries=_ledger_two())

    def found(row: dict[str, Any]) -> list[tuple[str, str]]:
        answer = {"sentences": [{**row, "passage": "introduction"}]}
        return [
            (v.code, v.message)
            for v in agreement_violations(answer, passages)
            if v.path.startswith("sentences.")
        ]

    def rewrite(sources: list[str], text: str) -> list[tuple[str, str]]:
        return found(_row(_UNKNOWN_CITED, "rewrite", sources, rewrite=text))

    assert rewrite(
        ["ledger.1"], f"Routine 0x5a10 calls `{CALLED}` [ev_0107]; its result at run time is unset."
    ) == [
        (
            REWRITE_DROPS_CITATION_CODE,
            "row 1: the sentence cites ev_0109, which the rewrite does not. Keep every id the "
            "sentence cites, " + _BODY_KEEP,
        )
    ]
    assert rewrite(
        ["inv.1"], f"Routine 0x5a10 calls `{CALLED}`, whose result is unset [ev_0109]."
    ) == [
        (
            REWRITE_UNGROUNDED_CODE,
            "row 1: the rewrite cites none of the ids its sources cite. Cite the entry a source "
            "rests on, " + _BODY_KEEP,
        )
    ]
    # Told of two calls a later call redid, it is told to cite each.
    assert rewrite(
        ["ledger.1", "inv.1", "inv.2"],
        _UNKNOWN_CITED.rstrip(".")
        + "; the decompiles of 0x5a10 and 0x6100 failed [ev_0101][ev_0111].",
    ) == [
        (
            FAILURE_REDONE_CODE,
            "row 1: the rewrite of introduction: the rewrite still says a call failed or a reading "
            "could not be made, but a later call redid it (ev_0101 by ev_0107; ev_0111 by "
            "ev_0112). Cite ev_0107 and ev_0112 and say what each answered, " + _BODY_KEEP,
        )
    ]
    # The keep it is offered stands.
    assert found(_row(_UNKNOWN_CITED, "keep", ["ledger.1"], quote=_SLOT_ROW)) == []


@pytest.mark.parametrize(
    "other",
    [
        # Set in what a run saw: not held, and kept on its reason as on a run without the
        # ledger's names.
        f"No `{CALLED}` call from the listed routine was observed at run time.",
        f"The code index call lines of `{CALLED}` were not observed in the sandbox.",
        "Whether the sample is packed is not known.",
    ],
)
def test_a_fact_of_a_name_speaks_only_to_the_sentences_held_on_it(other: str) -> None:
    passages = passages_of(_report(f"{_UNKNOWN} {other}"), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert dict(limitations.ledger_named).keys() == {_UNKNOWN}
    rows = [
        _row(_UNKNOWN, "drop", [], reason="the lines shown do not state its result"),
        _row(other, "keep", [], reason="stated by the analysts"),
    ]
    assert agreement_violations({"sentences": rows}, passages) == []


def test_a_negated_sentence_naming_an_api_in_a_run_s_words_is_held_on_it() -> None:
    # "No sandbox run" sets no denial in what a run saw: the name is held, the sentence the
    # model's to rewrite or drop.
    other = f"No sandbox run exercised the `{CALLED}` gate."
    passages = passages_of(_report(f"{_UNKNOWN} {other}"), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert other in dict(limitations.ledger_named)


_ORDER_PROBE = """
import sys
from malspark.reporting.limitation_facts import FailedCall
from malspark.reporting.section_agreement import _failure_redone_check
calls = [
    FailedCall(entry=f"ev_02{i}0", tool=f"tool{i}", error="bad", asked=(0x2000 + i,),
               redone_by=(f"ev_02{i}1",), lists_code=True, kind=kind)
    for i, kind in enumerate(("emulate", "disassemble", "decompile"))
]
text = "The emulator, the disassembler and the decompiler failed."
sys.stdout.write(_failure_redone_check(calls, [], (), {})(text, [], "")[0].message)
"""


def test_the_finding_on_failed_calls_reads_the_same_under_every_hash_seed() -> None:
    import os
    import subprocess
    import sys

    seen = set()
    for seed in ("1", "2", "3", "4"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": os.pathsep.join(sys.path)}
        done = subprocess.run(
            [sys.executable, "-c", _ORDER_PROBE],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        seen.add(done.stdout)
    (message,) = seen
    # The kind stems in order: decompile, disassemble, emulate.
    assert "(ev_0220 by ev_0221; ev_0210 by ev_0211; ev_0200 by ev_0201)" in message
    calls = [
        FailedCall(
            entry=f"ev_03{i}", tool="t", error="e", asked=(0x3000,), redone_by=("ev_0399",), kind=k
        )
        for i, k in enumerate(("emulate", "decompile"))
    ]
    assert [
        c.entry for c in _stale_calls("Decompiling and emulating failed.", calls, (), broad=True)
    ] == [
        "ev_031",
        "ev_030",
    ]


# ---------------------------------------------------------------------------
# What else holds a sentence on a name: the kind words of a quoted text, prose spelled
# like an API, a name written as a call, another file's answers.
# ---------------------------------------------------------------------------


def _text(text: str, *keys: str) -> TextHeld:
    return TextHeld(text=text, held_as=dict.fromkeys(keys))


_TEXTS = RunNames(
    texts={
        "plainmode": _text("plainmode", "plain_strings"),
        "codedmode": _text("codedmode", "decoded_strings"),
    },
    index_whole=True,
)


@pytest.mark.parametrize(
    "sentence",
    [
        "'plainmode' is not decoded.",
        "'codedmode' is not a plain string.",
        "'codedmode' is not decoded.",
        "'plainmode' is not a string.",
        "The 'codedmode' text is not there.",
    ],
)
def test_a_quoted_text_is_held_where_its_clause_writes_a_word_it_is_held_in(
    sentence: str,
) -> None:
    assert len(name_readings(sentence, "", _TEXTS)) == 1


def test_a_quoted_text_beside_no_word_it_is_held_in_is_not_held() -> None:
    assert name_readings("'codedmode' is not there.", "", _TEXTS) == []


def test_a_text_s_keys_are_read_off_the_index() -> None:
    ledger = _ledger()
    names = run_names(ledger, ledger_facts(ledger).image_bases)
    assert set(names.texts[TEXT].held_as) == {"decoded_strings"}


_WORDS = RunNames(
    apis={
        "connect": ApiHeld(name="connect", calls=[ApiCall(0x1400, None)], imported={"ev_3": None}),
        "sleep": ApiHeld(name="Sleep", calls=[ApiCall(0x1400, 0x2000)]),
        "openprocess": ApiHeld(name="OpenProcess", calls=[ApiCall(0x1400, None)]),
        "createprocessw": ApiHeld(name="CreateProcessW", calls=[ApiCall(0x1500, None)]),
    },
    exports={"run": ExportHeld(names=("run",), address=0x1600, entries=("ev_4",))},
    by_address={0x1600: ExportHeld(names=("run",), address=0x1600, entries=("ev_4",))},
    rows=frozenset({0x1400, 0x1500, 0x1600}),
    index_whole=True,
)


def test_a_word_of_prose_spelled_like_an_api_is_no_name_of_the_run_s() -> None:
    assert _held("The sample does not connect to any server.", names=_WORDS) == set()
    assert _held("The sample does not sleep.", names=_WORDS) == set()
    # Written as code or beside a word saying it is a function, it is the API.
    assert _held("The `connect` function is not called.", names=_WORDS) == {"connect"}
    assert _held("`Sleep` is not called.", names=_WORDS) == {"Sleep"}


def test_a_name_written_as_a_call_is_the_name() -> None:
    assert _held("`connect()` is not called.", names=_WORDS) == {"connect"}
    assert _held("`Sleep()` is not called.", names=_WORDS) == {"Sleep"}


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        ("OpenProcess is not called through a slot.", {"OpenProcess"}),
        ("No callee of 0x1400 calls OpenProcess.", {"OpenProcess"}),
        ("OpenProcess is not called outside 0x1400.", {"OpenProcess"}),
        ("OpenProcess is not never called.", {"OpenProcess"}),
        ("No other routine calls OpenProcess.", {"OpenProcess"}),
        ("Apart from 0x1400, no routine calls OpenProcess.", {"OpenProcess"}),
        ("If the check fails, OpenProcess is not called.", {"OpenProcess"}),
        ("No call to OpenProcess was executed.", {"OpenProcess"}),
        ("`Sleep` is not resolved.", {"Sleep"}),
        ("`connect` is not imported.", {"connect"}),
        ("`run` is not exported.", {"run"}),
        ("OpenProcess does not call CreateProcessW.", {"OpenProcess", "CreateProcessW"}),
        (
            "No routine calls both OpenProcess and CreateProcessW.",
            {"OpenProcess", "CreateProcessW"},
        ),
    ],
)
def test_a_denial_of_a_name_is_held_whatever_else_it_says(sentence: str, held: set[str]) -> None:
    assert _held(sentence, names=_WORDS) == held


def test_a_generic_word_is_no_plain_word_of_a_denial() -> None:
    # "loader" stands in most passages, yet "the loader" may be one routine of many.
    sentence = "The loader does not call OpenProcess."
    readings = name_readings(sentence, "", _WORDS, frozenset({"loader"}))
    assert [r.shown for r in readings] == ["OpenProcess"]


def test_a_negated_sentence_pointing_back_is_held_on_the_names_before_it() -> None:
    previous = "Routine 0x1400 starts the child with OpenProcess."
    sentence = "This is an immediate launch and not a persistence step."
    assert [(r.shown, r.back) for r in name_readings(sentence, previous, _WORDS)] == [
        ("OpenProcess", True)
    ]
    readings = name_readings("These are not shown being called.", previous, _WORDS)
    assert [(r.shown, r.back) for r in readings] == [("OpenProcess", True)]
    # An export the sentence before names by its own name is held the same way.
    after_export = name_readings("It is not a loader.", "The `run` export starts it.", _WORDS)
    assert [(r.kind, r.shown, r.back) for r in after_export] == [("export", "run", True)]
    # A denial of no subject of its own is of what the sentence points back to.
    readings = name_readings(
        "They serve the volume lookup, not a persistence step.", previous, _WORDS
    )
    assert [(r.shown, r.back) for r in readings] == [("OpenProcess", True)]


@pytest.mark.parametrize(
    "sentence",
    [
        # Not negated.
        "This is an immediate launch.",
        # Opening with no word pointing back.
        "A launch is not a persistence step.",
        # Naming an address or a name of its own: about that, never the sentence before.
        "This is not routine 0x1500.",
        "This is not CreateProcessW.",
        # Pointing back only where nothing is denied: the denial is of something of its own.
        "It resolves the names by hash, so the working set is not in the import table.",
    ],
)
def test_a_sentence_not_pointing_back_alone_is_not_held_on_the_names_before_it(
    sentence: str,
) -> None:
    previous = "Routine 0x1400 starts the child with OpenProcess."
    assert all(not r.back for r in name_readings(sentence, previous, _WORDS))


def test_a_relation_is_written_only_in_the_word_forms_of_its_keys() -> None:
    for word in ("call", "calls", "called", "calling"):
        assert relation_of(word, ("called",)) == "called", word
    for word in ("decode", "decodes", "decoded", "decoding"):
        assert relation_of(word, ("decoded",)) == "decoded", word
    for word in ("resolve", "resolves", "resolved", "resolving"):
        assert relation_of(word, ("resolved",)) == "resolved", word
    for word in ("import", "imports", "imported", "export", "exports", "exported", "plain"):
        assert relation_of(word, ("imported", "exported", "plain")) is not None, word
    for word in _NEAR:
        assert relation_of(word, tuple(RELATION_KEYS)) is None, word


# Words that begin with a relation's root and write none.
_NEAR = [
    "callee",
    "callees",
    "caller",
    "callback",
    "important",
    "exporter",
    "plainly",
    "decoder",
    "resolver",
]


def test_an_answer_about_another_file_is_none_of_the_sample_s() -> None:
    ledger = [
        *_ledger(),
        LedgerEntry(
            id="ev_0110",
            tool="file_header",
            args={"carved_path": "/work/carved/dropped.bin"},
            structured={
                "export_rows": [{"rva": "0x9000", "name": "spare"}],
                "imports": [{"function": RESOLVED_ONLY}],
            },
        ),
    ]
    names = run_names(ledger, ledger_facts(ledger).image_bases)
    assert "spare" not in names.exports
    assert 0x9000 not in names.by_address
    assert _held("`spare` is not exported.", names=names) == set()
    # Nor is its import one of the sample's.
    assert not names.apis[RESOLVED_ONLY.lower()].imported
    # The sample's own row still counts.
    assert names.exports["begin"].address == ENTRY
    assert _held("`begin` is not exported.", names=names) == {"begin"}


@pytest.mark.parametrize("unset", ["null", '""', "  ", "''"])
def test_an_unset_file_argument_reads_the_sample(unset: str) -> None:
    ledger = [
        *_ledger(),
        LedgerEntry(
            id="ev_0110",
            tool="file_header",
            args={"carved_path": unset},
            structured={"export_rows": [{"rva": "0x9000", "name": "spare"}]},
        ),
    ]
    names = run_names(ledger, ledger_facts(ledger).image_bases)
    assert names.exports["spare"].address == BASE + 0x9000
