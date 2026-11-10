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
    DROPPED_CODE,
    FACT,
    FAILURE_REDONE_CODE,
    KEEP_UNQUOTED_CODE,
    QUALIFIED_CODE,
    _failure_redone_check,
    agreement_violations,
    ask_section_agreement,
    held_limitation_sentences,
    name_readings,
    passages_of,
    prompt_text,
    redone_calls_named,
    relation_of,
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


def test_the_export_table_is_named_by_its_word_only_as_what_is_denied() -> None:
    assert _held("Which export the loader calls is not established.") == {"begin"}
    assert _held("The hash set was not reproduced against the export tables of 27 DLLs.") == set()
    # The export table writes "begin": a "Begin" key is none of its names.
    assert _held("No 'Begin' key path appears in the strings read.") == set()


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
    # Held and shown its fact; no row answered it, and code adds nothing to it.
    assert report.intro_background == denied
    assert QUALIFIED_CODE not in {r["code"] for r in done.tally.unresolved}
    assert DROPPED_CODE not in {r["code"] for r in done.tally.unresolved}


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
    check = _failure_redone_check([_REDONE], [], ())
    for sentence in (
        "The decompiler produced no function at 0x2200.",
        "The decompile of 0x2200 shows no network call.",
    ):
        (found,) = check(sentence, [], "")
        assert found.code == FAILURE_REDONE_CODE
        assert found.message == (
            "it names a call that failed and a later call redid (ev_0201 by ev_0202) and "
            "cites none of the calls that redid it. Cite ev_0202 for what it states, or "
            "rewrite it on what ev_0202 answered, or drop it."
        )
        # The same words citing the call that redid it pass the check.
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
    check = _failure_redone_check([_REDONE, redone_twice], [], ())
    sentence = "The decompiler produced no function at 0x2200 or 0x1030."
    (found,) = check(sentence, [], "")
    assert "Cite ev_0202 and ev_0204 or ev_0205 for what it states" in found.message
    # One redo of each call passes; the redo of one call alone does not.
    assert check(sentence.rstrip(".") + " [ev_0202][ev_0205].", [], "") == []
    assert check(sentence.rstrip(".") + " [ev_0202].", [], "") != []


def test_a_sentence_saying_a_call_failed_keeps_its_finding() -> None:
    check = _failure_redone_check([_REDONE], [], ())
    (found,) = check("The decompile of 0x2200 failed.", [], "")
    assert found.message.startswith("the rewrite still says a call failed")


_TRUE = "The decompile of 0x5a10 shows no network call."


def test_the_round_is_shown_the_redo_to_cite_and_refuses_an_uncited_keep() -> None:
    passages = passages_of(_report(_TRUE), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert limitations.redone_named == ((_TRUE, ("ev_0107",)),)
    text = prompt_text(passages)
    assert (
        "- [failed.1] tool call that failed, and whether a later call redid it (cites ev_0101, "
        'ev_0107): ev_0101 ("lift_routine") failed: "no function there"; the later call ev_0107 '
        "answered for every address it asked (offset 0x5a10), so it did not fail for good"
    ) in text
    assert (
        "  [limitations] each of these names a call that failed and a later call redid, and "
        "cites none of the calls that redid it: a keep of it as written is refused; rewrite it "
        "citing the call named here for what it states, or on what that call answered, or "
        f'drop it: "{_TRUE}" (cite ev_0107)'
    ) in text
    keep = {"sentences": [_keep("limitations", _TRUE, [], "no source speaks of it")]}
    refused = [v for v in agreement_violations(keep, passages) if v.code == FAILURE_REDONE_CODE]
    assert [v.message for v in refused] == [
        "row 1: limitations keeps a sentence the ledger says otherwise of: it names a call "
        "that failed and a later call redid (ev_0101 by ev_0107) and cites none of the calls "
        "that redid it. Cite ev_0107 for what it states, or rewrite it on what ev_0107 "
        "answered, or drop it."
    ]
    # Its words citing the call that redid it are accepted by the failure check.
    cited = {
        "sentences": [
            {
                "passage": "limitations",
                "sentence": _TRUE,
                "sources": ["failed.1"],
                "decision": "rewrite",
                "rewrite": "The decompile of 0x5a10 shows no network call [ev_0107].",
            }
        ]
    }
    assert FAILURE_REDONE_CODE not in {v.code for v in agreement_violations(cited, passages)}
    assert limitations.sourced_check is not None
    assert limitations.sourced_check(cited["sentences"][0]["rewrite"], ["failed.1"], "") == []


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
