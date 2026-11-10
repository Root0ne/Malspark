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
tied to. Code decides only a denial that says no more than the relation the
ledger states ("no routine calls X"); the rest is the model's, with the fact
shown. Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
from datetime import UTC, datetime
from functools import lru_cache
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
    BACKED,
    CONTRADICTED,
    DROPPED_CODE,
    FACT,
    FAILURE_REDONE_CODE,
    KEEP_UNQUOTED_CODE,
    LEDGER_CONTRADICTS_CODE,
    QUALIFIED_CODE,
    UNDECIDED,
    agreement_violations,
    ask_section_agreement,
    held_limitation_sentences,
    name_readings,
    passages_of,
    prompt_text,
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


def _verdicts(sentence: str, previous: str = "") -> dict[str, str]:
    return {r.shown: r.verdict for r in name_readings(sentence, previous, _names())}


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


def test_a_denial_of_the_relation_the_index_states_is_contradicted() -> None:
    assert _verdicts(f"No routine calls {CALLED}.") == {CALLED: CONTRADICTED}
    assert _verdicts(f"{CALLED} is not called.") == {CALLED: CONTRADICTED}
    assert _verdicts(f"{CALLED} is unresolved.") == {CALLED: CONTRADICTED}
    # In the routine the clause names, the call stands; in another, the index lists none.
    assert _verdicts(f"Routine 0x5a10 does not call {CALLED}.") == {CALLED: CONTRADICTED}
    assert _verdicts(f"Routine 0x6100 does not call {CALLED}.") == {CALLED: BACKED}


def test_a_denial_the_whole_index_backs_is_backed() -> None:
    assert _verdicts(f"No routine calls {RESOLVED_ONLY}.") == {RESOLVED_ONLY: BACKED}


def test_a_denial_saying_more_than_the_relation_is_the_model_s_to_read() -> None:
    assert _verdicts(f"{CALLED} is never called with a remote handle.") == {CALLED: UNDECIDED}
    assert _verdicts(f"The decryption routine does not call {CALLED}.") == {CALLED: UNDECIDED}
    assert _verdicts(f"{CALLED} is not used to test for a debugger.") == {CALLED: UNDECIDED}
    # The subject is the rest of the sentence: the clause stating the absence is bare.
    assert _verdicts(
        f"The target of the {CALLED} call in 0x5a10, and whether a write follows, "
        "were not established [ev_0109]."
    ) == {CALLED: UNDECIDED}


def test_a_name_beside_a_denial_of_something_else_is_not_held() -> None:
    assert _verdicts(f"Emulating 0x5a10 against the {CALLED} value returned no match.") == {}
    assert _verdicts(f"Routine 0x5a10 calls {CALLED}.") == {}


def test_a_denial_of_what_a_run_saw_names_nothing() -> None:
    assert _verdicts(f"{CALLED} was not observed being called in the sandbox.") == {}


def test_a_sentence_pointing_back_is_read_on_the_apis_before_it() -> None:
    previous = f"Routine 0x6100 resolves {RESOLVED_ONLY} and {CALLED} by hash."
    sentence = "These names are shown only as resolved; the code does not show them being called."
    readings = name_readings(sentence, previous, _names())
    assert {(r.shown, r.verdict, r.back) for r in readings} == {
        (RESOLVED_ONLY, UNDECIDED, True),
        (CALLED, UNDECIDED, True),
    }
    # A sentence naming an address of its own is about it, never the sentence before.
    assert name_readings("Their bytes at 0x5a10 were not read.", previous, _names()) == []


def test_the_export_table_is_named_by_its_word_only_as_what_is_denied() -> None:
    assert _verdicts("Which export the loader calls is not established.") == {"begin": UNDECIDED}
    assert _verdicts("The hash set was not reproduced against the export tables of 27 DLLs.") == {}
    # The export table writes "begin": a "Begin" key is none of its names.
    assert _verdicts("No 'Begin' key path appears in the strings read.") == {}


def test_a_quoted_text_is_decided_against_the_decoded_strings() -> None:
    assert _verdicts(f"No '{TEXT}' text is decoded.") == {TEXT: CONTRADICTED}
    # "appears" says more than the relation: the model reads it, with the fact shown.
    assert _verdicts(f"No '{TEXT}' text appears in the decoded strings.") == {TEXT: UNDECIDED}
    # A text the run holds none of is no name of the run's: the sentence is not held.
    assert _verdicts("No 'loudmode' text appears in the decoded strings.") == {}


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
    assert limitations.ledger_decided == ()
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


def test_a_closing_keep_the_ledger_contradicts_is_left_out() -> None:
    first = "The gate reads a host mode [ev_0107]."
    denied = f"No routine calls {CALLED} [ev_0109]."
    report = _report(f"{first} {denied}")
    rows = [
        _keep("limitations", first, ["string_resolution"]),
        _keep("limitations", denied, [], "none"),
    ]
    done = _ask(report, _Reporter({"sentences": rows}, {"sentences": rows}))
    assert report.technical_analysis is not None
    assert report.technical_analysis.analyst_limitations is not None
    assert denied not in report.technical_analysis.analyst_limitations.body
    dropped = [r["message"] for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert [m for m in dropped if denied.rstrip(".") in m and LEDGER_CONTRADICTS_CODE in m]


def test_a_body_sentence_the_ledger_contradicts_gets_the_ledger_s_fact() -> None:
    denied = f"No routine calls {CALLED}."
    report = _report("The gate reads a host mode [ev_0107].", background=denied)
    done = _ask(report, _Reporter({"sentences": []}, {"sentences": []}))
    assert report.intro_background == (
        f"No routine calls {CALLED}; the function index lists a call to {CALLED} from the "
        "routine at offset 0x5a10 [ev_0102][ev_0107][ev_0109]."
    )
    assert QUALIFIED_CODE in {r["code"] for r in done.tally.unresolved}


def test_a_keep_or_a_rewrite_still_denying_the_ledger_s_fact_is_refused() -> None:
    denied = f"No routine calls {CALLED}."
    passages = passages_of(
        _report("The gate reads a host mode [ev_0107].", denied), entries=_ledger()
    )
    keep = {"sentences": [_keep("introduction", denied, [], "no source speaks of it")]}
    assert LEDGER_CONTRADICTS_CODE in {v.code for v in agreement_violations(keep, passages)}
    fact = next(p for p in passages if p.id.startswith("ledger."))
    still = {
        "sentences": [
            {
                "passage": "introduction",
                "sentence": denied,
                "sources": [fact.id],
                "decision": "rewrite",
                "rewrite": f"{CALLED} is not called [ev_0109].",
            }
        ]
    }
    assert LEDGER_CONTRADICTS_CODE in {v.code for v in agreement_violations(still, passages)}
    stated = {
        "sentences": [
            {
                **still["sentences"][0],
                "rewrite": (
                    f"Routine 0x5a10 calls {CALLED} through a slot [ev_0102][ev_0107][ev_0109]."
                ),
            }
        ]
    }
    assert LEDGER_CONTRADICTS_CODE not in {v.code for v in agreement_violations(stated, passages)}


def test_a_closing_keep_on_no_source_is_refused_where_a_ledger_fact_speaks_of_it() -> None:
    sentence = (
        f"The target of the {CALLED} call in 0x5a10, and whether a write follows, "
        "were not established [ev_0109]."
    )
    passages = passages_of(_report(sentence), entries=_ledger())
    keep = {"sentences": [_keep("limitations", sentence, [], "no source speaks of it")]}
    assert KEEP_UNQUOTED_CODE in {v.code for v in agreement_violations(keep, passages)}


def test_a_denial_of_a_redone_call_s_output_is_held_to_the_failed_calls() -> None:
    sentence = "The decompiler produced no function at 0x5a10 [ev_0109]."
    passages = passages_of(_report(sentence), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert limitations.sourced_check is not None
    keep = {"sentences": [_keep("limitations", sentence, [], "no source speaks of it")]}
    assert FAILURE_REDONE_CODE in {v.code for v in agreement_violations(keep, passages)}


def test_a_sentence_on_a_redone_routine_s_content_is_not_held_to_the_failed_calls() -> None:
    sentence = "0x5a10, decompiled later, shows no network call [ev_0107]."
    passages = passages_of(_report(sentence), entries=_ledger())
    limitations = next(p for p in passages if p.id == "limitations")
    assert limitations.sourced_check is None


# ---------------------------------------------------------------------------
# Code decides only a denial saying nothing beyond the relation the ledger holds
# the name under; anything more is the model's, with the deciding lines shown.
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


@pytest.mark.parametrize(
    "sentence",
    [
        "The decompile of 0x2200 shows no network call.",
        "The decompiled code at 0x2200 does not reference any registry key.",
        "The decompilation of 0x2200 contains no loop.",
    ],
)
def test_a_denial_of_a_redone_call_s_content_is_not_held_to_the_failed_calls(
    sentence: str,
) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == []


def test_a_denial_of_a_redone_call_s_own_output_is_still_held_to_the_failed_calls() -> None:
    sentence = "The decompiler produced no function at 0x2200 or at either address."
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == [sentence]


def _held(text: str, *keys: str) -> TextHeld:
    return TextHeld(text=text, held_as=dict.fromkeys(keys))


_TEXTS = RunNames(
    texts={
        "plainmode": _held("plainmode", "plain_strings"),
        "codedmode": _held("codedmode", "decoded_strings"),
    },
    index_whole=True,
)


def test_a_text_is_contradicted_only_under_the_key_it_is_held_under() -> None:
    def verdict(sentence: str) -> dict[str, str]:
        return {r.shown: r.verdict for r in name_readings(sentence, "", _TEXTS)}

    assert verdict("'plainmode' is not decoded.") != {"plainmode": CONTRADICTED}
    assert verdict("'codedmode' is not a plain string.") != {"codedmode": CONTRADICTED}
    assert verdict("'codedmode' is not decoded.") == {"codedmode": CONTRADICTED}
    assert verdict("'plainmode' is not a plain string.") == {"plainmode": CONTRADICTED}
    # "text" and "string" alone name no key.
    assert CONTRADICTED not in verdict("'plainmode' is not a string.").values()
    assert CONTRADICTED not in verdict("The 'codedmode' text is not there.").values()


def test_a_text_s_keys_are_read_off_the_index() -> None:
    ledger = _ledger()
    names = run_names(ledger, ledger_facts(ledger).image_bases)
    assert set(names.texts[TEXT].held_as) == {"decoded_strings"}


_WORDS = RunNames(
    apis={
        "connect": ApiHeld(name="connect", calls=[ApiCall(0x1400, None)], imported={"ev_3": None}),
        "sleep": ApiHeld(name="Sleep", calls=[ApiCall(0x1400, 0x2000)]),
        "openprocess": ApiHeld(name="OpenProcess", calls=[ApiCall(0x1400, None)]),
    },
    rows=frozenset({0x1400}),
    index_whole=True,
)


def _word_verdicts(sentence: str, previous: str = "") -> dict[str, str]:
    return {r.shown: r.verdict for r in name_readings(sentence, previous, _WORDS)}


def test_a_word_of_prose_spelled_like_an_api_is_no_name_of_the_run_s() -> None:
    assert _word_verdicts("The sample does not connect to any server.") == {}
    assert _word_verdicts("The sample does not sleep.") == {}
    # Written as code or beside a word saying it is a function, it is the API.
    assert _word_verdicts("The `connect` function is not called.") == {"connect": CONTRADICTED}
    assert _word_verdicts("`Sleep` is not called.") == {"Sleep": CONTRADICTED}


def test_a_slot_narrows_the_call_and_code_does_not_decide_it() -> None:
    # The only call the index lists is an import call: no slot.
    assert _word_verdicts("OpenProcess is not called through a slot.") == {"OpenProcess": UNDECIDED}
    assert _word_verdicts("OpenProcess is not called.") == {"OpenProcess": CONTRADICTED}


def test_a_sentence_pointing_back_is_held_only_where_it_denies_a_relation() -> None:
    previous = "Routine 0x1400 starts the child with OpenProcess."
    assert _word_verdicts("This is an immediate launch and not a persistence step.", previous) == {}
    readings = name_readings("These are not shown being called.", previous, _WORDS)
    assert [(r.shown, r.back) for r in readings] == [("OpenProcess", True)]


def test_an_answer_about_another_file_decides_nothing_of_the_sample() -> None:
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
    # Read as the sample's, the ledger would contradict it; it is another file's.
    assert {r.shown: r.verdict for r in name_readings("`spare` is not exported.", "", names)} == {}
    # Nor is its import one of the sample's.
    assert not names.apis[RESOLVED_ONLY.lower()].imported
    # The sample's own row still counts.
    assert names.exports["begin"].address == ENTRY


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
    assert not names.set_aside


def test_a_denial_is_not_backed_where_an_answer_was_set_aside() -> None:
    ledger = [
        *_ledger(),
        LedgerEntry(
            id="ev_0110",
            tool="file_header",
            args={"carved_path": "/work/carved/dropped.bin"},
            structured={"export_rows": [{"rva": "0x9000", "name": "spare"}]},
        ),
    ]
    names = run_names(ledger, ledger_facts(ledger).image_bases)
    assert names.set_aside
    # The sample's own export still contradicts; an absence is no longer backed.
    assert _named("`begin` is not exported.", names) == {"begin": CONTRADICTED}
    assert _named(f"{RESOLVED_ONLY} is not imported.", names) == {RESOLVED_ONLY: UNDECIDED}
    whole = run_names(_ledger(), ledger_facts(_ledger()).image_bases)
    assert _named(f"{RESOLVED_ONLY} is not imported.", whole) == {RESOLVED_ONLY: BACKED}


def _named(sentence: str, names: Any) -> dict[str, str]:
    return {r.shown: r.verdict for r in name_readings(sentence, "", names)}


def test_a_name_written_as_a_call_is_the_name() -> None:
    assert _word_verdicts("`connect()` is not called.") == {"connect": CONTRADICTED}
    assert _word_verdicts("`Sleep()` is not called.") == {"Sleep": CONTRADICTED}


_CALLEES = RunNames(
    apis={"openprocess": ApiHeld(name="OpenProcess", calls=[ApiCall(0x1400, None)])},
    callees={0x1400: (0x1600,), 0x1600: ()},
    rows=frozenset({0x1400, 0x1600}),
    index_whole=True,
)


@pytest.mark.parametrize(
    "sentence",
    [
        "No callee of 0x1400 calls OpenProcess.",
        "OpenProcess is not called by any callee of 0x1400.",
        "OpenProcess is not called by the callees of 0x1400.",
        "No caller of 0x1600 calls OpenProcess.",
    ],
)
def test_a_callee_or_caller_narrows_the_call_and_code_does_not_decide_it(sentence: str) -> None:
    assert _named(sentence, _CALLEES) == {"OpenProcess": UNDECIDED}


@pytest.mark.parametrize(
    "sentence",
    [
        "OpenProcess is not called outside 0x1400.",
        "OpenProcess is not called except in 0x1400.",
        "OpenProcess is not called from 0x1400.",
        "OpenProcess is not never called.",
    ],
)
def test_a_preposition_on_an_address_or_a_second_negation_leaves_it_to_the_model(
    sentence: str,
) -> None:
    assert _named(sentence, _CALLEES) == {"OpenProcess": UNDECIDED}


def test_a_routine_named_as_the_call_s_own_is_still_decided() -> None:
    assert _named("Routine 0x1400 does not call OpenProcess.", _CALLEES) == {
        "OpenProcess": CONTRADICTED
    }
    assert _named("Routine 0x1600 does not call OpenProcess.", _CALLEES) == {"OpenProcess": BACKED}


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


def test_a_generic_word_is_no_plain_word_of_a_denial() -> None:
    # "loader" stands in most passages, yet "the loader" may be one routine of many.
    sentence = "The loader does not call OpenProcess."
    assert {
        r.shown: r.verdict for r in name_readings(sentence, "", _CALLEES, frozenset({"loader"}))
    } == {"OpenProcess": UNDECIDED}


@pytest.mark.parametrize(
    "sentence",
    [
        "The network-call search in the decompile of 0x2200 found nothing.",
        "The decompile of 0x2200 for registry keys returned nothing.",
        "The decompiled routine at 0x2200 calls nothing.",
        "The decompile of 0x2200 calls nothing.",
        "The decompiled routine at 0x2200 writes nothing.",
        "The decompile of 0x2200 returned nothing.",
    ],
)
def test_a_clause_ending_in_its_negation_is_read_whole(sentence: str) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Lift_routine returned nothing for 0x2200.",
        "The decompiler produced nothing at 0x2200.",
    ],
)
def test_a_clause_ending_in_its_negation_on_the_call_s_output_is_held(sentence: str) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == [sentence]


# ---------------------------------------------------------------------------
# Code decides only where every word of the whole sentence is accounted for: the one
# name decided, the word forms of one relation, an address or a routine noun where the
# decider scopes by routine, one negation, a few function words and the citations. A
# word beyond them, in any clause, leaves the sentence to the model.
# ---------------------------------------------------------------------------

_RUN = RunNames(
    apis={
        "openprocess": ApiHeld(name="OpenProcess", calls=[ApiCall(0x1400, None)]),
        "createprocessw": ApiHeld(name="CreateProcessW", calls=[ApiCall(0x1500, None)]),
        "connect": ApiHeld(name="connect", calls=[ApiCall(0x1400, None)], imported={"ev_3": None}),
        "sleep": ApiHeld(name="Sleep", resolved={"ev_2": None}),
    },
    exports={"run": ExportHeld(names=("run",), address=0x1600, entries=("ev_4",))},
    by_address={0x1600: ExportHeld(names=("run",), address=0x1600, entries=("ev_4",))},
    texts={
        "secret.dat": _held("secret.dat", "decoded_strings"),
        "cmd.exe": _held("cmd.exe", "plain_strings"),
    },
    rows=frozenset({0x1400, 0x1500, 0x1600}),
    index_whole=True,
)
# Each sentence code still decides, the name it decides and its verdict.
_DECIDED = [
    ("OpenProcess is never called.", "OpenProcess", CONTRADICTED),
    ("No routine calls OpenProcess.", "OpenProcess", CONTRADICTED),
    ("`Sleep` is not resolved.", "Sleep", CONTRADICTED),
    ("`connect` is not imported.", "connect", CONTRADICTED),
    ("'secret.dat' was not decoded.", "secret.dat", CONTRADICTED),
    ("'cmd.exe' is not a plain string.", "cmd.exe", CONTRADICTED),
    ("`run` is not exported.", "run", CONTRADICTED),
    ("Routine 0x1400 does not call OpenProcess.", "OpenProcess", CONTRADICTED),
    ("Routine 0x1600 does not call OpenProcess.", "OpenProcess", BACKED),
]


@pytest.mark.parametrize(("sentence", "shown", "verdict"), _DECIDED)
def test_a_denial_saying_only_the_relation_is_still_decided(
    sentence: str, shown: str, verdict: str
) -> None:
    assert _named(sentence, _RUN) == {shown: verdict}


@pytest.mark.parametrize(
    "sentence",
    [
        # A word the content-word reader drops still says something.
        "No other routine calls OpenProcess.",
        "OpenProcess is not called by other routines.",
        "Not all routines call OpenProcess.",
        "`connect` is not only imported but also called.",
        # A clause beside the negated one scopes it.
        "Apart from 0x1400, no routine calls OpenProcess.",
        "OpenProcess is not called, except in 0x1400.",
        "OpenProcess is not called (except by 0x1400).",
        "If the check fails, OpenProcess is not called.",
        # A word saying what a run did is no word of the index.
        "No call to OpenProcess was executed.",
        "No call to OpenProcess was reached.",
        "No call to OpenProcess was traced.",
        "No call to OpenProcess was exercised.",
        "No call to OpenProcess was completed.",
        "No call of OpenProcess was executed.",
        "No call of OpenProcess was reached.",
    ],
)
def test_a_sentence_saying_more_than_the_relation_in_any_word_is_the_model_s(
    sentence: str,
) -> None:
    verdicts = _named(sentence, _RUN)
    assert verdicts and set(verdicts.values()) == {UNDECIDED}, verdicts


@pytest.mark.parametrize(
    "sentence",
    [
        "OpenProcess does not call CreateProcessW.",
        "No routine calls both OpenProcess and CreateProcessW.",
    ],
)
def test_a_second_name_the_run_holds_is_a_word_beyond_the_one_decided(sentence: str) -> None:
    assert _named(sentence, _RUN) == {"OpenProcess": UNDECIDED, "CreateProcessW": UNDECIDED}


@pytest.mark.parametrize(
    "sentence",
    [
        "The decompiler produced no other function at 0x2200.",
        "The decompiler produced no more functions at 0x2200.",
        "Apart from a thunk, the decompiler produced no function at 0x2200.",
    ],
)
def test_a_denial_of_a_redone_call_saying_more_in_any_word_is_not_held(sentence: str) -> None:
    assert held_limitation_sentences(sentence, [_REDONE], [], ()) == []


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
        "The decompiler produced no function at 0x2200 or 0x1030 [ev_0109].",
        "The decompiler produced no function at 0x2200, 0x1030 or at either address.",
        # The reason a denial gives is read as a sentence of its own.
        "The function boundaries of 0x2200 and 0x1030 are not confirmed, because the "
        "decompiler produced no function at either address [ev_0109].",
    ],
)
def test_a_denial_of_redone_calls_at_a_list_of_addresses_is_held(sentence: str) -> None:
    assert held_limitation_sentences(sentence, _REDONE_AT_TWO, [], ()) == [sentence]


@pytest.mark.parametrize(
    "sentence",
    [
        "The function boundaries of 0x2200 and 0x1030 are not confirmed, because the "
        "decompiler produced no other function at either address.",
        "The decompiler produced no function at 0x2200 and other 0x1030.",
        "The decompiler produced no function at either 0x2200.",
    ],
)
def test_a_reason_or_an_address_list_saying_more_is_not_held(sentence: str) -> None:
    assert held_limitation_sentences(sentence, _REDONE_AT_TWO, [], ()) == []


def test_a_sentence_citing_a_redone_call_and_not_its_redo_is_held_whatever_else_it_says() -> None:
    cited = "The decompiler produced no function at 0x2200 [ev_0201], and its bytes were read."
    assert held_limitation_sentences(cited, [_REDONE], [], ()) == [cited]
    uncited = "The decompiler produced no function at 0x2200, and its bytes were read."
    assert held_limitation_sentences(uncited, [_REDONE], [], ()) == []
    redone = "The decompiler produced no function at 0x2200 [ev_0201][ev_0202]."
    assert held_limitation_sentences(redone, [_REDONE], [], ()) == []


def test_both_deciders_read_the_sentence_through_one_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from malspark.reporting import section_agreement

    held = "The decompiler produced no function at 0x2200."
    assert _named("No routine calls OpenProcess.", _RUN) == {"OpenProcess": CONTRADICTED}
    assert held_limitation_sentences(held, [_REDONE], [], ()) == [held]
    monkeypatch.setattr(section_agreement, "_words_left", lambda *_a, **_k: None)
    assert _named("No routine calls OpenProcess.", _RUN) == {"OpenProcess": UNDECIDED}
    assert held_limitation_sentences(held, [_REDONE], [], ()) == []


# The property: one word inserted anywhere in a sentence code decides, or added as a
# clause of its own, leaves it to the model (never contradicted by code, never held to
# a failed call); the sentence as it stands is decided.
_PROPERTY_NAMES = RunNames(
    apis={
        "queryhostmode": ApiHeld(
            name="QueryHostMode",
            calls=[ApiCall(0x1400, 0x2000)],
            resolved={"ev_0102": None},
            imported={"ev_0104": None},
        ),
        "readselftoken": ApiHeld(name="ReadSelfToken", calls=[ApiCall(0x1500, None)]),
    },
    exports={"begin": ExportHeld(names=("begin",), address=0x1400, entries=("ev_0104",))},
    by_address={0x1400: ExportHeld(names=("begin",), address=0x1400, entries=("ev_0104",))},
    texts={
        "quietmode": _held("quietmode", "decoded_strings", "plain_strings"),
        "loudmode": _held("loudmode", "plain_strings"),
    },
    rows=frozenset({0x1400, 0x1500, 0x1600}),
    index_whole=True,
)
# Each sentence code decides, and the names the run holds it does not write.
_NAME_BASES = [
    ("QueryHostMode is never called.", ["ReadSelfToken", "`begin`", "'loudmode'"]),
    ("No routine calls QueryHostMode.", ["ReadSelfToken", "'quietmode'"]),
    ("`QueryHostMode` is not resolved.", ["ReadSelfToken", "`begin`"]),
    ("QueryHostMode isn't imported [ev_0104].", ["ReadSelfToken", "'loudmode'"]),
    ("Routine 0x1400 does not call QueryHostMode.", ["ReadSelfToken", "`begin`"]),
    ("Routine 0x1600 does not call QueryHostMode.", ["ReadSelfToken"]),
    ("QueryHostMode is unresolved.", ["ReadSelfToken"]),
    ("'quietmode' was not decoded.", ["'loudmode'", "QueryHostMode"]),
    ("'quietmode' is not a plain string.", ["'loudmode'", "ReadSelfToken"]),
    ("`begin` is not exported.", ["QueryHostMode", "'quietmode'"]),
]
# Each sentence held to the failed calls, and the part of it a word is put in: a reason
# a denial gives is read on its own, so a word is put in the reason.
_FAILED_BASES = [
    ("", "The decompiler produced no function at 0x2200."),
    ("", "Lift_routine returned nothing for 0x2200."),
    ("", "The decompiler produced nothing at 0x2200 [ev_0109]."),
    ("", "The decompiler produced no function at 0x2200 or 0x1030."),
    (
        "The function boundaries of 0x2200 and 0x1030 are not confirmed, because ",
        "the decompiler produced no function at either address.",
    ),
]
# Letters no relation root, stop word, negation or hex number is spelled with.
_LETTERS = "ghjklmnpqrstvwxz"
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
# The stems of the keys' words; a word built on one with a letter no ending starts with
# ("s", "e", "d", "i") is no form of it.
_STEMS = sorted(
    {
        word[:-2] if word.endswith("ed") else word[:-1] if word.endswith("s") else word
        for keys in RELATION_KEYS.values()
        for key in keys
        for word in key.split("_")
    }
)
_NO_ENDING = "bcfhjklmopqrtuvwxyz"
# How a word is put in: on its own, or as a clause of its own.
_JOINED = ("{}", ", {}", "and {}", "but {}", "({})")


@lru_cache(maxsize=1)
def _held_in() -> frozenset[str]:
    """Every word form of every key's word."""
    from malspark.reporting.section_agreement import word_forms

    return frozenset(
        form
        for keys in RELATION_KEYS.values()
        for key in keys
        for word in key.split("_")
        for form in word_forms(word)
    )


def _by_design(word: str) -> bool:
    """Whether a word is one the rule reads in a decided sentence: a function word, a
    negation, a relation's or a key's word form, a routine noun, an address word, or a
    word naming the failed call."""
    from malspark.pipeline.validation import _ROUTINE_NOUNS
    from malspark.reporting.absence_answers import carries_negation
    from malspark.reporting.section_agreement import _ADDRESS_WORDS, _FUNCTION_WORDS

    return (
        word in _FUNCTION_WORDS
        or carries_negation(word)
        or relation_of(word, tuple(RELATION_KEYS)) is not None
        or word in _held_in()
        or word in _ROUTINE_NOUNS
        or any(word in (plain, plain + "s", plain + "es") for plain in _ADDRESS_WORDS)
        or word.startswith(("decompil", "disassembl", "emulat", "listing", "lift"))
    )


def _ordinary_words() -> list[str]:
    """A seeded sample of the ordinary English words this file's own text writes."""
    from pathlib import Path

    text = Path(__file__).read_text(encoding="utf-8")
    words = sorted({w for w in re.findall(r"(?<![\w`'])[a-z]{3,}(?![\w`'])", text)})
    # The run's own names are the name a sentence decides, or a second one put in apart.
    held = {*_PROPERTY_NAMES.apis, *_PROPERTY_NAMES.exports, *_PROPERTY_NAMES.texts}
    words = [w for w in words if not _by_design(w) and w not in held]
    assert len(words) >= 300, len(words)
    return random.Random(600).sample(words, 300)


def _inserted() -> list[str]:
    """Every word the property puts in: the stop words the content-word reader drops,
    ordinary words, the words saying what a run did, words built on a relation's stem."""
    from malspark.reporting.absence_answers import _STOPWORDS
    from malspark.reporting.section_agreement import _ABSENCE_PREDICATES

    rng = random.Random(601)
    stems = [
        stem + rng.choice(_NO_ENDING) + "".join(rng.choice(_NO_ENDING) for _ in range(n))
        for stem in _STEMS
        for n in (0, 2)
    ]
    letters = ["".join(rng.choice(_LETTERS) for _ in range(rng.randint(4, 8))) for _ in range(5)]
    drawn = [
        *sorted(_STOPWORDS),
        # The word joining a list of addresses, too short for the content-word reader.
        "or",
        *_ordinary_words(),
        *sorted(_ABSENCE_PREDICATES),
        *stems,
        *_NEAR,
        *letters,
    ]
    return [w for w in dict.fromkeys(drawn) if not _by_design(w)]


def _put_in(lead: str, part: str, word: str) -> list[str]:
    """``lead`` + ``part`` with ``word`` put in ``part`` at every place, on its own or as
    a clause of its own."""
    words = part.rstrip(".").split()
    end = "." if part.endswith(".") else ""
    return [
        lead + " ".join([*words[:at], joined.format(word), *words[at:]]) + end
        for at in range(len(words) + 1)
        for joined in _JOINED
    ]


def test_a_word_put_in_a_decided_denial_of_a_name_leaves_it_to_the_model() -> None:
    inserted = _inserted()
    for base, others in _NAME_BASES:
        readings = name_readings(base, "", _PROPERTY_NAMES)
        # The sentence as it stands is decided: the property is not vacuous.
        assert readings and all(r.verdict != UNDECIDED for r in readings), base
        for word in [*inserted, *others]:
            for sentence in _put_in("", base, word):
                readings = name_readings(sentence, "", _PROPERTY_NAMES)
                assert all(r.verdict != CONTRADICTED for r in readings), sentence
                assert all(r.verdict == UNDECIDED for r in readings), sentence


def test_a_word_put_in_a_denial_of_a_redone_call_leaves_it_unheld() -> None:
    from malspark.reporting.section_agreement import _denies_a_failed_call

    inserted = [*_inserted(), "QueryHostMode", "'quietmode'"]
    for lead, part in _FAILED_BASES:
        base = lead + part
        assert _denies_a_failed_call(base, _REDONE_AT_TWO, ()), base
        assert held_limitation_sentences(base, _REDONE_AT_TWO, [], ()) == [base], base
        for word in inserted:
            for sentence in _put_in(lead, part, word):
                assert not _denies_a_failed_call(sentence, _REDONE_AT_TWO, ()), sentence
