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
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.agreement_facts import ledger_facts
from malspark.reporting.ledger_entities import (
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
    assert _verdicts(f"No '{TEXT}' text appears in the decoded strings.") == {TEXT: CONTRADICTED}
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


# The property: a negated clause saying anything beyond names, relation words and the
# plain words is never contradicted by code, and never held to a failed call.
_PROPERTY_NAMES = RunNames(
    apis={
        "queryhostmode": ApiHeld(
            name="QueryHostMode",
            calls=[ApiCall(0x1400, 0x2000)],
            resolved={"ev_0102": None},
            imported={"ev_0104": None},
        )
    },
    exports={"begin": ExportHeld(names=("begin",), address=0x1400, entries=("ev_0104",))},
    by_address={0x1400: ExportHeld(names=("begin",), address=0x1400, entries=("ev_0104",))},
    texts={"quietmode": _held("quietmode", "decoded_strings", "plain_strings")},
    rows=frozenset({0x1400}),
    index_whole=True,
)
_RELATION_WORDS = {
    "api": ["called", "calls", "resolved", "imported"],
    "export": ["exported", "exports"],
    "text": ["decoded", "plain"],
}
_FILLER = ["routine", "function", "at", "in", "of", "through", "established", "shown", "0x1400"]
_FAILED_FILLER = ["function", "routine", "at", "in", "address", "0x2200", "decompiled", "listed"]
# Letters no relation root, stop word, negation or hex number is spelled with.
_LETTERS = "ghjklmnpqrstvwxz"
# Words of prose a clause may add: "slot" narrows a call to one through a slot.
_PROSE = ["slot", "slots", "remote", "handle", "network", "registry", "loop", "debugger"]


def _extra(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(_PROSE)
    return "".join(rng.choice(_LETTERS) for _ in range(rng.randint(4, 8)))


def _clause(rng: random.Random, kind: str, extra: str, before: str = "") -> str:
    """A negated clause denying a relation of a name, ``extra`` among the words after its
    negation and ``before`` (a word and a space) before the name."""
    after = [rng.choice(_RELATION_WORDS[kind]), *rng.sample(_FILLER, rng.randint(0, 3))]
    if extra:
        after.insert(rng.randint(0, len(after)), extra)
    tail = " ".join(after)
    if kind == "api":
        return rng.choice(
            [f"{before}QueryHostMode is not {tail}.", f"No {before}routine {tail} QueryHostMode."]
        )
    if kind == "export":
        return f"{before}`begin` is not {tail}."
    return f"No {before}'quietmode' text is {tail}."


def test_a_clause_saying_more_than_the_relation_is_never_contradicted_by_code() -> None:
    rng = random.Random(600)
    decided = 0
    for _ in range(400):
        kind = rng.choice(list(_RELATION_WORDS))
        extra = _extra(rng)
        seed = rng.random()
        for sentence in (
            _clause(random.Random(seed), kind, extra),
            _clause(random.Random(seed), kind, "", before=f"{extra} "),
        ):
            readings = name_readings(sentence, "", _PROPERTY_NAMES)
            assert all(r.verdict != CONTRADICTED for r in readings), sentence
        # The same clause without the word is decided: the property is not vacuous.
        plain = _clause(random.Random(seed), kind, "")
        decided += any(r.verdict == CONTRADICTED for r in name_readings(plain, "", _PROPERTY_NAMES))
    assert decided > 300


def test_a_clause_saying_more_than_the_call_s_output_is_never_held_to_the_failed_calls() -> None:
    rng = random.Random(601)
    for _ in range(400):
        extra = _extra(rng)
        words = [*rng.sample(_FAILED_FILLER, rng.randint(1, 4))]
        words.insert(rng.randint(0, len(words)), extra)
        lead = rng.choice(
            ["The decompiler produced", "lift_routine returned", "The decompile shows"]
        )
        sentence = f"{lead} no {' '.join(words)} at 0x2200."
        assert held_limitation_sentences(sentence, [_REDONE], [], ()) == [], sentence
        without = f"{lead} no {' '.join(w for w in words if w != extra)} at 0x2200."
        assert held_limitation_sentences(without, [_REDONE], [], ()) == [without], without
