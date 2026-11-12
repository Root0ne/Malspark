"""A body absence is held as a closing one is; a no-source keep reads the entry it cites (T-580).

haiku13's section 5 said "The analysed sample is therefore not shown to use
anti-debug or environment checks", while section 4, the ATT&CK table and the
limitations described the gates and the ledger listed them: the absence check
held only the limitations' sentences. Its limitations kept "The injection target
and the parent of sandbox processes 83 and 88 are not established [ev_0012]" on
the answer that no source states the parent, while ev_0012 holds each process's
ppid.

A whole-code absence of any section is now held, "not shown to", "not
confirmed" and "no evidence of" among the shapes, and a keep of one is held as
a closing keep is: on a source's words, or on the reason where no source,
another passage of the body included, speaks of it. It is never left out; a keep
not tied to a source's words is recorded. A keep on no source of a sentence
citing an entry whose rows record a value it names is asked again with the rows
shown. Every address, entry and value here is a neutral one.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.absence_answers import denied_subject
from malspark.reporting.entry_fields import named_values, rows_naming
from malspark.reporting.models import (
    FileHashes,
    FlowStep,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    HELD_KEPT_CODE,
    KEEP_UNQUOTED_CODE,
    UNKNOWN_PASSAGE_CODE,
    _sentences_of,
    agreement_violations,
    ask_section_agreement,
    passages_of,
    prompt_text,
)
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

DENIED = "The analysed sample is therefore not shown to use timing or locale checks."
GATES = "Routine 0x1400 runs timing and locale checks before the beacon starts [ev_0002]."
FLOW_ABSENT = "The sleep constants are not confirmed."
PARENTS = "The parent of the guest processes 41 and 47 is not established [ev_0003]."
COUNTED = "The capture holds 41 external conversations and no contact is shown [ev_0003]."
CITABLE = [f"ev_{n:04d}" for n in range(1, 6)]


def _ledger() -> list[LedgerEntry]:
    processes = {
        "processes": [
            {"pid": 41, "ppid": 12, "name": "host.exe"},
            {"pid": 47, "ppid": 41, "name": "host.exe"},
            {"pid": 90, "ppid": 4, "name": "other.exe"},
        ],
        "total": 3,
    }
    return [
        LedgerEntry(id="ev_0001", tool="image_facts", output='{"image_base": "0x2470000"}'),
        LedgerEntry(id="ev_0002", tool="lift_routine", output="int f(void) { return 0; }"),
        LedgerEntry(
            id="ev_0003",
            tool="guest_processes",
            output=json.dumps(processes),
            structured=processes,
        ),
    ]


def _report(
    *,
    evasion: str = f"Strings are encoded [ev_0002]. {DENIED}",
    flow: str = GATES,
    limitations: str = PARENTS,
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            execution_flow=[
                FlowStep(order=1, action=flow),
                FlowStep(order=2, action=f"It sleeps [ev_0002]. {FLOW_ABSENT}"),
            ],
            evasion_antiforensics=TechnicalSubsection(
                title="Evasion", body=evasion, evidence_refs=["ev_0002"]
            ),
            analyst_conclusion=TechnicalSubsection(
                title="Conclusion", body="The file is a loader [ev_0002]."
            ),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
    )


def _by_id(report: MalwareReport) -> dict[str, Any]:
    return {p.id: p for p in passages_of(report, entries=_ledger())}


def _row(passage: str, sentence: str, sources: list[str], **kw: Any) -> dict[str, Any]:
    return {"passage": passage, "sentence": sentence, "sources": sources, "decision": "keep", **kw}


def _found(report: MalwareReport, row: dict[str, Any]) -> list[Any]:
    passages = passages_of(report, entries=_ledger())
    return [
        v
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.path.startswith("sentences")
    ]


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _ask(report: MalwareReport, *answers: Any) -> tuple[Any, _Reporter]:
    ledger = _ledger()
    reporter = _Reporter(*answers)
    done = asyncio.run(
        ask_section_agreement(
            reporter, report, citable_ids=CITABLE, evidence_texts=EntryTexts.from_ledger(ledger)
        )
    )
    return done, reporter


def _rest(report: MalwareReport, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows, and a keep on the reason for every other held sentence."""
    named = {(r["passage"], r["sentence"]) for r in rows}
    return [
        *rows,
        *(
            _row(p.id, s, [], reason="no source speaks of it")
            for p in passages_of(report, entries=_ledger())
            for s in p.held
            if (p.id, s) not in named
        ),
    ]


# -- what is held ------------------------------------------------------------------


def test_a_whole_code_absence_of_any_section_is_held() -> None:
    by_id = _by_id(_report())
    assert by_id["evasion_antiforensics"].absences == (DENIED,)
    assert DENIED in by_id["evasion_antiforensics"].held
    assert by_id["execution_flow.2"].absences == (FLOW_ABSENT,)
    # A sentence stating no absence is not held, and the closing passage holds all.
    assert by_id["execution_flow.1"].held == ()
    assert by_id["limitations"].absences == ()


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        ("The sample is therefore not shown to use timing checks.", True),
        ("The key schedule is not separately confirmed.", True),
        ("There is no evidence of a second stage.", True),
        ("The sleep constants have not been established.", True),
        # What a run did not see is an observation, and an address is held by what it names.
        ("No beacon was observed in the run.", False),
        ("The body of 0x1400 is not confirmed.", False),
    ],
)
def test_the_absence_shapes(sentence: str, held: bool) -> None:
    by_id = _by_id(_report(flow=sentence))
    assert by_id["execution_flow.1"].absences == ((sentence,) if held else ())


def test_the_prompt_asks_how_a_body_absence_is_kept() -> None:
    text = prompt_text(passages_of(_report(), entries=_ledger()))
    assert "[execution_flow.2] each of these states an absence" in text
    assert '"quote": its words that state the same absence' in text
    assert '"sources": [] and "reason" where no source speaks of it' in text


# -- how a body absence is kept -----------------------------------------------------


@pytest.mark.parametrize(
    ("sentence", "held"),
    [
        ("The key is unknown.", True),
        ("Persistence template; mechanism unknown", True),
        ("It is unknown whether the gate passes.", True),
        # "unknown" modifying a noun says nothing is unknown.
        ("The loader can place an unknown second stage on the host.", False),
    ],
)
def test_unknown_is_read_only_as_what_is_said_of_something(sentence: str, held: bool) -> None:
    assert _by_id(_report(flow=sentence))["execution_flow.1"].absences == (
        (sentence,) if held else ()
    )


def test_a_determiner_after_to_is_no_doing() -> None:
    from malspark.reporting.absence_answers import denied_items

    # "not shown to the analyst" names no doing: the subject stays what is denied.
    assert denied_subject("The key schedule is not shown to the analyst.") == {"key", "schedule"}
    assert denied_items(DENIED)


@pytest.mark.parametrize(
    ("absence", "flow"),
    [
        # A run-set absence: no passage of code says otherwise of it.
        ("Whether the timing gate passes in the sandbox is not established.", GATES),
        # The words spread over two sentences: no one sentence could be quoted.
        (
            "The beacon interval is not confirmed.",
            "The beacon is built by 0x1400 [ev_0002]. Its interval comes from a tick count.",
        ),
    ],
)
def test_no_source_speaks_that_could_not_be_quoted(absence: str, flow: str) -> None:
    report = _report(evasion=f"Strings are encoded [ev_0002]. {absence}", flow=flow)
    assert absence in _by_id(report)["evasion_antiforensics"].absences
    assert _found(report, _row("evasion_antiforensics", absence, [], reason="nothing")) == []


def test_a_run_set_absence_is_spoken_of_by_what_a_run_saw() -> None:
    absence = "Whether the timing gate passes in the sandbox is not established."
    saw = "In the sandbox run the timing gate passes and the beacon starts [ev_0002]."
    report = _report(evasion=f"Strings are encoded [ev_0002]. {absence}", flow=saw)
    found = _found(report, _row("evasion_antiforensics", absence, [], reason="nothing"))
    assert [v.code for v in found] == [KEEP_UNQUOTED_CODE]


def test_every_refusal_can_be_answered_by_what_it_names() -> None:
    from malspark.reporting.section_agreement import _speaking_sources

    family = "The family is not confirmed."
    report = _report(
        evasion=f"Strings are encoded by 0x1400 [ev_0002]. {family}",
        flow="Engines label routine 0x1400 as a loader family [ev_0002].",
    )
    by_id = _by_id(report)
    speaking = _speaking_sources(family, by_id, by_id["evasion_antiforensics"])
    assert [pid for pid, _excerpt in speaking] == ["execution_flow.1"]
    for pid, excerpt in speaking:
        # Its words state no absence: a keep quoting them is refused, a rewrite on them
        # passes (T-652).
        keep = _row("evasion_antiforensics", family, [pid], quote=excerpt)
        assert [v.code for v in _found(report, keep)] == [KEEP_UNQUOTED_CODE]
        rewrite = {**keep, "decision": "rewrite", "rewrite": f"{excerpt[:1].upper()}{excerpt[1:]}"}
        assert _found(report, rewrite) == []


def test_a_body_keep_resting_only_on_another_written_passage_is_recorded() -> None:
    agreeing = "No timing or locale checks are shown in the code read [ev_0002]."
    report = _report(
        evasion="Strings are encoded [ev_0002].",
        flow=agreeing,
        limitations="This analysis does not establish the operator.",
    )
    report.technical_analysis.execution_flow[1].action = f"It sleeps [ev_0002]. {DENIED}"
    row = _row("execution_flow.2", DENIED, ["execution_flow.1"], quote=agreeing)
    done, reporter = _ask(report, {"sentences": _rest(report, [row])})
    assert len(reporter.asked) == 1
    records = [r["message"] for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert any(DENIED[:30] in m and "only on another written passage" in m for m in records)


def test_what_a_doing_is_not_shown_of_is_its_object() -> None:
    assert denied_subject(DENIED) == {"timing", "locale", "checks"}
    # Values coordinated with the item before are part of it, never a bare verb.
    assert {"parent", "guest", "processes"} <= denied_subject(PARENTS)


def test_a_no_source_keep_is_refused_where_another_passage_of_the_body_speaks() -> None:
    found = _found(_report(), _row("evasion_antiforensics", DENIED, [], reason="none does"))
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert "execution_flow.1" in refused.message
    # Never "drop it": a body sentence is never left out.
    assert "drop" not in refused.message


def test_a_no_source_keep_stands_where_no_source_speaks() -> None:
    report = _report(flow="It resolves its imports [ev_0002].")
    assert _found(report, _row("evasion_antiforensics", DENIED, [], reason="none does")) == []


def test_a_keep_quoting_a_passage_that_states_the_same_absence_passes() -> None:
    agreeing = "No timing or locale checks are shown in the code read [ev_0002]."
    report = _report(flow=agreeing)
    row = _row("evasion_antiforensics", DENIED, ["execution_flow.1"], quote=agreeing)
    assert _found(report, row) == []
    # Its own passage is never its source, and a quote stating no absence passes no keep.
    own = _row("evasion_antiforensics", DENIED, ["evasion_antiforensics"], quote=DENIED)
    assert _found(report, own)
    # A quote stating no absence, from a source that speaks of it, is refused: the passage
    # stating what the sentence denies backs no keep of it (T-652).
    present = _row("evasion_antiforensics", DENIED, ["execution_flow.1"], quote=GATES)
    assert [v.code for v in _found(_report(), present)] == [KEEP_UNQUOTED_CODE]
    unrelated = _row("evasion_antiforensics", DENIED, ["conclusion"], quote="The file is a loader")
    assert [v.code for v in _found(_report(), unrelated)] == [KEEP_UNQUOTED_CODE]


def test_a_keep_on_words_stating_no_absence_is_recorded() -> None:
    report = _report(limitations="This analysis does not establish the operator.")
    row = _row("evasion_antiforensics", DENIED, ["execution_flow.1"], quote=GATES)
    # Refused, asked again, and kept as written on the retry: it stands, recorded (T-652).
    rows = _rest(report, [row])
    done, reporter = _ask(report, {"sentences": rows}, {"sentences": rows})
    assert len(reporter.asked) == 2
    assert DENIED in report.technical_analysis.evasion_antiforensics.body
    records = [r["message"] for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert any(DENIED[:30] in m and "the checks refused" in m for m in records)


def test_a_body_absence_is_never_left_out() -> None:
    row = {**_row("evasion_antiforensics", DENIED, []), "decision": "drop", "reason": "false"}
    assert UNKNOWN_PASSAGE_CODE in [v.code for v in _found(_report(), row)]


def test_a_refused_body_keep_stands_after_the_retry_and_is_recorded() -> None:
    report = _report(limitations="This analysis does not establish the operator.")
    rows = _rest(report, [_row("evasion_antiforensics", DENIED, [], reason="none does")])
    done, reporter = _ask(report, {"sentences": rows}, {"sentences": rows})
    assert len(reporter.asked) == 2
    assert DENIED in report.technical_analysis.evasion_antiforensics.body
    records = [r for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert any(DENIED[:30] in r["message"] and KEEP_UNQUOTED_CODE in r["message"] for r in records)
    assert not [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]


def test_a_rewrite_on_the_passage_that_states_otherwise_is_put_in() -> None:
    # The passage written without the code names an address the sentence's passage names.
    report = _report(evasion=f"Strings are encoded by 0x1400 [ev_0002]. {DENIED}")
    rewrite = "Routine 0x1400 runs timing and locale checks [ev_0002]."
    row = {
        **_row("evasion_antiforensics", DENIED, ["execution_flow.1"]),
        "decision": "rewrite",
        "rewrite": rewrite,
    }
    # A held absence of section 5 is rewritten on any source that speaks of it, the
    # claim stating the checks included (T-652).
    done, _ = _ask(report, {"sentences": _rest(report, [row])})
    assert done.summary["rewritten"] == 1
    assert DENIED not in report.technical_analysis.evasion_antiforensics.body
    # One sharing only words with it grounds nothing: asked again, the sentence stands.
    untied = _report()
    done, _ = _ask(untied, {"sentences": _rest(untied, [row])})
    assert done.summary["rewritten"] == 0
    assert DENIED in untied.technical_analysis.evasion_antiforensics.body
    flow = _report(evasion="Strings are encoded [ev_0002].", flow=DENIED)
    row = {**row, "passage": "execution_flow.1", "sources": ["evasion_antiforensics"]}
    row["rewrite"] = "Strings are encoded, and no gate is described [ev_0002]."
    done, _ = _ask(flow, {"sentences": _rest(flow, [row])})
    assert done.summary["rewritten"] == 1


# -- a no-source keep reads the entry it cites ---------------------------------------


def test_the_rows_of_a_cited_entry_holding_a_named_value_are_shown_and_speak() -> None:
    by_id = _by_id(_report())
    (fact,) = [p for p in by_id.values() if p.id.startswith("entry.")]
    assert fact.cites == {"ev_0003"} and fact.speaks_to == (PARENTS,)
    assert 'ppid "12"' in fact.text and 'ppid "41"' in fact.text
    assert "other.exe" not in fact.text
    found = _found(_report(), _row("limitations", PARENTS, [], reason="no source states it"))
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert fact.id in refused.message


def test_a_count_and_an_uncited_entry_name_no_row() -> None:
    assert named_values(COUNTED) == {}
    assert named_values(PARENTS) == {"41": "41", "47": "47"}
    by_id = _by_id(_report(limitations=PARENTS.replace(" [ev_0003]", "")))
    assert not [p for p in by_id.values() if p.id.startswith("entry.")]


@pytest.mark.parametrize(
    ("sentence", "values"),
    [
        # A grouped number, a year, a count and a word's apostrophe name nothing.
        ("No more than 14,000 bytes were read and the key is not established.", {}),
        ("Port 443 contact was not observed in 2026.", {}),
        ("The 12 strings are not confirmed.", {}),
        ("The sample's own path and the analyst's view are not established.", {}),
        ("The name 'alphaname' is not established.", {"alphaname": "alphaname"}),
        # A four-digit number is dropped only when written as a date.
        ("The parent of process 2040 is not established.", {"2040": "2040"}),
        ("No contact with process 41 was seen in 2026.", {"41": "41"}),
        ("The key of process 41 is not established on 2026-11 records.", {"41": "41"}),
    ],
)
def test_the_values_a_sentence_names(sentence: str, values: dict[str, str]) -> None:
    assert named_values(sentence) == values


def _entry_fact(report: MalwareReport) -> Any:
    return next(p for p in passages_of(report, entries=_ledger()) if p.id.startswith("entry."))


@pytest.mark.parametrize(
    "quote",
    [
        # The header, the tool's name, or a row naming no value the sentence names.
        '("guest_processes") records 2 rows',
        "records 2 rows holding",
        'name "host.exe"',
    ],
)
def test_a_quote_of_the_rows_lies_in_one_row_naming_a_value(quote: str) -> None:
    report = _report(flow="It resolves its imports [ev_0002].")
    fact = _entry_fact(report)
    assert quote in fact.text
    found = _found(report, _row("limitations", PARENTS, [fact.id], quote=quote))
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert "no single row" in refused.message


def test_a_closing_keep_quoting_a_row_that_says_otherwise_is_left_out_after_the_retry() -> None:
    report = _report(flow="It resolves its imports [ev_0002].")
    fact = _entry_fact(report)
    quote = 'pid "41"; ppid "12"'
    assert quote in fact.row_texts[0]
    row = _row("limitations", PARENTS, [fact.id], quote=quote)
    (refused,) = [v for v in _found(report, row) if v.code == KEEP_UNQUOTED_CODE]
    assert "state no absence" in refused.message and "drop" in refused.message
    rows = _rest(report, [row])
    done, reporter = _ask(report, {"sentences": rows}, {"sentences": rows})
    assert len(reporter.asked) == 2
    assert PARENTS not in report.technical_analysis.analyst_limitations.body
    dropped = [r["message"] for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert any(PARENTS[:30] in m for m in dropped)


def test_a_body_absence_kept_on_a_row_of_the_entry_it_cites_is_recorded() -> None:
    report = _report(flow=PARENTS, limitations="This analysis does not establish the operator.")
    fact = _entry_fact(report)
    assert fact.speaks_to == (PARENTS,)
    row = _row("execution_flow.1", PARENTS, [fact.id], quote='pid "47"; ppid "41"')
    done, reporter = _ask(report, {"sentences": _rest(report, [row])})
    assert len(reporter.asked) == 1
    records = [r["message"] for r in done.tally.unresolved if r["code"] == HELD_KEPT_CODE]
    assert any(PARENTS[:30] in m and "rows of an entry the sentence cites" in m for m in records)


def test_the_same_rows_of_one_entry_are_one_fact_naming_every_value() -> None:
    # Process 41 stands in both rows (its own, and as the parent of 47).
    launcher = "The launcher of process 41 is not established [ev_0003]."
    report = _report(flow=launcher, limitations=PARENTS)
    (fact,) = [p for p in passages_of(report, entries=_ledger()) if p.id.startswith("entry.")]
    assert set(fact.speaks_to) == {launcher, PARENTS}
    assert 'holding "41", "47"' in fact.text
    again = _entry_fact(report)
    assert (again.id, again.text) == (fact.id, fact.text)


def test_an_answer_too_deep_or_too_large_is_read_in_part_and_said() -> None:
    deep = LedgerEntry(id="ev_0009", tool="t", output="[" * 200_000 + "]" * 200_000)
    assert rows_naming(deep, {"41": "41"}) is None
    wide = {"rows": [{"pid": n} for n in range(30_000)]}
    found = rows_naming(LedgerEntry(id="ev_0008", tool="t", structured=wide), {"25000": "25000"})
    assert found is None or found.cut
    found = rows_naming(LedgerEntry(id="ev_0008", tool="t", structured=wide), {"41": "41"})
    assert found is not None and found.cut


def test_a_rewrite_on_the_rows_is_put_in() -> None:
    report = _report(flow="It resolves its imports [ev_0002].")
    fact = next(p for p in passages_of(report, entries=_ledger()) if p.id.startswith("entry."))
    rewrite = "The guest processes 41 and 47 have the parents 12 and 41 [ev_0003]."
    row = {**_row("limitations", PARENTS, [fact.id]), "decision": "rewrite", "rewrite": rewrite}
    done, _ = _ask(report, {"sentences": _rest(report, [row])})
    assert report.technical_analysis.analyst_limitations.body == rewrite
    assert done.summary["rewritten"] == 1


# -- the stored run the defects were read in ------------------------------------------


def _haiku13() -> tuple[MalwareReport, list[Any]]:
    from malspark.reporting.follow_up import stored_ledger

    root = stored_runs()
    if root is None or not (root / "haiku13" / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    report = MalwareReport.model_validate(
        json.loads((root / "haiku13" / "report.json").read_text())
    )
    rows = json.loads((root / "haiku13" / "evidence.json").read_text())["items"]
    return report, stored_ledger(rows)[0]


def test_haiku13_s_section_5_denial_of_the_gates_is_held_and_not_kept_on_no_source() -> None:
    report, ledger = _haiku13()
    passages = passages_of(report, entries=ledger)
    by_id = {p.id: p for p in passages}
    passage = by_id["evasion_antiforensics"]
    (sentence,) = [s for s in _sentences_of(passage.text) if "anti-debug or environment" in s]
    assert sentence in passage.absences
    row = _row(passage.id, sentence, [], reason="No source states it.")
    found = [
        v
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.path.startswith("sentences")
    ]
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert "execution_flow.3" in refused.message


def test_haiku13_s_parents_of_83_and_88_are_not_kept_on_no_source() -> None:
    report, ledger = _haiku13()
    passages = passages_of(report, entries=ledger)
    (fact,) = [p for p in passages if p.id.startswith("entry.")]
    assert fact.cites == {"ev_0012"}
    assert 'ppid "56"' in fact.text and 'ppid "82"' in fact.text
    (sentence,) = fact.speaks_to
    assert sentence.startswith("The injection target and the parent of sandbox processes 83")
    row = _row("limitations", sentence, [], reason="No source states the parent.")
    found = [
        v
        for v in agreement_violations({"sentences": [row]}, passages)
        if v.path.startswith("sentences")
    ]
    (refused,) = [v for v in found if v.code == KEEP_UNQUOTED_CODE]
    assert fact.id in refused.message


@pytest.mark.parametrize(
    ("sentence", "in_a_run"),
    [
        ("No write on the Run key is present in the code read.", False),
        ("The key is not established from the execution path of 0x10 routine.", False),
        ("The key schedule is not confirmed by the decompiled execution flow.", False),
        ("The decryption key is not confirmed for the session token routine.", False),
        ("The sample is not shown to use timing checks.", False),
        ("Whether the gate passes in the sandbox is not established.", True),
        ("The run gives no evidence that any command was sent.", True),
        (
            "Observed in the sandbox for two processes; its own launch is not established.",
            True,
        ),
        ("The key was not seen during execution.", True),
    ],
)
def test_an_absence_is_set_in_a_run_by_its_frame_its_first_clause_or_its_subject(
    sentence: str, in_a_run: bool
) -> None:
    from malspark.reporting.absence_answers import set_in_a_run

    assert set_in_a_run(sentence) is in_a_run


@pytest.mark.parametrize(
    ("sentence", "saw"),
    [
        ("As shown in section 4, routine 0x10 builds the beacon [ev_0002].", False),
        ("The routine writes the run key value [ev_0002].", False),
        ("In the sandbox run the gate passes [ev_0002].", True),
        ("The capture recorded a POST to the host [ev_0002].", True),
    ],
)
def test_what_states_what_a_run_saw(sentence: str, saw: bool) -> None:
    from malspark.reporting.absence_answers import observes

    assert observes(sentence) is saw


def test_a_row_quote_names_a_value_as_a_whole_word() -> None:
    from malspark.reporting.section_agreement import _quotes_a_row

    fact = _entry_fact(_report(flow="It resolves its imports [ev_0002]."))
    assert _quotes_a_row('pid "41"; ppid "12"', fact)
    assert not _quotes_a_row('ppid "412"; pid "41"'.replace('"41"', '"410"'), fact)


def test_a_long_speaking_sentence_is_quoted_by_its_shortest_passing_beginning() -> None:
    from malspark.pipeline.events import FINDING_VALUE_LIMIT
    from malspark.reporting.section_agreement import _speaking_sources

    tail = ", ".join(f"then check{i} runs" for i in range(600))
    report = _report(
        evasion=f"Strings are encoded by 0x1400 [ev_0002]. {DENIED}",
        flow=f"{GATES[: -len(' [ev_0002].')]}, {tail} [ev_0002].",
    )
    by_id = _by_id(report)
    ((pid, excerpt),) = _speaking_sources(DENIED, by_id, by_id["evasion_antiforensics"])
    assert len(excerpt) <= FINDING_VALUE_LIMIT
    # It speaks of the sentence: a rewrite on it passes (a keep quoting words that state no
    # absence does not, T-652).
    rewrite = {
        **_row("evasion_antiforensics", DENIED, [pid]),
        "decision": "rewrite",
        "rewrite": "Routine 0x1400 runs timing and locale checks [ev_0002].",
    }
    assert _found(report, rewrite) == []
    # With no beginning short enough that passes, the source does not speak.
    flat = _report(flow="Routine 0x1400 runs timing and locale checks " + "and more " * 400 + ".")
    by_id = _by_id(flat)
    assert _speaking_sources(DENIED, by_id, by_id["evasion_antiforensics"]) == []


def test_a_true_closing_absence_kept_twice_on_its_rows_is_left_out_and_recorded() -> None:
    # Consistent with T-568: a closing keep the checks refuse after the retry is left
    # out and recorded; the retry points to the rewrite on the rows.
    true = "No child of process 90 is recorded [ev_0003]."
    report = _report(flow="It resolves its imports [ev_0002].", limitations=true)
    fact = _entry_fact(report)
    row = _row("limitations", true, [fact.id], quote='pid "90"; ppid "4"')
    (refused,) = [v for v in _found(report, row) if v.code == KEEP_UNQUOTED_CODE]
    assert "rewrite it on them" in refused.message
    rows = _rest(report, [row])
    done, _ = _ask(report, {"sentences": rows}, {"sentences": rows})
    assert true not in report.technical_analysis.analyst_limitations.body
    assert any(
        r["code"] == DROPPED_CODE and true[:25] in r["message"] for r in done.tally.unresolved
    )
