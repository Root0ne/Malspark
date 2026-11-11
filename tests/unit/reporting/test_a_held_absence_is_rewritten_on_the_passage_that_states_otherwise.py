"""A held absence is rewritten on the passage that states otherwise; a keep quotes a denial (T-652).

haiku13's section 5 said "The analysed sample is therefore not shown to use
anti-debug or environment checks." while section 4's third step and the ATT&CK
procedure for host checks stated the gates with entries. The round held the
sentence and named both passages as speaking of it, but a rewrite in the model's
words could rest only on a fact or a section 5 passage, so the rewrite on the step
that states the gates was refused; and a keep quoting that very step passed, since
a body keep's quote needed state no absence.

A held absence of the body now rests a rewrite on any source the round names as
speaking of it, a passage written without the code included, and a keep's quote
states an absence where the sentence does, as a closing keep's does. A keep on its
reason where no source speaks passes as before, and the sentence is never left
out. The passages are haiku13's and haiku12's, shortened.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import (
    BoundValue,
    FileHashes,
    FlowStep,
    KeyFinding,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
    TechniqueProcedure,
)
from malspark.reporting.section_agreement import (
    HELD_KEPT_CODE,
    KEEP_UNQUOTED_CODE,
    UNKNOWN_SOURCE_CODE,
    _speaking_of,
    agreement_violations,
    ask_section_agreement,
    passages_of,
)
from malspark.schemas.evidence import LedgerEntry

# haiku13 §5.1 L116, its passage's sentence before it, and the two passages stating the gates.
DENIED = "The analysed sample is therefore not shown to use anti-debug or environment checks."
PEB = (
    "The anti-analysis scan matched only a single PEB read (GS segment, offset 0x60) at "
    "0x8690 [ev_0024][ev_0008]."
)
GATES = (
    "Routine 0x3868 resolves its Windows APIs by CRC32 hash through the tables at 0x84e4, "
    "0x904c, 0x9484, 0xa59c and 0xac50, and runs environment gates before the beacon starts: "
    "a PEB BeingDebugged read (0x8690, 0x309c, 0x3074), an OS-version check (0x8560), a "
    "process-count check (0x8820) and an adapter check (0x68e8). A failed gate returns -1, "
    "and 0x3cb4 then loops on Sleep(1000) without returning."
)
GATES_QUOTE = (
    "and runs environment gates before the beacon starts: a PEB BeingDebugged read "
    "(0x8690, 0x309c, 0x3074), an OS-version check (0x8560)"
)
HOST_CHECKS = (
    "The sample checks host properties before its beacon work: routine 0x8820 walks the "
    "process list with CreateToolhelp32Snapshot, Process32FirstW and Process32NextW, and "
    "routine 0x8560 reads the OS version through GetVersionExW and RtlGetVersion, which "
    "likely serves as an environment check."
)
REWRITE = (
    "Section 4 describes environment gates in 0x3868: a PEB BeingDebugged read, an "
    "OS-version check, a process-count check and an adapter check [ev_0025]."
)
# haiku12 §5.1 L115 and §5.2 L144, with what states otherwise of each.
MUTEX = (
    "We assess a single-instance guard with low confidence; the mutex name was not "
    'recovered; the code passes "runnung" to CreateMutexW as argument 3 (lpName) '
    "[ev_0021][ev_0025]."
)
MUTEX_FINDING = (
    "The decoded text runnung at 0xfa00 is passed to CreateMutexW as argument 3, the mutex "
    "name, on the path where every conditional jump falls through [ev_0021, ev_0025]."
)
FNV = "What the FNV routine hashes is not established."
FNV_STATED = (
    'The body template at 0xfd40 holds counter, type, guid, os and group; the guid uses "%04X" '
    '(0x8c4c) and the group value is an FNV hash of "Littlehw" computed by 0xc99c '
    "[ev_0019, ev_0021, ev_0086]."
)
CITABLE = [f"ev_{n:04d}" for n in range(1, 100)]


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(id=f"ev_{n:04d}", tool="lift_routine", output="int f(void) { return 0; }")
        for n in (8, 19, 20, 21, 24, 25, 77, 86)
    ]


def _report(
    *,
    evasion: str = f"{PEB} {DENIED}",
    flow: str = GATES,
    procedure: str = HOST_CHECKS,
    strings: str = "Routine 0xae78 decodes the strings [ev_0021].",
    channel: str = "The beacon is thread routine 0x5750 [ev_0025].",
    findings: tuple[str, ...] = (),
    limitations: str = "The operator is not named.",
    bound: bool = False,
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        key_findings=[KeyFinding(text=text) for text in findings],
        bound_values=[
            BoundValue(
                value="runnung",
                kind="mutex",
                role="mutex_name",
                role_words="the name of the mutex the call creates or opens",
                api="CreateMutexW",
                argument=3,
                parameter="lpName",
                entry="ev_0021",
                tool="decoder",
                site="0x3935",
                function="0x3868",
                decoder_call="0x3939",
                call_at="0x3962",
                slot="0x10c60",
                named_by="ev_0025",
            )
        ]
        if bound
        else [],
        technical_analysis=TechnicalAnalysis(
            execution_flow=[
                FlowStep(order=1, action="The export #1 runs [ev_0020]."),
                FlowStep(order=2, action="It decodes its strings [ev_0021]."),
                FlowStep(
                    order=3,
                    action=flow,
                    evidence_refs=["ev_0008", "ev_0020", "ev_0024", "ev_0025", "ev_0077"],
                ),
            ],
            technique_procedures=[
                TechniqueProcedure(
                    technique_id="T1497.001",
                    procedure=procedure,
                    evidence_refs=["ev_0020", "ev_0025"],
                )
            ],
            evasion_antiforensics=TechnicalSubsection(
                title="Defense Evasion & Anti-Forensics",
                body=evasion,
                evidence_refs=["ev_0008", "ev_0024"],
            ),
            string_resolution=TechnicalSubsection(
                title="API and String Resolution", body=strings, evidence_refs=["ev_0021"]
            ),
            command_and_control=TechnicalSubsection(
                title="Command and Control", body=channel, evidence_refs=["ev_0025"]
            ),
            analyst_limitations=TechnicalSubsection(title="Limitations", body=limitations),
        ),
    )


def _row(passage: str, sentence: str, sources: list[str], **kw: Any) -> dict[str, Any]:
    return {"passage": passage, "sentence": sentence, "sources": sources, "decision": "keep", **kw}


def _rewrite(passage: str, sentence: str, sources: list[str], rewrite: str) -> dict[str, Any]:
    return {**_row(passage, sentence, sources), "decision": "rewrite", "rewrite": rewrite}


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
    reporter = _Reporter(*answers)
    done = asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=CITABLE,
            evidence_texts=EntryTexts.from_ledger(_ledger()),
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


def _speaking(report: MalwareReport, pid: str, sentence: str) -> list[str]:
    by_id = {p.id: p for p in passages_of(report, entries=_ledger())}
    return _speaking_of(sentence, by_id, by_id[pid])


# -- haiku13's denial of the gates -----------------------------------------------------


def test_the_passages_stating_the_gates_speak_of_the_denial() -> None:
    assert _speaking(_report(), "evasion_antiforensics", DENIED) == [
        "execution_flow.3",
        "procedures.1",
    ]


def test_a_keep_quoting_the_passage_that_states_the_gates_is_refused() -> None:
    row = _row("evasion_antiforensics", DENIED, ["execution_flow.3"], quote=GATES_QUOTE)
    assert [(v.code, v.message) for v in _found(_report(), row)] == [
        (
            KEEP_UNQUOTED_CODE,
            "row 1: evasion_antiforensics keeps 'The analysed sample is therefore not shown to "
            "use anti-debug or environment checks.' on execution_flow.3, but its quote states "
            "no absence, while the sentence states one: quote the words of a source that state "
            "the same thing, or rewrite the sentence on the source that states otherwise. The "
            'shown sources that speak of it: [execution_flow.3] "and runs environment gates '
            "before the beacon starts: a PEB BeingDebugged read (0x8690, 0x309c, 0x3074), an "
            'OS-version check (0x8560)"; [procedures.1] "which likely serves as an environment '
            'check.". Rewrite it on the one that states otherwise (a section 5 sentence too: on '
            "any of these, a passage written without the code included); their words state no "
            "absence, so no keep rests on them.",
        )
    ]


def test_a_rewrite_on_the_step_that_states_the_gates_passes_and_is_put_in() -> None:
    report = _report()
    row = _rewrite("evasion_antiforensics", DENIED, ["execution_flow.3"], REWRITE)
    assert _found(report, row) == []
    done, reporter = _ask(report, {"sentences": _rest(report, [row])})
    assert len(reporter.asked) == 1
    assert done.summary["rewritten"] == 1
    body = report.technical_analysis.evasion_antiforensics.body
    assert DENIED not in body and REWRITE in body


def test_a_rewrite_on_a_written_passage_that_does_not_speak_of_it_is_refused() -> None:
    # Only what speaks of the absence grounds a rewrite of it: the first step does not.
    row = _rewrite("evasion_antiforensics", DENIED, ["execution_flow.1"], REWRITE)
    assert [v.code for v in _found(_report(), row)][0] == UNKNOWN_SOURCE_CODE


def test_a_keep_on_its_reason_where_no_source_speaks_passes_as_before() -> None:
    report = _report(flow="It resolves its imports [ev_0020].", procedure="It sleeps [ev_0025].")
    assert _speaking(report, "evasion_antiforensics", DENIED) == []
    assert _found(report, _row("evasion_antiforensics", DENIED, [], reason="none does")) == []


def test_a_keep_quoting_a_passage_that_states_the_same_absence_still_passes() -> None:
    agreeing = "No anti-debug or environment checks are shown in the code read [ev_0025]."
    report = _report(flow=agreeing)
    row = _row("evasion_antiforensics", DENIED, ["execution_flow.3"], quote=agreeing)
    assert _found(report, row) == []


def test_a_refused_keep_stands_after_the_retry() -> None:
    report = _report()
    rows = _rest(
        report, [_row("evasion_antiforensics", DENIED, ["execution_flow.3"], quote=GATES_QUOTE)]
    )
    done, reporter = _ask(report, {"sentences": rows}, {"sentences": rows})
    assert len(reporter.asked) == 2
    # A body absence is never left out: the keep a check still refuses stands, recorded.
    assert DENIED in report.technical_analysis.evasion_antiforensics.body
    assert any(
        r["code"] == HELD_KEPT_CODE and DENIED in r["message"] and "checks refused" in r["message"]
        for r in done.tally.unresolved
    )


# -- a closing absence, as before --------------------------------------------------------


def test_a_closing_absence_is_answered_as_before() -> None:
    denied = "The sample is not shown to use anti-debug or environment checks."
    report = _report(evasion=PEB, limitations=denied)
    keep = _row("limitations", denied, ["execution_flow.3"], quote=GATES_QUOTE)
    assert [(v.code, v.message) for v in _found(report, keep)] == [
        (
            UNKNOWN_SOURCE_CODE,
            "row 1 names execution_flow.3 as what states otherwise than limitations, but only "
            "the facts, the section 5 passages and the debate rounds listed are sources. Name "
            "the sources by their ids.",
        ),
        (
            KEEP_UNQUOTED_CODE,
            "row 1: limitations keeps 'The sample is not shown to use anti-debug or environment "
            "checks.' on execution_flow.3, but its quote does not stand in a source it names: "
            "quote the words of a source that state the same thing, or rewrite the sentence on "
            "the source that states otherwise.",
        ),
    ]
    rewrite = _rewrite("limitations", denied, ["execution_flow.3"], REWRITE)
    assert [v.code for v in _found(report, rewrite)][0] == UNKNOWN_SOURCE_CODE


# -- haiku12's mutex and FNV sentences -----------------------------------------------------


def test_haiku12_s_mutex_sentence_keeps_no_quote_of_the_finding_and_is_rewritten_on_the_fact() -> (
    None
):
    report = _report(evasion=MUTEX, findings=(MUTEX_FINDING,), bound=True)
    speaking = _speaking(report, "evasion_antiforensics", MUTEX)
    assert "bound.1" in speaking and "key_findings.1" in speaking
    keep = _row("evasion_antiforensics", MUTEX, ["key_findings.1"], quote="the mutex name")
    assert [v.code for v in _found(report, keep)] == [KEEP_UNQUOTED_CODE]
    rewrite = _rewrite(
        "evasion_antiforensics",
        MUTEX,
        ["bound.1"],
        'We assess a single-instance guard with low confidence; the code passes "runnung" '
        "to CreateMutexW as argument 3 (lpName) [ev_0021][ev_0025].",
    )
    assert _found(report, rewrite) == []


def test_haiku12_s_fnv_sentence_keeps_no_quote_of_the_channel_and_is_rewritten_on_it() -> None:
    report = _report(
        strings=f"Routine 0xae78 decodes the strings [ev_0021]. {FNV}",
        channel=FNV_STATED,
        flow="It resolves its imports [ev_0020].",
    )
    assert _speaking(report, "string_resolution", FNV) == ["command_and_control"]
    keep = _row(
        "string_resolution",
        FNV,
        ["command_and_control"],
        quote='the group value is an FNV hash of "Littlehw" computed by 0xc99c',
    )
    assert [v.code for v in _found(report, keep)] == [KEEP_UNQUOTED_CODE]
    rewrite = _rewrite(
        "string_resolution",
        FNV,
        ["command_and_control"],
        'The FNV routine 0xc99c hashes the group value "Littlehw" [ev_0021].',
    )
    assert _found(report, rewrite) == []
