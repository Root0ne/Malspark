"""A composed text that names the code of a check a claim states carries what the check tests.

haiku13 (T-580 D3): the claims in force said that 0x3868 fails on an
IsWow64Process test, when the process count is below 75 (OS code 6 or higher)
or below 50, and when 0x68e8 finds an adapter address longer than 6 bytes. The
execution flow was shown every one of them and wrote "a process-count check
(0x8820) and an adapter check (0x68e8)"; the ATT&CK procedure dropped the
thresholds too. No check refused the values: none asked for them.

A claim states a check when a clause of it says the code fails, exits, aborts,
stalls or returns failure on a condition. Where an answer's text names the
code the claim names, the check's API-style names and compared numbers are
asked for once, kept with a finding if the model keeps the text; a procedure
is held to its own technique's claims. The claims are stubs written here.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage, BaseMessage

from malspark.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    VALUE_NOT_CARRIED_CODE,
)
from malspark.reporting import composer as composer_module
from malspark.reporting.composer import ReportComposer
from malspark.reporting.composer_pro import check_value_violations
from malspark.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

# The claims as haiku13's reverser wrote them (claims 32, 33 and 35).
WOW64 = (
    "[WOW64 check] Routine 0x3868 calls GetCurrentProcess and IsWow64Process (slots c38 and "
    "b90). It returns failure when the process is 32-bit on 64-bit Windows, which stalls the "
    "export. — ev_0069 (0x3868 body)"
)
THRESHOLDS = (
    "[Environment check on system-property thresholds] Routine 0x8560 maps the OS version to a "
    "code from 0 to 7. Routine 0x8820 counts running processes with a Toolhelp snapshot. "
    "Routine 0x3868 exits with failure (-1) when the process count is below 75 on code 6 or "
    "higher, or below 50 on lower codes. — ev_0082; ev_0069"
)
ADAPTER = (
    "[Adapter gate] Routine 0x68e8 calls GetAdaptersInfo (slot eb8) and returns failure when an "
    "adapter reports a hardware address longer than 6 bytes (the length at +0x194 of each "
    "adapter record). — ev_0082"
)
# haiku13's flow step 3, as written.
STEP_3 = (
    "Routine 0x3868 runs environment gates before the beacon starts: a PEB BeingDebugged read "
    "(0x8690, 0x309c, 0x3074), an OS-version check (0x8560), a process-count check (0x8820) and "
    "an adapter check (0x68e8)."
)


def _flow(*actions: str) -> dict[str, Any]:
    return {
        "steps": [
            {"order": n, "action": action, "voice": "assessed", "evidence_refs": ["ev_0001"]}
            for n, action in enumerate(actions, 1)
        ]
    }


def _asked(payload: Any, claims: Any) -> list[tuple[str, ...]]:
    return [v.values for v in check_value_violations(payload, claims)]


class TestWhatACheckTests:
    def test_haiku13_s_flow_is_asked_for_each_gate_s_values(self) -> None:
        asked = _asked(_flow(STEP_3), [WOW64, THRESHOLDS, ADAPTER])
        # The WOW64 clause points back ("It returns failure when …"): it takes the
        # code of the sentence before it and the last function that sentence calls.
        assert asked == [
            ("IsWow64Process",),
            ("75", "6", "50"),
            ("GetAdaptersInfo", "6", "0x194"),
        ]

    def test_a_clause_pointing_back_takes_the_called_functions_before_it(self) -> None:
        plain = (
            "Routine 0x3868 calls GetCurrentProcess and IsWow64Process. It returns failure "
            "when the process count is below 75."
        )
        assert _asked(_flow("Routine 0x3868 runs the gates."), [plain]) == [
            ("IsWow64Process", "75")
        ]
        # The same fact written with more calls before the check asks the same thing.
        more = (
            "0x3868 calls VirtualAlloc, CreateThread and IsWow64Process. It returns failure "
            "when the process count is below 75."
        )
        assert _asked(_flow("Routine 0x3868 runs the gates."), [more]) == [("IsWow64Process", "75")]

    def test_a_function_written_only_as_another_call_s_argument_is_not_asked(self) -> None:
        nested = (
            "Routine 0x3868 tests IsWow64Process(GetCurrentProcess()). It returns failure "
            "when that reports a 32-bit process."
        )
        assert _asked(_flow("Routine 0x3868 runs the gates."), [nested]) == [("IsWow64Process",)]
        own = "0x3868 returns -1 when IsWow64Process(GetCurrentProcess()) is true."
        assert _asked(_flow("Routine 0x3868 runs the gates."), [own]) == [("IsWow64Process",)]
        # A note in brackets after an address or a word is no call.
        noted = "0x3868 fails when the adapter check 0x68e8 (GetAdaptersInfo) finds none."
        assert _asked(_flow("Routine 0x3868 runs the gates."), [noted]) == [("GetAdaptersInfo",)]

    def test_a_step_that_carries_them_is_not_asked(self) -> None:
        carried = (
            "Routine 0x3868 fails when IsWow64Process (through GetCurrentProcess) reports a "
            "32-bit process, when the process count of 0x8820 is below 0x4b with OS code 6 or "
            "more or below 50 otherwise, and when 0x68e8 (GetAdaptersInfo) finds an address "
            "length at +0x194 above six."
        )
        assert _asked(_flow(carried), [WOW64, THRESHOLDS, ADAPTER]) == []

    def test_the_values_are_looked_for_only_where_the_check_s_code_is_named(self) -> None:
        # 75 and 50 elsewhere in the answer do not carry the check of 0x3868.
        elsewhere = _flow(STEP_3, "The beacon sleeps 75 s and retries 50 times.")
        assert ("75", "6", "50") in _asked(elsewhere, [THRESHOLDS])

    def test_a_claim_whose_code_the_answer_does_not_name_is_not_asked(self) -> None:
        assert _asked(_flow("The export 0x3ce4 calls 0x3cb4."), [WOW64, ADAPTER]) == []

    def test_an_error_path_and_a_bracketed_aside_are_no_check(self) -> None:
        claims = [
            "Routine 0x4f58 loops on InternetReadFile (slot 0x10e30). It returns 0 if an append "
            "fails, and returns FALSE if an append fails.",
            "The read chain is: 0x3cb4, then 0x33ac (taken only when the gate at 0x378c returns "
            "failure), then 0xc5e8 (CoCreateInstance).",
        ]
        answer = _flow("0x4f58 reads the reply.", "0x378c tests the copy; 0xc5e8 creates the task.")
        assert _asked(answer, claims) == []

    def test_a_check_written_after_its_condition_compares_a_number(self) -> None:
        compared = "If the count 0x8820 returns is below 75, 0x3868 returns -1."
        bare = "If the copy at 0x378c exists, 0x3868 returns -1 and calls ExitProcess."
        answer = _flow("0x3868 checks 0x8820 and 0x378c.")
        assert _asked(answer, [compared]) == [("75",)]
        assert _asked(answer, [bare]) == []

    def test_a_question_no_larger_than_another_is_asked_once(self) -> None:
        again = "Routine 0x68e8 fails when an adapter's hardware address is longer than six bytes."
        assert _asked(_flow(STEP_3), [again, ADAPTER]) == [("GetAdaptersInfo", "6", "0x194")]

    def test_a_prose_body_is_read_by_sentence(self) -> None:
        body = {"body": "Process discovery uses 0x1c38. The gate 0x3868 checks the host."}
        assert _asked(body, [THRESHOLDS]) == [("75", "6", "50")]

    def test_a_prose_body_carries_the_values_in_the_sentences_after_the_code(self) -> None:
        carried = {
            "body": "Routine 0x3868 runs the environment gates. It exits when the process "
            "count is below 75 on OS code 6 or higher, or below 50 otherwise. Routine 0x1c38 "
            "lists processes."
        }
        assert _asked(carried, [THRESHOLDS]) == []
        # The sentences after the next code are that code's, not the gate's.
        later = {"body": "Routine 0x3868 runs the gates. Routine 0x1c38 lists 75 or 50 processes."}
        assert _asked(later, [THRESHOLDS]) == [("75", "6", "50")]

    def test_two_routines_checks_in_one_body_are_each_asked(self) -> None:
        body = {"body": "0x5a00 checks the processor count. 0x7b00 checks the disk count."}
        claims = [
            "0x5a00 exits if GetSystemInfo reports fewer than 2 processors.",
            "0x7b00 exits if the disk count is below 2.",
        ]
        assert _asked(body, claims) == [("GetSystemInfo", "2"), ("2",)]

    def test_the_check_s_code_is_its_subject_not_another_routine_or_a_slot(self) -> None:
        claim = (
            "The routine at 0x401a00 decrypts the config with RC4 and 0x402b10 exits if "
            "IsDebuggerPresent returns nonzero."
        )
        assert _asked(_flow("0x401a00 decrypts the configuration blob with RC4."), [claim]) == []
        assert _asked(_flow("0x402b10 checks for a debugger."), [claim]) == [("IsDebuggerPresent",)]
        slot = "0x3868 calls slot 0x10c38 and fails when the count is below 75."
        assert _asked(_flow("The resolver fills slot 0x10c38."), [slot]) == []

    def test_checks_written_in_other_families_phrasing(self) -> None:
        cases = [
            (
                "0x5000 calls ExitProcess when the uptime is below 600000.",
                ("ExitProcess", "600000"),
            ),
            ("0x5000 terminates the process if the uptime is below 600000.", ("600000",)),
            ("0x5000 bails out unless the disk is at least 60 GB.", ("60",)),
            (
                "0x5000 quits if GlobalMemoryStatusEx reports less than 4096 MB.",
                ("GlobalMemoryStatusEx", "4096"),
            ),
            (
                "0x5000 exits when GetUserDefaultUILanguage returns 0x419.",
                ("GetUserDefaultUILanguage", "0x419"),
            ),
            ("0x5000 returns 0 when GetTickCount is greater than 1000.", ("GetTickCount", "1000")),
            (
                "If GetSystemInfo reports fewer than 2 processors, 0x5000 halts.",
                ("GetSystemInfo", "2"),
            ),
        ]
        for claim, values in cases:
            assert _asked(_flow("Routine 0x5000 runs a host check."), [claim]) == [values], claim

    def test_a_long_question_counts_what_it_does_not_name(self) -> None:
        claim = (
            "0x1000 exits if AaaFunc, BbbFunc, CccFunc, DddFunc, EeeFunc, FffFunc, GggFunc, "
            "HhhFunc or IiiFunc returns above 2, above 3 or above 4."
        )
        (found,) = check_value_violations(_flow("0x1000 runs the gate."), [claim])
        assert len(found.values) == 12
        assert "and 4 more" in found.message

    def test_a_procedure_is_held_to_its_own_technique_s_claims(self) -> None:
        payload = {
            "procedures": [
                {"technique_id": "T1497.001", "procedure": "0x3868 compares the 0x8820 count."},
                {"technique_id": "T1057", "procedure": "0x8820 walks the process list."},
            ]
        }
        found = check_value_violations(
            payload, {"T1497.001": [THRESHOLDS], "T1057": ["0x8820 lists processes."]}
        )
        assert [(v.path, v.values) for v in found] == [
            ("procedures[0].procedure", ("75", "6", "50"))
        ]
        assert "its own technique" in found[0].message

    def test_the_finding_is_kept_with_the_text_and_not_marked(self) -> None:
        (found,) = check_value_violations(_flow(STEP_3), [ADAPTER])
        assert found.code == VALUE_NOT_CARRIED_CODE
        assert VALUE_NOT_CARRIED_CODE in KEPT_WITH_A_FINDING
        assert VALUE_NOT_CARRIED_CODE not in MARKED_IN_PLACE
        assert "GetAdaptersInfo" in found.message and "keep it as it is" in found.message

    def test_a_counted_one_is_a_check_value(self) -> None:
        counted = "0x5000 exits if the processor count is 1."
        assert _asked(_flow("Routine 0x5000 runs a host check."), [counted]) == [("1",)]
        counted_of = "0x5000 exits if the number of monitors is 1."
        assert _asked(_flow("Routine 0x5000 runs a host check."), [counted_of]) == [("1",)]
        below = "0x5000 exits if fewer than 1 disk is attached."
        assert _asked(_flow("Routine 0x5000 runs a host check."), [below]) == [("1",)]

    def test_a_truth_value_and_an_exit_code_read_are_no_check_values(self) -> None:
        # "returns 0 when …" is a branch's status, carried by any wording of it.
        branch = "0x3cb4 returns 0 when 0x3868 returns nonzero, and loops when it returns 0."
        assert _asked(_flow("0x3cb4 calls 0x3868."), [branch]) == []
        # Reading a thread's exit code ends nothing: no outcome of its own.
        read = "0x5750 reads GetExitCodeThread when the worker is done."
        assert _asked(_flow("0x5750 waits for the worker."), [read]) == []

    def test_a_number_the_text_writes_for_another_reason_carries_the_check_s(self) -> None:
        # Documented: a number is carried wherever it stands in the texts naming the code.
        claim = "0x68e8 fails when the adapter address is longer than 6 bytes."
        assert _asked(_flow("Step 6: 0x68e8 reads the adapter table."), [claim]) == []


# ---------------------------------------------------------------------------
# The composer asks the flow section once, with the claims its bundle showed it
# ---------------------------------------------------------------------------

_LEAD = "The evidence for the "


def _section_of(messages: list[BaseMessage]) -> str:
    text = str(messages[1].content)
    start = text.index(_LEAD) + len(_LEAD)
    return text[start : text.index(" section follows.", start)]


class _Stub:
    def __init__(self, answers: dict[str, list[Any]]) -> None:
        self.answers = answers
        self.asked: dict[str, list[str]] = {}

    def with_structured_output(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("unused")

    async def ainvoke(self, messages: list[BaseMessage], **_: Any) -> AIMessage:
        section = _section_of(messages)
        self.asked.setdefault(section, []).append(str(messages[-1].content))
        turns = self.answers.get(section, [{}])
        return AIMessage(content=json.dumps(turns[min(len(self.asked[section]), len(turns)) - 1]))


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        static=StaticAnalysis(exports=["extra"]),
        evidence_index=[EvidenceIndexRow(id="ev_0001", agent="static", tool="tool")],
    )


def _compose(flow: list[Any]) -> tuple[_Stub, ReportComposer, MalwareReport]:
    report = _report()
    llm = _Stub({"execution_flow": flow})
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    isr = {
        "reverser": AgentISR(
            agent_id="reverser",
            domain="static",
            claims=[ClaimEvidence(claim=ADAPTER, evidence_ref="ev_0001", confidence=0.8)],
        )
    }
    with patch.object(composer_module, "structured_output_supported_for_llm", return_value=False):
        asyncio.run(comp.compose(report, isr, citable_ids=["ev_0001"]))
    return llm, comp, report


class TestTheComposerAsksOnce:
    def test_the_flow_is_asked_and_the_fixed_answer_kept(self) -> None:
        fixed = (
            "Routine 0x68e8 fails when GetAdaptersInfo reports an address length at +0x194 "
            "above 6 [ev_0001]."
        )
        llm, _comp, report = _compose([_flow(STEP_3), _flow(fixed)])
        assert len(llm.asked["execution_flow"]) == 2
        assert VALUE_NOT_CARRIED_CODE in llm.asked["execution_flow"][1]
        assert report.technical_analysis is not None
        assert [s.action for s in report.technical_analysis.execution_flow] == [fixed]

    def test_a_kept_text_stands_and_the_finding_is_recorded(self) -> None:
        llm, comp, report = _compose([_flow(STEP_3), _flow(STEP_3)])
        assert len(llm.asked["execution_flow"]) == 2
        assert report.technical_analysis is not None
        assert [s.action for s in report.technical_analysis.execution_flow] == [STEP_3]
        tally = comp.validation_tally.to_dict()
        assert VALUE_NOT_CARRIED_CODE in (tally.get("by_code") or {})
