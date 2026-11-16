"""A signature's indicator row is a run root of the process it names and of its target.

A sandbox signature's indicators say which process did what to which, each
process resolved to the report's own row (``SignatureIndicators``). Wherever an
answer holds them (the declared record parts of its kind: a signature view's
``indicators``, the item reader's ``items.*.indicators``), each row gives the
root of the process that acted and of the one acted on, by the process's task
and the report's own id (``schemas.process_identity``); a row naming no process
the report settles says so, and a signature with no indicator row still says
it names none. A statement picks a process out by the number it writes after
``pid`` or ``procid``, the report's id or the guest's pid; a number two
processes answer to picks none. What a run observation is stays as it was.

Every value is synthetic.
"""

from __future__ import annotations

from typing import Any

from tests.linear_cost import assert_ratio

from malspark.analysis.evidence_roots import (
    INDICATOR_UNSETTLED,
    NAMES_NO_ROW,
    READING_RULE,
    READING_RUN,
    READING_UNPLACED,
    SIGNATURE_UNPLACED,
    run_roots,
    summary_of_sources,
)
from malspark.pipeline.validation import technique_sources
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

SAMPLE = "a1b2c3.exe"
WROTE = "Suspicious use of WriteProcessMemory"
P85 = "sandbox process 85"
P87_T1 = "sandbox process 87 in task t1"
P87_T2 = "sandbox process 87 in task t2"
P89 = "sandbox process 89"


def _entry(eid: str, tool: str, structured: Any, **kwargs: Any) -> LedgerEntry:
    return LedgerEntry(id=eid, tool=tool, structured=structured, agent="pipeline", **kwargs)


def _proc(pid: str, guest: str, image: str, **more: Any) -> dict[str, Any]:
    return {"id": pid, "guest_pid": guest, "image": image, **more}


def _processes() -> LedgerEntry:
    return _entry(
        "ev_0011",
        "sandbox_processes",
        {
            "processes": [
                {"pid": 85, "ppid": 56, "name": SAMPLE, "task": "t1"},
                {"pid": 87, "ppid": 85, "name": "defrag.exe", "task": "t1", "marked": True},
                {"pid": 87, "ppid": 81, "name": SAMPLE, "task": "t2"},
                {"pid": 89, "ppid": 87, "name": "defrag.exe", "task": "t2", "marked": True},
            ]
        },
    )


def _wrote() -> LedgerEntry:
    """The indicator page of one signature: two tasks, each a pairing of two processes."""
    return _entry(
        "ev_0082",
        "sandbox_signatures",
        {
            "indicators": [
                {
                    "signature": WROTE,
                    "task": "t1",
                    "process": _proc("85", "1496", SAMPLE),
                    "target": _proc("87", "1924", "defrag.exe", marked=True),
                    "description": "PID 1496 wrote to memory of 1924",
                    "times": 7,
                },
                {
                    "signature": WROTE,
                    "task": "t2",
                    "process": _proc("87", "3756", SAMPLE),
                    "target": _proc("89", "4156", "defrag.exe", marked=True),
                    "description": "PID 3756 wrote to memory of 4156",
                },
            ],
            "matched": 2,
            "offset": 0,
        },
        args={"signature": WROTE},
    )


def _items() -> LedgerEntry:
    return _entry(
        "ev_0089",
        "sandbox_items",
        {
            "section": "signatures",
            "matched": 2,
            "items": [
                {"id": "sig:1", "kind": "signatures", "fields": {"name": "Family: X"}},
                {
                    "id": "sig:2",
                    "kind": "signatures",
                    "fields": {"name": "Creates a file in the Startup directory"},
                    "indicators_stated": 1,
                    "indicators": [
                        {
                            "task": "t1",
                            "process": _proc("87", "1924", "defrag.exe", marked=True),
                            "description": "File created",
                        }
                    ],
                },
            ],
        },
        args={"section": "signatures"},
    )


def _index() -> LedgerEntry:
    return _entry(
        "ev_0024",
        "sandbox_sections",
        {
            "sections": {
                "processes": {"items": 4, "prefix": "proc", "pids": [[85, 85], [87, 87], [89, 89]]},
                "signatures": {"items": 2, "prefix": "sig"},
            }
        },
    )


def _ledger(*more: LedgerEntry) -> list[LedgerEntry]:
    return [_processes(), _index(), _wrote(), _items(), *more]


def _sources(text: str, *cited: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    return run_roots(_ledger()).sources_of_statement(text, list(cited))


def _isr(name: str, text: str, ref: str, tid: str = "T1055") -> AgentISR:
    claim = ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.6, technique_id=tid)
    return AgentISR(agent_id=name, domain=name, claims=[claim])


class TestEachIndicatorRowGivesTheRootsOfItsProcesses:
    def test_the_acting_and_the_target_process_of_every_row_are_roots(self) -> None:
        found = run_roots(_ledger()).of_entry("ev_0082")

        assert found.roots == [P85, P87_T1, P87_T2, P89]
        assert found.reason == ""

    def test_an_id_one_task_lists_is_written_alone_and_a_shared_one_with_its_task(self) -> None:
        roots = run_roots(_ledger()).of_entry("ev_0011").roots

        assert roots == [P85, P87_T1, P87_T2, P89]

    def test_a_signature_listing_gives_its_rows_and_its_indicators(self) -> None:
        listing = _entry(
            "ev_0013",
            "sandbox_signatures",
            {
                "signatures": [{"name": WROTE}],
                "indicators": _wrote().structured["indicators"][:1],
            },
        )
        found = run_roots(_ledger(listing)).of_entry("ev_0013")

        assert found.roots == [f"sandbox signature {WROTE}", P85, P87_T1]

    def test_a_row_naming_no_process_the_report_settles_says_so(self) -> None:
        page = _entry(
            "ev_0090",
            "sandbox_signatures",
            {
                "indicators": [
                    {
                        "signature": WROTE,
                        "process": {"id": "91", "not_settled": "listed in 2 tasks"},
                        "description": "an act",
                    }
                ]
            },
        )
        found = run_roots(_ledger(page)).of_entry("ev_0090")

        assert found.roots == []
        assert found.reason == INDICATOR_UNSETTLED
        assert found.reason != SIGNATURE_UNPLACED

    def test_a_signature_with_no_indicator_row_still_names_none(self) -> None:
        bare = _entry("ev_0091", "sandbox_signatures", {"indicators": [], "matched": 0})

        assert run_roots(_ledger(bare)).of_entry("ev_0091").reason == SIGNATURE_UNPLACED


class TestAStatementPicksAProcessByTheNumberItWrites:
    def test_a_guest_pid_after_pid_picks_its_process(self) -> None:
        held = _sources("PID 1496 wrote to the memory of PID 1924 [ev_0082].", "ev_0082")

        assert held == {"ev_0082": (READING_RUN, (P85, P87_T1))}

    def test_the_report_s_id_after_procid_picks_its_process(self) -> None:
        held = _sources("procid 85 wrote into another process [ev_0082].", "ev_0082")

        assert held["ev_0082"] == (READING_RUN, (P85,))

    def test_an_id_two_tasks_list_picks_none(self) -> None:
        roots, reasons = run_roots(_ledger()).of_statement(
            "pid 87 wrote into another process [ev_0082].", ["ev_0082"]
        )

        assert roots == []
        assert reasons == [f"ev_0082: {NAMES_NO_ROW.format(entry='ev_0082')}"]

    def test_a_number_written_without_pid_picks_none(self) -> None:
        held = _sources("The value 1496 is written [ev_0082].", "ev_0082")

        assert held["ev_0082"] == (READING_UNPLACED, ())

    def test_a_process_listing_is_picked_from_the_same_way(self) -> None:
        held = _sources("The sample ran as pid 85 [ev_0011].", "ev_0011")

        assert held["ev_0011"] == (READING_RUN, (P85,))


class TestASignatureItemIsPlacedByItsIndicators:
    def test_an_item_of_one_indicator_gives_its_process(self) -> None:
        held = _sources("A startup file was created [sig:2].", "sig:2")

        assert held == {"sig:2": (READING_RUN, (P87_T1,))}

    def test_an_item_with_no_indicator_is_unplaced_as_it_was(self) -> None:
        roots, reasons = run_roots(_ledger()).of_statement("The family is X [sig:1].", ["sig:1"])

        assert roots == []
        assert reasons == [f"sig:1: {SIGNATURE_UNPLACED}"]

    def test_the_item_reader_s_answer_gives_the_roots_of_its_indicators(self) -> None:
        assert run_roots(_ledger()).of_entry("ev_0089").roots == [P87_T1]


class TestATechniqueOnIndicatorRowsIsObserved:
    def test_an_injection_cited_by_its_pids_is_a_behaviour_source(self) -> None:
        said = "PID 1496 wrote to the memory of PID 1924 and set its thread context."
        isrs = {n: _isr(n, said, "[ev_0082]") for n in ("a", "b")}

        held = technique_sources(isrs, _ledger())["T1055"]
        summary = summary_of_sources(held)

        assert held == {"ev_0082": (READING_RULE, (P85, P87_T1))}
        assert summary.support == ""
        assert summary.independent == 1

    def test_a_statement_naming_no_process_stays_unobserved(self) -> None:
        isrs = {n: _isr(n, "The sample injects code.", "[ev_0082]") for n in ("a", "b")}

        held = technique_sources(isrs, _ledger())["T1055"]

        assert held == {"ev_0082": (READING_UNPLACED, ())}
        assert summary_of_sources(held).support == "unobserved"


class TestTheCost:
    def test_reading_indicator_rows_is_linear(self) -> None:
        def ledger(n: int) -> list[LedgerEntry]:
            rows = [{"pid": i, "task": f"t{i % 2}", "name": f"p{i}.exe"} for i in range(1, n + 1)]
            page = [
                {
                    "signature": WROTE,
                    "task": f"t{i % 2}",
                    "process": _proc(str(i), str(10_000 + i), "a.exe"),
                    "target": _proc(str(i + 1), str(10_001 + i), "b.exe"),
                }
                for i in range(1, n)
            ]
            return [
                _entry("ev_0001", "sandbox_processes", {"processes": rows}),
                _entry("ev_0002", "sandbox_signatures", {"indicators": page}),
            ]

        small, large = ledger(2000), ledger(20000)
        assert_ratio(
            lambda: run_roots(small).of_entry("ev_0002"),
            lambda: run_roots(large).of_entry("ev_0002"),
            30,
            what="20,000 indicator rows against 2,000",
        )
