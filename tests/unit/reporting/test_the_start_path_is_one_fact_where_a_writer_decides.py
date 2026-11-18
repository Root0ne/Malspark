"""The place the sandbox started the submitted file from is one fact where a writer decides.

The facts of the execution-flow, configuration and host-identifier sections,
the narrative's facts block (which the question round shares) and the
agreement round's facts each carry ONE line: the path and what the record
shows of it, the T-718 sentence unchanged (``sandbox_report.STAGED_NOTE``).
One writer (``evidence_bundles.sandbox_start_facts``); listed only where a row
is marked, so a report with no mark reads as it did. Offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting import composer, evidence_bundles
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.models import MalwareReport
from malspark.reporting.narrative_agent import findings_lines
from malspark.reporting.section_agreement import FACT, passages_of
from malspark.schemas.evidence import EvidenceCounter
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE, STAGED_NOTE_KEY, STAGED_WORDS
from tests.unit._ledger_helpers import entry
from tests.unit.reporting._report_shapes import rich_report

STAGED = "C:\\Users\\u\\AppData\\Local\\Temp\\" + "c" * 64 + ".exe"
SECTIONS = ("execution_flow", "configuration", "host_identifiers")


def _report(marked: bool = True) -> MalwareReport:
    row: dict[str, Any] = {"pid": 10, "ppid": 4, "name": STAGED, "command_line": f'"{STAGED}"'}
    if marked:
        row[STAGED_KEY] = True
    answer = {
        **({STAGED_NOTE_KEY: STAGED_NOTE} if marked else {}),
        "processes": [row, {"pid": 11, "ppid": 10, "name": "C:\\Windows\\System32\\cmd.exe"}],
        "total": 2,
    }
    dynamic = dynamic_from_ledger(
        [entry("sandbox_processes", answer, EvidenceCounter(), agent="dynamic")]
    )
    assert dynamic is not None
    report = rich_report()
    assert report.dynamic is not None
    report.dynamic.process_tree = dynamic.process_tree
    return report


class TestTheOneWriter:
    def test_the_fact_is_the_path_the_mark_s_words_and_the_t718_sentence(self) -> None:
        facts = evidence_bundles.sandbox_start_facts(_report())
        assert facts == {STAGED: f"{STAGED_WORDS} (pid 10). {STAGED_NOTE}"}

    def test_a_pid_two_tasks_share_is_two_marked_rows_each_named_with_its_task(self) -> None:
        from malspark.reporting.models import ProcessNode
        from malspark.schemas.sandbox_report import staged_note

        report = _report()
        assert report.dynamic is not None
        report.dynamic.process_tree = [
            ProcessNode(pid=10, name=STAGED, task=task, staged_by_sandbox=True)
            for task in ("behavioral1", "behavioral2")
        ]
        assert evidence_bundles.sandbox_start_facts(report) == {
            STAGED: (
                f"{STAGED_WORDS} (pid 10 in task behavioral1, pid 10 in task behavioral2). "
                f"{staged_note(2)}"
            )
        }

    def test_a_process_listed_twice_in_one_task_is_one_marked_row(self) -> None:
        from malspark.reporting.models import ProcessNode

        report = _report()
        assert report.dynamic is not None
        report.dynamic.process_tree = [
            ProcessNode(pid=10, name=STAGED, task="behavioral1", staged_by_sandbox=True)
            for _ in range(2)
        ]
        assert evidence_bundles.sandbox_start_facts(report) == {
            STAGED: f"{STAGED_WORDS} (pid 10). {STAGED_NOTE}"
        }

    def test_a_report_with_no_marked_row_has_none(self) -> None:
        assert evidence_bundles.sandbox_start_facts(_report(marked=False)) == {}
        assert evidence_bundles.sandbox_start_line(_report(marked=False)) == ""


class TestEachWriterIsShownOneLine:
    @pytest.mark.parametrize("section", SECTIONS)
    def test_the_section_s_facts_carry_it_once(self, section: str) -> None:
        report = _report()
        bundle = composer.section_bundle(section, report, None)
        assert bundle["facts"][evidence_bundles.SANDBOX_START_FACT] == (
            evidence_bundles.sandbox_start_facts(report)
        )
        text = composer._bundle_text(section, bundle)
        assert text.count(STAGED_NOTE) == 1
        (line,) = [one for one in text.splitlines() if STAGED_NOTE in one]
        assert line.startswith(f"- {evidence_bundles.SANDBOX_START_FACT}: ")

    @pytest.mark.parametrize("section", SECTIONS)
    def test_a_section_of_a_report_with_no_mark_reads_as_before(self, section: str) -> None:
        bundle = composer.section_bundle(section, _report(marked=False), None)
        assert evidence_bundles.SANDBOX_START_FACT not in bundle["facts"]

    def test_the_narrative_s_facts_block_carries_it_once(self) -> None:
        report = _report()
        lines = [line for line in findings_lines(report) if STAGED_NOTE in line]
        assert lines == [f"Sandbox start path: {evidence_bundles.sandbox_start_line(report)}"]
        assert not [line for line in findings_lines(_report(marked=False)) if STAGED_WORDS in line]

    def test_the_agreement_round_s_facts_carry_it_once(self) -> None:
        report = _report()
        facts = [p for p in passages_of(report) if p.kind == FACT and STAGED_NOTE in p.text]
        assert [p.text for p in facts] == [evidence_bundles.sandbox_start_line(report)]
        unmarked = passages_of(_report(marked=False))
        assert not [p for p in unmarked if STAGED_NOTE in p.text]
