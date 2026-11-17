"""Every surface that shows a model a process row or its image path carries the mark's words.

The place the sandbox started the submitted file from is marked on its row
(``staged_by_sandbox``) and every surface writes the same words beside it,
read from one helper (``sandbox_report.staged_words``): the behaviour links'
pack line and their report table (the marked process's command line), the
composer's execution-flow tree, and the note naming the entries that hold a
value a claim quotes. A row or a value not marked reads as it did. Offline.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from malspark.analysis import behaviour_code as bc
from malspark.pipeline.triage_pack import render_pack
from malspark.pipeline.validation import EntryTexts
from malspark.reporting import composer, evidence_bundles
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.ledger_report import BEHAVIOUR_CODE_SECTION, build_sections
from malspark.reporting.models import MalwareReport
from malspark.schemas.evidence import EvidenceCounter
from malspark.schemas.sandbox_report import STAGED_KEY, STAGED_NOTE, STAGED_NOTE_KEY, STAGED_WORDS
from tests.unit._ledger_helpers import entry
from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import _entry
from tests.unit.reporting._report_shapes import rich_report

DIGEST = "c" * 64
STAGED = f"C:\\Users\\u\\AppData\\Local\\Temp\\{DIGEST}.exe"
RENAMED = "C:\\Users\\u\\AppData\\Local\\Temp\\a8f3k2.exe"
CHILD = "C:\\Windows\\System32\\cmd.exe"


def _sandbox(image: str) -> dict[str, Any]:
    return {
        "target": {"name": "invoice.exe", "sha256": DIGEST},
        "behavior": {
            "processes": [
                {"pid": 4, "ppid": 1, "process_name": image, "command_line": f'"{image}"'},
                {"pid": 5, "ppid": 4, "process_name": CHILD, "command_line": "cmd /c ver"},
            ]
        },
        # A file written during the run that no process runs: the record states its writes.
        "dropped": [{"name": "run.log", "filepath": "C:\\Users\\u\\AppData\\Local\\Temp\\run.log"}],
    }


def _links(image: str) -> dict[str, Any]:
    return bc.link_behaviour_to_code(_sandbox(image), None, bc.StaticInputs())


def _command(answer: dict[str, Any], image: str) -> dict[str, Any]:
    return next(row for row in answer["links"] if row["value"] == f'"{image}"')


ANSWER: dict[str, Any] = {
    STAGED_NOTE_KEY: STAGED_NOTE,
    "processes": [
        {"pid": 10, "ppid": 4, "name": STAGED, "command_line": f'"{STAGED}"', STAGED_KEY: True},
        {"pid": 11, "ppid": 10, "name": CHILD, "command_line": "cmd"},
    ],
    "total": 2,
}


def _report() -> tuple[MalwareReport, list[Any]]:
    ledger = [entry("sandbox_processes", ANSWER, EvidenceCounter(), agent="dynamic")]
    dynamic = dynamic_from_ledger(ledger)
    assert dynamic is not None
    report = rich_report()
    assert report.dynamic is not None
    report.dynamic.process_tree = dynamic.process_tree
    return report, ledger


class TestTheBehaviourLinks:
    def test_the_marked_process_s_command_line_carries_the_mark(self) -> None:
        answer = _links(STAGED)
        assert _command(answer, STAGED).get(STAGED_KEY) is True
        child = next(row for row in answer["links"] if row["value"] == "cmd /c ver")
        assert STAGED_KEY not in child

    def test_the_pack_line_and_the_table_write_the_words_beside_its_items(self) -> None:
        link = _entry(bc.TOOL, _links(STAGED), 8)
        line = render_pack([link], 0)
        assert f"(proc:4; {STAGED_WORDS})" in line
        assert line.count(STAGED_WORDS) == 1
        table = next(s for s in build_sections([link]) if s.key == BEHAVIOUR_CODE_SECTION)
        cells = [row[2] for row in table.rows]
        assert f"proc:4 ({STAGED_WORDS})" in cells
        assert "proc:5" in cells

    def test_a_process_the_sandbox_did_not_start_from_its_path_reads_as_before(self) -> None:
        answer = _links(RENAMED)
        assert all(STAGED_KEY not in row for row in answer["links"])
        line = render_pack([_entry(bc.TOOL, answer, 8)], 0)
        assert STAGED_WORDS not in line
        assert "(proc:4)" in line


class TestTheComposerFacts:
    def test_the_execution_flow_tree_writes_the_words_beside_the_marked_row(self) -> None:
        report, _ledger = _report()
        tree = composer.section_bundle("execution_flow", report, None)["facts"]["process_tree"]
        assert tree[0] == f'pid 10 {STAGED} ({STAGED_WORDS}): "{STAGED}"'
        assert tree[1] == f"  pid 11 {CHILD}: cmd"

    def test_the_note_on_a_claim_quoting_the_path_carries_the_words(self) -> None:
        report, ledger = _report()
        bundle = {"claims": [{"claim": f'It runs from "{STAGED}".', "evidence_ref": "ev_0001"}]}
        text = composer._bundle_text(
            "execution_flow",
            bundle,
            EntryTexts.from_ledger(ledger),
            started=evidence_bundles.sandbox_start_matcher(report),
        )
        assert f"({STAGED_WORDS}) is in ev_0001" in text
        assert text.count(STAGED_WORDS) == 1

    def test_the_note_on_a_claim_quoting_another_value_reads_as_before(self) -> None:
        report, ledger = _report()
        bundle = {"claims": [{"claim": f'It starts "{CHILD}".', "evidence_ref": "ev_0001"}]}
        entries = EntryTexts.from_ledger(ledger)
        shown = composer._bundle_text(
            "execution_flow",
            bundle,
            entries,
            started=evidence_bundles.sandbox_start_matcher(report),
        )
        assert shown == composer._bundle_text("execution_flow", bundle, entries)
        assert STAGED_WORDS not in shown


class _RawLLM:
    """A model that answers a section's question with an empty table and keeps what it was sent."""

    def __init__(self) -> None:
        self.sent: list[Any] = []

    def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
        raise RuntimeError("structured output is unavailable")

    async def ainvoke(self, messages: Any) -> Any:
        self.sent.append(list(messages))
        return SimpleNamespace(content=json.dumps({"steps": []}))


def _section_prompt(claim: str) -> str:
    """The question the composer's own section prompt builder sends for the execution flow."""
    report, ledger = _report()
    llm = _RawLLM()
    comp = composer.ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    comp._citable = ["ev_0001"]
    comp._report = report
    comp._entries = EntryTexts.from_ledger(ledger)
    bundle = {"claims": [{"claim": claim, "evidence_ref": "ev_0001"}]}
    with (
        patch("malspark.reporting.composer.bundle_for", return_value=bundle),
        patch(
            "malspark.reporting.composer.structured_output_supported_for_llm", return_value=False
        ),
    ):
        asyncio.run(
            comp._author(
                "execution_flow",
                report,
                None,
                composer._FlowOut,
                composer._INSTRUCTIONS["execution_flow"],
            )
        )
    return str(llm.sent[0][-1].content)


class TestTheComposerSectionPrompt:
    def test_the_question_sent_shows_the_words_beside_the_quoted_path(self) -> None:
        sent = _section_prompt(f'It runs from "{STAGED}".')
        assert f"({STAGED_WORDS}) is in ev_0001" in sent

    def test_the_question_sent_for_another_value_carries_no_words(self) -> None:
        sent = _section_prompt(f'It starts "{CHILD}".')
        assert f"({STAGED_WORDS}) is in" not in sent


class TestTheStartMatcher:
    def test_the_command_line_with_arguments_is_matched_as_written(self) -> None:
        report, _ledger = _report()
        assert report.dynamic is not None
        node = report.dynamic.process_tree[0]
        node.command_line = f'"{STAGED}" -k netsvcs /quiet'
        started = evidence_bundles.sandbox_start_matcher(report)
        assert started is not None
        assert started(f'"{STAGED}" -k netsvcs /quiet')
        assert started(f'  "{STAGED}" -k netsvcs /quiet ')
        assert started(STAGED)
        assert not started(f'"{STAGED}" -k other')
        assert not started(f"{CHILD} -k netsvcs /quiet")
