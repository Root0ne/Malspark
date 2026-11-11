"""What the run could not do is measured once by code and printed from that one record (T-601).

Section 11 of the analyst report was one paragraph the report model wrote,
with the platform's sentences after it each reading a different record: a
stored run printed "4 of 158 tool calls failed and were not redone" beside a
ledger whose failed calls were all redone. The limitations inventory is now
built once from the ledger before the report's prose is written and stored
on the report; section 11 prints each row of it that states a limit, the
evidence bundle prints every row, the limitations' writer is shown every row
and the list as printed, and the agreement round is shown them as ``inv.N``
facts. Every address, entry and tool name in the synthetic tests is a neutral
value; the sandbox and the capture are read by declared kind, never by a
tool's name.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from malspark.agents.tool_fence import quoted_value
from malspark.pipeline.nodes import evidence_summary
from malspark.reporting.composer import _INSTRUCTIONS, _bundle_text
from malspark.reporting.composer_pro import (
    LISTED_QUESTIONS_FACT,
    MEASURED_LIST_FACT,
    NOT_PRINTED_FACT,
    OTHER_QUESTIONS_FACT,
    analyst_bundle,
)
from malspark.reporting.limitation_inventory import (
    LIST_LABEL,
    build_inventory,
    inventory_rows,
    printed_rows,
)
from malspark.reporting.models import (
    DynamicBehavior,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import FACT, passages_of
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import plain, stored_runs

GATE, OTHER, HELPER = 0x401A30, 0x401B40, 0x401C50
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_SECTIONS = {"v": 1, "kind": "sandbox_sections"}
_CAPTURE = {"v": 1, "kind": "pcap"}
GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "limitation_inventory"
PARAGRAPH = "Whether the decoded commands run in the analysed sample was not observed [ev_0003]."


def _listing(entry_id: str, address: int, calls: int | None = None) -> LedgerEntry:
    body = f"  FUN_{calls:x}();\n" if calls is not None else ""
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n{body}  return a;\n}}\n",
        facts=_DECOMPILE,
        agent="reader",
    )


def _failed(entry_id: str, address: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        ok=False,
        error="the program is not open",
        facts=_DECOMPILE,
        agent="reader",
    )


def _index(
    entry_id: str = "ev_0001",
    tool: str = "section_index",
    source: str = "mcp:box",
    facts: dict[str, Any] | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool=tool,
        source=source,
        facts=_SECTIONS if facts is None else facts,
        structured={
            "sections": {
                "processes": {"items": 3, "prefix": "proc"},
                "network": {"items": 2, "prefix": "net"},
                "registry": {
                    "no": "no: the report lists `registry` as unavailable from its sandbox"
                },
                "mutexes": {"no": "no: the report holds no `mutexes`"},
            },
            "tool": "sandbox_items",
        },
    )


def _capture(
    entry_id: str = "ev_0002",
    tool: str = "flows_of_the_run",
    source: str = "mcp:wire",
    facts: dict[str, Any] | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool=tool,
        source=source,
        facts=_CAPTURE if facts is None else facts,
        structured={"duration_s": 300.25, "packets_in_capture": 1234, "packets_read": 1234},
    )


def _ledger() -> list[LedgerEntry]:
    return [
        _index(),
        _capture(),
        _listing("ev_0003", GATE, calls=HELPER),
        _failed("ev_0004", OTHER),
        _failed("ev_0005", GATE),
        _listing("ev_0006", GATE),
    ]


def _questions() -> EvidenceSection:
    return EvidenceSection(
        key="open_questions",
        kind="table",
        title="Open questions",
        columns=["Agent", "Question", "Why open", "What would answer it", "Evidence"],
        rows=[
            ["reader", "Which key does 0x401a30 load?", "tool_failed: x", "a listing", "ev_0005"],
            ["reader", "Does the beacon run?", "needs_sandbox_run", "a run", "ev_0003"],
        ],
    )


def _report(ledger: list[LedgerEntry], *, paragraph: str = PARAGRAPH, build: bool = True) -> Any:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32 DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        dynamic=DynamicBehavior(),
        degradation_reasons=[
            "server.lookup.check_name_unavailable(KEY is not configured); set it",
            "triage.rules_failed",
        ],
        sections=[_questions()],
        run_summary={"evidence": evidence_summary(ledger)},
        technical_analysis=TechnicalAnalysis(
            analyst_limitations=TechnicalSubsection(
                title="Limitations", body=paragraph, evidence_refs=["ev_0003"]
            )
        )
        if paragraph
        else None,
    )
    if build:
        report.limitation_inventory = build_inventory(report, ledger)
    return report


def _section_11(report: MalwareReport) -> str:
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    return analyst.split("## 11. Limitations", 1)[1].split("\n## ", 1)[0]


# -- the record ----------------------------------------------------------------


def test_the_record_holds_each_part_read_off_the_ledger() -> None:
    inventory = _report(_ledger()).limitation_inventory
    assert inventory.entries == 6
    by_entry = {call.entry: call for call in inventory.failed}
    # ev_0005 asked for GATE, which ev_0006 lists after it; ev_0004's address no later call
    # asked for.
    assert by_entry["ev_0005"].redone_by == ["ev_0006"]
    assert by_entry["ev_0004"].redone_by == [] and by_entry["ev_0004"].asked == [OTHER]
    assert (inventory.listed, inventory.unread) == (1, 1)
    assert [(t.tool, t.reason) for t in inventory.not_offered] == [
        ("check_name", "KEY is not configured")
    ]
    assert inventory.recorded == ["triage.rules_failed"]
    assert inventory.sandbox_entry == "ev_0001"
    assert {(s.name, s.items, s.unavailable) for s in inventory.sandbox_sections} == {
        ("processes", 3, False),
        ("network", 2, False),
        ("registry", None, True),
        ("mutexes", None, False),
    }
    assert inventory.capture is not None and inventory.capture.entry == "ev_0002"
    assert inventory.capture.duration_s == 300.25 and inventory.capture.packets == 1234
    marked = [q for q in inventory.questions if q.all_listed]
    assert [q.question for q in marked] == ["Which key does 0x401a30 load?"]
    # Listed by ev_0003 and ev_0006, both before the filer's last entry: not "after".
    assert marked[0].listed == [(GATE, ["ev_0003", "ev_0006"])] and not marked[0].listed_after


def test_a_listing_after_the_filer_s_last_entry_is_marked_so() -> None:
    ledger = [*_ledger(), _listing("ev_0007", OTHER)]
    ledger[-1] = ledger[-1].model_copy(update={"agent": "second"})
    report = _report(ledger)
    report.sections[0].rows.append(
        ["reader", "What does 0x401b40 hold?", "tool_failed: y", "a listing", "ev_0004"]
    )
    inventory = build_inventory(report, ledger)
    (late,) = [q for q in inventory.questions if q.addresses == [OTHER]]
    assert late.all_listed and late.listed_after


def test_the_sandbox_and_the_capture_are_read_by_declared_kind_only() -> None:
    # A tool of another name declaring the kind is read; an undeclared tool holding the
    # same answer, or one of the shipped name with a source and no kind, is not.
    undeclared = {"source": "mcp:other", "facts": {"v": 1}}
    for ledger, read in (
        ([_index("ev_0001", "boxes_index"), _capture("ev_0002", "net_timeline")], True),
        ([_index(**undeclared), _capture(**undeclared)], False),
        ([_index(tool="sandbox_sections", **undeclared)], False),
    ):
        inventory = build_inventory(_report(ledger, build=False), ledger)
        assert bool(inventory.sandbox_entry) is read
        assert (inventory.capture is not None) is (read and len(ledger) > 1)


def test_a_stored_report_without_the_record_reads_and_dumps_as_it_did() -> None:
    report = _report(_ledger(), build=False)
    assert "limitation_inventory" not in report.model_dump(mode="json")
    again = MalwareReport.model_validate(json.loads(_report(_ledger()).model_dump_json()))
    assert again.limitation_inventory == _report(_ledger()).limitation_inventory


# -- what section 11 prints ----------------------------------------------------


def test_section_11_prints_only_the_rows_that_state_a_limit_then_the_paragraph() -> None:
    report = _report(_ledger())
    section = _section_11(report)
    rows = printed_rows(report.limitation_inventory)
    assert LIST_LABEL in section
    assert len(rows) <= 7
    # Each printed row as the record's template wrote it, citations moved to notes.
    listed = [line[2:] for line in section.splitlines() if line.startswith("- ")]
    assert [plain(line) for line in listed] == [plain(row.text) for row in rows]
    assert [row.part for row in rows] == ["failed", "code", "recorded", "sandbox", "capture",
                                          "questions"]  # fmt: skip
    # The failed call a later call redid prints nothing of its own; the one no call redid
    # does, and so does each limit; the paragraph follows the list.
    assert plain("Tool calls: 1 of 6 failed and was not redone: lift_routine for 0x401b40") in (
        plain(section)
    )
    assert "registry is unavailable from the sandbox; mutexes is not in the report" in section
    assert "300.2 s, 1,234 packets" in section
    assert section.index(LIST_LABEL) < section.index("Whether the decoded commands run")
    # dev's platform sentences are folded into the list: none is printed beside it.
    assert "The evidence is partial" not in section and "The run recorded 2" not in section


def test_a_run_with_nothing_measured_prints_no_item_for_it() -> None:
    ledger = [_listing("ev_0003", GATE)]
    report = _report(ledger)
    report.sections = []
    report.degradation_reasons = []
    report.limitation_inventory = build_inventory(report, ledger)
    assert printed_rows(report.limitation_inventory) == []
    section = _section_11(report)
    assert LIST_LABEL not in section
    assert "Whether the decoded commands run" in section


def test_without_the_record_section_11_is_dev_s() -> None:
    section = _section_11(_report(_ledger(), build=False))
    assert LIST_LABEL not in section
    assert "The evidence is partial: 1 of 6 tool calls failed and were not redone." in section
    assert "The run recorded 2 limitations" in section


def test_the_list_and_the_bundle_s_bounds_count_the_same_failed_and_redone_calls() -> None:
    report = _report(_ledger())
    # The run summary's own rows say otherwise (a summary written before the one map):
    # every count printed reads the record.
    report.run_summary["evidence"]["redone"] = []
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert "2 failed (1 of them redone by a later call for the same address: ev_0005 by " in (
        bundle.replace("\\_", "_")
    )
    assert "**Measured limitations:**" in bundle
    rows = inventory_rows(report.limitation_inventory)
    measured = bundle.split("**Measured limitations:**", 1)[1].split("\n\n", 2)[1]
    assert len(measured.splitlines()) == len(rows)
    assert "Tool calls redone: 1 of 6 failed and was redone" in plain(measured)
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert "1 of 6 failed and was not redone" in plain(analyst)


# -- what the writer is shown --------------------------------------------------


def test_the_writer_is_shown_every_row_and_the_split_questions() -> None:
    report = _report(_ledger())
    facts = analyst_bundle("limitations", report)["facts"]
    rows = inventory_rows(report.limitation_inventory)
    assert facts[MEASURED_LIST_FACT] == [row.text for row in rows if row.printed]
    assert facts[NOT_PRINTED_FACT] == [row.text for row in rows if not row.printed]
    assert facts[LISTED_QUESTIONS_FACT] == [
        '"Which key does 0x401a30 load?" (filed by reader as tool_failed; cites ev_0005): '
        "every routine it names has listed code: 0x401a30 in ev_0003, ev_0006"
    ]
    assert facts[OTHER_QUESTIONS_FACT] == [
        '"Does the beacon run?" (filed by reader as needs_sandbox_run; cites ev_0003)'
    ]
    assert "limitations_recorded" not in facts and "failed_calls_redone" not in facts


def test_the_writer_s_message_says_what_the_renderer_prints() -> None:
    report = _report(_ledger())
    text = _bundle_text("limitations", analyst_bundle("limitations", report))
    instruction = _INSTRUCTIONS["limitations_measured"]
    # The instruction names each key the message shows, and says the list is printed.
    for key in (MEASURED_LIST_FACT, NOT_PRINTED_FACT, LISTED_QUESTIONS_FACT):
        assert key in instruction and f"- {key}: " in text
    assert "prints each line under measured_list above your paragraph as written" in instruction
    # Every line shown under measured_list is a line section 11 prints, in its words.
    shown = re.search(rf"- {MEASURED_LIST_FACT}: \[(.*)\]", text)
    assert shown is not None
    section = _section_11(report)
    printed = [plain(line[2:]) for line in section.splitlines() if line.startswith("- ")]
    for row in printed_rows(report.limitation_inventory):
        assert quoted_value(row.text) in shown.group(1)
        assert plain(row.text) in printed


def test_a_report_without_the_record_is_shown_what_dev_showed() -> None:
    facts = analyst_bundle("limitations", _report(_ledger(), build=False))["facts"]
    assert "limitations_recorded" in facts and MEASURED_LIST_FACT not in facts


# -- what the agreement round is shown -------------------------------------------


def test_the_round_is_shown_the_rows_wherever_the_paragraph_stands() -> None:
    ledger = _ledger()
    passages = {p.id: p for p in passages_of(_report(ledger), entries=ledger)}
    rows = [p for i, p in passages.items() if i.startswith("inv.")]
    assert rows and all(p.kind == FACT for p in rows)
    texts = [p.text for p in rows]
    assert texts[0].startswith('ev_0004 ("lift_routine") failed')
    assert texts[1].startswith('ev_0005 ("lift_routine") failed')
    assert any(t.startswith("Sandbox report [ev_0001]: holds processes (3)") for t in texts)
    assert any(t.startswith("Packet capture [ev_0002]") for t in texts)
    # The gated ids are gone, and the paragraph, which agrees, is not held.
    assert not any(i.split(".")[0] in ("failed", "not_run", "recorded", "open") for i in passages)
    assert passages["limitations"].label == "11. Limitations"
    # The failed call no later call redid counts as shown (T-600 R6).
    assert passages["limitations"].unredone_failed == {"ev_0004"}


def test_no_paragraph_no_rows() -> None:
    ledger = _ledger()
    passages = passages_of(_report(ledger, paragraph=""), entries=ledger)
    assert not any(p.id.startswith("inv.") for p in passages)


# -- the stored runs -------------------------------------------------------------

_RUNS = ("hk14-ref-haiku", "haiku13", "haiku12", "haiku11", "haiku10", "haiku8")


def _stored(name: str) -> tuple[MalwareReport, Any]:
    from scripts.replay.limitation_inventory import stored_inventory

    root = stored_runs()
    if root is None or not (root / name / "evidence.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    return stored_inventory(root / name)


@pytest.mark.parametrize("name", _RUNS)
def test_a_stored_run_builds_its_golden_inventory(name: str) -> None:
    report, inventory = _stored(name)
    golden = json.loads((GOLDEN / f"{name}.json").read_text())
    assert inventory.model_dump(mode="json") == golden["inventory"]
    rows = inventory_rows(inventory, claims_not_discussed=len(report.claims_not_discussed))
    assert [row.text for row in rows if row.printed] == golden["printed"]


# Section B of the scope, per run: failed / redone by the map / answered in part; listed /
# unread; tools not offered (+ withheld); sandbox sections held / absent; capture window;
# open questions; those naming only listed routines, and of them listed after filing.
_TABLE = {
    "hk14-ref-haiku": ((3, 3, 0), (61, 68), (3, 16), (6, 12), 600.2, 29, 8, 6),
    "haiku13": ((1, 0, 1), (92, 42), (3, 16), (6, 12), 576.0, 41, 14, 0),
    "haiku12": ((6, 6, 0), (72, 59), (3, 16), (6, 12), 590.4, 24, 8, 6),
    "haiku11": ((5, 5, 0), (71, 56), (3, 16), (6, 12), 598.0, 28, 7, 2),
    "haiku10": ((1, 1, 0), (63, 63), (3, 16), (6, 12), 583.6, 40, 7, 2),
    "haiku8": ((5, 3, 0), (83, 53), (3, 16), (6, 12), 590.8, 20, 6, 1),
}


@pytest.mark.parametrize("name", _RUNS)
def test_a_stored_run_s_rows_are_the_scope_s_table(name: str) -> None:
    _report_, inventory = _stored(name)
    failed = inventory.failed
    marked = [q for q in inventory.questions if q.all_listed]
    assert (
        (
            len(failed),
            sum(1 for c in failed if c.redone_by),
            sum(1 for c in failed if not c.redone_by and c.answered),
        ),
        (inventory.listed, inventory.unread),
        (len(inventory.not_offered), inventory.withheld),
        (
            sum(1 for s in inventory.sandbox_sections if s.items is not None),
            sum(1 for s in inventory.sandbox_sections if s.items is None),
        ),
        inventory.capture.duration_s if inventory.capture else None,
        len(inventory.questions),
        len(marked),
        sum(1 for q in marked if q.listed_after),
    ) == _TABLE[name]


def test_haiku13_names_a_partial_answer_and_haiku8_its_calls_not_redone() -> None:
    _r13, haiku13 = _stored("haiku13")
    (call,) = haiku13.failed
    assert call.redone_by == [] and [e for _a, e in call.answered] == ["ev_0142"]
    _r8, haiku8 = _stored("haiku8")
    assert {c.entry for c in haiku8.failed if not c.redone_by} == {"ev_0008", "ev_0122"}
    (row,) = [r for r in printed_rows(haiku8) if r.part == "failed"]
    assert "ev_0008" in row.text and "ev_0122" in row.text
