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
    reason_label,
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
    assert (
        "registry is unavailable from the sandbox; mutexes is not in the sandbox report as read"
        in section
    )
    assert plain(
        "Packet capture [ev_0002] covers 300.2 s (1,234 packets); traffic outside that window "
        "was not captured."
    ) in plain(section)
    # An open question's reason prints by its label, never its code.
    assert "Open questions: 2 filed (needs a sandbox run: 1, a tool failed: 1)" in section
    assert "tool_failed" not in section and "needs_sandbox_run" not in section
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
    rows = inventory_rows(report.limitation_inventory, reason_as=reason_label)
    # The list as printed, open questions' reasons by their labels; the marked questions'
    # row is shown once, under its own key.
    assert facts[MEASURED_LIST_FACT] == [
        row.text for row in printed_rows(report.limitation_inventory)
    ]
    assert facts[NOT_PRINTED_FACT] == [
        row.text for row in rows if not row.printed and row.part != "marks"
    ]
    assert not any(
        text.startswith("Open questions naming only") for text in facts[NOT_PRINTED_FACT]
    )
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
    # Not held, the paragraph is dev's closing passage: no failure check, no failed call
    # counted as shown (T-600's gating, untouched).
    assert passages["limitations"].unredone_failed == frozenset()
    assert passages["limitations"].sourced_check is None


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
    rows = printed_rows(inventory, claims_not_discussed=len(report.claims_not_discussed))
    assert [row.text for row in rows] == golden["printed"]


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


# -- late reasons, the round's gating, escaping, labels and the keep rules -----------


def test_a_reason_recorded_after_the_record_is_counted_as_the_others() -> None:
    from malspark.pipeline.nodes import _limitations_as_recorded
    from malspark.reporting.limitation_facts import recorded_reasons

    report = _report(_ledger())
    # A section the composer left out, recorded after the record was built.
    report.degradation_reasons.append("The conclusion section was left out after its retries.")
    _limitations_as_recorded(report)
    inventory = report.limitation_inventory
    not_run, withheld, recorded = recorded_reasons(report)
    assert inventory.recorded == recorded and len(recorded) == 2
    assert [t.tool for t in inventory.not_offered] == [t.tool for t in not_run]
    assert inventory.withheld == withheld
    # Section 11's count is the bundle's list of what limited the run, minus its tool line.
    assert "2 other limitations the run recorded" in _section_11(report)
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    limited = bundle.split("**What limited this run:**", 1)[1].split("\n\n", 2)[1]
    items = [line for line in limited.splitlines() if line.startswith("- ")]
    assert len(items) - len(inventory.not_offered) == 2


def test_an_unheld_paragraph_raises_dev_s_refusals_and_ends() -> None:
    from malspark.reporting.section_agreement import (
        FAILURE_REDONE_CODE,
        KEEP_UNQUOTED_CODE,
        agreement_violations,
    )
    from tests.unit.reporting.test_every_refusal_offers_only_the_ends_that_pass import (
        _CELL_ID,
        _FAILED,
        _LIMITATION,
        CONCLUSION,
        VALUE_CELL,
        _report_of,
        _row,
        _Subject,
    )
    from tests.unit.reporting.test_every_refusal_offers_only_the_ends_that_pass import (
        _ledger as _table_ledger,
    )

    # The limitations paragraph agrees with the ledger, so it is not held; a closing
    # sentence and a cell say a call failed that a later call redid. On dev no failure
    # check reads a passage then: a rewrite saying so passes, a keep naming no source is
    # refused as dev refuses it, the inventory's rows shown besides and speaking of none.
    ledger = _table_ledger()
    for subject in (
        _Subject(CONCLUSION, "conclusion", _FAILED, (("conclusion", _FAILED),)),
        _Subject(VALUE_CELL, _CELL_ID, _FAILED, ((_CELL_ID, _FAILED),)),
    ):
        report = _report_of(_Subject(subject.kind, subject.pid, subject.sentence, (
            *subject.fields, ("limitations", _LIMITATION))))  # fmt: skip
        passages = passages_of(report, entries=ledger)
        (limitations,) = [p for p in passages if p.id == "limitations"]
        assert limitations.label == "11. Limitations"
        assert limitations.unredone_failed == frozenset()
        assert all(p.sourced_check is None for p in passages if p.write is not None)
        assert not any(p.id == "calls.1" for p in passages)

        def codes(row: dict[str, Any], passages: Any = passages) -> list[str]:
            found = agreement_violations({"sentences": [row]}, passages)
            return [v.code for v in found if v.path.startswith("sentences.0")]

        rewrite = _row(subject, "rewrite", ["answered.1"], rewrite=_FAILED)
        assert FAILURE_REDONE_CODE not in codes(rewrite)
        assert codes(rewrite) == []
        keep = _row(subject, "keep", [], reason="x")
        (refused,) = [
            v
            for v in agreement_violations({"sentences": [keep]}, passages)
            if v.path.startswith("sentences.0")
        ]
        assert refused.code == KEEP_UNQUOTED_CODE
        # origin/dev's message: answered.1 alone speaks, no row of the inventory.
        assert "naming no source, but answered.1 speaks of what it names" in refused.message
        assert "The shown sources that speak of it: [answered.1] " in refused.message
        assert "inv." not in refused.message
    # Where no other fact speaks, an unheld paragraph's rows raise nothing.
    assert _gate_codes(held=False) == _UNHELD_DEV_CODES


# The gate case: a failed call no later call answered, which a conclusion sentence says
# failed; the limitations paragraph either says nothing of it (not held) or says it too
# (held). Keyed by the row's passage: (path, code) of every violation origin/dev raises
# for a keep naming no source.
_GATE_CONCLUSION = "The routine at 0x8000 could not be decompiled [ev_0201]."
_GATE_AGREES = "The gate reads a host mode [ev_0107]."
_GATE_FAILED = "The decompile of 0x8000 failed [ev_0201]."
_HELD_UNLISTED = "agreement.held_unlisted"
_KEEP_UNQUOTED = "agreement.keep_unquoted"
# origin/dev's codes (7e919a623), not held: no row refuses the keep.
_UNHELD_DEV_CODES = {
    "conclusion": [("held.limitations", _HELD_UNLISTED)],
    "limitations": [("held.conclusion", _HELD_UNLISTED)],
}
# origin/dev's codes, held: failed.2 speaks of both sentences.
_HELD_DEV_CODES = {
    "conclusion": [
        ("sentences.0.sources", _KEEP_UNQUOTED),
        ("held.limitations", _HELD_UNLISTED),
        ("held.limitations", _HELD_UNLISTED),
    ],
    "limitations": [
        ("sentences.0.sources", _KEEP_UNQUOTED),
        ("held.conclusion", _HELD_UNLISTED),
        ("held.limitations", _HELD_UNLISTED),
    ],
}
# origin/dev's refusal of the held conclusion keep, word for word; the row's id there is
# failed.2, the inventory's inv.2 here.
_HELD_DEV_MESSAGE = (
    "row 1: conclusion keeps 'The routine at 0x8000 could not be decompiled [ev_0201].' "
    "naming no source, but failed.2 speaks of what it names: name the source and quote its "
    "words that state the same thing, or rewrite the sentence on it. The shown sources that "
    'speak of it: [failed.2] "ev_0201 (\\"lift_routine\\") failed: \\"no function there\\"; '
    'no later call answered for offset 0x8000". Keep it on one of these, quoting its words, '
    "or rewrite or drop it."
)


def _gate_passages(held: bool) -> Any:
    from malspark.schemas.evidence import LedgerEntry
    from tests.unit.reporting import (
        test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger as denial,
    )

    failed = LedgerEntry(
        id="ev_0201",
        tool="lift_routine",
        args={"address": hex(denial.BASE + 0x8000)},
        ok=False,
        error="no function there",
        facts=denial._DECOMPILE,
    )
    ledger = [*denial._ledger(), failed]
    report = denial._report(f"{_GATE_AGREES} {_GATE_FAILED}" if held else _GATE_AGREES)
    report.technical_analysis.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body=_GATE_CONCLUSION
    )
    return passages_of(report, entries=ledger)


def _gate_violations(held: bool) -> dict[str, list[Any]]:
    from malspark.reporting.section_agreement import agreement_violations

    passages = _gate_passages(held)
    rows = {
        "conclusion": _GATE_CONCLUSION,
        "limitations": _GATE_FAILED if held else _GATE_AGREES,
    }
    return {
        pid: agreement_violations(
            {
                "sentences": [
                    {
                        "passage": pid,
                        "sentence": sentence,
                        "decision": "keep",
                        "sources": [],
                        "rewrite": "",
                        "quote": "",
                        "reason": "no source speaks of it",
                    }
                ]
            },  # fmt: skip
            passages,
        )
        for pid, sentence in rows.items()
    }


def _gate_codes(held: bool) -> dict[str, list[tuple[str, str]]]:
    return {pid: [(v.path, v.code) for v in found] for pid, found in _gate_violations(held).items()}


def test_an_unheld_paragraph_s_rows_are_shown_and_speak_of_no_sentence() -> None:
    passages = _gate_passages(held=False)
    rows = [p for p in passages if p.id.startswith("inv.")]
    # Shown: the failed call no later call answered is among them, citing its entry.
    assert any("ev_0201" in p.cites for p in rows)
    assert next(p for p in passages if p.id == "limitations").sourced_check is None
    # origin/dev showed none of these and refused no keep: the codes are dev's.
    assert _gate_codes(held=False) == _UNHELD_DEV_CODES


def test_a_held_paragraph_s_rows_speak_as_dev_s_facts_did() -> None:
    passages = _gate_passages(held=True)
    assert next(p for p in passages if p.id == "limitations").sourced_check is not None
    assert _gate_codes(held=True) == _HELD_DEV_CODES
    (refused,) = [v for v in _gate_violations(held=True)["conclusion"] if v.code == _KEEP_UNQUOTED]
    assert refused.message == _HELD_DEV_MESSAGE.replace("failed.2", "inv.2")


def test_entries_trimmed_to_the_budget_are_a_printed_limit() -> None:
    ledger = _ledger()
    report = _report(ledger, build=False)
    report.run_summary["evidence"]["trimmed"] = 2
    report.limitation_inventory = build_inventory(report, ledger)
    assert report.limitation_inventory.trimmed == 2
    (row,) = [r for r in printed_rows(report.limitation_inventory) if r.part == "failed"]
    assert row.text.endswith(" 2 of 6 ledger entries were trimmed to the budget.")
    # The bundle's bounds read the record's count, as section 11 does.
    report.run_summary["evidence"]["trimmed"] = 5
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert "2 trimmed to the budget" in bundle and "5 trimmed" not in bundle
    # With no failed call left standing, the trimmed entries still print a row.
    alone = [_listing("ev_0003", GATE)]
    report = _report(alone, build=False)
    report.run_summary["evidence"]["trimmed"] = 1
    report.limitation_inventory = build_inventory(report, alone)
    (row,) = [r for r in printed_rows(report.limitation_inventory) if r.part == "failed"]
    assert row.text == "Tool calls: 1 of 1 ledger entry was trimmed to the budget."


def test_the_writer_is_shown_every_printed_line_but_the_claims_count() -> None:
    from malspark.reporting.models import ClaimNotDiscussed

    report = _report(_ledger())
    report.claims_not_discussed = [
        ClaimNotDiscussed(agent="reader", claim_number=n, claim=f"claim {n}") for n in (1, 2)
    ]
    text = _bundle_text("limitations", analyst_bundle("limitations", report))
    instruction = _INSTRUCTIONS["limitations_measured"]
    assert "counting the analyst claims the report does not discuss" in instruction
    shown = analyst_bundle("limitations", report)["facts"][MEASURED_LIST_FACT]
    assert all(quoted_value(line) in text for line in shown)
    section = _section_11(report)
    printed = [plain(line[2:]) for line in section.splitlines() if line.startswith("- ")]
    claims = (
        "2 analyst claims in force are not discussed in this report and are printed whole in "
        "the bundle."
    )
    assert printed == [plain(line) for line in shown] + [plain(claims)]


def test_a_hostile_tool_name_and_reason_print_escaped() -> None:
    from malspark.reporting.models import InventoryTool
    from malspark.reporting.renderers.html import HtmlRenderer

    report = _report(_ledger())
    report.limitation_inventory.not_offered.append(
        InventoryTool(
            tool="evil_*tool*", reason="see [click](https://example.org/x) **now** <b>x</b>"
        )
    )
    section = _section_11(report)
    (line,) = [line for line in section.splitlines() if "evil" in line]
    assert "evil\\_\\*tool\\*" in line
    assert "\\[click\\]" in line and "\\*\\*now\\*\\*" in line and "\\<b\\>" in line
    assert "https://example.org" not in line
    html = HtmlRenderer(layout=ANALYST).render(report)
    at = html.index("evil")
    item = html[at : html.index("</li>", at)]
    assert "<a " not in item and "<strong>" not in item and "<em>" not in item
    assert "<b>" not in item


def test_every_open_question_reason_has_a_printed_label() -> None:
    from malspark.schemas.isr_models import OPEN_QUESTION_REASON_LABELS, OPEN_QUESTION_REASONS

    assert set(OPEN_QUESTION_REASON_LABELS) == set(OPEN_QUESTION_REASONS)
    for reason in OPEN_QUESTION_REASONS:
        label = reason_label(reason)
        assert label == label.lower() and "_" not in label and label.strip() == label
    # The round's row keeps the codes it is matched by.
    ledger = _ledger()
    passages = passages_of(_report(ledger), entries=ledger)
    (row,) = [p for p in passages if p.text.startswith("Open questions:")]
    assert "needs_sandbox_run: 1" in row.text and "tool_failed: 1" in row.text


def test_an_unheld_paragraph_s_rows_leave_out_no_item_and_speak_of_no_body_absence() -> None:
    from malspark.reporting.section_agreement import (
        SECTION_5,
        Passage,
        _quote_problem,
        _speaking_sources,
        generic_words,
    )

    ledger = _ledger()
    by_id = {p.id: p for p in passages_of(_report(ledger), entries=ledger)}
    rows = [p for p in by_id.values() if p.id.startswith("inv.")]
    assert rows and all(p.silent for p in rows)
    # A closing keep on a section 5 sentence leaving out the capture item, which a row
    # names; and a body absence a row's words bear on.
    flow = Passage(
        id="flow",
        label="5. flow",
        text="Whether the gate routine passes on a live host is not established.",
        kind=SECTION_5,
    )
    absence = "No routine they call has listed code."
    body = Passage(
        id="body", label="5. body", text=absence, kind=SECTION_5, absences=(absence,),
        write=lambda _text: None,
    )  # fmt: skip
    by_id.update(flow=flow, body=body)
    sentence = (
        "Whether the gate routine passes, and the packet capture window, were not established."
    )

    def read() -> tuple[str, list[str]]:
        problem = _quote_problem(sentence, flow.text, [flow], generic_words(by_id), by_id)
        return problem, [pid for pid, _excerpt in _speaking_sources(absence, by_id, body)]

    # origin/dev showed no row here: nothing is left out, nothing speaks.
    assert read() == ("", [])
    # The same rows, speaking as a held paragraph's do, would raise both.
    for row in rows:
        row.silent = False
    problem, speaking = read()
    assert problem.startswith("leaves out an item") and speaking


def test_an_unheld_paragraph_s_rows_alone_ask_no_question() -> None:
    import asyncio

    from malspark.pipeline.validation import EntryTexts
    from malspark.reporting.section_agreement import ask_section_agreement
    from tests.unit.reporting import (
        test_every_closing_sentence_is_answered_and_no_rewrite_keeps_its_absence as closing,
    )

    # Two closing passages and a failed call neither says failed: origin/dev showed no fact
    # and asked nothing; the rows shown now ask nothing either.
    ledger = [_failed("ev_0004", OTHER)]
    report = _report(ledger, paragraph="The beacon interval is fixed [ev_0004].")
    report.technical_analysis.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The sample loads a key [ev_0004]."
    )
    assert any(p.id.startswith("inv.") for p in passages_of(report, entries=ledger))
    reporter = closing._Reporter()
    asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=["ev_0004"],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert reporter.asked == []


def _with_reasons(*whys: str) -> Any:
    ledger = _ledger()
    report = _report(ledger, build=False)
    report.sections[0].rows = [
        ["reader", f"Question {n}?", why, "a listing", "ev_0003"] for n, why in enumerate(whys)
    ]
    report.limitation_inventory = build_inventory(report, ledger)
    return report, ledger


def test_an_undeclared_reason_prints_under_the_label_of_other() -> None:
    # Alone, and beside a declared "other": one item, its count summed, never the word.
    for whys, printed in (
        (("made_up_word: x",), "Open questions: 1 filed (other: 1)"),
        (("made_up_word: x", "other: y"), "Open questions: 2 filed (other: 2)"),
        (
            ("made_up_word: x", "other: y", "tool_failed: z"),
            "Open questions: 3 filed (other: 2, a tool failed: 1)",
        ),
        # Equal counts: the smallest code counted under a label decides, not the last seen.
        (
            ("other: a", "zzz: b", "tool_failed: c", "tool_failed: d"),
            "Open questions: 4 filed (other: 2, a tool failed: 2)",
        ),
    ):
        report, ledger = _with_reasons(*whys)
        assert reason_label("made_up_word") == reason_label("other") == "other"
        (row,) = [r for r in printed_rows(report.limitation_inventory) if r.part == "questions"]
        assert row.text.startswith(printed)
        word = "zzz" if "zzz: b" in whys else "made_up_word"
        assert word not in _section_11(report)
        # The round's facts keep the word the run recorded.
        passages = passages_of(report, entries=ledger)
        (fact,) = [p for p in passages if p.text.startswith("Open questions:")]
        assert f"{word}: 1" in fact.text


@pytest.mark.parametrize("name", ("haiku11", "haiku13"))
def test_the_appendix_of_a_stored_run_is_dev_s_with_the_record(name: str) -> None:
    report, inventory = _stored(name)
    without = MarkdownRenderer(layout=ANALYST).render(report)
    report.limitation_inventory = inventory
    held = MarkdownRenderer(layout=ANALYST).render(report)

    def appendix(text: str) -> str:
        # The notes are numbered in the order the report cites: the list's citations come
        # before the appendix's, so only the numbers differ.
        return re.sub(r"\[\[\d+\]\]|#cite-\d+", "#", text[text.index("\n## Appendix") :])

    assert LIST_LABEL in held and LIST_LABEL not in without
    assert appendix(held) == appendix(without)


def test_a_capture_entry_that_failed_is_not_read() -> None:
    failed = _capture("ev_0002").model_copy(update={"ok": False, "error": "x"})
    good = _capture("ev_0007").model_copy(
        update={"structured": {"duration_s": 12.5, "packets_in_capture": 9}}
    )
    ledger = [_index(), failed, good]
    inventory = build_inventory(_report(ledger, build=False), ledger)
    assert inventory.capture is not None and inventory.capture.entry == "ev_0007"
    assert inventory.capture.duration_s == 12.5
    ledger = [_index(), failed]
    assert build_inventory(_report(ledger, build=False), ledger).capture is None


def test_the_start_path_names_only_a_callee_on_it(monkeypatch: pytest.MonkeyPatch) -> None:
    import malspark.agents.callees_question as callees

    ledger = _ledger()

    def ranked(on_path: bool) -> Any:
        callee = callees.CalleeToRead(
            address=HELPER, callers=(GATE,), depth=1, start=GATE, called_from=1, calls=0,
            on_path=on_path,
        )  # fmt: skip
        return callees.CalleesFound(ranked=(callee,), starts=callees.STARTS_STATED)

    for on_path, first in ((False, []), (True, [HELPER])):
        monkeypatch.setattr(callees, "callees_to_read", lambda *a, o=on_path, **k: ranked(o))
        assert build_inventory(_report(ledger, build=False), ledger).unread_first == first


def test_the_marked_questions_row_names_up_to_twelve_routines() -> None:
    def run(count: int) -> str:
        addresses = [0x402000 + 0x10 * n for n in range(count)]
        ledger = [_listing(f"ev_{n + 1:04d}", a) for n, a in enumerate(addresses)]
        report = _report(ledger, build=False)
        report.sections[0].rows = [
            ["reader", f"What does {hex(a)} hold?", "tool_failed: x", "a listing", "ev_0001"]
            for a in addresses
        ]
        inventory = build_inventory(report, ledger)
        (row,) = [r for r in inventory_rows(inventory) if r.part == "marks"]
        return row.text

    five = run(5)
    assert five.count(" in ev_") == 5 and "more." not in five
    fourteen = run(14)
    assert fourteen.count(" in ev_") == 12 and fourteen.endswith("; and 2 more.")
