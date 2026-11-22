"""The ATT&CK table's note on `(rule match)` names the sources that table marks (T-845).

The table marks `(rule match)` beside every deterministic source that asserted a technique
(a sandbox's signatures, Sigma, YARA, a capability-rule tool) and beside every rule hit over
the binary. The note under it names each source the table marks, read from the rows it
printed, and says "with no sandbox" only of the rules over the binary, whose names the
Procedure cell carries.
"""

from __future__ import annotations

import re
from typing import Any

from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import BUNDLE

_TAIL = (
    " each with its base rate: how much ordinary software it fires on, over the corpus it "
    "names. It says nothing about how likely this sample is to be benign, and `not measured` "
    "means the rule has no measurement, not that it never fires._"
)


def _cell(tid: str, name: str) -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0002",
        tactic_name="Execution",
        technique_id=tid,
        technique_name=name,
        evidence=["The code calls it."],
        contributing_layers=["static"],
    )


def _report(hits: list[dict[str, Any]], asserted: dict[str, list[str]]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        verdict="Malware",
        static=StaticAnalysis(api_technique_hits=hits),
        capability_matrix=[
            _cell("T1059", "Command and Scripting Interpreter"),
            _cell("T1490", "Inhibit System Recovery"),
        ],
        run_summary={
            "corroboration": {
                tid: {"asserted_by": sources, "claimed_by": ["static"]}
                for tid, sources in asserted.items()
            }
        },
    )


_CAPA = {"source": "capa", "kind": "capability_rules", "technique_id": "T1059", "rule": "run cmd"}
_TABLE = {
    "source": "api_capability",
    "technique_id": "T1490",
    "name": "Inhibit System Recovery",
    "matched_apis": ["DeleteVolumeShadow"],
}


def _note(report: MalwareReport) -> str:
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    found = re.findall(r"^_(?:A source marked|No source in this table)[^\n]*$", bundle, re.M)
    assert len(found) == 1, found
    return found[0]


def test_every_source_the_table_marks_is_named() -> None:
    report = _report([_CAPA], {"T1059": ["capa", "sandbox"], "T1490": ["sigma", "yara"]})
    assert _note(report) == (
        "_A source marked `(rule match)` is a rule that fired, with no model; this table marks "
        "capa, sandbox, sigma and yara. The Procedure cell names the rules that fired over the "
        "binary with no sandbox — a capability rule tool's over its code —" + _TAIL
    )


def test_the_knowledge_table_is_named_only_where_its_rules_fired() -> None:
    report = _report([_CAPA, _TABLE], {"T1059": ["capa"]})
    note = _note(report)
    assert note.startswith(
        "_A source marked `(rule match)` is a rule that fired, with no model; this table marks "
        "api_capability and capa. The Procedure cell names the rules that fired over the binary "
        "with no sandbox — a capability rule tool's over its code, the knowledge table's over "
        "its imports —"
    )
    alone = _note(_report([_TABLE], {}))
    assert alone == (
        "_A source marked `(rule match)` is a rule that fired, with no model; this table marks "
        "api_capability. The Procedure cell names the rules that fired over the binary with no "
        "sandbox — the knowledge table's over its imports —" + _TAIL
    )


def test_no_absence_of_a_source_the_table_shows() -> None:
    report = _report([_CAPA], {"T1059": ["capa", "sandbox"], "T1490": ["sigma"]})
    note = _note(report)
    assert "with no sandbox and no model" not in note
    marked = set(
        re.findall(
            r"([a-z_]+) \(rule match\)",
            MarkdownRenderer(layout=BUNDLE)
            .render(report)
            .split("## 8.", 1)[1]
            .split("_A source", 1)[0],
        )
    )
    named = (
        note.split("this table marks ", 1)[1].split(".", 1)[0].replace(" and ", ", ").split(", ")
    )
    assert marked == set(named) == {"capa", "sandbox", "sigma"}


def test_a_source_marked_by_a_rule_match_on_resolved_names_is_named() -> None:
    resolved = {**_TABLE, "resolved_apis": ["DeleteVolumeShadow"]}
    report = _report([resolved], {})
    report.capability_matrix = [_cell("T1490", "Inhibit System Recovery")]
    table = MarkdownRenderer(layout=BUNDLE).render(report).split("## 8.", 1)[1]
    assert "api_capability (rule match on names resolved at runtime" in table
    assert _note(report).startswith(
        "_A source marked `(rule match)` is a rule that fired, with no model; this table marks "
        "api_capability. The Procedure cell names the rules that fired over the binary with no "
        "sandbox — the knowledge table's over names resolved at runtime —"
    )


def test_a_table_that_marks_no_source_says_so() -> None:
    from malspark.reporting.renderers.markdown import _Context, _rule_match_note

    report = _report([], {})
    note = _rule_match_note(report, report.capability_matrix, {}, {}, _Context.of(report))
    assert note.startswith("_No source in this table is marked `(rule match)`.")


def test_no_model_reads_the_note() -> None:
    """The note is written by the report renderer only: no module of the pipeline, the agents,
    the prompts or the model-facing reporting code names it."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    readers = sorted(
        str(path.relative_to(root))
        for path in (root / "src").rglob("*.py")
        if "_rule_match_note" in path.read_text(encoding="utf-8")
    )
    assert readers == ["src/malspark/reporting/renderers/markdown.py"]
