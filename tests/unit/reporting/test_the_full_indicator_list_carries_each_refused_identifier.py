"""The full indicator list carries each identifier row the rule refuses, with its refusal.

The report's identifier table prints every host value the analysis states, each with
the publish rule's answer; the IOC table held only the ones it publishes, so the full
list (``consolidated_iocs``, ``/iocs?include=all``) said nothing of a refused one. Each
refused row is now a row of the table under source ``analysis``, its answer the
refusal, where no row of the same kind and value is held. The identifier table prints
it, so no indicator table prints it again, and a cell that reads the table by value
reads what it read before: no printed line changes.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting import builder as builder_module
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import StaticAnalysis, StringIOC
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, publishes
from malspark.reporting.stated_host_values import refused_identifier_row
from tests.unit.reporting.test_a_host_value_the_analysis_states_is_exported_when_code_finds_it_whole import (  # noqa: E501
    _report,
    _row,
)

SYSTEM_FILE = "C:\\Windows\\System32\\cmd.exe"


def _mixed() -> Any:
    report = _report(
        [
            _row("folder", "Custom_update"),
            _row("folder", "AppData"),
            _row("file path", SYSTEM_FILE),
            _row("scheduled task", "Updater"),
        ]
    )
    # A string of note of a kind the table holds no string row for.
    report.static = StaticAnalysis(
        interesting_strings=[
            StringIOC(value=SYSTEM_FILE, kind="path"),
            StringIOC(value="AppData", kind="other"),
        ]
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _refused(report: Any) -> dict[str, Any]:
    return {row.value: row for row in report.consolidated_iocs if refused_identifier_row(row)}


def test_each_refused_row_is_an_unpublished_analysis_row_with_its_refusal() -> None:
    rows = _refused(_report([_row("folder", "AppData"), _row("folder", "Custom_update")]))

    assert sorted(rows) == ["AppData"]
    folder = rows["AppData"]
    assert folder.source == "analysis" and folder.kind == "folder"
    assert folder.type == "Folder" and folder.context == "stated by the analysis"
    assert not publishes(folder.published)
    assert folder.published.startswith("no: a Windows known folder")


def test_a_published_analysis_row_is_no_refused_row() -> None:
    published = [
        row
        for row in _mixed().consolidated_iocs
        if row.source == "analysis" and publishes(row.published)
    ]

    assert {row.value for row in published} == {"Custom_update", "Updater"}
    assert not any(refused_identifier_row(row) for row in published)


def test_a_value_a_row_already_holds_is_not_added_again() -> None:
    report = _report([_row("folder", "AppData"), _row("folder", "AppData")])
    assert [row.value for row in report.consolidated_iocs if row.source == "analysis"] == [
        "AppData"
    ]
    # The file's strings hold the system file: that row stands, with its own answer.
    rows = [row for row in _mixed().consolidated_iocs if row.value == SYSTEM_FILE]
    assert [row.source for row in rows] == ["strings"]


def _without_added(monkeypatch: pytest.MonkeyPatch) -> None:
    built = builder_module.build_consolidated_iocs

    def _dev_table(report: Any) -> list[Any]:
        return [row for row in built(report) if not refused_identifier_row(row)]

    monkeypatch.setattr(builder_module, "build_consolidated_iocs", _dev_table)


@pytest.mark.parametrize("layout", [ANALYST, BUNDLE, FULL])
def test_no_printed_line_changes(monkeypatch: pytest.MonkeyPatch, layout: Any) -> None:
    report = _mixed()
    assert _refused(report)
    printed = MarkdownRenderer(layout=layout).render(report)
    page = HtmlRenderer(layout=layout).render(report)

    _without_added(monkeypatch)
    report.consolidated_iocs = builder_module.build_consolidated_iocs(report)
    assert not _refused(report)
    assert MarkdownRenderer(layout=layout).render(report) == printed
    assert HtmlRenderer(layout=layout).render(report) == page


def test_the_strings_of_note_cell_reads_no_refused_identifier_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _mixed()
    built = builder_module.build_consolidated_iocs

    def _with_a_same_kind_row(report: Any) -> list[Any]:
        rows = built(report)
        (refused,) = [row for row in rows if refused_identifier_row(row)]
        return [*rows, refused.model_copy(update={"kind": "other"})]

    monkeypatch.setattr(builder_module, "build_consolidated_iocs", _with_a_same_kind_row)
    printed = MarkdownRenderer(layout=FULL).render(report)
    strings = printed.split("Strings of note", 1)[1].split("\n## ", 1)[0]
    (line,) = [cell for cell in strings.splitlines() if "`AppData`" in cell]

    assert line.rstrip().endswith("| - |")
    assert "known folder" not in line


def test_the_export_carries_no_refused_row(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _mixed()
    exported = ExtendedSTIXRenderer().render(report).model_dump(mode="json")["objects"]

    _without_added(monkeypatch)
    report.consolidated_iocs = builder_module.build_consolidated_iocs(report)
    again = ExtendedSTIXRenderer().render(report).model_dump(mode="json")["objects"]
    patterns = sorted(o["pattern"] for o in exported if o["type"] == "indicator")
    assert patterns == sorted(o["pattern"] for o in again if o["type"] == "indicator")
    assert not any("AppData" in p or "cmd.exe" in p for p in patterns)
