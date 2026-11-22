"""The line over an analyst's table of values counts the rows of that table (C15).

Each row is counted once, by where the indicator section holds the values the report's
reading takes from it (a URL row gives its host as well): as the analyst's row, under another
source, not at all, more than one of these, or no value. Two numbers in one sentence are
counts over the table's rows.
"""

from __future__ import annotations

from malspark.reporting.models import (
    DynamicBehavior,
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import BUNDLE
from malspark.reporting.renderers.markdown import INDICATORS_TITLE, analyst_list_note
from malspark.reporting.renderers.prose_forms import section_reference

W = section_reference(INDICATORS_TITLE)
_HEAD = "_Listed by the dynamic analyst: a model's table, not a tool's output."
_TAIL = " No measured table, count, rule match or capability profile reads it._"


def _report(section: EvidenceSection, **fields: object) -> MalwareReport:
    base: dict[str, object] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        "verdict": "Malware",
        "sections": [section],
    }
    base.update(fields)
    return MalwareReport.model_validate(base)


def _endpoints(*rows: list[str]) -> EvidenceSection:
    return EvidenceSection(
        key="artifact_endpoints",
        title="Endpoints",
        kind="table",
        columns=["Listed by", "Evidence", "Value", "Column 4"],
        rows=list(rows),
        source="artifact:dynamic",
    )


def _line(report: MalwareReport) -> str:
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    return next(ln for ln in bundle.splitlines() if ln.startswith("_Listed by the dynamic"))


_SANDBOX = {
    "evidence_index": [EvidenceIndexRow(id="ev_0001", server="sandbox", tool="detonate")],
    "dynamic": DynamicBehavior(),
}


def test_a_url_row_and_its_host_count_as_one_row() -> None:
    report = _report(
        _endpoints(
            ["dynamic", "ev_0001", "url", "http://evil.example/a"],
            ["dynamic", "ev_0001", "domain", "other.example"],
        ),
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn="evil.example", source="sandbox"),
                NetworkDomain(fqdn="other.example", source="sandbox"),
            ],
            urls=[NetworkURL(url="http://evil.example/a", source="sandbox")],
        ),
        **_SANDBOX,
    )
    assert _line(report) == (
        _HEAD + " Of its 2 rows, 2 give only values in §9 under another source." + _TAIL
    )


def test_one_value_listed_twice_is_counted_in_each_row() -> None:
    report = _report(
        _endpoints(
            ["dynamic", "ev_0001", "domain", "other.example"],
            ["static", "ev_0001", "domain", "other.example"],
            ["dynamic", "ev_0001", "domain", "unseen.example"],
        ),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="other.example", source="sandbox")]),
        **_SANDBOX,
    )
    line = _line(report)
    assert line.endswith(
        " Of its 3 rows, 2 give only values in §9 under another source; 1 gives only values "
        "not in §9." + _TAIL
    ), line


class TestTheWordsOfEachForm:
    def test_rows_of_each_kind_are_counted(self) -> None:
        note = analyst_list_note(
            ["static"],
            "iocs",
            [{"analyst"}, {"analyst"}, {"other"}, {"absent"}, {"analyst", "absent"}, set()],
        )
        assert (
            f" Of its 6 rows, 2 give only values in {W} as the analyst's, with the publish rule's "
            f"answer; 1 gives only values in {W} under another source; 1 gives only values not in "
            f"{W}; 1 gives values of more than one kind: in {W} as the analyst's, in {W} under "
            f"another source, or not in {W}; 1 gives no value the report reads as an indicator."
        ) in note

    def test_a_table_of_one_row(self) -> None:
        assert f" Its one row gives only values in {W} under another source." in (
            analyst_list_note(["static"], "iocs", [{"other"}])
        )
        assert (
            f" Its one row gives values of more than one kind: in {W} as the analyst's, in {W} "
            f"under another source, or not in {W}."
        ) in analyst_list_note(["static"], "iocs", [{"other", "absent"}])

    def test_every_row_s_values_the_analyst_s_keeps_the_sentence(self) -> None:
        note = analyst_list_note(["static"], "iocs", [{"analyst"}, {"analyst"}, set()])
        assert (
            f" Each value it types as an indicator is in {W} as the analyst's, with the publish "
            "rule's answer."
        ) in note

    def test_no_row_gives_a_value(self) -> None:
        note = analyst_list_note(["static"], "iocs", [set(), set()])
        assert " The report reads no value of it as an indicator." in note


def test_no_model_reads_the_line() -> None:
    """The line is written by the report renderer only: no module of the pipeline, the agents,
    the prompts or the model-facing reporting code names it or its count."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    readers = sorted(
        str(path.relative_to(root))
        for path in (root / "src").rglob("*.py")
        if "analyst_list_note" in (text := path.read_text(encoding="utf-8"))
        or "_typed_values_shown" in text
    )
    assert readers == ["src/malspark/reporting/renderers/markdown.py"]
