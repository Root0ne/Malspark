"""The line over an analyst's table of values counts the rows of that table (C15).

Each row is counted once, by where the indicator section holds the values the report's
reading types as an indicator in it (a URL row gives its host as well): each as the analyst's
row, each under another source, none of them, more than one of these, or no value. The words
say the values are the ones the reading types as an indicator: a row's other cells are not
read. A row of more than one kind names only the places the counted rows show. Two numbers in
one sentence are counts over the table's rows.
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
    NetworkIP,
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
        _HEAD
        + " Of its 2 rows, 2 give values it types as an indicator, each in §9 under another source."
        + _TAIL
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
        " Of its 3 rows, 2 give values it types as an indicator, each in §9 under another "
        "source; 1 gives values it types as an indicator, none of them in §9." + _TAIL
    ), line


_NET = NetworkIOCs(
    domains=[NetworkDomain(fqdn="quietrelay.top", source="sandbox")],
    ips=[NetworkIP(address="45.77.12.9", source="sandbox")],
)


def test_a_row_s_cells_the_reading_does_not_type_are_not_said_to_be_in_the_section() -> None:
    report = _report(
        _endpoints(
            ["dynamic", "ev_0001", "quietrelay.top", "C:\\Users\\u\\a.exe"],
            ["dynamic", "ev_0001", "45.77.12.9", "d41d8cd98f00b204e9800998ecf8427e"],
        ),
        network=_NET,
        **_SANDBOX,
    )
    line = _line(report)
    assert "only" not in line
    assert line == (
        _HEAD
        + " Of its 2 rows, 2 give values it types as an indicator, each in §9 under another source."
        + _TAIL
    )


def test_an_address_with_its_port_and_process() -> None:
    report = _report(
        _endpoints(["dynamic", "ev_0001", "45.77.12.9", "443 (pid 1200)"]),
        network=_NET,
        **_SANDBOX,
    )
    line = _line(report)
    assert "only" not in line
    assert line == (
        _HEAD
        + " Its one row gives values it types as an indicator, each in §9 under another source."
        + _TAIL
    )


class TestTheWordsOfEachForm:
    def test_rows_of_each_kind_are_counted(self) -> None:
        note = analyst_list_note(
            ["static"],
            "iocs",
            [{"analyst"}, {"analyst"}, {"other"}, {"absent"}, {"analyst", "absent"}, set()],
        )
        assert (
            f" Of its 6 rows, 2 give values it types as an indicator, each in {W} as the "
            f"analyst's, with the publish rule's answer; 1 gives values it types as an indicator, "
            f"each in {W} under another source; 1 gives values it types as an indicator, none of "
            f"them in {W}; 1 gives values of more than one kind: in {W} as the analyst's or not in "
            f"{W}; 1 gives no value the report reads as an indicator."
        ) in note

    def test_a_row_of_more_than_one_kind_names_the_places_its_rows_show(self) -> None:
        note = analyst_list_note(["static"], "iocs", [{"other", "absent"}, {"other"}])
        assert (
            f" 1 gives values of more than one kind: in {W} under another source or not in {W}."
        ) in note
        every = analyst_list_note(["static"], "iocs", [{"analyst", "other"}, {"other", "absent"}])
        assert (
            f" 2 give values of more than one kind: in {W} as the analyst's, in {W} under another "
            f"source, or not in {W}."
        ) in every

    def test_a_table_of_one_row(self) -> None:
        assert (
            f" Its one row gives values it types as an indicator, each in {W} under another source."
            in (analyst_list_note(["static"], "iocs", [{"other"}]))
        )
        assert (
            f" Its one row gives values of more than one kind: in {W} under another source or not "
            f"in {W}."
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
