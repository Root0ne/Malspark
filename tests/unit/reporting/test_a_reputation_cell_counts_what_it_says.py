"""A network value's reputation cell prints the counts under the record's own names.

The cell of the indicator table prints, for a report that carries the lookups'
records, the counts its enrichment record holds with the helper the header
cell prints its counts with (``core.reputation.counts_line``): the flagged
count, each other count the record holds that is not zero, under the name the
record holds it under, and the engine count the service gave. It sums no
denominator and writes no "of": a category the record holds no count of is
not named, and a total is not printed, since a server record's total may be
the sum of the members its reader kept. A value that is no whole number, a
digit string too long to convert among them, is no count; a timestamp that
converts to no date prints no date, and a service name that is no text names
no service. Nothing a record holds stops the render. A report stored before
the records keeps its cell as it was printed where the value's record holds
all four counts as whole numbers; any other record of such a report is printed
by its counts.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from malspark.core.reputation import ReputationRecord, counts_line
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from malspark.reporting.renderers.markdown import _inline_safe, _reputations

FRAME = "counts in the lookup's record"


def _report(record: dict[str, Any], *, stored: bool = False) -> MalwareReport:
    """A report whose one domain carries ``record``; ``stored`` is one stored before the records."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn="one.example.org", source="sandbox", reputation=record)]
        ),
        reputation=None if stored else [],
    )


def _cell(record: dict[str, Any], *, stored: bool = False) -> str | None:
    return _reputations(_report(record, stored=stored)).get("one.example.org")


# Each record and the cell it gives: every figure printed is a field of the record.
CELLS = [
    (
        {"source": "VirusTotal", "malicious": 0, "suspicious": 3, "harmless": 2, "undetected": 70},
        f"VirusTotal, {FRAME}: malicious 0, suspicious 3, harmless 2, undetected 70",
    ),
    (
        {
            "source": "VirusTotal",
            "malicious": 19,
            "suspicious": 0,
            "harmless": 41,
            "undetected": 31,
        },
        f"VirusTotal, {FRAME}: malicious 19, harmless 41, undetected 31",
    ),
    # A server source's record: its total is never printed, its engine count is.
    (
        {"source": "intel", "malicious": 2, "suspicious": 1, "total": 75, "engines": 75},
        f"intel, {FRAME}: malicious 2, suspicious 1; engines 75",
    ),
    (
        {"source": "intel", "malicious": 2, "suspicious": 1, "total": 3},
        f"intel, {FRAME}: malicious 2, suspicious 1",
    ),
    ({"source": "acme", "malicious": 4}, f"acme, {FRAME}: malicious 4"),
    (
        {"source": "acme", "malicious": "4", "harmless": 10},
        f"acme, {FRAME}: malicious 4, harmless 10",
    ),
    # A count the record does not hold is not printed as one.
    (
        {"source": "acme", "malicious": None, "harmless": 5},
        f"acme, {FRAME}: malicious not counted, harmless 5",
    ),
    ({"source": "acme", "malicious": 1, "harmless": "many"}, f"acme, {FRAME}: malicious 1"),
]


@pytest.mark.parametrize(("record", "said"), CELLS)
def test_the_cell_prints_each_count_under_the_record_s_name_and_no_fraction(
    record: dict[str, Any], said: str
) -> None:
    cell = _cell(record)

    assert cell == said
    assert not re.search(r"\d+ of \d+|/", cell)
    assert "total" not in cell


def test_the_cell_is_written_by_the_header_cell_s_helper() -> None:
    record = {
        "source": "Virus*Total_",
        "malicious": 3,
        "suspicious": 1,
        "harmless": 9,
        "engines": 70,
    }

    cell = _cell(record)

    written = counts_line(
        ReputationRecord(
            service="Virus*Total_",
            malicious=3,
            suspicious=1,
            engines=70,
            stats={"malicious": 3, "suspicious": 1, "harmless": 9},
        ),
        unnamed="reputation",
        written=lambda text: _inline_safe(text, pipes=False),
    )
    assert cell == written
    # The service's name is the answer's text: escaped by the inline rule.
    assert cell.startswith("Virus\\*Total\\_, ")


def test_a_record_with_no_count_and_a_record_with_no_flagged_name_print_no_cell() -> None:
    assert _cell({"source": "acme", "malicious": None}) is None
    assert _cell({"source": "score", "score": 80}) is None


def test_the_cell_keeps_the_analysis_date_and_an_address_is_read_as_a_domain_is() -> None:
    record = {
        "source": "VirusTotal",
        "malicious": 1,
        "harmless": 53,
        "last_analysis_date_unix": 1758672000,
    }
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(
            ips=[NetworkIP(address="192.0.2.7", source="sandbox", reputation=record)]
        ),
        reputation=[],
    )

    assert _reputations(report)["192.0.2.7"] == (
        f"VirusTotal, {FRAME}: malicious 1, harmless 53 (analysed 2025-09-24)"
    )


@pytest.mark.parametrize(
    ("record", "said"),
    [
        (
            {
                "source": "VirusTotal",
                "malicious": 0,
                "suspicious": 3,
                "harmless": 2,
                "undetected": 70,
            },
            "VirusTotal: 0 of 75 engines flag it as malicious",
        ),
        (
            {
                "source": "VirusTotal",
                "malicious": 19,
                "suspicious": 0,
                "harmless": 41,
                "undetected": 31,
                "last_analysis_date_unix": 1758672000,
            },
            "VirusTotal: 19 of 91 engines flag it as malicious (analysed 2025-09-24)",
        ),
    ],
)
def test_a_report_stored_before_the_records_keeps_its_cell(
    record: dict[str, Any], said: str
) -> None:
    assert _cell(record, stored=True) == said


# A digit string too long to convert is no count, as any value that is no whole number.
LONG = "9" * 5000


@pytest.mark.parametrize(
    ("record", "said"),
    [
        ({"source": "acme", "malicious": 1, "engines": LONG}, f"acme, {FRAME}: malicious 1"),
        (
            {"source": "acme", "malicious": LONG, "harmless": 9},
            f"acme, {FRAME}: malicious not counted, harmless 9",
        ),
        ({"source": "acme", "malicious": 1, "harmless": LONG}, f"acme, {FRAME}: malicious 1"),
        ({"source": "acme", "malicious": 1, "harmless": 4.0}, f"acme, {FRAME}: malicious 1"),
    ],
)
def test_a_value_that_is_no_whole_number_is_no_count_and_the_whole_report_renders(
    record: dict[str, Any], said: str
) -> None:
    from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer

    # Read back as the stored report.json holds it.
    report = MalwareReport.model_validate_json(_report(record).model_dump_json())

    assert _reputations(report)["one.example.org"] == said
    for layout in ("analyst", "bundle", "full"):
        rendered = MarkdownRenderer(layout=layout).render(report)
        assert "rendering failed" not in rendered, layout
    assert said in MarkdownRenderer(layout="full").render(report)
    for layout in ("bundle", "full"):
        assert FRAME in HtmlRenderer(layout=layout).render(report, embed_figures=False), layout


@pytest.mark.parametrize(
    "record",
    [
        {"source": "intel", "malicious": 2, "suspicious": 1, "total": 75, "engines": 75},
        {"source": "acme", "malicious": 4, "harmless": 10},
        {"source": "acme", "malicious": 1, "suspicious": 0, "harmless": 3, "undetected": LONG},
    ],
)
def test_a_stored_report_enriched_by_a_source_keeping_some_counts_prints_no_summed_total(
    record: dict[str, Any],
) -> None:
    cell = _cell(record, stored=True)

    assert cell is not None and cell.startswith(f"{record['source']}, {FRAME}: ")
    assert not re.search(r"\d+ of \d+|/", cell)
    assert "total" not in cell


def _stored_json(record_json: str, *, stored: bool) -> MalwareReport:
    """A report read from report.json text whose one domain's record is ``record_json``."""
    held = "" if stored else ', "reputation": []'
    return MalwareReport.model_validate_json(
        f'{{"identity": {{"hashes": {{"sha256": "{"a" * 64}"}}}}, "network": {{"domains": '
        f'[{{"fqdn": "one.example.org", "source": "sandbox", "reputation": {record_json}}}]}}'
        f"{held}}}"
    )


def _renders_whole(report: MalwareReport) -> None:
    from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer

    for layout in ("analyst", "bundle", "full"):
        assert "rendering failed" not in MarkdownRenderer(layout=layout).render(report), layout
    for layout in ("bundle", "full"):
        assert "one[.]example[.]org" in HtmlRenderer(layout=layout).render(
            report, embed_figures=False
        ), layout


# A timestamp that converts to no date is no date: the cell prints no date clause.
STAMPS = [str(10**30), str(-(10**30)), '"abc"', "NaN", "Infinity", "true"]


@pytest.mark.parametrize("stamp", STAMPS)
@pytest.mark.parametrize(
    ("stored", "said"),
    [
        (False, f"acme, {FRAME}: malicious 1, harmless 2, undetected 3"),
        (True, "acme: 1 of 6 engines flag it as malicious"),
    ],
)
def test_a_timestamp_that_converts_to_no_date_prints_no_date_and_the_report_renders(
    stamp: str, stored: bool, said: str
) -> None:
    record = (
        '{"source": "acme", "malicious": 1, "suspicious": 0, "harmless": 2, "undetected": 3, '
        f'"last_analysis_date_unix": {stamp}}}'
    )
    report = _stored_json(record, stored=stored)

    assert _reputations(report)["one.example.org"] == said
    _renders_whole(report)


@pytest.mark.parametrize(
    ("stored", "said"),
    [
        (False, f"reputation, {FRAME}: malicious 1, harmless 2, undetected 3"),
        (True, "reputation: 1 of 6 engines flag it as malicious"),
    ],
)
@pytest.mark.parametrize("source", ['["acme"]', '{"name": "acme"}', "7", "true"])
def test_a_service_name_that_is_no_text_is_left_out_and_the_report_renders(
    source: str, stored: bool, said: str
) -> None:
    record = (
        f'{{"source": {source}, "malicious": 1, "suspicious": 0, "harmless": 2, "undetected": 3}}'
    )
    report = _stored_json(record, stored=stored)

    assert _reputations(report)["one.example.org"] == said
    _renders_whole(report)


def test_a_count_held_as_a_list_or_an_object_is_no_count_and_the_report_renders() -> None:
    record = '{"source": "acme", "malicious": [1], "harmless": {"n": 2}, "engines": [9]}'
    report = _stored_json(record, stored=False)

    assert "one.example.org" not in _reputations(report)
    _renders_whole(report)
    report = _stored_json('{"source": "acme", "malicious": 1, "harmless": [2]}', stored=True)
    assert _reputations(report)["one.example.org"] == f"acme, {FRAME}: malicious 1"
    _renders_whole(report)
