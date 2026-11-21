"""A network value's reputation cell prints the counts under the record's own names.

The cell of the indicator table prints, for a report that carries the lookups'
records, the counts its enrichment record holds with the helper the header
cell prints its counts with (``core.reputation.counts_line``): the flagged
count, each other count the record holds that is not zero, under the name the
record holds it under, and the engine count the service gave. It sums no
denominator and writes no "of": a category the record holds no count of is
not named, and a total is not printed, since a server record's total may be
the sum of the members its reader kept. A report stored before the records
keeps its cell as it was printed.
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
            {"source": "intel", "malicious": 2, "suspicious": 1, "total": 75, "engines": 75},
            "intel: 2 of 3 engines flag it as malicious",
        ),
    ],
)
def test_a_report_stored_before_the_records_keeps_its_cell(
    record: dict[str, Any], said: str
) -> None:
    assert _cell(record, stored=True) == said
