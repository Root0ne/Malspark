"""Section 11 states what left the machine, and three wordings read as they should (T-719).

The analyst report's limitations printed "Tools the run could not offer: check_hash ... (KEY is
not configured)", which reads as if no outside lookup was made, while the run's disclosure
record held the lookups another tool server made and the sample's upload to a sandbox: only
the bundle printed them. Section 11 now prints one row stating what left this machine, each
lookup host with its kinds and counts and each sample upload with its host, in the words the
bundle's disclosure block gives them, and that the full record is in the bundle. A record
placing nothing outside the machine prints no row, and the row is never one a count cuts.
The composer is shown nothing new.

And: a category the judge states as "none" takes no article; a technique row ends
"(evidence: note)" rather than on a dangling "; evidence"; and "n of N ledger entries"
agrees its verb with n. Every value here is made up.
"""

from __future__ import annotations

import re
from typing import Any

from malspark.analysis.disclosure import LEFT_THE_MACHINE_RECORD
from malspark.reporting.limitation_inventory import LIST_LABEL, build_inventory, printed_rows
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from tests.unit.reporting._report_inventory import plain
from tests.unit.reporting.test_the_limitations_inventory_is_written_by_code import (
    _ledger,
    _report,
    _section_11,
)

LOOKUP = {
    "why": "",
    "host": "lookup.example",
    "calls": 4,
    "kinds": {"ip": 1, "hash": 2, "domain": 1},
    "where": "remote",
    "served": 1,
    "source": "mcp:lookups",
    "transport": "streamable-http",
    "without_indicator": 0,
}
SANDBOX = {
    "by": "sandbox",
    "why": "",
    "host": "sandbox.example",
    "calls": 1,
    "where": "remote",
    "failed": 0,
    "source": "detonator",
    "transport": "",
    "launch_arguments": "--quiet",
    "launch_arguments_honoured": True,
}
# A local tool server handed the sample: where it went cannot be told; the bundle says so.
STAGED = {
    "by": "tool",
    "why": "the settings do not say where a local tool server sends what it is given",
    "host": "",
    "calls": 3,
    "where": "unknown",
    "failed": 0,
    "served": 0,
    "source": "mcp:local",
    "transport": "stdio",
}


def _record(lookups: list[Any], uploads: list[Any]) -> dict[str, Any]:
    return {"v": 5, "models": [], "lookups": lookups, "uploads": uploads, "servers": []}


def _with(record: dict[str, Any] | None) -> Any:
    report = _report(_ledger())
    if record is not None:
        report.run_summary["disclosure"] = record
    return report


def _row(section: str) -> str:
    (line,) = [line for line in section.splitlines() if LEFT_THE_MACHINE_RECORD in line]
    return line


def test_section_11_states_each_lookup_host_and_what_kinds_were_sent() -> None:
    row = plain(_row(_section_11(_with(_record([LOOKUP], [SANDBOX, STAGED])))))
    assert re.search(
        r"Lookups: lookup(\.|\[\.\])example \(outside this machine\) was asked 4 times "
        r"\(\+1 answered without a run\)",
        row,
    )
    assert "ip 1, hash 2, domain 1" in row


def test_section_11_states_the_sample_upload_and_its_host() -> None:
    section = _section_11(_with(_record([LOOKUP], [SANDBOX, STAGED])))
    row = plain(_row(section))
    assert re.search(
        r"Sample upload: the sample was submitted once to the detonator sandbox at "
        r"sandbox(\.|\[\.\])example \(outside this machine\)\.",
        row,
    )
    # Hosts, kinds and counts only: no launch argument, and nothing whose place is unknown.
    assert "--quiet" not in row and "launch arguments" not in row
    assert "cannot be told" not in row and "stdio" not in row
    assert row.startswith("- Lookups:") and row.endswith(LEFT_THE_MACHINE_RECORD)
    assert section.index(LIST_LABEL) < section.index(LEFT_THE_MACHINE_RECORD)


def test_no_disclosure_row_where_the_record_has_none() -> None:
    for record in (None, _record([], []), _record([], [STAGED])):
        assert LEFT_THE_MACHINE_RECORD not in _section_11(_with(record))


def test_section_11_disclosure_words_match_the_bundle_block() -> None:
    report = _with(_record([LOOKUP], [SANDBOX, STAGED]))
    row = _row(_section_11(report))[2:].removesuffix(LEFT_THE_MACHINE_RECORD).strip()
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    block = [line[2:] for line in bundle.splitlines() if line.startswith("- ")]
    lookup, upload = re.split(r"(?<=\.) (?=Sample upload:)", row)
    assert lookup in block
    # The submission's sentence opens the bundle's line, its launch arguments after.
    assert any(line.startswith(upload) and line != upload for line in block)


def test_the_disclosure_row_is_never_the_one_a_count_cuts() -> None:
    report = _with(_record([LOOKUP], [SANDBOX]))
    rows = printed_rows(report.limitation_inventory)
    section = _section_11(report)
    listed = [line for line in section.splitlines() if line.startswith("- ")]
    assert len(listed) == len(rows) + 1
    assert LEFT_THE_MACHINE_RECORD in listed[-1]


def test_the_disclosure_row_is_stated_without_the_inventory_too() -> None:
    report = _with(_record([LOOKUP], []))
    report.limitation_inventory = None
    assert LEFT_THE_MACHINE_RECORD in _section_11(report)


def test_the_composer_is_shown_no_disclosure_row() -> None:
    report = _with(_record([LOOKUP], [SANDBOX]))
    ledger = _ledger()
    inventory = build_inventory(report, ledger)
    assert all(LEFT_THE_MACHINE_RECORD not in row.text for row in printed_rows(inventory))


# -- Ruling 14: the wordings ---------------------------------------------------------------


def _conclusion(category: str) -> str:
    report = _report(_ledger())
    report.malware_category = category
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    return analyst.split("## 7. Conclusion", 1)[1].split("\n## ", 1)[0]


def test_a_category_stated_as_none_takes_no_article() -> None:
    said = _conclusion("none (a legitimate archiver)")
    assert ", category: none (a legitimate archiver)" in said
    assert "a none" not in said
    assert ", a loader," in _conclusion("loader")
    # A word that only opens with the letters is a category like any other.
    assert ", a nonexistent-class loader," in _conclusion("nonexistent-class loader")


def test_a_trimmed_count_agrees_with_its_own_number() -> None:
    report = _report(_ledger(), build=False)
    report.run_summary["evidence"]["trimmed"] = 1
    report.limitation_inventory = build_inventory(report, _ledger())
    (row,) = [r for r in printed_rows(report.limitation_inventory) if r.part == "failed"]
    assert row.text.endswith(" 1 of 6 ledger entries was trimmed to the budget.")


def test_the_disclosure_row_prints_where_the_inventory_prints_none() -> None:
    from tests.unit.reporting.test_the_limitations_inventory_is_written_by_code import (
        GATE,
        _listing,
    )

    ledger = [_listing("ev_0003", GATE)]
    report = _report(ledger)
    report.sections = []
    report.degradation_reasons = []
    report.limitation_inventory = build_inventory(report, ledger)
    assert printed_rows(report.limitation_inventory) == []
    report.run_summary["disclosure"] = _record([LOOKUP], [])
    section = _section_11(report)
    assert LIST_LABEL in section and LEFT_THE_MACHINE_RECORD in section
