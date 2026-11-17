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
    # Who received it, how many times, and what it was asked: nothing else.
    assert re.search(
        r"Lookups: lookup(\.|\[\.\])example \(outside this machine\) was asked 4 times: "
        r"ip 1, hash 2, domain 1\.",
        row,
    )
    assert "answered without a run" not in row and "streamable-http" not in row


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
    assert "cannot be told" not in row and "stdio" not in row and "mcp:local" not in row
    assert row.startswith("- Lookups:") and row.endswith(LEFT_THE_MACHINE_RECORD)
    assert section.index(LIST_LABEL) < section.index(LEFT_THE_MACHINE_RECORD)


def test_no_disclosure_row_where_the_record_has_none() -> None:
    local = {**LOOKUP, "where": "local", "host": "127.0.0.1"}
    for record in (None, _record([], []), _record([local], [])):
        assert LEFT_THE_MACHINE_RECORD not in _section_11(_with(record))


MODEL = {
    "why": "",
    "host": "",
    "calls": 12,
    "where": "remote",
    "agents": {"judge": 5, "reporter": 7},
    "global": True,
    "runtime": "",
    "service": "a model service",
    "configured_for": [],
}
SERVER = {
    "why": "",
    "host": "tools.example",
    "calls": 9,
    "where": "remote",
    "served": 0,
    "source": "mcp:remote",
    "transport": "http",
}
RUNNING = {"asked": [], "state": "running", "may_reach": []}


def test_section_11_states_every_kind_the_record_places_outside() -> None:
    record = {
        **_record([LOOKUP], [SANDBOX, STAGED, {**STAGED, "calls": 2}]),
        "models": [MODEL],
        "servers": [SERVER],
        "enrichment": RUNNING,
        "tracing": True,
    }
    row = plain(_row(_section_11(_with(record))))
    # The model requests and the remote tool server, in the block's own words.
    assert "Model prompts: a model service (outside this machine) received 12 calls." in row
    # The calls per role stay in the bundle.
    assert "judge" not in row and "reporter" not in row
    assert re.search(
        r"Tool calls: tool server remote at tools(\.|\[\.\])example \(outside this machine\): "
        r"9 calls\.",
        row,
    )
    # A kind whose destination the record cannot tell: named, with its count.
    # Who received each upload is named, the tool server, though its place is not recorded.
    assert "Sample upload: tool server local was handed the sample 3 times, destination not " in row
    assert "Sample upload: tool server local was handed the sample 2 times, destination not " in row
    assert (
        "Enrichment questions about the report's indicators: count not recorded, destination "
        "not recorded." in row
    )
    assert "Tracing of every prompt and answer: count not recorded, destination not recorded." in (
        row
    )
    assert row.endswith(LEFT_THE_MACHINE_RECORD)


def test_hosts_a_kind_may_reach_are_named_as_such() -> None:
    reach = {
        "asked": [],
        "state": "running",
        "may_reach": [
            {"hosts": ["rdap.example"], "kinds": ["ip"], "where": "remote", "source": "rdap"},
            {"hosts": ["intel.example"], "kinds": ["ip"], "where": "remote", "source": "intel"},
        ],
    }
    row = plain(_row(_section_11(_with({**_record([], []), "enrichment": reach}))))
    assert re.search(
        r"Enrichment questions about the report's indicators: count not recorded, may reach "
        r"rdap(\.|\[\.\])example and intel(\.|\[\.\])example\.",
        row,
    )
    assert "destination not recorded" not in row


def test_the_row_stays_short() -> None:
    record = {
        **_record([LOOKUP], [SANDBOX, STAGED]),
        "models": [{**MODEL, "configured_for": ["mediator", "summarizer"]}],
    }
    row = _row(_section_11(_with(record)))
    assert "model list" not in row and "mediator" not in row
    assert len(row) < 500


def test_a_record_stated_as_partial_says_so_in_the_row() -> None:
    record = {**_record([LOOKUP], []), "partial_reason": "the run was stopped part-way"}
    row = plain(_row(_section_11(_with(record))))
    assert row.startswith("- This record may be incomplete: the run was stopped part-way")


def test_section_11_disclosure_words_match_the_bundle_block() -> None:
    report = _with(_record([LOOKUP], [SANDBOX, STAGED]))
    row = _row(_section_11(report))[2:].removesuffix(LEFT_THE_MACHINE_RECORD).strip()
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    block = [line[2:] for line in bundle.splitlines() if line.startswith("- ")]
    lookup, upload, untold = re.split(r"(?<=\.) (?=Sample uploads?:)", row)
    # The short form of each writer: the block's line opens with the same words.
    head = lookup.split(": ip ")[0]
    assert any(line.startswith(head) and line != lookup for line in block)
    assert untold == (
        "Sample upload: tool server `local` was handed the sample 3 times, destination not "
        "recorded."
    )
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


def test_a_technique_row_with_no_evidence_prints_no_evidence_bracket() -> None:
    from malspark.reporting.models import CapabilityCell

    report = _report(_ledger())
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1055",
            technique_name="Process Injection",
            not_published="the judge dropped it",
        )
    ]
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    (line,) = [line for line in analyst.splitlines() if line.startswith("- T1055")]
    assert "evidence" not in line


def _left(record: dict[str, Any]) -> str:
    return plain(_row(_section_11(_with({**_record([], []), **record}))))


NO_CALL = "no answered call recorded, so whether it received anything cannot be told"


def test_a_kind_placed_outside_with_no_recorded_call_is_stated() -> None:
    model = {**MODEL, "calls": 0, "agents": {}}
    row = _left({"models": [model], "partial_reason": "the run was stopped part-way"})
    assert f"Model prompts: a model service (outside this machine): {NO_CALL}." in row
    row = _left({"servers": [{**SERVER, "calls": 0}]})
    assert re.search(r"Tool calls: tool server remote at tools(\.|\[\.\])example \(outside", row)
    assert NO_CALL in row
    row = _left({"lookups": [{**LOOKUP, "calls": 0, "served": 0}]})
    assert re.search(r"Lookups: lookup(\.|\[\.\])example \(outside this machine\): no answ", row)
    row = _left({"uploads": [{**SANDBOX, "calls": 0}]})
    assert re.search(r"Sample upload: the detonator sandbox at sandbox(\.|\[\.\])example", row)
    assert NO_CALL in row


def test_a_model_row_naming_no_receiver_prints_no_calls_per_role() -> None:
    model = {**MODEL, "service": "", "where": "unknown", "why": "the ledger filed them"}
    row = _left({"models": [model]})
    assert "Model prompts: 12 calls, destination not recorded." in row
    assert "judge" not in row and "reporter" not in row


def test_each_short_form_names_its_receiver() -> None:
    store = {"why": "", "host": "store.example", "where": "remote", "backend": "vectors"}
    row = _left({"stores": [store]})
    assert re.search(
        r"Case memory: the vectors case-memory store at store(\.|\[\.\])example "
        r"\(outside this machine\)\.",
        row,
    )
    staged = {**STAGED, "by": "staging", "host": "files.example", "where": "remote", "why": ""}
    row = _left({"uploads": [staged]})
    assert re.search(
        r"Sample upload: the sample was staged 3 times to tool server local at "
        r"files(\.|\[\.\])example \(outside this machine\)\.",
        row,
    )
    handed = {**STAGED, "host": "tools.example", "where": "remote", "why": ""}
    row = _left({"uploads": [handed]})
    assert re.search(
        r"Sample upload: tool server local at tools(\.|\[\.\])example \(outside this "
        r"machine\) was handed the sample 3 times\.",
        row,
    )
    # A receiver whose host the record names but does not place.
    placed_not = {**STAGED, "host": "tools.example"}
    row = _left({"uploads": [placed_not]})
    assert re.search(
        r"Sample upload: tool server local at tools(\.|\[\.\])example was handed the sample "
        r"3 times, where it runs is not recorded\.",
        row,
    )


def test_a_sandbox_submission_that_may_not_have_arrived_says_so_in_its_short_form() -> None:
    row = _left({"uploads": [{**SANDBOX, "calls": 2, "failed": 1}]})
    assert re.search(
        r"Sample upload: the sample was submitted 2 times to the detonator sandbox at "
        r"sandbox(\.|\[\.\])example \(outside this machine\); 1 of the attempts failed or did "
        r"not finish, so whether it arrived cannot be told\.",
        row,
    )


def test_a_technique_row_citing_no_ledger_entry_prints_no_evidence_bracket() -> None:
    from malspark.reporting.models import CapabilityCell

    report = _report(_ledger())
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id="T1055",
            technique_name="Process Injection",
            not_published="the judge dropped it",
            evidence_ids=[],
        )
    ]
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    (line,) = [line for line in analyst.splitlines() if line.startswith("- T1055")]
    assert "evidence" not in line
