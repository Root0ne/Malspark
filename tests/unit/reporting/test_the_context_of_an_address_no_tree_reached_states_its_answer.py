"""The context cell of a sandbox address the publish rule places in no tree states its answer.

For such a row the cell is built by the one function that decides the publish
answer's reason (``stix_renderer.address_flow_reason``), from the same parts,
so the cell and the answer beside it never state different facts; each name a
sandbox wrote is written through the table's writer for a word. The MISP
attribute comment carries the cell, as data: the characters the record holds.
The cells of a row inside the sample's tree, outside it, and disputed are
written as before.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.pipeline.validation import (
    UNATTRIBUTED_INDICATOR_CODE,
    unattributed_indicator_violations,
)
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from malspark.reporting.renderers import stix_renderer
from malspark.reporting.renderers.stix_renderer import (
    FLOW_NOT_PLACED,
    address_flow_reason,
    publishes,
    sandbox_facts_for_the_judge,
)

SHA256 = "a" * 64
ADDRESS = "93.184.216.34"
# A process image holding every character Markdown or HTML reads.
IMAGE = "a`b`*c*_d_[x](y)<img src=z>|e\nf.exe (procid 49)"


def _report(ip: NetworkIP, *, kept: bool = False) -> MalwareReport:
    network = NetworkIOCs(ips=[ip])
    asked: list[dict[str, Any]] = []
    if kept:
        facts = sandbox_facts_for_the_judge(network, None, None, {"file_name": "s.exe"})
        bundle = SimpleNamespace(
            objects=[
                SimpleNamespace(
                    type="indicator", name="i", pattern=f"[ipv4-addr:value = '{ip.address}']"
                )
            ]
        )
        asked = [
            {
                "agent": "judge",
                "code": UNATTRIBUTED_INDICATOR_CODE,
                "message": "kept",
                "answered": "true",
                "subject": v.subject,
            }
            for v in unattributed_indicator_violations(bundle, facts)
        ]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network,
        judge_indicators=[JudgeIndicator(kind="ip", value=ip.address)] if kept else [],
        run_summary={"validation": {"unresolved": asked}} if kept else {},
    )


def _row(report: MalwareReport) -> Any:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == ADDRESS]
    return row


def _tree_less(**facts: Any) -> NetworkIP:
    return NetworkIP(address=ADDRESS, source="sandbox", sample_process_tree=None, **facts)


@pytest.mark.parametrize(
    "facts",
    [
        {"unlisted_processes": ["procid 49"]},
        {"unlisted_processes": ["procid 46", "procid 47"]},
        {"launcher_unsettled_processes": ["powershell.exe (procid 12)"]},
        {},
    ],
    ids=["unlisted", "two unlisted", "launcher unsettled", "no process named"],
)
def test_the_cell_of_a_tree_less_address_states_its_answer_s_reason(facts: Any) -> None:
    ip = _tree_less(**facts)
    row = _row(_report(ip))
    reason = address_flow_reason(ip)
    assert row.context == reason
    assert row.description == reason
    assert row.published.startswith(f"no: {reason}")


def test_the_cell_beside_an_answer_naming_an_unlisted_process_names_it() -> None:
    row = _row(_report(_tree_less(unlisted_processes=["procid 49"])))
    assert "procid 49" in row.context
    assert "does not say" not in row.context


def test_the_cell_follows_the_answer_s_reason_wherever_it_is_worded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    said = "the publish rule's reworded reason"
    monkeypatch.setattr(stix_renderer, "address_flow_reason", lambda row, word=str: said)
    row = _row(_report(_tree_less()))
    assert row.context == said
    assert said in row.published


def test_the_cell_beside_a_row_with_no_reading_says_the_decision() -> None:
    row = _row(_report(_tree_less()))
    assert row.context == FLOW_NOT_PLACED


def test_each_name_in_a_tree_less_cell_is_written_by_the_word_writer() -> None:
    ip = _tree_less(unlisted_processes=[IMAGE])
    report = _report(ip)

    def word(text: str) -> str:
        return f"<<{text}>>"

    (row,) = [r for r in build_consolidated_iocs(report, word=word) if r.value == ADDRESS]
    assert row.context == address_flow_reason(ip, word)
    assert f"<<{IMAGE}>>" in row.context
    assert row.context.replace(f"<<{IMAGE}>>", IMAGE) == address_flow_reason(ip)


def test_the_cells_inside_outside_and_disputed_are_written_as_before() -> None:
    def word(text: str) -> str:
        return f"<<{text}>>"

    cases = [
        (NetworkIP(address=ADDRESS, source="sandbox", sample_process_tree=True), None),
        (
            NetworkIP(
                address=ADDRESS,
                source="sandbox",
                sample_process_tree=False,
                outside_processes=["svchost.exe (procid 9)"],
            ),
            "reached by a process outside the sample's process tree (<<svchost.exe (procid 9)>>)",
        ),
        (
            _tree_less(
                marked_only_processes=["m.exe"],
                file_only_processes=["f.exe"],
                marked_by=" Sandbox ",
                unlisted_processes=["procid 49"],
            ),
            stix_renderer.disputed_flow_reason(["<<m.exe>>"], ["<<f.exe>>"], "<<Sandbox>>"),
        ),
    ]
    for ip, expected in cases:
        (row,) = [r for r in build_consolidated_iocs(_report(ip), word=word) if r.value == ADDRESS]
        if expected is None:
            assert row.context == "reached by the sample's process tree"
        else:
            assert row.context == expected


def test_a_published_tree_less_row_s_misp_comment_states_its_answer_s_fact() -> None:
    ip = _tree_less(unlisted_processes=[IMAGE])
    report = _report(ip, kept=True)
    row = _row(report)
    assert publishes(row.published)
    reason = address_flow_reason(ip)
    assert reason in row.published
    (attribute,) = [
        a
        for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="o")
        if a.get("value") == ADDRESS
    ]
    # MISP is data: the comment holds the record's characters, no escape added.
    assert attribute["comment"].split("; published because ")[0] == reason
    assert IMAGE in attribute["comment"]
    assert "\\" not in attribute["comment"]
