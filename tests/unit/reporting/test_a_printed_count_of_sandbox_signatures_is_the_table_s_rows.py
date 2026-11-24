"""A count of the sandbox's signatures a report prints is the rows its signature table prints.

The reason a report gives for having no Sigma draft says how many signatures the sandbox
recorded; it counted the distinct description texts a draft's description lists, so two
signatures sharing one description were counted once. Now every printed count of them
(that reason and the line saying what the held sandbox report lists) is the length of one
list, ``dedupe.printed_signatures``: the rows the signature table prints, told apart by
what a row prints. The draft's description keeps its own list of texts (T-882).
"""

from __future__ import annotations

import re

from malspark.reporting import detection_signatures as ds
from malspark.reporting.dedupe import printed_signatures
from malspark.reporting.models import (
    DynamicBehavior,
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    SandboxSignature,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.markdown import _sandbox_held

# Synthetic signatures; no stored run holds these words.
SHARED = "The probe service keeps quarterly ledgers of its own."
SIGNATURES = [
    SandboxSignature(name="Touches probe ledger provider", description=SHARED, severity=3),
    SandboxSignature(name="Touches probe ledger interface", description=SHARED, severity=3),
    SandboxSignature(name="Writes a probe marker", description="Writes a marker.", severity=2),
    # The same row again in another process: the table prints it once.
    SandboxSignature(
        name="Writes a probe marker", description="Writes a marker.", severity=2, pids=["4711"]
    ),
]


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="9" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.8,
        # A grounded family: the Sigma gate stands aside and the reason is written.
        attribution=FamilyAttribution(family="Probelock", family_grounded=True),
        dynamic=DynamicBehavior(sandbox_signatures=SIGNATURES),
    )


def _table_rows(markdown: str) -> int:
    lines = markdown.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().endswith("Sandbox signatures"))
    rows = 0
    for line in lines[start + 4 :]:
        if not line.startswith("|"):
            break
        rows += 1
    return rows


def test_the_table_prints_each_signature_once_by_what_its_row_prints() -> None:
    assert [s.name for s in printed_signatures(SIGNATURES)] == [
        "Touches probe ledger provider",
        "Touches probe ledger interface",
        "Writes a probe marker",
    ]


def test_the_absent_sigma_reason_counts_the_rows_the_table_prints() -> None:
    report = _report()

    (item,) = ds.drafts_not_built(report, [])

    assert "the 3 signatures the sandbox recorded are its reading" in item.why
    assert _table_rows(MarkdownRenderer().render(report)) == 3


def test_the_held_sandbox_report_s_line_counts_the_same_rows() -> None:
    (line,) = [said for said in _sandbox_held(_report()) if "signature" in said]

    assert re.search(r"\b3 signatures\b", line)


def test_the_draft_s_description_keeps_its_own_list_of_texts() -> None:
    assert ds._collect_signature_names(_report()) == [SHARED, "Writes a marker."]
