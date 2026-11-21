"""The analyst report's sentence on the evidence bundle says what the bundle and its index hold.

The bundle lists every tool call in its evidence index, with the parts of the
answers the report reads; it holds no answer whole. Where no row of the index
is marked trimmed, the sentence says the evidence endpoint serves each answer
whole; where some are, it says the endpoint serves each answer as the ledger
holds it and counts the rows the index marks trimmed (T-780).
"""

from __future__ import annotations

from malspark.reporting.models import EvidenceIndexRow, FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST


def _sentence(*trimmed: bool) -> str:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        verdict="Malware",
        evidence_index=[
            EvidenceIndexRow(id=f"ev_{n:04d}", tool="t", truncated=cut)
            for n, cut in enumerate(trimmed, 1)
        ],
    )
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    return next(ln for ln in analyst.splitlines() if ln.startswith("What this report does not"))


def test_the_bundle_is_not_said_to_hold_every_output() -> None:
    said = _sentence(False, True)

    assert "with its output" not in said
    assert "every tool call in its index with the parts of the answers the report reads" in said


def test_an_index_with_no_trimmed_row_says_each_answer_is_served_whole() -> None:
    assert "The evidence endpoint serves each answer whole." in _sentence(False, False)


def test_an_index_with_trimmed_rows_counts_them_and_claims_no_whole_answer() -> None:
    one = _sentence(False, True)
    two = _sentence(True, False, True)

    for said in (one, two):
        assert "whole" not in said
    assert (
        "The evidence endpoint serves each answer as the ledger holds it; the index marks 1 of "
        "them trimmed."
    ) in one
    assert "the index marks 2 of them trimmed." in two
