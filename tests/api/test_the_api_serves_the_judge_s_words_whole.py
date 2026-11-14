"""The API serves the judge's words whole after the round leaves a sentence of them out.

The agreement round leaves a judge's sentence it listed out of the analyst report only; the
stored report, which ``/reports/{id}/full`` serves, keeps every judge text as written and names
the sentence left out beside it (T-613). Every value here is a neutral synthetic one.
"""

from __future__ import annotations

from app.services.report_service import with_current_iocs
from malspark.reporting.section_agreement import DROPPED_CODE, apply_rows, passages_of
from malspark.reporting.section_servers import with_source_servers
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    IMPACT,
    report_of,
)


def test_the_full_report_carries_the_judge_s_text_whole() -> None:
    report = report_of()
    row = {
        "passage": "judge.business_impact",
        "sentence": "It reaches 0x5c30 first.",
        "decision": "drop",
        "sources": ["string_resolution"],
        "reason": "No source states it.",
    }
    apply_rows({"sentences": [row]}, passages_of(report))

    served, _note = with_current_iocs(
        with_source_servers(report.model_dump(mode="json")), "a-report-id"
    )

    assert served["severity"]["business_impact"] == IMPACT
    assert {
        "sentence": "It reaches 0x5c30 first.",
        "code": DROPPED_CODE,
        "label": "judge.business_impact",
        "asked": True,
        "left_out": ["judge.business_impact"],
    } in served["flagged_statements"]
