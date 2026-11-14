"""The agreement round never rewrites the judge: its words stand as written.

The judge's texts the analyst report prints (its severity rationale and conclusion in section
7, its note on a published technique, its reason for one not published) are shown to the round
like any passage, and a listed one is kept on a quote that passes or left out of the analyst
report. No answer of the round has a way to reword them, and the verdict itself, the
classification, the confidence, the rating and the decided techniques, is never touched: the
report's fields and the bundle keep the judge's words whole (T-613). Every address, entry and
name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import BUNDLE
from malspark.reporting.section_agreement import apply_rows, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    IMPACT,
    NOTE_WORDS,
    REASON,
    REASON_WORDS,
    report_of,
)

_JUDGE = ("judge.business_impact", "attack_note.T1622", "attack_note.T1055")


def _verdict(report: MalwareReport) -> dict[str, Any]:
    """What the judge decided, as the report stores it."""
    return {
        "verdict": report.verdict,
        "category": report.malware_category,
        "confidence": report.overall_confidence,
        "severity": report.severity.model_dump() if report.severity else None,
        "techniques": [cell.model_dump() for cell in report.capability_matrix],
        "mappings": [m.model_dump() for m in report.ttp_mappings],
    }


def test_no_answer_rewrites_a_judge_text_or_touches_the_verdict() -> None:
    report = report_of()
    before = _verdict(report)
    passages = {p.id: p for p in passages_of(report)}
    assert all(passages[pid].write is None for pid in _JUDGE)
    assert all(passages[pid].verbatim.startswith("the judge's") for pid in _JUDGE)

    rows = [
        {
            "passage": "judge.business_impact",
            "sentence": "It reaches 0x5c30 first.",
            "decision": "rewrite",
            "sources": ["string_resolution"],
            "rewrite": "It reaches 0x5b20 first [ev_0103].",
        },
        {
            "passage": "attack_note.T1622",
            "sentence": NOTE_WORDS,
            "decision": "drop",
            "sources": ["string_resolution"],
            "reason": "No.",
        },
        {
            "passage": "attack_note.T1055",
            "sentence": REASON_WORDS,
            "decision": "rewrite",
            "sources": ["string_resolution"],
            "rewrite": "The judge kept it [ev_0104].",
        },
    ]
    counts, _found = apply_rows({"sentences": rows}, list(passages.values()))

    assert counts["rewritten"] == 0 and counts["dropped"] == 3
    assert _verdict(report) == before
    assert report.severity is not None and report.severity.business_impact == IMPACT


def test_the_bundle_and_the_stored_report_keep_the_judge_s_words_whole() -> None:
    report = report_of()
    rows = [
        {
            "passage": "judge.business_impact",
            "sentence": "It reaches 0x5c30 first.",
            "decision": "drop",
            "sources": ["string_resolution"],
            "reason": "No.",
        },
        {
            "passage": "attack_note.T1055",
            "sentence": REASON_WORDS,
            "decision": "drop",
            "sources": ["string_resolution"],
            "reason": "No.",
        },
    ]
    apply_rows({"sentences": rows}, passages_of(report))
    stored = MalwareReport.model_validate(report.model_dump(mode="json"))
    bundle = MarkdownRenderer(layout=BUNDLE).render(stored)

    assert stored.severity is not None and stored.severity.business_impact == IMPACT
    assert {c.technique_id: c.not_published for c in stored.capability_matrix}["T1055"] == REASON
    assert "It reaches 0x5c30 first." in bundle
    assert "No write into another process is shown" in bundle
