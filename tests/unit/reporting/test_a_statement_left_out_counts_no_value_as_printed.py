"""A statement the agreement round left out whole counts none of its values as printed.

The appendix prints an analyst's statement only where it names a value printed nowhere else.
A statement every sentence of which the round left out prints nothing, so its values stay
unprinted and a later statement naming one of them is printed. The judge's sentences section
7 keeps beside a composed conclusion keep their order once one is left out (T-613). Every
address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.reporting.models import MalwareReport, TechnicalSubsection
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.section_agreement import apply_rows, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

_AGAIN = "static: Routine 0x5a10 compares HOST_MODE once more [ev_0102]."


def _drop(report: MalwareReport, pid: str, *sentences: str) -> MalwareReport:
    rows = [
        {
            "passage": pid,
            "sentence": sentence,
            "decision": "drop",
            "sources": ["string_resolution"],
            "reason": "Section 5 says otherwise.",
        }
        for sentence in sentences
    ]
    apply_rows({"sentences": rows}, passages_of(report))
    return report


def _appendix(report: MalwareReport) -> str:
    return MarkdownRenderer(layout=ANALYST).render(report).split("## Appendix", 1)[1]


def test_a_statement_left_out_whole_leaves_its_values_to_a_later_one() -> None:
    report = report_of()
    for cell in report.capability_matrix:
        if cell.technique_id == "T1057":
            cell.statements.append(_AGAIN)
    assert "compares HOST_MODE once more" not in _appendix(report)

    _drop(
        report,
        "statements.T1057.1",
        "Routine 0x5a10 reads the process list through Process32FirstW [ev_0101].",
        "It compares each name with HOST_MODE [ev_0102].",
    )

    appendix = _appendix(report)
    assert "Process32FirstW" not in appendix
    assert "Routine 0x5a10 compares HOST_MODE once more" in appendix


def test_the_judge_s_kept_sentences_keep_their_order_once_one_is_left_out() -> None:
    report = report_of()
    assert report.severity is not None
    report.severity.business_impact = (
        "It reaches 0x5c30 first. It writes 0x6d40 next. It ends at 0x7e50."
    )
    ta = report.technical_analysis
    assert ta is not None
    ta.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The file is a loader that checks for a debugger [ev_0103]."
    )
    _drop(report, "judge.business_impact", "It writes 0x6d40 next.")

    conclusion = MarkdownRenderer(layout=ANALYST).render(report).split("## 7. Conclusion", 1)[1]
    assert "It reaches 0x5c30 first. It ends at 0x7e50." in conclusion
    assert "0x6d40" not in conclusion.split("_In the evidence bundle")[0]
