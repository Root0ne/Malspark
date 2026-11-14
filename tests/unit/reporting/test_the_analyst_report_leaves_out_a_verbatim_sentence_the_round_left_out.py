"""The analyst report leaves out a sentence printed as written that the round left out.

Where the agreement round leaves out a sentence of a text printed in its writer's own words,
the analyst report, in Markdown and in HTML, prints the text without that sentence where it
would have printed and counts it where it already counts what it leaves out: the appendix's
own line for a statement, the section's line elsewhere. The bundle prints the text whole, and
the round's record names the passage. Every other text prints as written (T-613). Every
address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import AGREEMENT_PRODUCER, apply_rows, passages_of
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    IMPACT,
    NOTE_WORDS,
    REASON_WORDS,
    STATEMENT,
    report_of,
)


def _dropped(pid: str, sentence: str) -> MalwareReport:
    """The report after a round that dropped ``sentence`` of ``pid``, its record stored."""
    report = report_of()
    row = {
        "passage": pid,
        "sentence": sentence,
        "decision": "drop",
        "sources": ["string_resolution"],
        "reason": "Not so.",
    }
    _counts, found = apply_rows({"sentences": [row]}, passages_of(report))
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, found)
    report.run_summary = {
        **(report.run_summary or {}),
        "validation": {"unresolved": tally.unresolved},
    }
    return report


def _section(markdown: str, heading: str) -> str:
    return markdown.split(heading, 1)[1].split("\n## ", 1)[0]


def _printed(report: MalwareReport) -> tuple[str, str, str]:
    return (
        MarkdownRenderer(layout=ANALYST).render(report),
        HtmlRenderer(layout=ANALYST).render(report),
        MarkdownRenderer(layout=BUNDLE).render(report),
    )


def _bundle_keeps(bundle: str, pid: str, *texts: str) -> None:
    for text in texts:
        assert text in bundle
    assert f"({pid}) out of the analyst report, which the bundle prints whole" in bundle


def test_an_appendix_statement_prints_without_it_and_the_appendix_counts_it() -> None:
    before = _section(MarkdownRenderer(layout=ANALYST).render(report_of()), "## Appendix")
    assert "It compares each name with HOST_MODE" in before
    assert "Every statement is in the bundle." in before

    markdown, html, bundle = _printed(
        _dropped("statements.T1057.1", "It compares each name with HOST_MODE [ev_0102].")
    )
    appendix = _section(markdown, "## Appendix")

    assert "Routine 0x5a10 reads the process list through Process32FirstW" in appendix
    assert "HOST_MODE" not in appendix and "HOST_MODE" not in html
    assert "1 sentence of them was left out; the bundle prints every statement whole." in appendix
    _bundle_keeps(bundle, "statements.T1057.1", "It compares each name with HOST_MODE")
    assert STATEMENT.split(": ", 1)[1].split(" [ev_0101]")[0] in bundle


def test_a_claim_sentence_left_out_prints_a_dash_and_the_section_counts_it() -> None:
    sentence = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
    markdown, html, bundle = _printed(_dropped("attack_claim.T1622", sentence))
    attack = _section(markdown, "## 10. MITRE ATT&CK mapping")

    assert sentence not in attack and sentence not in html
    assert "| Defense Evasion | T1622 | Debugger Evasion | - _(" in attack
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        attack
    )
    _bundle_keeps(bundle, "attack_claim.T1622", "returns -1 when the BeingDebugged byte is set")


def test_a_judge_note_left_out_is_not_printed_and_is_counted() -> None:
    markdown, html, bundle = _printed(_dropped("attack_note.T1622", NOTE_WORDS))
    attack = _section(markdown, "## 10. MITRE ATT&CK mapping")

    assert "The judge read only the flag check" not in attack
    assert "The judge read only the flag check" not in html
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        attack
    )
    _bundle_keeps(bundle, "attack_note.T1622", "The judge read only the flag check")


def test_a_reason_left_out_leaves_the_technique_claimed_and_not_published() -> None:
    markdown, html, bundle = _printed(_dropped("attack_note.T1055", REASON_WORDS))
    attack = _section(markdown, "## 10. MITRE ATT&CK mapping")

    assert (
        "- T1055 Process Injection: claimed, not published: the judge dropped it; evidence -"
        in attack
    )
    assert "No write into another process" not in attack
    assert "No write into another process" not in html
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        attack
    )
    _bundle_keeps(bundle, "attack_note.T1055", "No write into another process is shown")


def test_a_judge_sentence_of_section_7_left_out_is_not_printed_and_is_counted() -> None:
    markdown, html, bundle = _printed(_dropped("judge.business_impact", "It reaches 0x5c30 first."))
    conclusion = _section(markdown, "## 7. Conclusion")

    assert "The loader checks for a debugger at 0x5b20" in conclusion
    assert "0x5c30" not in conclusion and "0x5c30" not in html
    assert "_1 sentence of this section was left out; the bundle lists each with the reason._" in (
        conclusion
    )
    _bundle_keeps(bundle, "judge.business_impact", IMPACT.split(" [ev_0103]")[0], "0x5c30 first")


def test_a_round_that_lists_none_prints_every_text_as_written() -> None:
    report = report_of()
    before = _printed(report)
    apply_rows({"sentences": []}, passages_of(report))

    after = _printed(report)
    assert report.flagged_statements == []
    assert after[0] == before[0] and after[2] == before[2]
