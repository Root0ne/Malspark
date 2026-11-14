"""The agreement round is shown every text the analyst report prints in its writer's words.

The analyst report prints some texts as an analyst or the judge wrote them: the appendix's
statements, the ATT&CK table's claim sentence where no procedure was written, the judge's
note on a published row and its reason for one not published, and the judge's sentences in
section 7. Each is a passage of the round, carrying who wrote it (``Passage.verbatim``) and
never a way to be rewritten; the question marks it once and says its ends once (T-613).
Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    SeverityAssessment,
    StaticAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.section_agreement import (
    CLAIM_LED,
    _writable,
    passages_of,
    prompt_text,
)

STATEMENT = (
    "static: Routine 0x5a10 reads the process list through Process32FirstW [ev_0101]. "
    "It compares each name with HOST_MODE [ev_0102]."
)
CLAIM = "Routine 0x5b20 returns -1 when the BeingDebugged byte is set [ev_0103]. It then exits."
# The judge's words, and the note and the reason the platform writes around them.
NOTE_WORDS = "The judge read only the flag check [ev_0103]."
NOTE = (
    "carried forward: the round-2 revision neither wrote it again nor withdrew it; kept by "
    f"the judge when asked ({NOTE_WORDS})"
)
REASON_WORDS = "No write into another process is shown [ev_0104]."
REASON = f"the judge dropped it ({REASON_WORDS})"
IMPACT = "The loader checks for a debugger at 0x5b20 [ev_0103]. It reaches 0x5c30 first."
# The section 5 passage the round reads every other passage against.
BODY = "Routine 0x5b20 reads the BeingDebugged byte and returns -1 when it is set [ev_0103]."


def report_of() -> MalwareReport:
    """A report printing one text of each kind in its writer's words, beside one section 5
    passage and a limitations paragraph the round asks of."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        static=StaticAnalysis(
            api_technique_hits=[
                {
                    "technique_id": "T1057",
                    "matched_apis": ["Process32FirstW"],
                    "resolved_apis": ["Process32FirstW"],
                }
            ]
        ),
        capability_matrix=[
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1057",
                technique_name="Process Discovery",
                statements=[STATEMENT],
                evidence=["Routine 0x5a10 lists processes [ev_0101]."],
            ),
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1622",
                technique_name="Debugger Evasion",
                evidence=[CLAIM],
                note=NOTE,
            ),
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published=REASON,
            ),
        ],
        severity=SeverityAssessment(rating="High", business_impact=IMPACT),
        run_summary={"profile": {"analysts": ["static", "dynamic"]}},
    )
    ta = report.technical_analysis
    if ta is None:
        from malspark.reporting.models import TechnicalAnalysis

        ta = report.technical_analysis = TechnicalAnalysis()
    ta.string_resolution = TechnicalSubsection(
        title="Strings", body=BODY, evidence_refs=["ev_0103"]
    )
    ta.analyst_limitations = TechnicalSubsection(
        title="Limitations", body="The second stage was not observed [ev_0105]."
    )
    return report


def _verbatim(report: MalwareReport) -> dict[str, object]:
    return {p.id: p for p in passages_of(report) if p.verbatim and not p.source_only}


def test_each_text_printed_as_written_is_a_passage_carrying_its_writer() -> None:
    shown = _verbatim(report_of())

    # In the order the analyst report prints them: section 7, the ATT&CK table (its
    # techniques not published after the rows, by the table's own order), the appendix.
    assert list(shown) == [
        "judge.business_impact",
        "attack_note.T1055",
        "attack_claim.T1622",
        "attack_note.T1622",
        "attack_claim.T1057",
        "statements.T1057.1",
    ]
    statement = shown["statements.T1057.1"]
    assert statement.text == (  # type: ignore[attr-defined]
        "Routine 0x5a10 reads the process list through Process32FirstW [ev_0101]. "
        "It compares each name with HOST_MODE [ev_0102]."
    )
    assert statement.cites == frozenset({"ev_0101", "ev_0102"})  # type: ignore[attr-defined]
    assert shown["attack_claim.T1622"].text == (  # type: ignore[attr-defined]
        "Routine 0x5b20 returns -1 when the BeingDebugged byte is set."
    )
    assert shown["attack_claim.T1622"].cites == frozenset({"ev_0103"})  # type: ignore[attr-defined]
    assert shown["attack_note.T1622"].text == NOTE_WORDS  # type: ignore[attr-defined]
    assert shown["attack_note.T1055"].text == REASON_WORDS  # type: ignore[attr-defined]
    assert shown["judge.business_impact"].text == IMPACT  # type: ignore[attr-defined]
    writers = {pid: p.verbatim for pid, p in shown.items()}  # type: ignore[attr-defined]
    assert writers == {
        "judge.business_impact": "the judge's own words, printed as written",
        "attack_note.T1055": "the judge's own words, printed as written",
        "attack_claim.T1622": "an analyst's own words, printed as written",
        "attack_note.T1622": "the judge's own words, printed as written",
        "attack_claim.T1057": "an analyst's own words, printed as written",
        "statements.T1057.1": "an analyst's own words, printed as written",
    }


def test_a_text_printed_as_written_is_never_one_to_rewrite() -> None:
    for passage in _verbatim(report_of()).values():
        assert passage.kind == CLAIM_LED  # type: ignore[attr-defined]
        assert passage.write is None  # type: ignore[attr-defined]
        assert not _writable(passage)  # type: ignore[arg-type]
        assert passage.held == ()  # type: ignore[attr-defined]
        assert not passage.closing  # type: ignore[attr-defined]


def test_they_come_after_every_other_passage_and_add_no_fact() -> None:
    report = report_of()
    passages = passages_of(report)
    ids = [p.id for p in passages]
    first = ids.index("judge.business_impact")
    assert all(p.verbatim for p in passages[first:])
    assert not any(p.verbatim for p in passages[:first])


def test_the_question_marks_each_and_says_its_ends_once() -> None:
    text = prompt_text(passages_of(report_of()))

    assert (
        "- [statements.T1057.1] Appendix, an analyst's statement on T1057 (verbatim) "
        "(cites ev_0101, ev_0102): "
    ) in text
    assert "- [judge.business_impact] 7. Conclusion, the judge's severity rationale (verbatim)" in (
        text
    )
    assert text.count("A passage marked (verbatim) prints") == 1
    assert (
        "A passage marked (verbatim) prints an analyst's or the judge's own words: list a "
        "sentence of it only where a source states otherwise; where it and a passage you may "
        "rewrite disagree, list and mend that passage. Never rewrite a verbatim sentence: keep "
        'it naming the source you read and found agreeing, with "quote": its words that state '
        'the same thing, copied exactly, or drop it naming in "sources" the source it '
        "contradicts (a fact, a section 5 passage, a debate round or a passage marked "
        '(verbatim, a source only)), with "reason". A keep no check passes, or a refused '
        "drop naming such a source, leaves it out of the analyst report, which the bundle "
        "prints whole; a drop naming no such source is recorded as asked about and left "
        "standing."
    ) in text
    assert "(read only)" not in text


def test_a_composed_conclusion_shows_only_the_judge_sentences_section_7_keeps() -> None:
    report = report_of()
    ta = report.technical_analysis
    assert ta is not None
    ta.analyst_conclusion = TechnicalSubsection(
        title="Conclusion", body="The file is a loader that checks for a debugger [ev_0103]."
    )
    shown = _verbatim(report)

    # 0x5c30 is printed nowhere else: the judge's sentence naming it stays, the one whose
    # values the report prints elsewhere does not.
    assert shown["judge.business_impact"].text == "It reaches 0x5c30 first."  # type: ignore[attr-defined]


def test_a_report_printing_none_shows_none_and_says_nothing_of_them() -> None:
    report = report_of()
    report.capability_matrix = []
    report.severity = None
    report.static = None

    assert not _verbatim(report)
    assert "(verbatim)" not in prompt_text(passages_of(report))
