"""A report section's own sentence is asked against the judge's decision.

A section 5 paragraph could assert a technique the judge dropped, with its reason in the
matrix, and nothing asked it against that: the round's sources for section 5 were the
platform's facts alone, and the judge's notes are passages printed in its own words, no
source. Now the judge's decision as the run recorded it (verdict and confidence band, family
or none, each technique published by id and name, each dropped with the judge's reason) is
shown as passages of their own, the source of a drop and of nothing else: a row naming one
in another form is refused, whatever else it names, and no sentence is read for what it
asserts. Which sentence states otherwise is the model's to say: code picks no sentence by a
name. A section 5 sentence answered on the decision is only left out, naming the judge passage
with a reason, and recorded under a code of its own. Nothing here changes the decision itself,
and the decision starts no question of its own (T-717). Every address, entry and name here is
a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.pipeline.validation import Violation
from malspark.reporting import section_agreement as agreement
from malspark.reporting.models import (
    CapabilityCell,
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
    TTPMapping,
)
from malspark.reporting.renderers.layout import ANALYST
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    HELD_UNLISTED_CODE,
    REWRITTEN_CODE,
    SYSTEM_PROMPT,
    UNKNOWN_PASSAGE_CODE,
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
)
from malspark.schemas.isr_models import is_judge_dropped, judge_dropped_reason

_REASON = "The loader resolves its imports by plain name at 0x4a10 [ev_0301], not by hash."
_INJECTION = "No write into another process is shown [ev_0303]."
NAMING = "Dynamic API resolution is the main import-hiding mechanism [ev_0301]."
WALK = "The loader walks a table of plain names at 0x4a10 [ev_0301]."
ASSESS = "We assess this as hiding its imports, serving evasion."
OTHER = "The routine at 0x4b20 formats a host name [ev_0302]."
DENIED = "Dynamic API resolution is not shown here [ev_0302]."
BODY = f"{NAMING} {WALK} {ASSESS}\n\n{OTHER}\n\n{DENIED}"
SECTION = "string_resolution"
CITABLE = ["ev_0301", "ev_0302", "ev_0303"]
DROPPED = "judge.technique.T1027.007"
CLOSING = "The routine formats a host name."


def report_of(
    body: str = BODY,
    *,
    verdict: str = "Benign",
    family: str | None = None,
    similar: str | None = None,
) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="cd" * 32), file_name="sample.bin"),
        verdict=verdict,  # type: ignore[arg-type]
        overall_confidence=0.6,
        attribution=FamilyAttribution(
            family=family,
            family_source="sandbox" if family else None,
            similar_samples=[{"family": similar}] if similar else [],
        ),
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1027.007",
                technique_name="Dynamic API Resolution",
                not_published=judge_dropped_reason(_REASON),
                evidence_ids=["ev_0301", "ev_0303"],
            ),
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published=judge_dropped_reason(_INJECTION),
                evidence_ids=["ev_0303"],
            ),
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1082",
                technique_name="System Information Discovery",
                evidence_ids=["ev_0302"],
            ),
        ],
        ttp_mappings=[
            TTPMapping(
                technique_id="T1082",
                technique_name="System Information Discovery",
                evidence_ids=["ev_0302"],
            )
        ],
    )
    report.technical_analysis = TechnicalAnalysis()
    report.technical_analysis.string_resolution = TechnicalSubsection(
        title="Strings", body=body, evidence_refs=["ev_0301", "ev_0302"]
    )
    return report


def _row(sentence: str, decision: str, **more: Any) -> dict[str, Any]:
    return {
        "passage": SECTION,
        "sentence": sentence,
        "sources": [DROPPED],
        "decision": decision,
        "rewrite": "",
        "reason": "",
        "quote": "",
        **more,
    }


def _refusals(report: MalwareReport, *rows: dict[str, Any]) -> list[Violation]:
    found = agreement_violations({"sentences": list(rows)}, passages_of(report), CITABLE)
    return [v for v in found if v.path.startswith("sentences.")]


def _body(report: MalwareReport) -> str:
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    return ta.string_resolution.body


def _decided(report: MalwareReport) -> tuple[Any, ...]:
    return (
        report.verdict,
        [m.model_dump() for m in report.ttp_mappings],
        [c.model_dump() for c in report.capability_matrix],
    )


def _closing(report: MalwareReport) -> TechnicalSubsection:
    ta = report.technical_analysis
    assert ta is not None
    ta.analyst_conclusion = TechnicalSubsection(title="Conclusion", body=CLOSING)
    return ta.analyst_conclusion


def _closing_row(rewrite: str, sources: list[str] | None = None) -> dict[str, Any]:
    return {
        **_row(CLOSING, "rewrite", rewrite=rewrite),
        "passage": "conclusion",
        "sources": sources or [DROPPED],
    }


def test_the_judge_s_decision_is_shown_as_passages_of_its_own() -> None:
    shown = {p.id: p for p in passages_of(report_of())}

    dropped = shown[DROPPED]
    assert dropped.kind == "judge" and dropped.write is None
    # A dropped technique rests on what the judge's reason cites, which its words show.
    assert dropped.cites == frozenset({"ev_0301"})
    assert dropped.text.startswith("T1027.007 Dynamic API Resolution: not published, ")
    assert _REASON in dropped.text
    published = shown["judge.technique.T1082"]
    assert published.text == "T1082 System Information Discovery: published"
    assert published.cites == frozenset()
    assert shown["judge.verdict"].text == "Benign, moderate confidence"
    assert shown["judge.family"].text == "no family named"
    assert shown["judge.family"].cites == frozenset()
    # A family the sandbox supplied where the judge abstained is no family of the judge's.
    sandbox = {p.id: p for p in passages_of(report_of(family="Quillfern"))}
    assert sandbox["judge.family"].text == "no family named"
    named = report_of(family="Quillfern")
    named.attribution.family_source = None
    assert {p.id: p for p in passages_of(named)}["judge.family"].text == '"Quillfern"'


def test_the_block_names_published_techniques_by_id_and_name_and_lists_no_cites() -> None:
    text = prompt_text(passages_of(report_of()))

    assert text.index("THE JUDGE'S DECISION") < text.index("SECTION 5, WRITTEN FROM THE CODE")
    block = text[text.index("THE JUDGE'S DECISION") : text.index("SECTION 5, WRITTEN")]
    assert (
        "- [judge.technique.T1082] a technique the judge published: T1082 System Information "
        "Discovery: published\n"
    ) in block
    assert f"- [{DROPPED}] a technique the judge dropped: T1027.007 Dynamic API" in block
    assert "(cites" not in block
    assert "- [judge.verdict] the judge's verdict: Benign, moderate confidence\n" in block


def test_no_sentence_is_picked_by_a_name_and_asked_about() -> None:
    report = report_of()
    passage = next(p for p in passages_of(report) if p.id == SECTION)
    text = prompt_text(passages_of(report))

    assert not {NAMING, WALK, ASSESS} & set(passage.held)
    assert "names a technique the judge dropped" not in text
    assert "held to the judge's decision" not in text
    # No row at all for them is asked for again, and none is left out for want of one.
    found = agreement_violations({"sentences": []}, passages_of(report), CITABLE)
    assert not [
        v
        for v in found
        if v.code == HELD_UNLISTED_CODE
        and any(repr(s) in v.message for s in (NAMING, WALK, ASSESS))
    ]
    other = _row(OTHER, "keep", sources=["judge.technique.T1082"])
    counts, records = apply_rows({"sentences": [other]}, passages_of(report), citable=CITABLE)
    assert counts["dropped"] == 0 and _body(report) == BODY
    assert not [v for v in records if v.code in agreement.LEFT_OUT_CODES]


def test_a_section_5_sentence_dropped_on_a_judge_passage_is_left_out_and_recorded() -> None:
    report = report_of()
    before = _decided(report)
    row = _row(ASSESS, "drop", reason="The judge reads the resolution as ordinary linking.")

    assert _refusals(report, row) == []
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert counts["dropped"] == 1
    assert ASSESS not in _body(report) and NAMING in _body(report)
    (left,) = [v for v in records if v.code == agreement.JUDGE_LEFT_OUT_CODE]
    assert left.stood == ASSESS and left.subject == SECTION
    assert DROPPED in left.message and "ordinary linking" in left.message
    assert left.code in agreement.LEFT_OUT_CODES and left.code != DROPPED_CODE
    assert _decided(report) == before


@pytest.mark.parametrize(
    "row",
    [
        _row(NAMING, "rewrite", rewrite="The loader resolves its imports by plain name [ev_0301]."),
        _row(
            OTHER,
            "rewrite",
            sources=["judge.technique.T1082"],
            rewrite="The routine at 0x4b20 collects system information for the operator [ev_0302].",
        ),
        _row(
            OTHER, "rewrite", sources=["judge.verdict"], rewrite="The routine is benign [ev_0302]."
        ),
        _row(NAMING, "keep", quote="Dynamic API Resolution: not published"),
    ],
)
def test_any_other_answer_on_a_judge_passage_leaves_a_section_5_sentence_standing(
    row: dict[str, Any],
) -> None:
    report = report_of()

    found = _refusals(report, row)
    assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
    assert 'which supports a drop alone: answer the sentence "decision": "drop"' in (
        found[0].message
    )
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert counts["rewritten"] == 0 and counts["dropped"] == 0
    assert _body(report) == BODY
    assert REWRITTEN_CODE not in [v.code for v in records]


def test_a_section_5_drop_naming_no_judge_passage_is_refused_as_before() -> None:
    report = report_of()
    row = _row(ASSESS, "drop", sources=[], reason="The judge reads the names as plain.")

    found = _refusals(report, row)
    assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
    assert "only a sentence of the conclusion" in found[0].message
    counts, _records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert counts["dropped"] == 0 and ASSESS in _body(report)


def test_a_section_5_source_refusal_names_the_judge_only_where_it_is_shown() -> None:
    on_a_claim = _row(ASSESS, "drop", sources=[DROPPED, "nowhere.1"], reason="No.")
    found = _refusals(report_of(), on_a_claim)
    assert [v.code for v in found] == [UNKNOWN_SOURCE_CODE]
    assert "; a sentence of it is left out on a passage of the judge's decision" in (
        found[0].message
    )

    bare = report_of()
    bare.capability_matrix = []
    bare.ttp_mappings = []
    bare.overall_confidence = None
    found = _refusals(bare, _row(OTHER, "rewrite", sources=["nowhere.1"], rewrite=OTHER))
    assert found and all("judge" not in v.message for v in found)


# A rewrite or a keep on a judge passage, of a passage written without the code and of a
# closing one: each refused, the sentence standing as written.
_SUMMARY_ABSENT = "The system information routine was not observed [ev_0302]."
_SUMMARY_VERDICT = "The file is malicious [ev_0302]."
_CONCLUSION_VERDICT = "The file is malicious."


def _summary_row(sentence: str, sources: list[str], decision: str, **more: str) -> dict[str, Any]:
    return {**_row(sentence, decision, **more), "passage": "executive_summary", "sources": sources}


@pytest.mark.parametrize(
    ("summary", "row"),
    [
        (
            _SUMMARY_ABSENT,
            _summary_row(
                _SUMMARY_ABSENT,
                ["judge.technique.T1082"],
                "rewrite",
                rewrite="The system information routine is published as observed [ev_0302].",
            ),
        ),
        (
            _SUMMARY_VERDICT,
            _summary_row(
                _SUMMARY_VERDICT,
                ["judge.verdict"],
                "rewrite",
                rewrite="The file is assessed benign [ev_0302].",
            ),
        ),
        (
            _SUMMARY_VERDICT,
            _summary_row(
                _SUMMARY_VERDICT, ["judge.verdict"], "keep", quote="Benign, moderate confidence"
            ),
        ),
    ],
)
def test_a_rewrite_or_a_keep_on_a_judge_passage_is_refused_and_the_summary_stands(
    summary: str, row: dict[str, Any]
) -> None:
    report = report_of(OTHER)
    report.executive_summary = summary

    found = [
        v
        for v in agreement_violations(
            {"sentences": [row]}, passages_of(report, narrative_written=True), CITABLE
        )
        if v.path.startswith("sentences.")
    ]
    assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
    assert "of the judge's decision, which supports a drop alone" in found[0].message
    counts, records = apply_rows(
        {"sentences": [row]}, passages_of(report, narrative_written=True), citable=CITABLE
    )
    assert counts["rewritten"] == 0 and counts["dropped"] == 0
    assert report.executive_summary == summary
    assert not [v for v in records if v.code in (REWRITTEN_CODE, *agreement.LEFT_OUT_CODES)]


@pytest.mark.parametrize(
    "row",
    [
        _closing_row("The file is benign.", ["judge.verdict"]),
        _closing_row("The file is benign [ev_0301].", [DROPPED, "judge.verdict"]),
        {**_closing_row(""), "decision": "keep", "quote": "Benign, moderate confidence"},
    ],
)
def test_a_closing_rewrite_or_keep_on_a_judge_passage_is_refused_and_the_sentence_stands(
    row: dict[str, Any],
) -> None:
    report = report_of(OTHER)
    conclusion = _closing(report)
    conclusion.body = _CONCLUSION_VERDICT
    row = {**row, "sentence": _CONCLUSION_VERDICT}

    found = _refusals(report, row)
    assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    # Refused, it is no source the closing sentence rests on: it stands as written.
    assert counts["dropped"] == 0 and counts["rewritten"] == 0
    assert conclusion.body == _CONCLUSION_VERDICT
    assert not [v for v in records if v.code in (REWRITTEN_CODE, *agreement.LEFT_OUT_CODES)]


def test_a_verdict_the_judge_never_gave_is_no_passage() -> None:
    report = report_of(similar="Quillfern")
    report.overall_confidence = None

    shown = {p.id for p in passages_of(report)}
    assert "judge.verdict" not in shown and "judge.family" not in shown
    assert DROPPED in shown


def test_no_sentence_is_read_for_what_it_asserts() -> None:
    import malspark.reporting.judge_decision as decided

    assert not hasattr(decided, "denied_in") and not hasattr(agreement, "judge_denied")
    assert not hasattr(agreement, "JUDGE_DENIED_CODE")


def test_the_round_s_texts_say_what_its_code_takes() -> None:
    text = prompt_text(passages_of(report_of()))

    assert 'a sentence so listed is only dropped, with "reason"' in text
    assert "It is a source of a drop alone, never of a keep or a rewrite" in text
    assert "rewritten in your own words" not in text
    assert "is dropped, naming the judge passage" in SYSTEM_PROMPT
    assert "left out on the judge's decision" in SYSTEM_PROMPT
    assert "or by the judge's decision, alone" not in SYSTEM_PROMPT
    assert "Leave out every sentence no source states otherwise than" not in SYSTEM_PROMPT
    assert "calls absent or not observed one it published" in SYSTEM_PROMPT


def test_a_matrix_row_the_judge_dropped_is_read_with_or_without_its_reason() -> None:
    assert is_judge_dropped(judge_dropped_reason("No write is shown."))
    assert is_judge_dropped(judge_dropped_reason(""))
    assert is_judge_dropped(f"{judge_dropped_reason('')}, asked after a finding")
    assert not is_judge_dropped("an id the ATT&CK catalogue has no entry for")


def test_a_sentence_left_out_on_the_judge_s_decision_is_counted_where_it_is_left_out() -> None:
    report = report_of(OTHER)
    _closing(report)
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": "agreement.judge_left_out", "message": "left out", "subject": "conclusion"}
            ]
        }
    }
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    conclusion = analyst.split("## 7. Conclusion", 1)[1].split("\n## ", 1)[0]
    assert "_1 sentence of this section was left out" in conclusion
