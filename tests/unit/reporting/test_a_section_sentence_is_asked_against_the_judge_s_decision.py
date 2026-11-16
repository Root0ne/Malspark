"""A report section's own sentence is asked against the judge's decision.

A section 5 paragraph could assert a technique the judge dropped, with its reason in the
matrix, and nothing asked it against that: the round's sources for section 5 were the
platform's facts alone, and the judge's notes are passages printed in its own words, no
source. Now the judge's decision as the run recorded it (verdict and confidence, family or
none, each technique published and each dropped with the judge's reason) is shown as
passages of their own, a source of every passage the round may rewrite; code holds each
sentence writing, with no negation in its clause, a dropped technique's id or catalogue name,
another verdict word or another family, and every sentence of its paragraph; the model
answers each: a rewrite cites an entry the judge's passage cites, a keep quotes a source, a
drop gives its reason, and a sentence no answer passes for is left out. Nothing here changes
the decision itself (T-717). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

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
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    HELD_UNLISTED_CODE,
    JUDGE_HELD_KEPT_CODE,
    KEEP_UNQUOTED_CODE,
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    SYSTEM_PROMPT,
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    prompt_text,
)
from malspark.schemas.isr_models import judge_dropped_reason

_REASON = "The loader resolves its imports by plain name at 0x4a10 [ev_0301], not by hash."
NAMING = "Dynamic API resolution is the main import-hiding mechanism [ev_0301]."
WALK = "The loader walks a table of plain names at 0x4a10 [ev_0301]."
ASSESS = "We assess this as hiding its imports, serving evasion."
OTHER = "The routine at 0x4b20 formats a host name [ev_0302]."
DENIED = "Dynamic API resolution is not shown here [ev_0302]."
BODY = f"{NAMING} {WALK} {ASSESS}\n\n{OTHER}\n\n{DENIED}"
SECTION = "string_resolution"
CITABLE = ["ev_0301", "ev_0302"]
DROPPED = "judge.technique.T1027.007"


def report_of(
    body: str = BODY, *, verdict: str = "Benign", family: str | None = None
) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="cd" * 32), file_name="sample.bin"),
        verdict=verdict,  # type: ignore[arg-type]
        overall_confidence=0.6,
        attribution=FamilyAttribution(family=family, family_source="sandbox" if family else None),
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1027.007",
                technique_name="Dynamic API Resolution",
                not_published=judge_dropped_reason(_REASON),
                evidence_ids=["ev_0301"],
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


def _refusals(report: MalwareReport, *rows: dict[str, Any]) -> list[Any]:
    found = agreement_violations({"sentences": list(rows)}, passages_of(report), CITABLE)
    return [v for v in found if v.path.startswith("sentences.")]


def test_the_judge_s_decision_is_shown_as_passages_of_its_own() -> None:
    shown = {p.id: p for p in passages_of(report_of())}

    dropped = shown[DROPPED]
    assert dropped.kind == "judge" and dropped.write is None
    assert dropped.cites == frozenset({"ev_0301"})
    assert dropped.text.startswith("T1027.007 Dynamic API Resolution: not published, ")
    assert _REASON in dropped.text
    assert shown["judge.technique.T1082"].text == "T1082 System Information Discovery: published"
    assert shown["judge.verdict"].text == "Benign, overall confidence 0.60 (moderate confidence)"
    assert shown["judge.family"].text == "no family named"


def test_a_naming_sentence_and_its_paragraph_are_held() -> None:
    passage = next(p for p in passages_of(report_of()) if p.id == SECTION)

    assert dict(passage.judged) == {NAMING: (DROPPED,), WALK: (DROPPED,), ASSESS: (DROPPED,)}
    assert {NAMING, WALK, ASSESS} <= set(passage.held)
    # Another paragraph, and a negated naming, are not held to the decision.
    assert OTHER not in dict(passage.judged)
    assert DENIED not in dict(passage.judged)


def test_the_question_shows_the_decision_after_the_facts_and_names_the_held_sentences() -> None:
    text = prompt_text(passages_of(report_of()))

    assert "THE JUDGE'S DECISION" in text
    assert text.index("THE JUDGE'S DECISION") < text.index("SECTION 5, WRITTEN FROM THE CODE")
    assert f"- [{DROPPED}] a technique the judge dropped (cites ev_0301): T1027.007" in text
    assert f'"{NAMING}" ({DROPPED})' in text
    assert "It is a source of every passage you may rewrite, section 5 included" in text
    assert "or by the judge's decision, alone" in SYSTEM_PROMPT


def test_a_rewrite_on_the_judge_s_passage_passes_and_takes_its_place() -> None:
    report = report_of()
    rewrite = "The loader resolves its imports by plain name, not to evade [ev_0301]."
    row = _row(NAMING, "rewrite", rewrite=rewrite)

    assert _refusals(report, row) == []
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert counts["rewritten"] == 1
    assert REWRITTEN_CODE in [v.code for v in records]
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert rewrite in ta.string_resolution.body and NAMING not in ta.string_resolution.body


def test_a_rewrite_citing_no_entry_of_the_judge_s_passage_is_refused() -> None:
    sources = [DROPPED, "judge.technique.T1082"]
    on_it = _row(ASSESS, "rewrite", sources=sources, rewrite="The names are plain [ev_0301].")
    assert _refusals(report_of(), on_it) == []

    beside = _row(ASSESS, "rewrite", sources=sources, rewrite="The names are plain [ev_0302].")
    found = _refusals(report_of(), beside)
    assert [v.code for v in found] == [REWRITE_UNGROUNDED_CODE]
    assert "cite one of ev_0301" in found[0].message


def test_a_keep_needs_its_quote() -> None:
    report = report_of()
    no_source = _row(NAMING, "keep", sources=[], reason="It is right.")
    no_quote = _row(NAMING, "keep")
    far_quote = _row(NAMING, "keep", quote="resolves its imports by plain name")

    assert [v.code for v in _refusals(report, no_source)] == [UNKNOWN_SOURCE_CODE]
    assert KEEP_UNQUOTED_CODE in [v.code for v in _refusals(report, no_quote)]
    assert "shares too few of the sentence's own words" in " ".join(
        v.message for v in _refusals(report, far_quote)
    )
    # Refused, it is left out, with the judge's passage named.
    counts, records = apply_rows({"sentences": [no_quote]}, passages_of(report), citable=CITABLE)
    assert counts["dropped"] >= 1
    left = [v for v in records if v.code == DROPPED_CODE and v.stood == NAMING]
    assert left and DROPPED in left[0].message


def test_a_keep_on_a_quote_that_passes_stands_and_is_recorded() -> None:
    report = report_of()
    quote = "Dynamic API Resolution: not published"
    row = _row(NAMING, "keep", quote=quote)

    assert _refusals(report, row) == []
    _counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    kept = [v for v in records if v.code == JUDGE_HELD_KEPT_CODE]
    assert len(kept) == 1 and DROPPED in kept[0].message
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert NAMING in ta.string_resolution.body


def test_a_drop_leaves_it_out_and_the_decision_is_unchanged() -> None:
    report = report_of()
    before = (
        report.verdict,
        [m.model_dump() for m in report.ttp_mappings],
        [c.model_dump() for c in report.capability_matrix],
    )
    row = _row(ASSESS, "drop", reason="The judge reads the resolution as ordinary linking.")

    assert _refusals(report, row) == []
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert counts["dropped"] >= 1
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert ASSESS not in ta.string_resolution.body
    assert any(v.code == DROPPED_CODE and DROPPED in v.message for v in records)
    after = (
        report.verdict,
        [m.model_dump() for m in report.ttp_mappings],
        [c.model_dump() for c in report.capability_matrix],
    )
    assert after == before


def test_a_held_sentence_no_row_lists_is_asked_again_and_left_out_unanswered() -> None:
    report = report_of()
    found = agreement_violations({"sentences": []}, passages_of(report), CITABLE)
    asked = [v for v in found if v.code == HELD_UNLISTED_CODE and repr(WALK) in v.message]
    assert asked and "held to the judge's decision" in asked[0].message

    dropped = _row(NAMING, "drop", reason="The judge reads plain names as no evasion.")
    counts, records = apply_rows({"sentences": [dropped]}, passages_of(report), citable=CITABLE)
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert ta.string_resolution.body.split() == f"{OTHER} {DENIED}".split()
    assert counts["dropped"] == 3
    assert all(DROPPED in v.message for v in records if v.code == DROPPED_CODE)


def test_a_question_with_no_answer_at_all_leaves_every_paragraph_standing() -> None:
    report = report_of()
    counts, _records = apply_rows({"sentences": []}, passages_of(report), citable=CITABLE)
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert counts["dropped"] == 0 and ta.string_resolution.body == BODY


def test_another_verdict_word_is_held_and_the_judge_s_own_is_not() -> None:
    malicious = "The file is malicious [ev_0302]."
    passage = next(p for p in passages_of(report_of(f"{OTHER} {malicious}")) if p.id == SECTION)
    assert dict(passage.judged) == {OTHER: ("judge.verdict",), malicious: ("judge.verdict",)}

    passage = next(
        p
        for p in passages_of(report_of(f"{OTHER} {malicious}", verdict="Malware"))
        if p.id == SECTION
    )
    assert passage.judged == ()


def test_a_family_the_judge_did_not_name_is_held() -> None:
    said = "The code matches the Quillfern loader [ev_0302]."
    passage = next(p for p in passages_of(report_of(said, family="Quillfern")) if p.id == SECTION)
    assert dict(passage.judged) == {said: ("judge.family",)}


def test_a_quoted_label_and_an_identifier_are_not_held() -> None:
    said = (
        'The rule "Dynamic API Resolution" matched, and the tag dynamic_api_resolution was '
        "set [ev_0302]."
    )
    passage = next(p for p in passages_of(report_of(said)) if p.id == SECTION)
    assert passage.judged == ()


def test_a_published_technique_named_is_not_held() -> None:
    said = "The routine reads system information [ev_0302] (T1082)."
    passage = next(p for p in passages_of(report_of(said)) if p.id == SECTION)
    assert passage.judged == ()


def test_a_verdict_the_judge_never_gave_shows_no_verdict_passage() -> None:
    report = report_of()
    report.overall_confidence = None
    shown = {p.id for p in passages_of(report)}
    assert "judge.verdict" not in shown and "judge.family" not in shown
    assert DROPPED in shown
