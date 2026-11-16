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
    assert dropped.label == "a technique the judge did not publish"
    assert dropped.text == f'T1027.007 Dynamic API Resolution: "the judge dropped it ({_REASON})"'
    # Said dropped once, by the record's own words.
    assert f"{dropped.label}: {dropped.text}".count("dropped") == 1
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
    assert (
        f"- [{DROPPED}] a technique the judge did not publish: T1027.007 Dynamic API "
        f'Resolution: "the judge dropped it ({_REASON})"\n'
    ) in block
    assert block.count("dropped") == 2
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
    assert (
        "; or left out on a passage of the judge's decision (judge.verdict, judge.family, "
        "judge.technique.ID), the one answer that decision supports."
    ) in found[0].message

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
def test_no_answer_on_a_judge_passage_is_taken_for_the_summary(
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
    # The summary is no passage a drop on a source leaves a sentence out of: the decision
    # supports no answer for it.
    assert [v.code for v in found] == [UNKNOWN_SOURCE_CODE]
    assert "which supports no answer for a sentence of executive_summary" in found[0].message
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

    # The one answer the decision supports, where it supports one, and when to list.
    assert agreement._JUDGE_TASK in text
    assert 'It supports one answer only, leaving a sentence out: "decision": "drop"' in text
    assert "A row naming a judge passage is a drop whatever else it names" in text
    assert (
        "It leaves a sentence out only of a section 5 passage you may rewrite or of a passage "
        "whose EVERY sentence the TASK asks you to answer"
    ) in text
    assert "as the report's own finding, what the record decided otherwise" in text
    assert "an analyst's view as such is not one" in text
    assert "each sentence the TASK says to list on it" in SYSTEM_PROMPT
    assert "the one answer a passage of the judge's decision supports" in SYSTEM_PROMPT
    assert "Leave out every sentence no source states otherwise than" not in SYSTEM_PROMPT


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


@pytest.mark.parametrize(
    "row",
    [
        {"decision": "drop", "sources": ["judge.verdict"], "reason": "The judge says otherwise."},
        {"decision": "drop", "sources": ["judge.technique.T1055"], "reason": "Dropped by it."},
        {"decision": "keep", "sources": ["judge.verdict"], "quote": "Benign"},
    ],
)
def test_a_judge_passage_is_no_source_of_any_answer_on_a_verbatim_passage(
    row: dict[str, Any],
) -> None:
    from tests.unit.reporting.test_one_verbatim_text_is_one_passage_wherever_it_prints import (
        _CLAIM_SENTENCE,
        _twice,
    )

    report = _twice()
    report.overall_confidence = 0.8
    row = {"passage": "attack_claim.T1497.001", "sentence": _CLAIM_SENTENCE, **row}
    assert {"judge.verdict", "judge.technique.T1055"} <= {p.id for p in passages_of(report)}

    found = [
        v
        for v in agreement_violations({"sentences": [row]}, passages_of(report))
        if v.path.startswith("sentences.")
    ]
    assert found and found[0].code in (UNKNOWN_PASSAGE_CODE, UNKNOWN_SOURCE_CODE)
    assert "no source of a passage marked (verbatim)" in found[0].message
    _counts, records = apply_rows({"sentences": [row]}, passages_of(report))
    # A drop naming the judge alone drops nothing; no answer on it is the judge's left out.
    assert agreement.JUDGE_LEFT_OUT_CODE not in [v.code for v in records]
    if row["decision"] == "drop":
        assert not [v for v in records if v.code in agreement.LEFT_OUT_CODES]
        assert not report.flagged_statements or all(
            not f.left_out for f in report.flagged_statements
        )


# A row naming a fact and a judge passage: a judge row whatever else it names (T-717).
def _fact_and_judge(row: dict[str, Any], *, held: bool) -> tuple[MalwareReport, Any, Any]:
    """The verdict shown beside a section 5 sentence a fact grounds: ``held`` one a decoded
    value's fact speaks to that the ledger's lines hold, else one an unlisted routine's fact
    qualifies."""
    from malspark.pipeline.validation import EntryTexts

    if held:
        from tests.unit.reporting.test_a_held_sentence_no_answer_passes_for_is_left_out import (
            _ledger,
            _on_fact_and_held,
        )

        report, sentence = _on_fact_and_held()
        row = {**row, "sources": ["bound.1", "judge.verdict"]}
    else:
        from tests.unit.reporting.test_a_section_5_sentence_is_asked_against_the_ledger_s_own_facts import (  # noqa: E501
            ABSENT as sentence,
        )
        from tests.unit.reporting.test_a_section_5_sentence_is_asked_against_the_ledger_s_own_facts import (  # noqa: E501
            _ledger,
            _report,
        )

        report = _report()
        row = {**row, "sources": ["unread.1", "judge.verdict"]}
    report.overall_confidence = 0.8
    ledger = _ledger()
    row = {"passage": "evasion_antiforensics", "sentence": sentence, **row}
    return report, {"sentences": [row]}, (ledger, EntryTexts.from_ledger(ledger))


@pytest.mark.parametrize("held", [False, True])
def test_a_section_5_rewrite_naming_a_fact_and_a_judge_passage_is_refused_and_not_put_in(
    held: bool,
) -> None:
    report, answer, (ledger, entries) = _fact_and_judge(
        {"decision": "rewrite", "rewrite": "The model's words [ev_0107]."}, held=held
    )
    citable = [str(e.id) for e in ledger]
    passages = passages_of(report, entries=ledger)
    by_id = {p.id: p for p in passages}
    body = report.technical_analysis.evasion_antiforensics.body  # type: ignore[union-attr]
    sentence = answer["sentences"][0]["sentence"]
    # The platform writes no rewrite of a row naming a judge passage: read as the model wrote
    # it, before and after.
    assert agreement._platform_rewrites(answer, by_id) == answer

    found = [
        v
        for v in agreement_violations(answer, passages, citable, entries=entries)
        if v.path.startswith("sentences.")
    ]
    assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
    assert "judge.verdict is a passage of the judge's decision" in found[0].message
    counts, records = apply_rows(
        answer, passages_of(report, entries=ledger), citable=citable, entries=entries
    )
    after = report.technical_analysis.evasion_antiforensics.body  # type: ignore[union-attr]
    # No rewrite and no platform qualification is put in on it.
    assert counts["rewritten"] == 0 and counts["qualified"] == 0
    assert not [v for v in records if v.code in (REWRITTEN_CODE, agreement.QUALIFIED_CODE)]
    assert agreement.JUDGE_LEFT_OUT_CODE not in [v.code for v in records]
    if held:
        # A sentence the ledger's lines hold ends as one no answer passes for: left out,
        # recorded with what holds it, as it is whatever its refused row names.
        assert sentence not in after and counts["dropped"] == 1
        (left,) = [v for v in records if v.code == DROPPED_CODE]
        assert "no rewrite of it passed the checks" in left.message
        assert "its last answer" not in found[0].message
        assert "If no answer for it passes the checks, it is left out" in found[0].message
    else:
        assert after == body and counts["dropped"] == 0


def test_a_section_5_drop_naming_a_fact_and_a_judge_passage_is_the_judge_s_drop() -> None:
    report, answer, (ledger, entries) = _fact_and_judge(
        {"decision": "drop", "reason": "The judge decided otherwise."}, held=False
    )
    citable = [str(e.id) for e in ledger]
    sentence = answer["sentences"][0]["sentence"]

    assert [
        v
        for v in agreement_violations(
            answer, passages_of(report, entries=ledger), citable, entries=entries
        )
        if v.path.startswith("sentences.")
    ] == []
    counts, records = apply_rows(
        answer, passages_of(report, entries=ledger), citable=citable, entries=entries
    )
    assert counts["dropped"] == 1
    assert sentence not in report.technical_analysis.evasion_antiforensics.body  # type: ignore[union-attr]
    (left,) = [v for v in records if v.code in agreement.LEFT_OUT_CODES]
    assert left.code == agreement.JUDGE_LEFT_OUT_CODE and left.stood == sentence


@pytest.mark.parametrize(
    ("decision", "more"),
    [("rewrite", {"rewrite": "The routine formats a host name [ev_0302]."}), ("drop", {})],
)
def test_a_closing_row_naming_a_fact_and_a_judge_passage_is_a_judge_row(
    decision: str, more: dict[str, str]
) -> None:
    report = report_of(OTHER)
    conclusion = _closing(report)
    row = {
        **_closing_row(""),
        "decision": decision,
        "sources": [SECTION, "judge.verdict"],
        "reason": "The judge decided otherwise.",
        **more,
    }
    by_id = {p.id: p for p in passages_of(report)}
    assert agreement._platform_rewrites({"sentences": [row]}, by_id) == {"sentences": [row]}

    found = _refusals(report, row)
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    if decision == "drop":
        # Left out on the judge's decision, recorded as such whatever else the row names.
        assert found == [] and counts["dropped"] == 1 and conclusion.body == ""
        (left,) = [v for v in records if v.code in agreement.LEFT_OUT_CODES]
        assert left.code == agreement.JUDGE_LEFT_OUT_CODE and left.stood == CLOSING
    else:
        # Refused, and no source a refused closing rewrite rests on: it stands as written.
        assert [v.code for v in found] == [UNKNOWN_PASSAGE_CODE]
        assert counts["dropped"] == 0 and counts["rewritten"] == 0
        assert conclusion.body == CLOSING


def _config_row(report: MalwareReport) -> str:
    """A configuration table row section 5 shows for reading, and its text."""
    from malspark.reporting.models import ConfigItem

    assert report.technical_analysis is not None
    report.technical_analysis.configuration = [
        ConfigItem(key="mode", value="quiet", evidence_refs=["ev_0302"])
    ]
    return next(p.text for p in passages_of(report) if p.id == "configuration.1")


@pytest.mark.parametrize("where", ["executive_summary", "configuration.1", "conclusion"])
def test_a_drop_on_the_judge_s_decision_passes_only_where_a_drop_leaves_a_sentence_out(
    where: str,
) -> None:
    report = report_of(OTHER)
    report.executive_summary = _SUMMARY_VERDICT
    conclusion = _closing(report)
    conclusion.body = _CONCLUSION_VERDICT
    sentence = {
        "executive_summary": _SUMMARY_VERDICT,
        "configuration.1": _config_row(report),
        "conclusion": _CONCLUSION_VERDICT,
    }[where]
    row = {
        **_row(sentence, "drop", reason="The judge decided otherwise."),
        "passage": where,
        "sources": ["judge.verdict"],
    }
    shown = passages_of(report, narrative_written=True)

    found = [
        v
        for v in agreement_violations({"sentences": [row]}, shown, CITABLE)
        if v.path.startswith("sentences.")
    ]
    counts, records = apply_rows(
        {"sentences": [row]}, passages_of(report, narrative_written=True), citable=CITABLE
    )
    if where == "conclusion":
        assert found == [] and counts["dropped"] == 1 and conclusion.body == ""
        assert [v.code for v in records] == [agreement.JUDGE_LEFT_OUT_CODE]
        return
    # A passage no drop on a source leaves a sentence out of takes no answer on the decision.
    assert [v.code for v in found] == [UNKNOWN_SOURCE_CODE]
    assert f"which supports no answer for a sentence of {where}: it leaves a sentence out " in (
        found[0].message
    )
    assert agreement._JUDGE_DROPS in found[0].message
    assert f"Name no judge passage for a sentence of {where}." in found[0].message
    assert counts["dropped"] == 0
    assert report.executive_summary == _SUMMARY_VERDICT
    assert not [v for v in records if v.code in agreement.LEFT_OUT_CODES]


def test_every_judge_refusal_offers_the_drop_only_where_it_passes() -> None:
    report = report_of()
    keep = _row(ASSESS, "keep", quote="Benign")
    (refused,) = _refusals(report, keep)
    assert 'answer the sentence "decision": "drop", naming the judge passage' in refused.message
    # Given back as the refusal says, the drop passes.
    drop = {**keep, "decision": "drop", "quote": "", "reason": "The judge decided otherwise."}
    assert _refusals(report, drop) == []
    # Where no drop on it passes, none is offered.
    report.executive_summary = _SUMMARY_VERDICT
    summary = _summary_row(_SUMMARY_VERDICT, ["judge.verdict"], "keep", quote="Benign")
    found = [
        v
        for v in agreement_violations(
            {"sentences": [summary]}, passages_of(report, narrative_written=True), CITABLE
        )
        if v.path.startswith("sentences.")
    ]
    assert found and all('"decision": "drop"' not in v.message for v in found)
    # A refusal of another source names the decision only where a drop on it passes.
    other = {**summary, "sources": ["nowhere.1"], "decision": "rewrite", "rewrite": OTHER}
    found = [
        v
        for v in agreement_violations(
            {"sentences": [other]}, passages_of(report, narrative_written=True), CITABLE
        )
        if v.code == UNKNOWN_SOURCE_CODE
    ]
    assert found and all("judge" not in v.message for v in found)


@pytest.mark.parametrize("decision", ["keep", "rewrite"])
def test_the_refusal_on_a_judge_passage_tells_the_end_the_round_gives(decision: str) -> None:
    from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (  # noqa: E501
        CALLED,
        _ledger,
        _report,
    )

    held = f"The runtime result of `{CALLED}` is not known."
    body = f"Routine 0x5a10 reads a host mode through a slot [ev_0107]. {held}"
    report = _report("The run ends.")
    assert report.technical_analysis is not None
    report.technical_analysis.string_resolution.body = body  # type: ignore[union-attr]
    report.overall_confidence = 0.8
    report.ttp_mappings = [
        TTPMapping(
            technique_id="T1082",
            technique_name="System Information Discovery",
            evidence_ids=["ev_0107"],
        )
    ]
    ledger = _ledger()
    citable = [str(e.id) for e in ledger]
    row = {
        "passage": "string_resolution",
        "sentence": held,
        "sources": ["judge.technique.T1082"],
        "decision": decision,
        "quote": "published",
        "rewrite": f"{held[:-1]} [ev_0107].",
    }
    passages = passages_of(report, entries=ledger)
    assert agreement._held_by_the_ledger(
        next(p for p in passages if p.id == "string_resolution"), held
    )

    (refused,) = [
        v
        for v in agreement_violations({"sentences": [row]}, passages, citable)
        if v.path.startswith("sentences.")
    ]
    # No fixed clause says the sentence stands: the end the round gives it is told, once.
    assert "stands as written" not in refused.message
    assert refused.message.count("If no answer for it passes the checks, it is left out") == 1
    counts, records = apply_rows(
        {"sentences": [row]}, passages_of(report, entries=ledger), citable=citable
    )
    assert counts["dropped"] == 1 and held not in report.technical_analysis.string_resolution.body  # type: ignore[union-attr]
    assert agreement.JUDGE_LEFT_OUT_CODE not in [v.code for v in records]

    # A sentence nothing holds is told no end, and stands as written.
    plain = report_of()
    (refused,) = _refusals(plain, _row(ASSESS, decision, quote="Benign", rewrite=ASSESS))
    assert "stands as written" not in refused.message and "left out of the report" not in (
        refused.message
    )
    apply_rows(
        {"sentences": [_row(ASSESS, decision, quote="Benign", rewrite=ASSESS)]},
        passages_of(plain),
        citable=CITABLE,
    )
    assert _body(plain) == BODY
