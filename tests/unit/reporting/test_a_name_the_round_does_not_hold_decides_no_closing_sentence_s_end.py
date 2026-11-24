"""A name the agreement round does not hold decides no closing sentence's end.

A sentence of the conclusion or the limitations whose rewrite still fails after the retry is
left out where every name its row gives is a source the round holds (a fact, a section 5
passage, a debate round or a passage shown as a source only). Where the row also gave a name
the round holds no source for, the same refused rewrite was not applied and the sentence
printed as written, unmarked: a name that is no source decided the end. Now, after the last
turn, such a sentence dev would print as written is left out and recorded where a refusal
other than the unknown name stands and the row names a source the round holds, whatever else
it names, and where the round read the rewrite as keeping the sentence and refused that keep,
whatever the row names. The record names only the sources the round holds, and says so where
none remain. A row refused only for an unknown name, a body sentence, and a sentence the
platform qualifies with the ledger's listing fact end as before (T-895). Every sentence, name
and id here is made up.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from malspark.pipeline.validation import ValidationTally
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    AGREEMENT_PRODUCER,
    DROPPED_CODE,
    KEEP_UNQUOTED_CODE,
    QUALIFIED_CODE,
    UNKNOWN_SOURCE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
    rewrites_violations,
)
from tests.unit.reporting.test_every_refusal_offers_only_the_ends_that_pass import (
    SUBJECTS,
    _asked,
    _end,
    _refusals,
)
from tests.unit.reporting.test_every_refusal_offers_only_the_ends_that_pass import (
    _row as _subject_row,
)

# The section 5 passage the rows name, and the sentence of it a keep could stand on.
DOCKS = (
    "The courier opens three pipes to its relay host [ev_0061]. "
    "The parcel it fetches was not seen unpacking in the sandbox [ev_0061]."
)
# The closing sentence, and a rewrite the round reads as keeping it: one count changed.
SAID = (
    "The courier opens two pipes to its relay host, and the parcel it fetches was not seen "
    "unpacking [ev_0061]."
)
RECOUNTED = (
    "The courier opens three pipes to its relay host, and the parcel it fetches was not seen "
    "unpacking [ev_0061]."
)
# The same rewrite citing an entry the source does not cite.
ELSEWHERE = RECOUNTED.replace("ev_0061", "ev_0088")
# A rewrite in other words, citing what the source cites.
OTHER = "Three pipes lead from the courier to the relay host [ev_0061]."
# A sentence of the same passage no row answers.
STAYS = "The courier is a small console program [ev_0062]."
# A name no passage of the round holds ("introduction" is a passage of the round, but no
# source of another passage).
NOWHERE = "parcel_marker"
CITABLE = ["ev_0061", "ev_0062", "ev_0088"]


def _report(conclusion: str, *, docks: str = DOCKS) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32 executable"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        intro_background="The courier was submitted by a mail gateway [ev_0062].",
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(
                title="C2", body=docks, evidence_refs=["ev_0061"]
            ),
            analyst_conclusion=TechnicalSubsection(title="Conclusion", body=conclusion),
        ),
    )


def _rewrite(rewrite: str, sources: list[str], sentence: str = SAID) -> dict[str, Any]:
    return {
        "passage": "conclusion",
        "sentence": sentence,
        "decision": "rewrite",
        "sources": sources,
        "rewrite": rewrite,
        "reason": "",
        "quote": "",
    }


def _codes(report: MalwareReport, row: dict[str, Any]) -> set[str]:
    passages = passages_of(report)
    payload = {"sentences": [row]}
    return {
        v.code
        for v in (
            *agreement_violations(payload, passages, CITABLE),
            *rewrites_violations(payload, CITABLE, None, None, passages),
        )
    }


def _applied(
    row: dict[str, Any], conclusion: str = f"{STAYS} {SAID}", **kw: str
) -> tuple[MalwareReport, dict[str, int], list[Any]]:
    report = _report(conclusion, **kw)
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    return report, counts, records


def _conclusion(report: MalwareReport) -> str:
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_conclusion is not None
    return ta.analyst_conclusion.body


# The record of the sentence left out, naming the source the round holds, and naming none.
LEFT_OUT = (
    "The agreement question lists a sentence of 7. Conclusion as saying otherwise than "
    f"command_and_control, and no rewrite of it passed the checks: it is left out of the "
    f"section: {SAID!r}."
)
LEFT_OUT_ON_NONE = (
    "The agreement question lists a sentence of 7. Conclusion, its row naming no source the "
    f"round holds, and no rewrite of it passed the checks: it is left out of the section: "
    f"{SAID!r}."
)
# The source without the sentence a keep could stand on: a keep of the closing sentence fails.
BARE = DOCKS.split(" The parcel")[0]


def test_a_rewrite_read_as_keeping_the_sentence_is_left_out_whatever_the_row_names() -> None:
    for sources in (
        ["command_and_control"],
        ["command_and_control", NOWHERE],
        [NOWHERE, "command_and_control"],
    ):
        codes = _codes(_report(SAID, docks=BARE), _rewrite(RECOUNTED, sources))
        assert KEEP_UNQUOTED_CODE in codes
        assert (UNKNOWN_SOURCE_CODE in codes) == (NOWHERE in sources)
        report, counts, records = _applied(_rewrite(RECOUNTED, sources), docks=BARE)
        # Left out, as the same row without the unknown name is: one record, naming only the
        # source the round holds.
        assert _conclusion(report) == STAYS
        assert counts["dropped"] == 1 and counts["not_applied"] == 0
        assert [(r.code, r.message, r.subject) for r in records] == [
            (DROPPED_CODE, LEFT_OUT, "conclusion")
        ]
        assert records[0].stood == SAID


def test_a_row_naming_only_names_the_round_does_not_hold_is_recorded_as_naming_no_source() -> None:
    for sources in ([NOWHERE], [NOWHERE, "introduction"]):
        report = _report(SAID, docks=BARE)
        assert {UNKNOWN_SOURCE_CODE, KEEP_UNQUOTED_CODE} <= _codes(
            report, _rewrite(RECOUNTED, sources)
        )
        report, counts, records = _applied(_rewrite(RECOUNTED, sources), docks=BARE)
        assert _conclusion(report) == STAYS
        assert counts["dropped"] == 1 and counts["not_applied"] == 0
        assert [r.message for r in records] == [LEFT_OUT_ON_NONE]


def test_the_fact_itself_beside_an_unknown_name_is_left_out_on_another_refusal() -> None:
    # The keep passes on the source's own sentence; the rewrite cites what no source cites.
    codes = _codes(_report(SAID), _rewrite(ELSEWHERE, ["command_and_control", NOWHERE]))
    assert UNKNOWN_SOURCE_CODE in codes and KEEP_UNQUOTED_CODE not in codes
    assert codes - {UNKNOWN_SOURCE_CODE}
    report, counts, records = _applied(_rewrite(ELSEWHERE, ["command_and_control", NOWHERE]))
    assert _conclusion(report) == STAYS
    assert counts["dropped"] == 1 and counts["not_applied"] == 0
    assert [r.message for r in records] == [LEFT_OUT]
    # The same end the row gets without the unknown name.
    without = _applied(_rewrite(ELSEWHERE, ["command_and_control"]))
    assert _conclusion(without[0]) == STAYS
    assert [r.message for r in without[2]] == [r.message for r in records]


def test_a_row_refused_only_for_an_unknown_name_prints_as_written() -> None:
    for rewrite in (RECOUNTED, OTHER):
        row = _rewrite(rewrite, ["command_and_control", NOWHERE])
        assert _codes(_report(SAID), row) == {UNKNOWN_SOURCE_CODE}
        report, counts, records = _applied(row)
        assert _conclusion(report) == f"{STAYS} {SAID}"
        assert counts["not_applied"] == 1 and counts["dropped"] == 0
        assert records == []


def test_a_body_sentence_s_refused_rewrite_ends_as_before() -> None:
    report = _report(STAYS, docks=BARE)
    background = "The courier was submitted by a mail gateway [ev_0062]."
    row = {
        **_rewrite(
            "The courier was handed in by a mail gateway [ev_0088].",
            ["command_and_control", NOWHERE],
            sentence=background,
        ),
        "passage": "introduction",
    }
    counts, records = apply_rows({"sentences": [row]}, passages_of(report), citable=CITABLE)
    assert report.intro_background == background
    assert counts["dropped"] == 0 and not [r for r in records if r.code == DROPPED_CODE]


def test_a_sentence_the_platform_qualifies_keeps_that_end_and_its_told_end() -> None:
    for name in ("conclusion unread", "limitations unread"):
        subject = SUBJECTS[name]
        answer = _subject_row(
            subject, "rewrite", [subject.listing, NOWHERE], rewrite=subject.sentence
        )
        refusals = _refusals(subject, answer)
        assert {UNKNOWN_SOURCE_CODE, KEEP_UNQUOTED_CODE} <= {code for code, _p, _m in refusals}
        told = [m for code, _p, m in refusals if code == "agreement.unread_standing"]
        assert told and all(
            "leaves it standing, and the platform appends the ledger's listing fact to it" in m
            for m in told
        )
        # Standing, with the ledger's fact appended, as the refusal tells it.
        assert _end(subject, answer) == "appended"


def test_a_qualified_sentence_is_recorded_as_qualified_not_left_out() -> None:
    subject = SUBJECTS["conclusion unread"]
    answer = _subject_row(subject, "rewrite", [subject.listing, NOWHERE], rewrite=subject.sentence)
    _report_, passages, payload, citable, entries = _asked(subject, answer)
    counts, records = apply_rows(payload, passages, citable=citable, entries=entries)
    assert counts["qualified"] == 1
    assert QUALIFIED_CODE in [r.code for r in records]
    assert subject.sentence not in [r.stood for r in records if r.code == DROPPED_CODE]


def _surfaces(report: MalwareReport) -> dict[str, str]:
    return {
        "analyst": MarkdownRenderer(layout=ANALYST).render(report),
        "analyst.html": HtmlRenderer(layout=ANALYST).render(report, embed_figures=False),
        "bundle": MarkdownRenderer(layout=BUNDLE).render(report),
    }


def _stored(report: MalwareReport, records: list[Any]) -> list[dict[str, Any]]:
    tally = ValidationTally()
    tally.record_unresolved(AGREEMENT_PRODUCER, records)
    report.run_summary = {"validation": tally.to_dict()}
    return tally.unresolved


def test_a_section_left_empty_says_so_on_every_surface_as_the_held_row_does() -> None:
    shown: dict[str, dict[str, str]] = {}
    for name, sources in (
        ("held", ["command_and_control"]),
        ("beside", ["command_and_control", NOWHERE]),
        ("none", [NOWHERE]),
    ):
        report, counts, records = _applied(
            _rewrite(RECOUNTED, sources), conclusion=SAID, docks=BARE
        )
        assert _conclusion(report) == "" and counts["dropped"] == 1
        # The run summary holds one left-out record of the conclusion, its sentence whole.
        (row,) = [r for r in _stored(report, records) if r["code"] == DROPPED_CODE]
        assert row["subject"] == "conclusion" and row["stood"] == SAID
        assert row["message"] == (LEFT_OUT_ON_NONE if name == "none" else LEFT_OUT)
        shown[name] = _surfaces(report)
    # Every surface prints the row naming an unknown name beside the source as it prints the
    # row naming the source alone.
    assert shown["beside"] == shown["held"]
    for name in ("held", "none"):
        analyst, html, bundle = (shown[name][k] for k in ("analyst", "analyst.html", "bundle"))
        for text in (analyst, html):
            assert "The courier opens two pipes" not in text
            assert (
                "The conclusion the report model wrote was left out; the bundle lists each of its "
                "sentences with the reason." in text
            )
            left = "1 sentence of this section was left out; the bundle lists each with the reason."
            assert left in text
        # The bundle lists the record, in its own words.
        said = LEFT_OUT_ON_NONE if name == "none" else LEFT_OUT
        assert f"`agreement.dropped` (agreement): {said[:120]}" in bundle
