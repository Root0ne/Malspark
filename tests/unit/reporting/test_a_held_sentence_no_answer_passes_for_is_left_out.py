"""A sentence the ledger's own lines hold ends as an answer that passes, or is left out.

The agreement question holds a sentence that denies something of a name the run
holds, a limitations sentence naming a failed call a later call redid, and one
saying such a call failed (T-600). A rewrite of one could restate its denial
behind a citation written in another clause, and a held sentence the answer
never listed printed as it stood. Now a rewrite of a held sentence follows each
clause denying something (the clause splitter's own clauses) with a citation of
an entry shown for that sentence; a held sentence no answer passing the checks
answers after the retry, refused or never answered, is left out and recorded
with the reason; a drop of one is an answer in the body too; where the platform
already changes such a sentence or leaves it out, that end stands with its own
record; and a printed line saying nothing was written for a passage says how
many of its sentences the checks left out. Every address, entry and name here is
a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import BoundValue, KeyFinding, MalwareReport, TechnicalSubsection
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    KEEP_UNQUOTED_CODE,
    QUALIFIED_CODE,
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    UNKNOWN_PASSAGE_CODE,
    _uncited,
    agreement_violations,
    apply_rows,
    passages_of,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _TRUE,
    _UNKNOWN,
    CALLED,
    _ask,
    _ledger,
    _report,
    _Reporter,
    _row,
)

# A sentence of the same passage no gate holds, which stays where it stands.
FIRST = "The gate reads a host mode [ev_0107]."
_LEFT_OUT = "If no answer for it passes the checks, it is left out of the report."
# The entries the round is shown for the held sentence: the ones ledger.1 cites.
_SHOWN = "ev_0102, ev_0107, ev_0109"


def _background(sentence: str = _UNKNOWN, first: str = FIRST) -> MalwareReport:
    return _report(FIRST, background=f"{first} {sentence}")


def _answered(report: MalwareReport, row: dict[str, Any]) -> tuple[list[Any], Any, list[Any]]:
    """The row's findings as the retry shows them, then the counts and records once applied."""
    ledger = _ledger()
    answer = {"sentences": [{**row, "passage": "introduction"}]}
    findings = [
        (v.code, v.message)
        for v in agreement_violations(answer, passages_of(report, entries=ledger))
        if v.path.startswith("sentences.")
    ]
    counts, records = apply_rows(
        answer,
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    return findings, counts, [(v.code, v.subject, v.message) for v in records]


def _uncited_denial(clause: str) -> str:
    return (
        f"row 1: the rewrite of introduction denies something in {clause!r} and no entry "
        "shown for the sentence follows that denial at once: in a rewrite of this sentence "
        "each denial is followed at once by the entry it rests on, cited in square brackets, "
        f"one of {_SHOWN}. {_LEFT_OUT}"
    )


def _left_out(why: str, sentence: str = _UNKNOWN, label: str = "12.3 Background") -> str:
    return (
        f"The agreement question leaves a sentence of {label} out of the section ({why}): "
        f"{sentence!r}."
    )


def _rewritten(rewrite: str) -> str:
    return (
        "The agreement question rewrote a sentence of 12.3 Background on ledger.1: "
        f"{_UNKNOWN!r} now reads {rewrite!r}."
    )


def test_a_denial_in_a_rewrite_is_followed_at_once_by_an_entry_shown_for_it() -> None:
    lead = f"Routine 0x5a10 calls `{CALLED}` [ev_0109], but"
    # Followed at once by an entry ledger.1 cites: the rewrite stands.
    cited = f"{lead} what it returns at run time is not recorded [ev_0107]."
    findings, counts, records = _answered(
        _background(), _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=cited)
    )
    assert findings == []
    assert counts["rewritten"] == 1 and counts["dropped"] == 0
    assert records == [(REWRITTEN_CODE, "", _rewritten(cited))]
    # The citation only in another clause: refused, with the full message, and left out.
    elsewhere = f"{lead} what it returns at run time is not recorded."
    report = _background()
    findings, counts, records = _answered(
        report, _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=elsewhere)
    )
    assert findings == [
        (REWRITE_UNGROUNDED_CODE, _uncited_denial("what it returns at run time is not recorded."))
    ]
    assert counts["dropped"] == 1 and counts["rewritten"] == 0
    assert report.intro_background == FIRST
    assert records == [
        (
            DROPPED_CODE,
            "introduction",
            _left_out(
                "no rewrite of it passed the checks; held on what ledger.1 holds lines on: "
                "agreement.rewrite_ungrounded"
            ),
        )
    ]


def test_a_denial_followed_by_an_entry_not_shown_for_the_sentence_is_refused() -> None:
    # The passage cites the failed call, so the rewrite may cite it, but ledger.1 does not.
    report = _background(first="The gate reads a host mode [ev_0101].")
    rewrite = (
        f"Routine 0x5a10 calls `{CALLED}` [ev_0107], but its result is not recorded [ev_0101]."
    )
    findings, counts, records = _answered(
        report, _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=rewrite)
    )
    assert findings == [(REWRITE_UNGROUNDED_CODE, _uncited_denial("its result is not recorded"))]
    assert counts["dropped"] == 1
    assert [code for code, _subject, _message in records] == [DROPPED_CODE]


def test_a_rewrite_with_no_denial_stands_and_two_denials_each_need_their_own() -> None:
    plain = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."
    findings, counts, records = _answered(
        _background(), _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=plain)
    )
    assert findings == [] and records == [(REWRITTEN_CODE, "", _rewritten(plain))]
    # The first denial cited, the second not: the second is named.
    two = f"No write follows the `{CALLED}` call [ev_0109], and its result is not recorded."
    findings, counts, _records = _answered(
        _background(), _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=two)
    )
    assert findings == [
        (REWRITE_UNGROUNDED_CODE, _uncited_denial("and its result is not recorded."))
    ]
    assert counts["dropped"] == 1
    # Each cited at once: it stands.
    both = (
        f"No write follows the `{CALLED}` call [ev_0109], and its result is not recorded [ev_0107]."
    )
    findings, counts, records = _answered(
        _background(), _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=both)
    )
    assert findings == [] and records == [(REWRITTEN_CODE, "", _rewritten(both))]


def test_a_held_sentence_no_turn_answers_is_left_out_with_the_reason() -> None:
    report = _background()
    reporter = _Reporter({"sentences": []}, {"sentences": []})
    done = _ask(report, reporter)
    assert report.intro_background == FIRST
    assert done.summary["dropped"] == 1
    records = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert [(r["subject"], r["message"]) for r in records] == [
        (
            "introduction",
            _left_out("no answer was given for it; held on what ledger.1 holds lines on"),
        )
    ]
    # The retry asked about it was told what becomes of it.
    retry = str(reporter.asked[1][-1].content)
    assert _LEFT_OUT in retry


def test_a_held_sentence_answered_only_in_the_retry_stands_on_that_answer() -> None:
    report = _background()
    plain = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."
    rewrite = {
        **_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=plain),
        "passage": "introduction",
    }
    reporter = _Reporter({"sentences": []}, {"sentences": [rewrite]})
    done = _ask(report, reporter)
    assert report.intro_background == f"{FIRST} {plain}"
    assert done.summary["dropped"] == 0 and done.summary["rewritten"] == 1
    # The first turn's question said what an unanswered held sentence ends as.
    assert (
        'keep it naming that fact, with "quote": words inside one of its rows that name what the '
        "sentence names, copied exactly; or rewrite it in your own words on the lines shown, "
        "citing an entry the fact cites, each denial in it followed at once by the entry it "
        "rests on, one shown for it; or drop it; if no answer for it passes the checks, it is "
        "left out of the report"
    ) in str(reporter.asked[0][-1].content)


def test_a_held_sentence_refused_in_the_first_turn_and_not_answered_again_is_left_out() -> None:
    report = _background()
    keep = {**_row(_UNKNOWN, "keep", [], reason="no source states it"), "passage": "introduction"}
    done = _ask(report, _Reporter({"sentences": [keep]}, {"sentences": []}))
    # The refused row stays its last answer through the merge: left out as refused.
    assert report.intro_background == FIRST
    records = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert [r["message"] for r in records] == [
        _left_out(
            "its last answer, a keep, was refused; held on what ledger.1 holds lines on: "
            f"{KEEP_UNQUOTED_CODE}"
        )
    ]


def test_a_drop_of_a_held_body_sentence_is_an_answer() -> None:
    report = _background()
    findings, counts, records = _answered(
        report, _row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise")
    )
    assert findings == []
    assert report.intro_background == FIRST and counts["dropped"] == 1
    assert records == [
        (
            DROPPED_CODE,
            "introduction",
            _left_out(
                "the round dropped it; held on what ledger.1 holds lines on; its reason: the "
                "lines shown say otherwise"
            ),
        )
    ]
    # A body sentence no gate holds keeps the rule: a drop of it is refused, and it stands.
    report = _background()
    findings, counts, _records = _answered(report, _row(FIRST, "drop", [], reason="x"))
    assert (
        UNKNOWN_PASSAGE_CODE,
        "row 1: only a sentence of the conclusion or the limitations is left out; answer the "
        "sentence of introduction with keep or rewrite.",
    ) in findings
    assert counts["not_applied"] == 1 and report.intro_background == FIRST


def test_a_closing_sentence_the_platform_already_leaves_out_has_its_one_record() -> None:
    report = _report(f"{FIRST} {_TRUE}")
    ledger = _ledger()
    answer = {"sentences": [_row(_TRUE, "keep", [], reason="no source")]}
    counts, records = apply_rows(
        answer,
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    assert report.technical_analysis.analyst_limitations.body == FIRST
    assert counts["dropped"] == 1
    assert [(v.code, v.message) for v in records] == [
        (
            DROPPED_CODE,
            _left_out(
                "the ledger says otherwise: agreement.keep_unquoted, agreement.failure_redone",
                _TRUE,
                "11. Limitations, the composed paragraph (each sentence saying a call failed or "
                "a reading could not be made is held to the failed calls, the tools not run, the "
                "recorded limitations and the open questi…",
            ),
        )
    ]


def _on_fact_and_held() -> tuple[MalwareReport, str]:
    """A section 5 sentence a decoded value's fact speaks to that names an API the run holds."""
    denied = f"The text passed to `{CALLED}` is not established."
    report = _report(FIRST)
    report.technical_analysis.evasion_antiforensics = TechnicalSubsection(
        title="Evasion", body=f"The gate calls `{CALLED}` [ev_0107]. {denied}"
    )
    report.bound_values = [
        BoundValue(
            value="quietmode",
            kind="text",
            role="mode_name",
            role_words="the mode the call reads",
            api=CALLED,
            argument=2,
            parameter="lpMode",
            entry="ev_0107",
            tool="decoder",
        )
    ]
    return report, denied


def test_a_section_5_sentence_on_a_fact_and_held_is_qualified_as_before() -> None:
    report, denied = _on_fact_and_held()
    ledger = _ledger()
    passages = passages_of(report, entries=ledger)
    evasion = next(p for p in passages if p.id == "evasion_antiforensics")
    assert denied in evasion.on_fact and denied in dict(evasion.ledger_named)
    # A rewrite in the model's words that passes no check: the platform adds the fact's
    # clause, as it does for any such sentence, and nothing else is recorded of it.
    row = {
        "passage": "evasion_antiforensics",
        "sentence": denied,
        "sources": ["bound.1"],
        "decision": "rewrite",
        "rewrite": "The text is not known.",
    }
    counts, records = apply_rows(
        {"sentences": [row]},
        passages,
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    assert counts["qualified"] == 1 and counts["dropped"] == 0
    assert [v.code for v in records] == [QUALIFIED_CODE]
    body = report.technical_analysis.evasion_antiforensics.body
    assert body.startswith(f"The gate calls `{CALLED}` [ev_0107]. {denied[:-1]}; the code passes")


def test_a_subsection_whose_only_sentence_is_left_out_says_so_in_print() -> None:
    report = _report(FIRST)
    report.technical_analysis.discovery = TechnicalSubsection(title="Discovery", body=_UNKNOWN)
    done = _ask(report, _Reporter({"sentences": []}, {"sentences": []}))
    assert report.technical_analysis.discovery.body == ""
    report.run_summary = {"validation": {"retries": 1, "unresolved": done.tally.unresolved}}
    # The bundle's line for the subsection says the checks left its one sentence out; the
    # next subsection, where the model wrote nothing, says that as before.
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert (
        "### 5.5 Discovery · _Measured_\n\nNot examined in this run: this report records no "
        "sandbox observation, no tool looked at the file, and the checks left out the 1 sentence "
        "the report model wrote on it.\n"
    ) in bundle
    assert (
        "### 5.7 Command and control · _Measured_\n\nNot examined in this run: this report "
        "records no sandbox observation, no tool looked at the file, and the report model wrote "
        "nothing on it."
    ) in bundle
    # The analyst report prints no empty subsection, and not the sentence.
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert _uncited(_UNKNOWN).rstrip(".") not in analyst
    assert "Discovery" not in analyst


def test_a_summary_emptied_with_its_findings_says_so_in_print() -> None:
    report = _report(FIRST)
    report.executive_summary = _UNKNOWN
    report.key_findings = [KeyFinding(text=_UNKNOWN)]
    done = _ask(report, _Reporter({"sentences": []}, {"sentences": []}))
    assert report.executive_summary == "" and report.key_findings[0].text == ""
    assert {r["subject"] for r in done.tally.unresolved if r["code"] == DROPPED_CODE} >= {
        "executive_summary",
        "key_findings.1",
    }
    report.run_summary = {"validation": {"retries": 1, "unresolved": done.tally.unresolved}}
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert "No summary is printed: the checks left out the 2 sentences the report model wrote." in (
        bundle
    )
    assert "No summary was written" not in bundle
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert (
        "No summary is printed in this run: the checks left out the 2 sentences the report "
        "model wrote; the findings below are the platform's own record of what the run "
        "established."
    ) in analyst
