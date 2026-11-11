"""A sentence the ledger's own lines hold ends once, whatever shape the answer takes.

The agreement question leaves out a sentence it holds to the ledger's lines (T-600) where
no answer for it passes. Some answers slipped past that end: the same words with a
citation added, in a body passage, printed as written; a held sentence the passage writes
twice, which no row can name, printed with no record; a call that raised printed every
held sentence; two rows for one sentence, one passing and one refused, left it out and
recorded it kept. Each now ends one way, with one record. Every address, entry and name
here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from malspark.core.spend import SpendCeilingStop
from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import KeyFinding, MalwareReport, TechnicalSubsection
from malspark.reporting.renderers.layout import BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    HELD_KEPT_CODE,
    HELD_UNLISTED_CODE,
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    agreement_violations,
    apply_rows,
    ask_section_agreement,
    passages_of,
    rewrites_violations,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    CALLED,
    _ask,
    _cited,
    _ledger,
    _report,
    _Reporter,
    _row,
)

FIRST = "The gate reads a host mode [ev_0107]."
_LEFT_OUT = "If no answer for it passes the checks, it is left out of the report."
_HELD = "held on what ledger.1 holds lines on"
_BACKGROUND = "12.3 Background"


def _left_out(why: str, label: str = _BACKGROUND, sentence: str = _UNKNOWN) -> str:
    return (
        f"The agreement question leaves a sentence of {label} out of the section ({why}): "
        f"{sentence!r}."
    )


def _applied(report: MalwareReport, rows: list[dict[str, Any]]) -> tuple[dict[str, int], list]:
    ledger = _ledger()
    counts, records = apply_rows(
        {"sentences": rows},
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    return counts, [(v.code, v.subject, v.message) for v in records]


def _intro(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "passage": "introduction"}


@pytest.mark.parametrize("where", ["end", "start"])
def test_the_same_words_with_a_citation_in_the_body_are_the_keep_they_are(where: str) -> None:
    same = _cited(_UNKNOWN, "[ev_0109]", where)
    # No quote of the fact's rows: refused as the keep it is, and left out.
    report = _report(FIRST, background=f"{FIRST} {_UNKNOWN}")
    counts, records = _applied(
        report, [_intro(_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=same))]
    )
    assert report.intro_background == FIRST
    assert counts["dropped"] == 1 and counts["rewritten"] == 0
    assert records == [
        (
            DROPPED_CODE,
            "introduction",
            _left_out(f"no rewrite of it passed the checks; {_HELD}: agreement.keep_unquoted"),
        )
    ]
    # Quoting a row of the fact that names what the sentence names, as a keep does: it stands.
    report = _report(FIRST, background=f"{FIRST} {_UNKNOWN}")
    row = _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=same, quote=CALLED)
    counts, records = _applied(report, [_intro(row)])
    assert report.intro_background == f"{FIRST} {same}"
    assert counts["rewritten"] == 1 and counts["dropped"] == 0
    assert records == [
        (
            REWRITTEN_CODE,
            "",
            f"The agreement question rewrote a sentence of {_BACKGROUND} on ledger.1: "
            f"{_UNKNOWN!r} now reads {same!r}.",
        )
    ]


def test_a_held_sentence_written_twice_is_left_out_each_time_it_stands() -> None:
    report = _report("", background=f"{FIRST} {_UNKNOWN} {_UNKNOWN}")
    # No row can name it, so it is no refusal of its own: nothing else wrong, no retry.
    reporter = _Reporter({"sentences": [_intro(_row(FIRST, "keep", ["ledger.1"]))]})
    done = _ask(report, reporter)
    assert len(reporter.asked) == 1
    assert done.tally.retries == 0
    assert report.intro_background.rstrip() == FIRST
    assert done.summary["dropped"] == 2
    why = f"it stands more than once in the passage, so no answer could name it; {_HELD}"
    assert [
        (r["code"], r["subject"], r["message"])
        for r in done.tally.unresolved
        if r["code"] == DROPPED_CODE
    ] == [(DROPPED_CODE, "introduction", _left_out(why))] * 2
    assert not [r for r in done.tally.unresolved if r["code"] == HELD_UNLISTED_CODE]


def test_a_sentence_written_twice_that_is_not_held_stands_as_before() -> None:
    twice = f"{FIRST} The gate returns. The gate returns."
    report = _report(FIRST, background=twice)
    assert [
        v
        for v in agreement_violations({"sentences": []}, passages_of(report, entries=_ledger()))
        if v.path == "held.introduction"
    ] == []
    counts, records = _applied(report, [])
    assert report.intro_background == twice
    assert counts["dropped"] == 0 and records == []


class _Raising(_Reporter):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def ask(self, turns: list[Any], *, call: str, what: str) -> Any:
        raise self.error


@pytest.mark.parametrize(
    ("reporter", "said"),
    [
        (
            _Raising(TimeoutError("late")),
            ["The section agreement question was not answered (TimeoutError)."],
        ),
        (
            _Raising(SpendCeilingStop("the ceiling")),
            ["The section agreement question was not asked: the ceiling."],
        ),
        (_Reporter("not json", "still not json"), []),
    ],
    ids=["the call raised", "the spend ceiling stopped it", "no row could be read"],
)
def test_no_answer_at_all_leaves_every_held_sentence_out_for_one_reason(
    reporter: _Reporter, said: list[str]
) -> None:
    report = _report(f"{FIRST} {_UNKNOWN}", background=f"{FIRST} {_UNKNOWN}")
    done = _ask(report, reporter)
    # The sentences no gate holds stand as written; each held one is left out.
    assert report.intro_background == FIRST
    assert report.technical_analysis.analyst_limitations.body == FIRST
    assert done.summary["dropped"] == 2
    assert done.degradations == said
    why = f"the agreement question got no answer at all; {_HELD}"
    assert [
        (r["code"], r["subject"], r["message"])
        for r in done.tally.unresolved
        if r["code"] == DROPPED_CODE
    ] == [
        (DROPPED_CODE, "introduction", _left_out(why)),
        (DROPPED_CODE, "limitations", _left_out(why, "11. Limitations")),
    ]


def test_a_call_that_raises_changes_no_sentence_that_is_not_held() -> None:
    report = _report(FIRST, background=FIRST)
    report.technical_analysis.discovery = TechnicalSubsection(
        title="Discovery", body="Routine 0x5a10 was not read."
    )
    done = _ask(report, _Raising(TimeoutError("late")))
    assert report.intro_background == FIRST
    assert report.technical_analysis.discovery.body == "Routine 0x5a10 was not read."
    assert report.technical_analysis.analyst_limitations.body == FIRST
    assert done.summary["dropped"] == 0 and done.summary["qualified"] == 0
    assert done.tally.unresolved == []


@pytest.mark.parametrize("passing_first", [True, False])
def test_an_answer_that_passes_answers_its_sentence_whatever_another_row_says(
    passing_first: bool,
) -> None:
    passing = _intro(_row(_UNKNOWN, "keep", ["ledger.1"], quote=CALLED))
    refused = _intro(_row(_UNKNOWN, "keep", [], reason="no source states it"))
    report = _report(FIRST, background=f"{FIRST} {_UNKNOWN}")
    counts, records = _applied(report, [passing, refused] if passing_first else [refused, passing])
    assert report.intro_background == f"{FIRST} {_UNKNOWN}"
    assert counts["dropped"] == 0 and counts["held_kept"] == 1
    assert records == [
        (
            HELD_KEPT_CODE,
            "",
            f"The agreement question kept a held sentence of {_BACKGROUND} on ledger.1, quoting "
            f"{CALLED!r}, resting on the rows of an entry the sentence cites, which state no "
            f"absence: {_UNKNOWN!r} stands as written.",
        )
    ]


def test_a_refused_answer_another_end_took_first_is_counted_not_applied() -> None:
    # The refused keep of a closing sentence is left out by the closing rule (dev's end, with
    # its own record); the refused rewrite of the same sentence after it ends nothing more.
    report = _report(f"{FIRST} {_UNKNOWN}")
    rewrite = f"Routine 0x5a10 calls `{CALLED}`; its result is not known."
    counts, records = _applied(
        report,
        [
            _row(_UNKNOWN, "keep", [], reason="no source states it"),
            _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=rewrite),
        ],
    )
    assert report.technical_analysis.analyst_limitations.body == FIRST
    assert counts["dropped"] == 1 and counts["not_applied"] == 1
    assert records == [
        (
            DROPPED_CODE,
            "limitations",
            _left_out(
                "kept on no source a check accepts: no source, because 'no source states it': "
                "agreement.keep_unquoted",
                "11. Limitations",
            ),
        )
    ]


def test_the_platform_s_section_5_qualification_is_no_rewrite_the_denial_check_reads() -> None:
    # R7: a section 5 sentence held on a name and rewritten by the platform on the fact
    # (the sentence and the fact's clause) is put in; its denial is the sentence's own.
    denied = f"Routine 0x5a10 does not call `{CALLED}`."
    report = _report(FIRST)
    report.technical_analysis.evasion_antiforensics = TechnicalSubsection(
        title="Evasion", body=f"The gate runs at 0x5a10 [ev_0107]. {denied}"
    )
    row = {**_row(denied, "rewrite", ["ledger.1"], rewrite="x"), "passage": "evasion_antiforensics"}
    counts, records = _applied(report, [row])
    qualified = (
        f"{denied[:-1]}; the function index lists a call to {CALLED} from the routine at offset "
        "0x5a10 [ev_0102][ev_0107][ev_0109]."
    )
    assert report.technical_analysis.evasion_antiforensics.body == (
        f"The gate runs at 0x5a10 [ev_0107]. {qualified}"
    )
    assert counts["rewritten"] == 1 and counts["dropped"] == 0
    assert [code for code, _subject, _message in records] == [REWRITTEN_CODE]


def test_the_retry_tells_a_refused_rewrite_of_a_held_sentence_what_becomes_of_it() -> None:
    # A refusal from the prose checks of the rewrite, not the row checks, also says the end.
    report = _report(FIRST, background=f"{FIRST} {_UNKNOWN}")
    rewrite = _intro(
        _row(
            _UNKNOWN, "rewrite", ["ledger.1"], rewrite=f"Routine 0x5a10 calls `{CALLED}` [ev_0999]."
        )
    )
    ledger = _ledger()
    (prose,) = rewrites_violations(
        {"sentences": [rewrite]},
        [str(e.id) for e in ledger],
        None,
        EntryTexts.from_ledger(ledger),
        passages_of(_report(FIRST, background=f"{FIRST} {_UNKNOWN}"), entries=ledger),
    )
    # The row's last refusal, it says the sentence's ends once, then that end.
    assert "… It names what ledger.1 holds lines on: keep it naming that fact" in prose.message
    assert prose.message.endswith(f"; or drop it. {_LEFT_OUT}")
    reporter = _Reporter({"sentences": [rewrite]}, {"sentences": []})
    asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )
    assert f"- [{prose.code}] ({prose.path}) {prose.message}\n" in str(
        reporter.asked[1][-1].content
    )


def test_a_rewrite_with_many_uncited_denials_draws_one_finding_with_the_count() -> None:
    report = _report(FIRST, background=f"{FIRST} {_UNKNOWN}")
    steps = "; ".join(f"step {i} is not shown" for i in range(5))
    rewrite = f"Routine 0x5a10 calls `{CALLED}` [ev_0109]; {steps}."
    found = agreement_violations(
        {"sentences": [_intro(_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=rewrite))]},
        passages_of(report, entries=_ledger()),
    )
    assert [(v.code, v.message) for v in found if v.path.startswith("sentences.")] == [
        (
            REWRITE_UNGROUNDED_CODE,
            "row 1: the rewrite of introduction denies something in 'step 0 is not shown'; "
            "'step 1 is not shown'; 'step 2 is not shown' and in 2 more clauses and no entry "
            "shown for the sentence follows any of them at once: in a rewrite of this sentence "
            "each denial is followed at once by the entry it rests on, cited in square "
            f"brackets, one of ev_0102, ev_0107, ev_0109. {_LEFT_OUT}",
        )
    ]


def test_a_summary_whose_every_finding_was_emptied_prints_as_one_written_alone() -> None:
    report = _report(FIRST)
    report.executive_summary = "The sample is a loader."
    report.key_findings = [KeyFinding(text="")]
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert (
        "# 1. Key findings · _Written by the report model_\n\nThe sample is a loader.\n\n"
        "_Written by the report model with no evidence cited; check it against the measured "
        "sections before quoting it._\n\n## 2."
    ) in bundle
