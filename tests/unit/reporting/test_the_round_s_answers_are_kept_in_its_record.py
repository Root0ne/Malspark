"""The agreement round's answers are kept in the run's record, and re-applied give its ends.

The round's last answer was stored nowhere: the worker log keeps request bodies only, and
the run record the counts and the finding rows. A stored run could not be put through the
round again, so no change to it could be measured on what the model really answered. Now
every answer of the round, the first and each retry, as parsed, is kept whole beside the
round's counts in the run summary (``section_agreement.answers``), shown to no model and
printed nowhere a person reads; the round's own code re-applies them with no model call and
reproduces its counts, its records and the report (T-736). Every name here is a neutral
synthetic value.
"""

from __future__ import annotations

import asyncio
import copy
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.bundle import bundle_json
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import ANSWERS, StoredAnswers, ask_section_agreement
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    CALLED,
    _ledger,
    _report,
    _Reporter,
    _row,
)

FIRST = "The gate reads a host mode [ev_0107]."
# A key no check reads, kept with the answer as parsed and printed nowhere.
_UNREAD = "unread-note-5c1e"


def _background() -> MalwareReport:
    return _report(FIRST, background=f"{FIRST} {_UNKNOWN}")


def _asked(report: MalwareReport, reporter: Any) -> Any:
    ledger = _ledger()
    return asyncio.run(
        ask_section_agreement(
            reporter,
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )


def _in(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "passage": "introduction"}


_PLAIN = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."
_ANSWERS: dict[str, tuple[Any, ...]] = {
    "answered in the retry": (
        {"sentences": [], "note": _UNREAD},
        {"sentences": [_in(_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_PLAIN))]},
    ),
    "refused, then nothing": (
        {"sentences": [_in(_row(_UNKNOWN, "keep", [], reason="no source states it"))]},
        {"sentences": []},
    ),
    "unreadable first answer": ("no rows, sorry", {"sentences": []}),
    "a bare list of rows": (
        [_in(_row(FIRST, "keep", ["ledger.1"]))],
        [_in(_row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise"))],
    ),
}


@pytest.mark.parametrize("answers", list(_ANSWERS.values()), ids=list(_ANSWERS))
def test_the_stored_answers_re_applied_give_the_round_s_counts_records_and_report(
    answers: tuple[Any, ...],
) -> None:
    report = _background()
    done = _asked(report, _Reporter(*answers))
    stored = done.summary[ANSWERS]
    # Every answer, as parsed, whole: an object as read, one that could not be read as its text.
    assert len(stored) == done.tally.retries + 1 == 2
    for kept, given in zip(stored, answers, strict=True):
        assert kept == given
    # Re-applied through the round's own code, with no model call.
    again = _background()
    replayed = _asked(again, StoredAnswers(copy.deepcopy(stored)))
    assert replayed.summary == done.summary
    assert replayed.tally.to_dict() == done.tally.to_dict()
    assert again.model_dump() == report.model_dump()


def test_the_answers_are_shown_to_no_model_and_printed_nowhere_a_person_reads() -> None:
    report = _background()
    reporter = _Reporter(*_ANSWERS["answered in the retry"])
    done = _asked(report, reporter)
    assert _UNREAD in repr(done.summary[ANSWERS])
    # The question and the retry's findings: the model's own answer, never the record.
    assert len(reporter.asked) == 2
    assert all(_UNREAD not in str(turns[-1].content) for turns in reporter.asked)
    report.run_summary = {"section_agreement": dict(done.summary)}
    for printed in (
        MarkdownRenderer(layout=ANALYST).render(report),
        MarkdownRenderer(layout=BUNDLE).render(report),
        HtmlRenderer(layout=BUNDLE).render(report, embed_figures=False),
        bundle_json(report),
    ):
        assert _UNREAD not in printed
