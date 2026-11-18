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
import json
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers import HtmlRenderer, MarkdownRenderer
from malspark.reporting.renderers.bundle import bundle_json
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.section_agreement import (
    ANSWERS,
    ANSWERS_MASKED,
    AnswerChangedByMask,
    StoredAnswers,
    ask_section_agreement,
)
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
    replayed = _asked(again, StoredAnswers.of_record(copy.deepcopy(done.summary)))
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


@pytest.fixture
def configured_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """A configured value registered as the worker registers a job's settings."""
    from malspark.pipeline import events
    from tests.credential_shapes import lowercase_body

    key = lowercase_body(24)
    monkeypatch.setattr(events, "_SECRET_SCOPES", {})
    monkeypatch.setattr(events, "_SHORT_SECRETS", {})
    monkeypatch.setattr(events, "_FAILED_SCOPES", set())
    monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
    events.remember_secret_values([key], scope="job")
    return key


def test_the_stored_answers_are_masked_as_every_stored_model_answer_is(
    configured_key: str,
) -> None:
    from malspark.pipeline.events import safe_answer_text

    said = f"the lines shown say otherwise; {configured_key} is the note"
    first = {
        "sentences": [_in(_row(_UNKNOWN, "drop", [], reason=said))],
        configured_key: [said],
    }
    unread = f"no rows, sorry: {configured_key}"
    report = _background()
    done = _asked(report, _Reporter(first, unread))
    stored = done.summary[ANSWERS]
    assert configured_key not in repr(stored)
    # The one masking rule for a whole model answer, on each text the answer holds, its
    # layout kept: a row's words, a key the model wrote, an answer read as its text.
    masked = safe_answer_text(said)
    assert masked != said
    assert stored[0] == {
        "sentences": [_in(_row(_UNKNOWN, "drop", [], reason=masked))],
        safe_answer_text(configured_key): [masked],
    }
    assert stored[1] == safe_answer_text(unread)
    # The mask changed both: neither is handed back as the answer given.
    assert done.summary[ANSWERS_MASKED] == [True, True]
    with pytest.raises(AnswerChangedByMask, match="answer 1"):
        StoredAnswers.of_record(copy.deepcopy(done.summary))


def test_the_record_s_answers_the_mask_left_unchanged_are_handed_back_as_stored() -> None:
    report = _background()
    done = _asked(report, _Reporter(*_ANSWERS["unreadable first answer"]))
    stored = done.summary[ANSWERS]
    assert done.summary[ANSWERS_MASKED] == [False, False]
    # Re-applied, the record's answers are what the round is handed, as stored.
    reporter = StoredAnswers.of_record(copy.deepcopy(done.summary))
    handed = [asyncio.run(reporter.ask([], call="c", what="w")).content for _answer in range(3)]
    assert handed == [stored[0], json.dumps(stored[1]), json.dumps({"sentences": []})]


def test_an_answer_the_mask_changed_is_flagged_and_not_handed_back_as_given(
    configured_key: str,
) -> None:
    from tests.credential_shapes import password

    # An address with user information: the mask takes it out of the stored answer, so the
    # stored row no longer copies the sentence the round answered.
    said = f"The sample uploads to ftp://bot:{password()}@203.0.113.9/drop [ev_0107]."
    answer = {"sentences": [_row(said, "drop", [], reason="the lines shown say otherwise")]}
    plain = {"sentences": []}
    report = _report(said)
    done = _asked(report, _Reporter(answer, plain))
    stored = done.summary[ANSWERS]
    assert stored[0] != answer
    assert done.summary[ANSWERS_MASKED] == [True, *([False] * (len(stored) - 1))]
    # Re-applied, the changed answer is refused, never handed back as the answer given.
    with pytest.raises(AnswerChangedByMask, match="answer 1"):
        StoredAnswers.of_record(done.summary)


def test_a_record_with_any_answer_the_mask_changed_is_refused_before_the_round(
    configured_key: str,
) -> None:
    from tests.credential_shapes import password

    # The first answer is unchanged and opens the retry with a refused keep; the retry's
    # answer copies a sentence the mask changes.
    said = f"The sample uploads to ftp://bot:{password()}@203.0.113.9/drop [ev_0107]."
    plain = f"Routine 0x5a10 calls `{CALLED}` through a slot [ev_0109]."
    first = {
        "sentences": [
            _in(_row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=plain)),
            _in(_row(FIRST, "keep", [], reason="no source states it")),
        ]
    }
    second = {"sentences": [_row(said, "drop", [], reason="the lines shown say otherwise")]}

    def written() -> MalwareReport:
        return _report(said, background=f"{FIRST} {_UNKNOWN}")

    done = _asked(written(), _Reporter(first, second))
    assert done.summary[ANSWERS_MASKED] == [False, True]
    # Refused up front: no round runs on the first answer and then stops at the second.
    with pytest.raises(AnswerChangedByMask, match="answer 2"):
        StoredAnswers.of_record(copy.deepcopy(done.summary))
    with pytest.raises(AnswerChangedByMask, match="answer 2"):
        StoredAnswers(done.summary[ANSWERS], masked=done.summary[ANSWERS_MASKED])
    # Nothing of the first answer is applied: the report stands as written.
    again = written()
    with pytest.raises(AnswerChangedByMask, match="answer 2"):
        _asked(again, StoredAnswers.of_record(copy.deepcopy(done.summary)))
    assert again.model_dump() == written().model_dump()


def test_answers_handed_back_without_a_flag_each_are_refused() -> None:
    answers = list(_ANSWERS["answered in the retry"])
    for flags in ([], [False]):
        with pytest.raises(AnswerChangedByMask, match="no flag"):
            StoredAnswers(answers, masked=flags)
        with pytest.raises(AnswerChangedByMask, match="no flag"):
            StoredAnswers.of_record({ANSWERS: answers, ANSWERS_MASKED: flags})


def test_an_answer_the_mask_left_unchanged_is_handed_back_as_stored() -> None:
    answers = _ANSWERS["answered in the retry"]
    report = _background()
    done = _asked(report, _Reporter(*answers))
    assert done.summary[ANSWERS_MASKED] == [False, False]
    again = _background()
    replayed = _asked(again, StoredAnswers.of_record(copy.deepcopy(done.summary)))
    assert replayed.summary == done.summary
    assert again.model_dump() == report.model_dump()
