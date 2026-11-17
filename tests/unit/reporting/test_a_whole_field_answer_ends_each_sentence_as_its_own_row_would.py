"""A keep or a drop copying a whole field ends each of its sentences as its own row would (T-719).

An answer whose copied text is the whole field is found, however many sentences the field
holds. It answers each of them: every sentence ends exactly as the same decision given
sentence by sentence would end it, in every kind of passage and on every path. The first
reading acted on the whole span where one sentence was refused: a closing paragraph of two
sentences, kept by one row, lost both where one sentence's keep alone was refused. Each case
here answers a field both ways and compares the report, the counts and the records. Every
value is made up.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import C2Channel, MalwareReport
from malspark.reporting.section_agreement import (
    _sentence_units,
    agreement_violations,
    apply_rows,
    passages_of,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _UNKNOWN,
    _ledger,
    _report,
)
from tests.unit.reporting.test_a_text_printed_as_written_is_shown_to_the_agreement_round import (
    report_of,
)

FIRST = "The analysis covers one file."
BODY = "Routine 0x5a10 reads a host mode through a slot [ev_0107]."
TWO = "Not established. A key of 16 bytes is read [ev_0107]."


def _closing() -> MalwareReport:
    return _report(f"{FIRST} {_UNKNOWN}")


def _section_5() -> MalwareReport:
    report = _report(FIRST)
    assert report.technical_analysis is not None
    sub = report.technical_analysis.string_resolution
    assert sub is not None
    sub.body = f"{BODY} {_UNKNOWN}"
    return report


def _cell() -> MalwareReport:
    report = _report(FIRST)
    report.c2_channels = [C2Channel(name="TLS channel", encryption=TWO)]
    return report


# Each field: how its report is built, the passage, and whether the run's ledger is read.
CASES: dict[str, tuple[Callable[[], MalwareReport], str, bool]] = {
    "closing passage": (_closing, "limitations", True),
    "section 5 with a held sentence": (_section_5, "string_resolution", True),
    "verbatim passage": (report_of, "statements.T1057.1", False),
    "value cell": (_cell, "communications.1.encryption", True),
}
ANSWERS: dict[str, dict[str, Any]] = {
    "keep": {"decision": "keep", "sources": [], "reason": "no source speaks of it"},
    "keep on a source": {
        "decision": "keep",
        "sources": ["string_resolution"],
        "quote": "reads a host mode through a slot",
    },
    "drop": {"decision": "drop", "sources": [], "reason": "no source states it"},
}


def _ended(make: Callable[[], MalwareReport], pid: str, ledger: bool, sentences: list[str]):
    report = make()
    entries = _ledger() if ledger else []
    passages = passages_of(report, entries=entries)
    citable = [str(e.id) for e in entries]
    texts = EntryTexts.from_ledger(entries) if ledger else None
    rows = [{"passage": pid, "sentence": s, **_ANSWER} for s in sentences]
    found = agreement_violations({"sentences": rows}, passages, citable, None, texts)
    counts, records = apply_rows({"sentences": rows}, passages, citable=citable, entries=texts)

    def plain(v: Any) -> tuple[str, str, str, str]:
        return (v.code, v.subject, re.sub(r"row \d+", "row N", v.message), v.stood)

    return (
        report.model_dump(mode="json", exclude={"generated_at"}),
        counts,
        sorted(map(plain, records)),
        sorted(set(map(plain, found))),
    )


_ANSWER: dict[str, Any] = {}


@pytest.mark.parametrize("answer", list(ANSWERS))
@pytest.mark.parametrize("case", list(CASES))
def test_a_whole_field_answer_ends_as_its_sentences_answered_apart(case: str, answer: str) -> None:
    make, pid, ledger = CASES[case]
    text = next(p for p in passages_of(make()) if p.id == pid).text
    starts, _ends = _sentence_units(text)
    sentences = [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]
    assert len(sentences) == 2
    _ANSWER.clear()
    _ANSWER.update(ANSWERS[answer])
    whole = _ended(make, pid, ledger, [text])
    apart = _ended(make, pid, ledger, sentences)
    assert whole[0] == apart[0]
    assert whole[1] == apart[1]
    assert whole[2] == apart[2]
    assert whole[3] == apart[3]


def test_a_closing_keep_refused_for_one_sentence_keeps_the_other() -> None:
    report = _closing()
    ledger = _ledger()
    row = {"passage": "limitations", "sentence": f"{FIRST} {_UNKNOWN}", **ANSWERS["keep"]}
    apply_rows(
        {"sentences": [row]},
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    assert report.technical_analysis is not None
    limitations = report.technical_analysis.analyst_limitations
    assert limitations is not None and limitations.body == FIRST


def test_a_whole_field_row_a_retry_leaves_unanswered_stays_as_its_sentences_would() -> None:
    from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (  # noqa: E501
        _ask,
        _Reporter,
    )

    text = f"{BODY} {_UNKNOWN}"

    def ended(sentences: list[str]) -> tuple[str, list[str]]:
        report = _report(FIRST, background=text)
        rows = [{"passage": "introduction", "sentence": s, **ANSWERS["keep"]} for s in sentences]
        done = _ask(report, _Reporter({"sentences": rows}, {"sentences": []}))
        records = [r["message"] for r in done.tally.unresolved if r["code"] == "agreement.dropped"]
        return report.intro_background, records

    # The retry answers nothing: the first answer's row for the held sentence is its last,
    # whole or apart, and the sentence is left out as refused, not as never answered.
    whole, apart = ended([text]), ended([BODY, _UNKNOWN])
    assert whole == apart
    assert whole[0] == BODY
    assert "its last answer, a keep, was refused" in whole[1][0]
