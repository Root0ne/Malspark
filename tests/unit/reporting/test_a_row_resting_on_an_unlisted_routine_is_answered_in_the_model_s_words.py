"""A row resting on a routine no entry lists is answered in the model's words, either way.

A section 5 rewrite resting on a fact was the platform's: the sentence as written with the
fact's clause appended, whatever the model wrote, but where the model's words said the
listed code was not read. The fact of a routine a read routine calls whose code no entry
lists (``unread.N``) contradicts only a sentence that says that code was read; a model
rewriting on it the reverse way ("the one routine read calls it, and its code is not listed")
was discarded and the clause appended to the sentence as it stood, beside words saying the
opposite. Now a row resting on such a fact is answered in the model's own words in either
direction and checked as any rewrite; the platform appends nothing to it. Keyed on the fact's
kind, never on wording; every other fact's qualification is as before (T-736). Every address,
entry and tool name here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.section_agreement import (
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    passages_of,
)
from tests.unit.reporting.test_a_section_5_sentence_is_asked_against_the_ledger_s_own_facts import (  # noqa: E501
    ABSENT,
    ANSWERED,
    CLAUSE,
    FAILED,
    _ask,
    _ledger,
    _report,
    _Reporter,
    _row,
)

GATE = "The gate at 0x5a10 returns early [ev_0107]."


def _answered(model_words: str, sources: list[str] | None = None) -> tuple[str, Any]:
    report = _report()
    row = _row("evasion_antiforensics", ABSENT, sources or ["unread.1"], model_words)
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}), _ledger())
    ta = report.technical_analysis
    assert ta is not None and ta.evasion_antiforensics is not None
    return ta.evasion_antiforensics.body, done


def test_the_fact_is_the_kind_the_rows_rest_on() -> None:
    by_id = {p.id: p for p in passages_of(_report(), entries=_ledger())}
    assert by_id["unread.1"].unlisted_callee
    assert not any(p.unlisted_callee for i, p in by_id.items() if not i.startswith("unread."))


@pytest.mark.parametrize(
    "model_words",
    [
        # That the code was not read, and the reverse: that the routine read calls it.
        "No environment check is established in 0x5a10; 0x5a38, which it calls, has no listed "
        "code, so it was not read [ev_0107].",
        "The one routine read, 0x5a10, calls 0x5a38 and returns early on its result [ev_0107].",
    ],
)
def test_a_rewrite_on_an_unlisted_routine_stands_in_the_model_s_words(model_words: str) -> None:
    body, done = _answered(model_words)
    assert body == f"{GATE} {model_words}"
    assert CLAUSE not in body
    assert done.summary["rewritten"] == 1 and done.summary["qualified"] == 0
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


def test_a_rewrite_on_it_is_checked_as_any_rewrite() -> None:
    # Citing none of the ids its source cites: refused, and the platform writes nothing.
    body, done = _answered("The routine at 0x5a38 is called from 0x5a10.")
    assert body == f"{GATE} {ABSENT}"
    assert REWRITE_UNGROUNDED_CODE in done.tally.by_code
    assert done.summary["rewritten"] == 0


def test_another_fact_s_qualification_is_the_platform_s_as_before() -> None:
    report = _report()
    words = "The listing of 0x5a10 succeeded at once [ev_0107]."
    row = _row("string_resolution", FAILED, ["answered.1", "answered.2"], words)
    _ask(report, _Reporter({"sentences": [row]}), _ledger())
    ta = report.technical_analysis
    assert ta is not None and ta.string_resolution is not None
    assert ta.string_resolution.body == f"Names resolve at run time [ev_0107]. {ANSWERED}"
