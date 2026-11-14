"""A passage shown as a source only never supplies the quote a keep stands on.

An agent's words the analyst report does not print are shown to the agreement round as a
source only. They are checked by nothing the round reads against, and the composer often
echoes them, so they hold no sentence up: no keep, of a verbatim sentence or of a passage the
round may rewrite, passes on a quote of them, nor a rewrite repeating its sentence, which is
a keep. They may be named as the source a verbatim sentence is dropped on, and as the source
a rewritable passage is listed or rewritten against (T-613). Every address, entry and name
here is a neutral synthetic value.
"""

from __future__ import annotations

from typing import Any

from malspark.reporting.section_agreement import (
    UNKNOWN_SOURCE_CODE,
    _sentences_of,
    agreement_violations,
    apply_rows,
    passages_of,
)
from tests.unit.reporting.test_the_judge_s_unprinted_words_are_a_source_of_the_round import (
    _SOURCE,
    _composed,
)

_QUOTE = "The loader checks for a debugger at 0x5b20"


def _conclusion_sentence() -> str:
    by_id = {p.id: p for p in passages_of(_composed())}
    return _sentences_of(by_id["conclusion"].text)[0].strip()


def _ended(row: dict[str, Any]) -> tuple[list[Any], dict[str, int]]:
    report = _composed()
    passages = passages_of(report)
    found = agreement_violations({"sentences": [row]}, passages)
    counts, _rows = apply_rows({"sentences": [row]}, passages)
    return [v for v in found if v.path.startswith("sentences.")], counts


def test_a_keep_of_a_rewritable_passage_on_its_quote_is_refused() -> None:
    refusals, counts = _ended(
        {
            "passage": "conclusion",
            "sentence": _conclusion_sentence(),
            "decision": "keep",
            "sources": [_SOURCE],
            "quote": _QUOTE,
        }
    )

    assert refusals
    assert counts["kept"] == 0


def test_a_rewrite_repeating_its_sentence_is_no_keep_on_it() -> None:
    sentence = _conclusion_sentence()
    refusals, counts = _ended(
        {
            "passage": "conclusion",
            "sentence": sentence,
            "decision": "rewrite",
            "sources": [_SOURCE],
            "rewrite": sentence,
        }
    )

    assert refusals
    assert counts["kept"] == 0


def test_a_keep_of_a_verbatim_sentence_on_its_quote_is_refused() -> None:
    refusals, counts = _ended(
        {
            "passage": "attack_claim.T1622",
            "sentence": "Routine 0x5b20 returns -1 when the BeingDebugged byte is set.",
            "decision": "keep",
            "sources": [_SOURCE],
            "quote": _QUOTE,
        }
    )

    assert refusals
    assert counts["kept"] == 0


def test_it_may_be_named_as_what_a_rewritable_passage_is_rewritten_against() -> None:
    refusals, _counts = _ended(
        {
            "passage": "conclusion",
            "sentence": _conclusion_sentence(),
            "decision": "rewrite",
            "sources": [_SOURCE],
            "rewrite": "The file is a loader that checks for a debugger at 0x5b20 [ev_0103].",
        }
    )

    assert UNKNOWN_SOURCE_CODE not in {v.code for v in refusals}
