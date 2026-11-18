"""The judge is shown the platform's confidence bands and asked to word its confidence by them.

The report prints the verdict's confidence through one fixed table, and the
judge's rationale worded the same number freely: two surfaces could state two
words for one number. The verdict question shows the bands of that table once;
nothing checks or rewrites what the judge writes.
"""

from __future__ import annotations

from malspark.agents.judge_agent import JUDGE_VERDICT_SYSTEM
from malspark.core import confidence_words
from malspark.core.confidence_words import CONFIDENCE_WORDS
from malspark.reporting.renderers import markdown


def test_the_verdict_question_carries_every_band_of_the_table() -> None:
    for floor, word in CONFIDENCE_WORDS:
        assert word in JUDGE_VERDICT_SYSTEM
        if floor:
            assert f"{floor:.2f}" in JUDGE_VERDICT_SYSTEM


def test_the_verdict_question_asks_for_the_band_of_the_number_it_gives() -> None:
    assert "use the band of the number you give under ``confidence``" in JUDGE_VERDICT_SYSTEM


def test_the_report_reads_the_same_table() -> None:
    assert markdown.confidence_word is confidence_words.confidence_word
    assert markdown.confidence_word(0.91) == "high confidence"
    assert markdown.confidence_word(None) == "not assessed"
