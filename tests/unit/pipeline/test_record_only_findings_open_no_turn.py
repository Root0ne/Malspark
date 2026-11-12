"""In ``record_only`` the shared retry loops record every finding and ask none (T-672).

``validation.feedback`` set to ``record_only``: every validator still runs and
every finding is returned, marked not asked, and the loop sends no correction
turn. A finding that says the answer could not be read
(``REASKED_IN_EVERY_MODE_CODES``) is asked in both modes. In ``feed_back``, the
default, the loops behave as they always did.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from malspark.pipeline.validation import (
    ANALYST_CUT_CODE,
    REASKED_IN_EVERY_MODE_CODES,
    SECTION_CUT_CODE,
    UNGROUNDED_CAPABILITY_CODE,
    UNPARSED_ANSWER_CODE,
    ValidationTally,
    Violation,
    record_flagged_statements,
    retry_with_feedback,
    retry_with_feedback_sync,
)

CONTENT = "attck.unknown_id"


def settings_with(mode: str) -> Any:
    from malspark.core.settings_overrides import build_settings

    return build_settings({"validation": {"feedback": mode}})


@pytest.fixture
def record_only(monkeypatch: pytest.MonkeyPatch) -> None:
    built = settings_with("record_only")
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)


@pytest.fixture
def feed_back(monkeypatch: pytest.MonkeyPatch) -> None:
    built = settings_with("feed_back")
    monkeypatch.setattr("malspark.core.config.get_settings", lambda: built)


def _answers(*texts: str) -> tuple[list[list[Any]], Any]:
    sent: list[list[Any]] = []
    queue = list(texts)

    def run(turns: list[Any]) -> str:
        sent.append(list(turns))
        return queue.pop(0)

    return sent, run


def _finds(code: str) -> Any:
    def validator(value: str) -> list[Violation]:
        return [] if value == "fixed" else [Violation(code, f"wrong: {value}", "p")]

    return validator


def test_every_named_code_is_one_a_stage_raises() -> None:
    """The set names the unreadable-answer codes and nothing about content."""
    assert {
        UNPARSED_ANSWER_CODE,
        ANALYST_CUT_CODE,
        SECTION_CUT_CODE,
        "isr.claims_repeated",
        "verdict.cut_at_output_cap",
        "verdict.not_json",
        "composer.schema",
        "narrative.schema",
        "question.schema",
        "agreement.schema",
    } == set(REASKED_IN_EVERY_MODE_CODES)


class TestTheSyncLoop:
    def test_feed_back_sends_the_turn(self, feed_back: None) -> None:
        sent, run = _answers("first", "fixed")
        tally = ValidationTally()
        result, left, retries = retry_with_feedback_sync(
            run, ["ask"], [_finds(CONTENT)], parse=str, on_feedback=tally.count
        )
        assert (result, left, retries) == ("fixed", [], 1)
        assert len(sent) == 2
        assert tally.by_code == {CONTENT: 1}

    def test_record_only_sends_no_turn_and_records_the_finding_not_asked(
        self, record_only: None
    ) -> None:
        sent, run = _answers("first", "fixed")
        tally = ValidationTally()
        result, left, retries = retry_with_feedback_sync(
            run, ["ask"], [_finds(CONTENT)], parse=str, on_feedback=tally.count
        )
        assert (result, retries) == ("first", 0)
        assert len(sent) == 1
        assert [(v.code, v.message, v.asked) for v in left] == [(CONTENT, "wrong: first", False)]
        assert tally.by_code == {}
        tally.record_unresolved("a", left)
        assert tally.unresolved[0]["asked"] == "false"

    def test_record_only_still_asks_an_answer_that_could_not_be_read(
        self, record_only: None
    ) -> None:
        sent, run = _answers("first", "fixed")
        result, left, retries = retry_with_feedback_sync(
            run, ["ask"], [_finds(UNPARSED_ANSWER_CODE)], parse=str
        )
        assert (result, left, retries) == ("fixed", [], 1)
        assert len(sent) == 2

    def test_record_only_asks_only_the_unreadable_finding_of_a_mixed_answer(
        self, record_only: None
    ) -> None:
        sent, run = _answers("first", "second")

        def both(value: str) -> list[Violation]:
            found = [Violation(CONTENT, f"wrong: {value}", "p")]
            if value == "first":
                found.append(Violation(ANALYST_CUT_CODE, "cut", ""))
            return found

        result, left, retries = retry_with_feedback_sync(run, ["ask"], [both], parse=str)
        assert (result, retries) == ("second", 1)
        question = str(sent[1][-1].content)
        assert ANALYST_CUT_CODE in question
        assert CONTENT not in question
        assert [(v.code, v.asked) for v in left] == [(CONTENT, False)]


@pytest.mark.asyncio
class TestTheAsyncLoop:
    @staticmethod
    def _async(run: Any) -> Any:
        async def call(turns: list[Any]) -> str:
            return run(turns)

        return call

    async def test_feed_back_sends_the_turn(self, feed_back: None) -> None:
        sent, run = _answers("first", "fixed")
        result, left, retries = await retry_with_feedback(
            self._async(run), ["ask"], [_finds(CONTENT)], parse=str
        )
        assert (result, left, retries) == ("fixed", [], 1)
        assert len(sent) == 2

    async def test_record_only_sends_no_turn(self, record_only: None) -> None:
        sent, run = _answers("first", "fixed")
        shown: list[Violation] = []
        result, left, retries = await retry_with_feedback(
            self._async(run), ["ask"], [_finds(CONTENT)], parse=str, on_feedback=shown.extend
        )
        assert (result, retries) == ("first", 0)
        assert len(sent) == 1
        assert not shown
        assert [(v.code, v.asked) for v in left] == [(CONTENT, False)]

    async def test_record_only_still_asks_a_section_the_cap_cut(self, record_only: None) -> None:
        sent, run = _answers("first", "fixed")
        result, left, retries = await retry_with_feedback(
            self._async(run), ["ask"], [_finds(SECTION_CUT_CODE)], parse=str
        )
        assert (result, left, retries) == ("fixed", [], 1)
        assert len(sent) == 2

    async def test_record_only_maps_the_leftovers_before_the_caller_s_answered(
        self, record_only: None
    ) -> None:
        sent, run = _answers("first")
        seen: list[list[Violation]] = []

        def answered(left: list[Violation], _told: list[Violation]) -> list[Violation]:
            seen.append(list(left))
            return left

        await retry_with_feedback(
            self._async(run), ["ask"], [_finds(CONTENT)], parse=str, answered=answered
        )
        assert [v.asked for v in seen[0]] == [False]


class TestFlaggedStatements:
    def _violation(self, *, asked: bool = True) -> Violation:
        return Violation(
            UNGROUNDED_CAPABILITY_CODE,
            "over-claims",
            "keylogging",
            quoted=("It logs keys.",),
            asked=asked,
        )

    def test_a_finding_recorded_not_asked_is_flagged_not_asked(self) -> None:
        report = SimpleNamespace(flagged_statements=[])
        record_flagged_statements(report, [self._violation(asked=False)])
        assert [row.asked for row in report.flagged_statements] == [False]

    def test_an_asked_finding_is_flagged_as_asked_as_before(self) -> None:
        report = SimpleNamespace(flagged_statements=[])
        record_flagged_statements(report, [self._violation()])
        record_flagged_statements(report, [self._violation()], asked=False)
        assert [row.asked for row in report.flagged_statements] == [True, False]
