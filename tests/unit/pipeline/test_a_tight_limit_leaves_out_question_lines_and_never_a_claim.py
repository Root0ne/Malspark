"""Under the hand-off's character limit the questions take only the room the claims leave.

Fitted line by line, in order, never a line cut: a line is shown while the
block, with the line counting what is left out, still fits. Where not even the
heading, one line and that count fit, there is no block. A limit the claims
alone pass cuts the claims as before and adds no question.
"""

from __future__ import annotations

import re

from malspark.pipeline.nodes import (
    UPSTREAM_QUESTIONS_HEADING,
    UPSTREAM_QUESTIONS_LEFT_OUT,
    upstream_findings,
)
from tests.unit.pipeline import handoff_isrs as h
from tests.unit.pipeline.test_the_hand_off_shows_the_upstream_questions_after_every_claim import (
    CLAIMS,
    QUESTION_LINES,
)

FULL = "\n".join([CLAIMS, "", UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES])
LEFT_OUT = re.compile(
    r"^- (\d+) more open question\(s\) are not shown here \(the upstream block's room\)$"
)


def _handoff(sets: dict, limit: int) -> str:
    built = h.container(reporting={"upstream_findings_max_chars": limit})
    return upstream_findings(h.later_stage(built), h.state(sets), built)  # type: ignore[arg-type]


def _block(shown: int) -> str:
    lines = [UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES[:shown]]
    if shown < len(QUESTION_LINES):
        lines.append(UPSTREAM_QUESTIONS_LEFT_OUT.format(count=len(QUESTION_LINES) - shown))
    return "\n".join(lines)


def test_the_tail_line_s_words() -> None:
    assert UPSTREAM_QUESTIONS_LEFT_OUT.format(count=3) == (
        "- 3 more open question(s) are not shown here (the upstream block's room)"
    )


def test_every_limit_keeps_every_claim_and_cuts_only_question_lines() -> None:
    sets = h.with_questions()
    seen_counts: set[int] = set()
    for limit in range(len(CLAIMS) - 50, len(FULL) + 2):
        shown = _handoff(sets, limit)
        before = _handoff(h.without_questions(sets), limit)
        if limit < len(CLAIMS):
            # The claims alone pass the limit: cut as before, no question.
            assert shown == before, limit
            assert shown.endswith("[upstream findings truncated]"), limit
            continue
        assert before == CLAIMS, limit
        if shown == CLAIMS:
            # Not even the heading, one line and the count fit.
            assert len("\n\n" + _block(1)) > limit - len(CLAIMS), limit
            seen_counts.add(0)
            continue
        assert shown.startswith(CLAIMS + "\n\n"), limit
        assert len(shown) <= limit, limit
        lines = shown[len(CLAIMS) + 2 :].split("\n")
        assert lines[0] == UPSTREAM_QUESTIONS_HEADING, limit
        tail = LEFT_OUT.match(lines[-1])
        questions = lines[1:-1] if tail else lines[1:]
        assert questions == QUESTION_LINES[: len(questions)], limit
        if tail:
            assert int(tail.group(1)) == len(QUESTION_LINES) - len(questions), limit
            # The next line would not have fitted, with or without the count.
            more = len(questions) + 1
            assert len(CLAIMS) + 2 + len(_block(more)) > limit, limit
        else:
            assert questions == QUESTION_LINES, limit
        seen_counts.add(len(questions))
    # The range walks through no block, every partial block and the whole one.
    assert seen_counts == {0, 1, 2, 3, 4}


def test_at_the_whole_length_every_question_is_shown_with_no_count() -> None:
    assert _handoff(h.with_questions(), len(FULL)) == FULL
    assert _handoff(h.with_questions(), len(FULL) - 1) != FULL


def test_with_no_claim_the_questions_take_the_whole_limit() -> None:
    whole = _handoff(h.questions_only(), 100_000)
    assert whole == "\n".join([UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES[:2]])
    assert _handoff(h.questions_only(), len(whole)) == whole
    assert _handoff(h.questions_only(), len(_block(1)) - 1) == ""
