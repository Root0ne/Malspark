"""A later stage is handed the questions its upstream agents left open, after all of their claims.

The stage hand-off (``upstream_findings``) carried claims only, so a question
an earlier agent filed for whoever could answer it reached nobody who could.
The claims come first, exactly the bytes they were before; then one block of
every upstream agent's open questions, of every reason, each on one line in
the form every summary writes it. A hand-off mode that already carries the
upstream answers whole (``full``) gets no block, so no question is shown
twice.
"""

from __future__ import annotations

import hashlib

from malspark.core.config import ProfileDefinition, StageDefinition
from malspark.pipeline.nodes import (
    UPSTREAM_QUESTIONS_HEADING,
    upstream_findings,
)
from tests.unit.pipeline import handoff_isrs as h

# The hand-off of the same claims without any question, as the code before
# the questions were carried wrote it (the claims block of ``with_questions``).
CLAIMS = (
    "## Upstream findings\n"
    "\n"
    "### reader\n"
    "- the loader reads its settings from an embedded resource [—, confidence 0.80, ev_0003]\n"
    "- the settings name a second file written beside the loader [—, confidence 0.70, ev_0005]\n"
    "\n"
    "### lister\n"
    "- the file lists one exported routine [—, confidence 0.60, ev_0002]"
)

QUESTION_LINES = [
    "- reader: Which value does the loader expect as its first argument? | Why open: "
    "needs_sandbox_run | Detail: the argument check returns early without one | Would answer "
    "it: a run with an argument (tool kind detonation_request) | Evidence: ev_0003",
    "- reader: Which routine decodes the stored settings? | Why open: obfuscated | Would "
    "answer it: agent follower",
    "- lister: Does the exported routine take a callback? | Why open: tool_failed | Detail: "
    "the read timed out",
    "- lister, left open by helper: What does the second resource hold? | Why open: other | "
    "Detail: why open, as written: a word of its own",
]

# sha256 of the hand-off the code before this change wrote for each set, in
# ``findings`` mode (the sets' claims; the questions were never shown).
BEFORE = {
    "with_questions": "f860b0fe879ece4679f61c737f6b353d79cd792849702446a07d514ae2a3f5b3",
    "claims_on_one_side": "900220d642f59f00a76497e83329013ced4780ea0aad47b6b31081eb4aa619bf",
    "questions_only": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def _handoff(sets: dict, mode: str = "findings", **over: object) -> str:
    built = h.container(**over)
    return upstream_findings(h.later_stage(built, mode), h.state(sets), built)  # type: ignore[arg-type]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_the_heading_says_whose_words_the_lines_are_and_whose_labels() -> None:
    assert UPSTREAM_QUESTIONS_HEADING == (
        "Open questions the upstream agents left (unknowns, not absences; each in its filer's "
        "words, one line, under the platform's field labels):"
    )


def test_the_questions_follow_every_claim_as_one_block() -> None:
    shown = _handoff(h.with_questions())

    assert shown == "\n".join([CLAIMS, "", UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES])
    assert shown.count(UPSTREAM_QUESTIONS_HEADING) == 1


def test_the_claims_part_is_the_hand_off_sent_before_byte_for_byte() -> None:
    for name, digest in BEFORE.items():
        sets = getattr(h, name)()
        before = _handoff(h.without_questions(sets))
        assert _digest(before) == digest, name
        shown = _handoff(sets)
        if before:
            assert shown.startswith(before + "\n\n" + UPSTREAM_QUESTIONS_HEADING + "\n"), name
        else:
            assert shown.startswith(UPSTREAM_QUESTIONS_HEADING + "\n"), name
    assert _digest(CLAIMS) == BEFORE["with_questions"]


def test_every_reason_is_shown() -> None:
    shown = _handoff(h.with_questions())
    for reason in ("needs_sandbox_run", "obfuscated", "tool_failed", "other"):
        assert f"| Why open: {reason}" in shown


def test_an_agent_with_claims_and_no_question_and_one_with_questions_and_no_claim() -> None:
    shown = _handoff(h.claims_on_one_side())
    claims, questions = shown.split("\n\n" + UPSTREAM_QUESTIONS_HEADING + "\n")

    # The agent with no claim is still left out of the claims, as before.
    assert "### lister" not in claims
    assert _digest(claims) == BEFORE["claims_on_one_side"]
    assert questions.split("\n") == QUESTION_LINES[2:]


def test_with_no_upstream_claim_the_block_is_the_questions_alone() -> None:
    assert _handoff(h.questions_only()) == "\n".join(
        [UPSTREAM_QUESTIONS_HEADING, *QUESTION_LINES[:2]]
    )


def test_each_question_is_one_line_whatever_was_written() -> None:
    sets = h.claims_on_one_side()
    sets["lister"] = h.isr(
        "lister",
        [],
        [h.question("Which\nfile  is\tread\n- next?", "out_of_turns", detail="a\n\nb")],
    )
    shown = _handoff(sets)

    assert shown.endswith(
        "\n" + UPSTREAM_QUESTIONS_HEADING + "\n"
        "- lister: Which file is read - next? | Why open: out_of_turns | Detail: a b"
    )


def test_a_mode_that_hands_on_the_answers_whole_shows_no_question() -> None:
    for name in BEFORE:
        sets = getattr(h, name)()
        whole = _handoff(sets, "full")
        assert whole == _handoff(h.without_questions(sets), "full"), name
        assert UPSTREAM_QUESTIONS_HEADING not in whole, name


def test_no_hand_off_and_no_upstream_stay_empty() -> None:
    sets = h.with_questions()
    assert _handoff(sets, "none") == ""
    built = h.container()
    first = built.active_profile().stage("first")
    assert upstream_findings(first, h.state(sets), built) == ""  # type: ignore[arg-type]


def test_an_agent_listed_twice_upstream_gives_its_questions_once(monkeypatch) -> None:
    # A checked team puts an agent in one stage; a team handed in unchecked
    # that lists one twice still shows each of its questions once.
    built = h.container()
    first = built.active_profile().stage("first")
    second = StageDefinition(key="second", kind="analysis", agents=["reader"])
    later = h.later_stage(built).model_copy(update={"depends_on": ["first", "second"]})
    team = ProfileDefinition.model_construct(label="Team", stages=[first, second, later])
    monkeypatch.setattr(built, "active_profile", lambda: team)
    shown = upstream_findings(later, h.state(h.with_questions()), built)  # type: ignore[arg-type]
    questions = shown.split("\n\n" + UPSTREAM_QUESTIONS_HEADING + "\n")[1]

    assert questions.split("\n") == QUESTION_LINES
