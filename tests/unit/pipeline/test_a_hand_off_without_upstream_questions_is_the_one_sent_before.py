"""Where no upstream agent left a question, the stage hand-off is byte for byte the one sent before.

Pinned as sha256 digests of what the code before the questions were carried
wrote for the same answers, in both hand-off modes that show claims, and with
no upstream answer at all.
"""

from __future__ import annotations

import hashlib

import pytest

from malspark.pipeline.nodes import upstream_findings
from tests.unit.pipeline import handoff_isrs as h

EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
BEFORE = {
    ("with_questions", "findings"): (
        "f860b0fe879ece4679f61c737f6b353d79cd792849702446a07d514ae2a3f5b3"
    ),
    ("with_questions", "full"): "f860b0fe879ece4679f61c737f6b353d79cd792849702446a07d514ae2a3f5b3",
    ("claims_on_one_side", "findings"): (
        "900220d642f59f00a76497e83329013ced4780ea0aad47b6b31081eb4aa619bf"
    ),
    ("claims_on_one_side", "full"): (
        "c6fc650fe87548a3cf89bb4e4a535a5aa8bed2188ba1b52deace7feed790b06b"
    ),
    ("questions_only", "findings"): EMPTY,
    ("questions_only", "full"): "ad9d3747b594d6305ee46cf3fb7297c99ac23aa02aff375c07d00676d8499b77",
}


def _digest(sets: dict, mode: str) -> str:
    built = h.container()
    shown = upstream_findings(h.later_stage(built, mode), h.state(sets), built)  # type: ignore[arg-type]
    return hashlib.sha256(shown.encode()).hexdigest()


@pytest.mark.parametrize(("name", "mode"), sorted(BEFORE))
def test_the_same_answers_without_a_question_give_the_same_bytes(name: str, mode: str) -> None:
    assert _digest(h.without_questions(getattr(h, name)()), mode) == BEFORE[(name, mode)]


def test_no_upstream_answer_gives_what_it_gave_before() -> None:
    assert _digest({}, "findings") == EMPTY
    # ``full`` names every upstream agent, with no claims.
    assert _digest({}, "full") == BEFORE[("questions_only", "full")]
