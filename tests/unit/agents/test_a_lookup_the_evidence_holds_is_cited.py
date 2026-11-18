"""A reputation answer the evidence already holds is cited, not looked up again.

Where an entry the analyst was given already holds a reputation answer for a
value (the pipeline's pack often holds the sample's lookup), the analyst cites
that entry by its evidence id; it looks a value up only where no entry holds
one. No lookup is forbidden. Every role that carries the sentence carries the
same one.
"""

from __future__ import annotations

import pytest

from malspark.agents.prompt_fragments import REPUTATION_LOOKUP_FRAGMENT
from malspark.agents.prompts import ANDROID_STATIC_PROMPT, REVERSER_PROMPT, TRIAGE_PROMPT


def _words(text: str) -> str:
    return " ".join(text.split())


def test_the_sentence_cites_an_entry_that_holds_the_answer_and_looks_up_only_without_one() -> None:
    said = _words(REPUTATION_LOOKUP_FRAGMENT)

    assert "already holds a reputation answer" in said
    assert "cite that entry by its evidence id" in said
    assert "look a value up only when no entry you were given holds one" in said
    assert "look the sample's hash up once" not in said


def test_the_static_analyst_s_prompt_carries_it() -> None:
    from malspark.agents.static_analyst import assemble_static_prompt

    prompt = assemble_static_prompt(None, "", (), for_a_clone=True)

    assert REPUTATION_LOOKUP_FRAGMENT in prompt


def test_the_network_analyst_whose_definition_has_a_reputation_tool_carries_it() -> None:
    from malspark.agents.network_analyst import assemble_network_prompt

    assert REPUTATION_LOOKUP_FRAGMENT in assemble_network_prompt("", (), for_a_clone=True)


@pytest.mark.parametrize(
    "prompt",
    [TRIAGE_PROMPT, ANDROID_STATIC_PROMPT, REVERSER_PROMPT],
    ids=["triage", "android_static", "reverser"],
)
def test_every_seeded_role_with_the_sentence_carries_the_same_one(prompt: str) -> None:
    assert _words(REPUTATION_LOOKUP_FRAGMENT) in _words(prompt)
    assert "hash up once" not in prompt
