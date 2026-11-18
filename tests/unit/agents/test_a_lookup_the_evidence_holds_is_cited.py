"""A reputation answer the evidence already holds is cited, not looked up again.

Where an entry the analyst was given already holds a reputation answer for a
value (the pipeline's pack often holds the sample's lookup), the analyst cites
that entry by its evidence id rather than asking again; a lookup adds what no
entry holds. No lookup is forbidden: the sentence never tells an agent when it
may not call a tool. Every role that carries the sentence carries the same one.
"""

from __future__ import annotations

import pytest

from malspark.agents.prompt_fragments import REPUTATION_LOOKUP_FRAGMENT
from malspark.agents.prompts import ANDROID_STATIC_PROMPT, REVERSER_PROMPT, TRIAGE_PROMPT


def _words(text: str) -> str:
    return " ".join(text.split())


def test_the_sentence_cites_an_entry_that_holds_the_answer_and_a_lookup_adds_to_it() -> None:
    said = _words(REPUTATION_LOOKUP_FRAGMENT)

    assert "already holds a reputation answer" in said
    assert "cite that entry by its evidence id rather than asking again" in said
    assert "a lookup adds what no entry you were given holds" in said
    assert "look the sample's hash up once" not in said


# Words that would make the sentence a limit on when a tool may be called.
_A_LIMIT_ON_A_CALL = ("only when", "only if", "only where", "never", "do not look", "don't look")


def _reputation_paragraph(prompt: str) -> str:
    start = prompt.index("When a reputation tool is among your tools")
    end = prompt.find("\n\n", start)
    return _words(prompt[start : end if end != -1 else len(prompt)])


@pytest.mark.parametrize(
    "prompt",
    [REPUTATION_LOOKUP_FRAGMENT, TRIAGE_PROMPT, ANDROID_STATIC_PROMPT, REVERSER_PROMPT],
    ids=["fragment", "triage", "android_static", "reverser"],
)
def test_the_reputation_sentence_sets_no_limit_on_a_lookup(prompt: str) -> None:
    """An agent's tool calls are never restricted: the sentence says what to cite
    and how to weigh an answer, never when a lookup may not be made."""
    said = _reputation_paragraph(prompt).lower()

    for words in _A_LIMIT_ON_A_CALL:
        assert words not in said, words


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
