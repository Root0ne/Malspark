"""A refusing reason that holds a comma of its own is read to the end of its clause group.

A writer who restates a value's state outside brackets ("X: <reason>", "X and
<reason>", "X because <reason>, so …") restates it whatever commas the reason
holds; the restatement is read to the end of the ";" clause group as well as to
the first comma. A claim that the value is published or kept, another value's
reason, or one value's state said for two values stays refused. Every value is
synthetic.
"""

from __future__ import annotations

import pytest

from malspark.pipeline.validation import _unstated_values
from malspark.reporting.publish_parts import refused

ONION = "abcdefg.onion"
ONION_REASON = (
    'the publish rule found that it fails the host test: its .onion label "abcdefg" is 7 '
    "characters long, and this rule accepts 16 or 56"
)
NAME = "cdn.example.net"
TWO_PARTS = ("the publish rule found no flow row to it", "no model kept it as an indicator")
TWO_REASON = ", and ".join(TWO_PARTS)
RESOLVER = "8.8.8.8"
RESOLVER_REASON = "a public DNS resolver, which this run never publishes, whoever names it"

ANSWERS = {
    ONION: refused(ONION_REASON),
    NAME: refused(*TWO_PARTS),
    RESOLVER: refused(RESOLVER_REASON),
}


def _flagged(sentence: str) -> list[str]:
    return [value for _kind, value, _state in _unstated_values(sentence, _answer)]


def _answer(_kind: str, value: str) -> str:
    return ANSWERS.get(value, "no: not in this table")


@pytest.mark.parametrize(("value", "reason"), [(ONION, ONION_REASON), (NAME, TWO_REASON)])
@pytest.mark.parametrize(
    "form",
    [
        "The sample reaches {value}: {reason}.",
        "The sample reaches {value} and {reason}.",
        "The sample reaches {value} because {reason}, so it is withheld.",
    ],
)
def test_a_restatement_outside_brackets_states_the_value_s_state(
    form: str, value: str, reason: str
) -> None:
    assert _flagged(form.format(value=value, reason=reason)) == []


class TestAContradictionStaysRefused:
    def test_another_value_s_reason_after_the_comma(self) -> None:
        sentence = (
            f"The sample reaches {NAME}: the publish rule found no flow row to it, and "
            f"{RESOLVER} is {RESOLVER_REASON}."
        )
        assert NAME in _flagged(sentence)

    def test_one_state_said_for_two_values(self) -> None:
        sentence = f"The sample reaches {NAME} and {RESOLVER}: {RESOLVER_REASON}."
        assert NAME in _flagged(sentence)

    @pytest.mark.parametrize("claim", ["so it is published", "so it is kept as an indicator"])
    def test_the_opposite_decision_after_the_comma(self, claim: str) -> None:
        assert _flagged(f"The sample reaches {NAME}: {TWO_REASON}, {claim}.") == [NAME]
        assert _flagged(f"The sample holds {ONION}: {ONION_REASON}, {claim}.") == [ONION]
