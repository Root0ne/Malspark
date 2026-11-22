"""A value's state restated word for word in the bracket after it states the value's publish state.

A value's text runs to the next place a value is written, so a state that names
another value (the address a host resolved to) cut the host's text short at that
address: the restatement was read only up to it, and a writer who restated the
table's answer word for word was told the state was not stated. A bracket right
after the value that holds the state, the state without its leading ``no:``, or
that under the state's own name, word for word, is read whole, whatever values
and brackets it holds, and the text after it is read as any value's text is.
Anything else is read as before: a restatement that changes the state's words or
stops short, a state restated after another value, a published or kept claim
after it. Every value is synthetic.
"""

from __future__ import annotations

import pytest

from malspark.pipeline.validation import _unstated_values
from malspark.reporting.publish_parts import answer_state, refused

HOST = "c.example.net"
RESOLVED = "192.0.2.94"
HOST_PARTS = (
    "the publish rule counted its requests as made by a process the report does not list "
    f"(procid 50) and the flows to {RESOLVED} (an address it resolved to) as made by a "
    "process the report does not list (procid 50)",
    "the judge did not keep it as an indicator",
)
NESTED = "198.51.100.7"
NESTED_PARTS = (
    "the publish rule found its flows made by svc.exe (procid 12, a child of "
    "loader.exe [procid 8]) which the report does not list",
    "no model kept it as an indicator",
)
OTHER = "203.0.113.9"
OTHER_PARTS = ("the publish rule found no flow row to it", "no model kept it as an indicator")
ANSWERS = {
    HOST: refused(*HOST_PARTS),
    NESTED: refused(*NESTED_PARTS),
    OTHER: refused(*OTHER_PARTS),
}


def _answer(_kind: str, value: str) -> str:
    return ANSWERS.get(value, "")


def _flagged(sentence: str) -> list[str]:
    return [value for _kind, value, _state in _unstated_values(sentence, _answer)]


def _state(value: str) -> str:
    return str(answer_state(ANSWERS[value]))


def _forms(value: str) -> list[str]:
    state = _state(value)
    return [f"({state})", f"({state[4:]})", f"(publish state: {state[4:]})"]


FORMS = ["whole", "reason", "named"]


@pytest.mark.parametrize("value", [HOST, NESTED, OTHER])
@pytest.mark.parametrize("form", range(3), ids=FORMS)
def test_a_state_restated_word_for_word_after_its_value_states_it(value: str, form: int) -> None:
    written = _forms(value)[form]
    assert value not in _flagged(f"The sample reaches {value} {written} during the run.")


@pytest.mark.parametrize("form", range(3), ids=FORMS)
def test_a_restatement_in_square_brackets_or_another_case_states_it(form: int) -> None:
    written = _forms(HOST)[form]
    square = "[" + written[1:-1] + "]"
    assert HOST not in _flagged(f"The sample reaches {HOST} {square}.")
    assert HOST not in _flagged(f"The sample reaches {HOST.upper()} {written.upper()}.")


@pytest.mark.parametrize("form", range(3), ids=FORMS)
def test_two_values_each_with_its_own_state_in_one_sentence(form: int) -> None:
    sentence = f"The sample reaches {HOST} {_forms(HOST)[form]} and {OTHER} {_forms(OTHER)[form]}."
    flagged = _flagged(sentence)
    assert HOST not in flagged
    assert OTHER not in flagged


class TestReadAsBefore:
    @pytest.mark.parametrize("form", range(1, 3), ids=FORMS[1:])
    def test_a_state_restated_after_another_value(self, form: int) -> None:
        assert OTHER in _flagged(f"The sample reaches {OTHER} {_forms(HOST)[form]}.")

    @pytest.mark.parametrize("form", range(1, 3), ids=FORMS[1:])
    def test_a_restatement_cut_short(self, form: int) -> None:
        written = _forms(HOST)[form]
        cut = written[: written.index(", and the judge")] + ")"
        assert HOST in _flagged(f"The sample reaches {HOST} {cut} during the run.")

    @pytest.mark.parametrize("form", range(1, 3), ids=FORMS[1:])
    def test_a_restatement_that_changes_the_state_s_words(self, form: int) -> None:
        written = _forms(HOST)[form].replace("does not list", "lists", 1)
        assert HOST in _flagged(f"The sample reaches {HOST} {written} during the run.")

    @pytest.mark.parametrize("form", range(1, 3), ids=FORMS[1:])
    @pytest.mark.parametrize("claim", ["so it is published", "so it is kept as an indicator"])
    def test_the_opposite_decision_after_the_restatement(self, form: int, claim: str) -> None:
        sentence = f"The sample reaches {HOST} {_forms(HOST)[form]}, {claim}."
        assert HOST in _flagged(sentence)

    def test_a_restatement_that_does_not_follow_the_value(self) -> None:
        sentence = f"The sample reaches {HOST} twice {_forms(HOST)[1]}."
        assert HOST in _flagged(sentence)
