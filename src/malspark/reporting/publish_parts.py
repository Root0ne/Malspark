"""A publish answer that refuses a value, given as the parts it is written from.

The function that writes a ``no:`` answer (``stix_renderer.publish_answer``)
gives it as parts: the **refusing parts**, each test that closed a way the rule
could have published the value, each whole and in the order the rule asks
them; and the **facts**, what a record holds of the value that did not decide
(what a tool recorded, who listed it, who mentioned it), in order. The printed
answer is composed from the parts (:class:`PublishAnswer`) and nothing reads
it back: a part may hold ``;`` or ``,`` (a URL, a ``passed_to`` phrase, an
entry list) and is never split, and a refusing part is never cut or dropped.

Every reader composes from the parts:

* the **state** (:func:`answer_state`) is the refusing parts alone: what a
  cell beside a value prints where the same render carries the whole answer,
  a mark's label, the writers' retry feedback and the reason a restatement is
  read against;
* the **whole answer** (:func:`told_whole`) is every refusing part whole, then
  the facts in order until the first that does not fit the bound, that one and
  every later one counted: what the recommendation retry and the export's
  decline say;
* a cell in a layout that prints the whole answer nowhere else is its only
  carrier and prints it with no bound: every refusing part whole, then every
  fact, the answer's own composition.

An answer read from a stored file is plain text with no parts: it prints as
stored, and every reader takes it as before, its state the text before the
first ``;`` and its whole answer bounded as a finding value is.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

# What joins two refusing parts, and what joins a fact to what comes before it.
REFUSING_JOINER = ", and "
FACT_JOINER = "; "


class PublishAnswer(str):
    """A ``no:`` answer as the report prints it, with the parts it is composed of.

    ``refusing`` holds each test that closed a way to publish the value, whole,
    in the order the rule asks them; ``facts`` what the record holds of it that
    did not decide, in order. ``bracketed`` prints the first fact in brackets
    right after the refusing parts, as the answer of a value no model kept
    prints who mentions it; every other fact follows a ``;``. The text is the
    composition, built here and nowhere else.
    """

    refusing: tuple[str, ...]
    facts: tuple[str, ...]
    bracketed: bool

    def __new__(
        cls, refusing: Iterable[str], facts: Iterable[str] = (), *, bracketed: bool = False
    ) -> PublishAnswer:
        held = tuple(part for part in refusing if part)
        said = tuple(fact for fact in facts if fact)
        if not held:
            raise ValueError("a refused answer names the test that refused it")
        text = "no: " + REFUSING_JOINER.join(held)
        for index, fact in enumerate(said):
            text += f" ({fact})" if bracketed and index == 0 else f"{FACT_JOINER}{fact}"
        answer = super().__new__(cls, text)
        answer.refusing = held
        answer.facts = said
        answer.bracketed = bracketed and bool(said)
        return answer

    def __reduce__(self) -> tuple[Any, ...]:
        return (_rebuilt, (self.refusing, self.facts, self.bracketed))


def _rebuilt(refusing: tuple[str, ...], facts: tuple[str, ...], bracketed: bool) -> PublishAnswer:
    return PublishAnswer(refusing, facts, bracketed=bracketed)


def refused(*refusing: str, facts: Iterable[str] = (), bracketed: bool = False) -> PublishAnswer:
    """``no: <refusing parts>[; <facts>]``, as :class:`PublishAnswer` composes it."""
    return PublishAnswer(refusing, facts, bracketed=bracketed)


def refusing_parts(answer: Any) -> tuple[str, ...] | None:
    """The refusing parts of an answer, or ``None`` for one read without its parts."""
    return answer.refusing if isinstance(answer, PublishAnswer) else None


def answer_state(answer: Any) -> str:
    """What refused the value: the refusing parts, as an answer of its own.

    An answer with no parts (read from a stored file) is read as before: its
    text before the first ``;``.
    """
    if isinstance(answer, PublishAnswer):
        return PublishAnswer(answer.refusing)
    return str(answer or "").split(";", 1)[0].strip()


def told(state: Any) -> str:
    """A state as a finding row tells it: whole where it is made of parts, and bounded as a
    model-written value is where it is not.

    The parts are written by the publish rule, and they carry values the platform did not
    write (a process name, a URL, an analyst's name); a part is never cut, and it is made
    fit to store and print as any finding value is, on one line and with every operator
    credential kept out (``events.safe_finding_value``). Escaping for a surface stays with
    each surface."""
    from malspark.pipeline.events import safe_finding_value

    return safe_finding_value(state, whole=isinstance(state, PublishAnswer))


def whole_answer(
    answer: PublishAnswer, limit: int | None = None, word: Callable[[str], str] = str
) -> str:
    """The whole answer within ``limit`` characters, each part written by ``word``.

    Every refusing part whole, never cut; then each fact in order while the
    text stays within the bound (``events.FINDING_VALUE_LIMIT`` by default);
    the first fact that does not fit and every later one are counted ("; and 2
    more facts").
    """
    from malspark.pipeline.events import FINDING_VALUE_LIMIT

    bound = FINDING_VALUE_LIMIT if limit is None else limit
    said = "no: " + REFUSING_JOINER.join(word(part) for part in answer.refusing)
    dropped = 0
    for index, fact in enumerate(answer.facts):
        written = word(fact)
        piece = f" ({written})" if answer.bracketed and index == 0 else f"{FACT_JOINER}{written}"
        if dropped or len(said) + len(piece) > bound:
            dropped += 1
            continue
        said += piece
    if dropped:
        said += f"{FACT_JOINER}and {dropped} more fact{'' if dropped == 1 else 's'}"
    return said


def told_whole(answer: Any) -> str:
    """The whole answer as a finding row tells it (:func:`whole_answer`), each part made fit
    to print whole; an answer with no parts is bounded as a finding value is
    (``events.safe_finding_value``)."""
    from malspark.pipeline.events import safe_finding_value

    if not isinstance(answer, PublishAnswer):
        return safe_finding_value(answer)
    return whole_answer(answer, word=lambda part: safe_finding_value(part, whole=True))
