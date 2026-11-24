"""The citation check offers no entry that holds a value whole only in its call's echo and
elsewhere only inside a longer run.

The citation check asks about a value cited to an entry that does not hold it,
offering the entries that do. An entry whose text holds the value whole only
where its answer repeats its own call's arguments, while its echo-free text
holds a spelling of the value only at places a letter, digit or ``_`` of the run
around it touches (read decoded), holds it no more than the cited entry may: it
is not offered, and where it was the only one, nothing is asked. Every other
entry is offered as before: one whose echo-free text holds no spelling of the
value (a search that found nothing, a lookup about its own argument — the right
citation of a sentence saying the value is absent), one holding a spelling at a
place nothing touches (a row bounded by a NUL), and one holding it outside the
echo. The cited-entry test, the echo check and every other reader are unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.pipeline.validation import (
    ECHO_FREE_HOLDS_IT,
    ECHO_FREE_HOLDS_IT_INSIDE,
    ECHO_FREE_HOLDS_NONE,
    EntryTexts,
    held_only_in_its_echo,
    wrong_entry_citations,
)
from malspark.schemas.evidence import LedgerEntry

NAME = "tasks.cfg"
OTHER = "notes.cfg"
CITED = ("ev_0003", {"rules": ["unrelated"]}, {"path": "s.bin"})


def _entry(entry_id: str, answer: Any, args: dict[str, Any] | None) -> LedgerEntry:
    output = answer if isinstance(answer, str) else json.dumps(answer)
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool="t", output=output, args=args or {}
    )


def _texts(*entries: tuple[str, Any, dict[str, Any] | None]) -> EntryTexts:
    return EntryTexts.from_ledger([_entry(*entry) for entry in entries])


def _asked(*holders: tuple[str, Any, dict[str, Any] | None], body: str = "") -> list[Any]:
    sentence = body or f"It writes `{NAME}` [ev_0003]."
    return wrong_entry_citations({"body": sentence}, _texts(CITED, *holders), prose=("body",))


INSIDE = ("ev_0001", {"pattern": NAME, "matches": [{"text": f"x{NAME}"}]}, {"pattern": NAME})


class TestAnEchoBesideARunIsNotOffered:
    def test_alone_it_raises_no_question(self) -> None:
        assert _asked(INSIDE) == []

    def test_beside_a_true_holder_only_that_holder_is_named(self) -> None:
        (found,) = _asked(INSIDE, ("ev_0002", {"strings": [NAME]}, {"path": "s.bin"}))

        assert "ev_0002" in found.message
        assert "ev_0001" not in found.message

    @pytest.mark.parametrize(
        ("answer", "args"),
        [
            # A nested argument object echoed.
            (
                {"opts": {"pattern": NAME}, "matches": [{"text": f"a{NAME}"}]},
                {"opts": {"pattern": NAME}},
            ),
            # A single result repeating the pattern, a context holding a run.
            (
                {"pattern": NAME, "result": {"pattern": NAME, "offset": 7}, "ctx": f"a{NAME}"},
                {"pattern": NAME},
            ),
        ],
    )
    def test_other_echo_shapes(self, answer: Any, args: dict[str, Any]) -> None:
        assert _asked(("ev_0001", answer, args)) == []


class TestEveryOtherHolderIsOfferedAsBefore:
    @pytest.mark.parametrize(
        ("answer", "args"),
        [
            # A search with no row: the right citation of an absence sentence.
            ({"pattern": NAME, "matches": []}, {"pattern": NAME}),
            # Existence lookups about their own argument, answering false and true.
            ({"path": NAME, "exists": False}, {"path": NAME}),
            ({"path": NAME, "exists": True}, {"path": NAME}),
            ({"key": NAME, "found": False}, {"key": NAME}),
            # A row bounded by a NUL: nothing of the decoded run touches the value.
            ({"pattern": NAME, "matches": [{"text": f"\u0000{NAME}"}]}, {"pattern": NAME}),
            # A row holding it whole.
            ({"pattern": NAME, "matches": [{"text": NAME}]}, {"pattern": NAME}),
            # A row equal to the argument.
            ({"pattern": NAME, "strings": [NAME]}, {"pattern": NAME}),
            # One- and two-character arguments beside a row holding the value.
            ({"pattern": "e", "matches": [{"text": NAME}]}, {"pattern": "e"}),
            ({"sep": "\\\\", "matches": [{"text": NAME}]}, {"sep": "\\\\"}),
            # A list argument echoed as a list: not told apart, as before.
            (
                {"patterns": [NAME, "x"], "matches": [{"text": f"a{NAME}"}]},
                {"patterns": [NAME, "x"]},
            ),
        ],
    )
    def test_it_is_offered(self, answer: Any, args: dict[str, Any]) -> None:
        (found,) = _asked(("ev_0001", answer, args))

        assert "ev_0001" in found.message

    def test_a_question_about_two_values_splits_where_their_holders_differ(self) -> None:
        both = ("ev_0001", {"strings": [NAME, OTHER]}, {"path": "s.bin"})
        echo = (
            "ev_0002",
            {"pattern": NAME, "matches": [{"text": f"x{NAME}"}, {"text": OTHER}]},
            {"pattern": NAME},
        )
        body = f"It writes `{NAME}` and `{OTHER}` [ev_0003]."

        found = _asked(both, echo, body=body)

        assert len(found) == 2
        by_value = {violation.values: violation.message for violation in found}
        assert "ev_0002" not in by_value[(NAME,)]
        assert "ev_0002" in by_value[(OTHER,)]


class TestTheSharedReading:
    @staticmethod
    def _found(answer: Any, args: dict[str, Any] | None) -> str:
        entries = _texts(("ev_0001", answer, args))
        return held_only_in_its_echo(entries, "ev_0001", lambda text: NAME in text, [NAME])

    def test_an_entry_nothing_echoes_never_answers(self) -> None:
        assert self._found({"pattern": NAME, "matches": [{"text": f"x{NAME}"}]}, None) == ""

    def test_a_holding_outside_the_echo_is_no_echo_holding(self) -> None:
        assert self._found({"pattern": NAME, "matches": [{"text": NAME}]}, {"pattern": NAME}) == ""

    def test_what_the_echo_free_text_holds(self) -> None:
        def test(text: str) -> bool:
            return f'"{NAME}"' in text

        entries = _texts(
            (
                "ev_0001",
                {"pattern": NAME, "matches": [{"text": f"\u0000{NAME}"}]},
                {"pattern": NAME},
            ),
            ("ev_0002", {"pattern": NAME, "matches": [{"text": f"x{NAME}"}]}, {"pattern": NAME}),
            ("ev_0003", {"pattern": NAME, "matches": []}, {"pattern": NAME}),
        )

        assert held_only_in_its_echo(entries, "ev_0001", test, [NAME]) == ECHO_FREE_HOLDS_IT
        assert held_only_in_its_echo(entries, "ev_0002", test, [NAME]) == ECHO_FREE_HOLDS_IT_INSIDE
        assert held_only_in_its_echo(entries, "ev_0003", test, [NAME]) == ECHO_FREE_HOLDS_NONE

    def test_the_byte_reading_reads_the_same_echo_free_text(self) -> None:
        entries = _texts(
            ("ev_0001", {"pattern": NAME, "hex": f"\0{NAME}\0".encode().hex()}, {"pattern": NAME})
        )

        ((_whole, rest),) = entries.echo_free_parts("ev_0001")
        assert rest is not None and NAME not in rest
        assert entries.holds_as_bytes("ev_0001", NAME)
