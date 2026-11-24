"""A citation question says of each entry holding a value what the search matched there.

The citation check offers the entries a value was found in. It says "found
whole in" an entry only where no letter, digit or ``_`` of the run the value
stands in, read decoded, touches the value. Of every other holder it says that
the value stands there only inside a longer run of text, where the search
matched it (between which characters, at the start or at the end of the run)
and the run; where the run cannot be shown it says so. In a question about
several values each value is worded for itself. The words change, nothing
else: the same entries are offered and the same questions asked.
"""

from __future__ import annotations

import json
import random
import re
from typing import Any

import pytest

from malspark.agents._indicator_denylists import whole_value_starts
from malspark.pipeline import events
from malspark.pipeline.validation import (
    CITATION_WRONG_ENTRY_CODE,
    RUN_NOT_SHOWN,
    EntryTexts,
    wrong_entry_citations,
)
from malspark.schemas.evidence import LedgerEntry

# Invented values: a switch, two program names and a host.
SWITCH = "/Apply"
RUNNER = "runner.exe"
HELPER = "helper.exe"
HOST = "gatehost.example"
NOTHING = json.dumps({"note": "a cited answer that holds none of the values"})


@pytest.fixture(autouse=True)
def _configured_values_registered() -> None:
    # As a worker runs: the operator's configured values are registered, so a
    # finding keeps the words of the evidence it quotes.
    events.remember_secret_values(["operator-configured-placeholder"], scope="job")


def _entry(entry_id: str, output: str, tool: str = "t") -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="static", server="static", tool=tool, output=output)


def _texts(*holders: str) -> EntryTexts:
    ledger = [_entry("ev_0001", NOTHING)]
    ledger += [_entry(f"ev_{at:04d}", text) for at, text in enumerate(holders, start=2)]
    return EntryTexts.from_ledger(ledger)


def _asked(sentence: str, texts: EntryTexts) -> Any:
    (found,) = wrong_entry_citations({"body": sentence}, texts, prose=("body",))
    assert found.code == CITATION_WRONG_ENTRY_CODE
    return found


class TestEachValueIsWordedForItself:
    def test_a_mixed_plural_group_says_of_each_value_what_holds_for_it(self) -> None:
        texts = _texts(json.dumps({"s": f"{RUNNER} {HELPER}=on"}))

        found = _asked(f"It starts `{RUNNER}` and `{HELPER}` [ev_0001].", texts)

        assert found.message.endswith(
            "; 'runner.exe' was found whole in ev_0002 (t); 'helper.exe' stands in ev_0002 (t) "
            "only inside a longer run of text; there the search matched it at the start of the "
            "run, before '=': 'helper.exe=on'. Cite an entry that holds the value as the text "
            "states it, or, where the cited entry writes it in another spelling, keep the "
            "citation and say so in the text."
        )
        assert "they stand" not in found.message
        assert "they were found whole" not in found.message
        assert found.labels == (
            '"runner.exe", "helper.exe" were not found whole in ev_0001; "runner.exe" was found '
            'whole in ev_0002 (t); "helper.exe" stands in ev_0002 (t) only inside a longer run '
            'of text: "helper.exe=on"',
        )

    def test_a_plural_group_held_whole_keeps_its_words(self) -> None:
        texts = _texts(json.dumps({"s": [RUNNER, HELPER]}))

        found = _asked(f"It starts `{RUNNER}` and `{HELPER}` [ev_0001].", texts)

        assert "; they were found whole in ev_0002 (t). Cite" in found.message
        assert found.labels[0].endswith("; they were found whole in ev_0002 (t)")


class TestTheRunIsReadDecoded:
    def test_a_letter_written_as_an_escape_beside_the_value_is_no_whole_holding(self) -> None:
        texts = _texts(json.dumps({"s": f"{HOST}\u00e9"}))

        found = _asked(f"It calls `{HOST}` [ev_0001].", texts)

        assert "found whole in ev_0002" not in found.message
        assert f"it stands in ev_0002 (t) only inside a longer run of text, {RUN_NOT_SHOWN}." in (
            found.message
        )

    def test_an_escape_that_writes_no_letter_bounds_the_value(self) -> None:
        texts = _texts(json.dumps({"s": f"{HOST}\u0000"}))

        found = _asked(f"It calls `{HOST}` [ev_0001].", texts)

        assert "; it was found whole in ev_0002 (t). Cite" in found.message


class TestWhatTheSearchMatchedIsSaid:
    def test_a_value_whole_between_quotes_is_said_found_whole(self) -> None:
        found = _asked(f"It calls `{HOST}` [ev_0001].", _texts(json.dumps({"s": HOST})))

        assert "; it was found whole in ev_0002 (t). Cite" in found.message
        assert found.labels == (
            '"gatehost.example" was not found whole in ev_0001; it was found whole in ev_0002 (t)',
        )

    def test_a_value_at_the_start_of_a_longer_run_says_where_and_shows_the_run(self) -> None:
        texts = _texts(json.dumps({"s": f"{SWITCH}/Removeonboot"}))

        found = _asked(f"It runs with `{SWITCH}` [ev_0001].", texts)

        assert (
            "; it stands in ev_0002 (t) only inside a longer run of text; there the search "
            "matched it at the start of the run, before '/': '/Apply/Removeonboot'. Cite"
        ) in found.message
        assert "found whole" not in found.message.split("; ", 1)[1]
        assert found.labels == (
            '"/Apply" was not found whole in ev_0001; it stands in ev_0002 (t) only inside a '
            'longer run of text: "/Apply/Removeonboot"',
        )

    def test_a_value_inside_a_run_names_the_characters_on_both_sides(self) -> None:
        texts = _texts(json.dumps({"s": f"mode={SWITCH}/now"}))

        found = _asked(f"It runs with `{SWITCH}` [ev_0001].", texts)

        assert "there the search matched it between '=' and '/': 'mode=/Apply/now'." in (
            found.message
        )

    def test_whole_and_inside_holders_are_named_apart(self) -> None:
        texts = _texts(
            json.dumps({"s": f"{SWITCH}/Removeonboot"}),
            json.dumps({"argv": ["tool", SWITCH]}),
            json.dumps({"s": f"x={SWITCH}"}),
        )

        found = _asked(f"It runs with `{SWITCH}` [ev_0001].", texts)

        assert (
            "; it was found whole in ev_0003 (t); it stands in ev_0002 (t), ev_0004 (t) only "
            "inside a longer run of text; in ev_0002 (t) the search matched it at the start of "
            "the run, before '/': '/Apply/Removeonboot'. Cite"
        ) in found.message
        assert found.labels[0].endswith(
            "; it was found whole in 1 other entry, and only inside a longer run of text in 2 more"
        )

    def test_several_holders_all_inside_are_counted_in_the_mark(self) -> None:
        texts = _texts(
            json.dumps({"s": f"{SWITCH}/Removeonboot"}), json.dumps({"s": f"{SWITCH}/Later"})
        )

        found = _asked(f"It runs with `{SWITCH}` [ev_0001].", texts)

        assert found.labels[0].endswith(
            "; it stands only inside a longer run of text in 2 other entries"
        )


class TestARunThatCannotBeShown:
    def test_a_place_that_splits_an_escape_keeps_the_words_for_a_run_not_shown(self) -> None:
        # ``c:\`` matched in ``c:\\tools`` ends between the two characters of one escape.
        texts = _texts(json.dumps({"s": "c:\\tools"}))

        found = _asked("It writes under `c:\\` [ev_0001].", texts)

        assert f"it stands in ev_0002 (t) only inside a longer run of text, {RUN_NOT_SHOWN}." in (
            found.message
        )
        assert "the search matched" not in found.message
        assert found.labels[0].endswith(
            f"; it stands in ev_0002 (t) only inside a longer run of text, {RUN_NOT_SHOWN}"
        )


# What a generated entry is written with: lower-case letters past ``f`` (no
# text of them is a byte run), and the characters that join or end a run.
_LETTERS = "ghijkmnpqrstuvwxyz"
_JOINS = ["/", "\\", ".", " ", "=", "-", ":", "_"]


def _word(rng: random.Random) -> str:
    return "".join(rng.choice(_LETTERS) for _ in range(rng.randint(3, 5)))


def _generated(rng: random.Random) -> tuple[list[str], list[str]]:
    words = [_word(rng) for _ in range(5)]
    values = [rng.choice(words) for _ in range(2)]
    values += [f"{rng.choice(words)}.{rng.choice(words)}", f"/{rng.choice(words)}"]
    texts = []
    for _ in range(rng.randint(2, 6)):
        pieces = []
        for _ in range(rng.randint(1, 6)):
            pieces.append(rng.choice([*words, *values]))
            pieces.append(rng.choice(_JOINS))
        text = "".join(pieces)
        texts.append(json.dumps({"s": text}) if rng.random() < 0.7 else text)
    return texts, values


_NAMED = re.compile(r"ev_\d{4}")


def _alone_in(text: str, value: str) -> bool:
    """Read apart from the check: at a place the search finds, the token between spaces or
    quotes, decoded where the text is JSON, holds no other letter, digit or ``_``."""
    lowered = value.lower()
    for start in whole_value_starts(lowered, text):
        begin = max(text.rfind(mark, 0, start) for mark in ' "') + 1
        ends = [text.find(mark, start + len(lowered)) for mark in ' "']
        token = text[begin : min((end for end in ends if end != -1), default=len(text))]
        if text.startswith("{"):
            token = json.loads(f'"{token}"')
        if re.fullmatch(rf"\W*{re.escape(lowered)}\W*", token):
            return True
    return False


def _holders_named(found: Any) -> set[str]:
    tail = found.message.split(" Cite an entry", 1)[0].split(" Where a value", 1)[0]
    after = tail.split("which the sentence cites", 1)[1]
    return set(_NAMED.findall(after))


def _sides_named(found: Any) -> tuple[set[str], set[str]]:
    """The entries a question names whole, and those it names only inside a run."""
    whole: set[str] = set()
    inside: set[str] = set()
    for clause in found.message.split("; "):
        if "found whole in" in clause:
            whole |= set(_NAMED.findall(clause.split("found whole in", 1)[1]))
        elif "only inside a longer run" in clause and " stands in " in clause:
            named = clause.split(" stands in ", 1)[1].split("only inside", 1)[0]
            inside |= set(_NAMED.findall(named))
    return whole, inside


class TestNoHolderChangesSides:
    def test_generated_entries_are_asked_and_offered_exactly_as_the_search_finds(self) -> None:
        rng = random.Random(888)
        checked = 0
        for _ in range(400):
            texts_written, values = _generated(rng)
            texts = _texts(*texts_written)
            for value in values:
                sentence = f"It writes `{value}` [ev_0001]."
                found = wrong_entry_citations({"body": sentence}, texts, prose=("body",))
                holders = texts.holding(value, fields=True)
                cited_holds = texts.holds("ev_0001", value, fields=True)
                asked = bool(holders) and not cited_holds
                assert bool(found) is asked, (texts_written, value)
                if not found:
                    continue
                (question,) = found
                assert question.values == (value,)
                named = _holders_named(question)
                if len(holders) <= 6:
                    assert named == set(holders), (texts_written, value, question.message)
                else:
                    assert named <= set(holders)
                whole_named, inside_named = _sides_named(question)
                for holder in holders[:6]:
                    whole = holder in whole_named
                    assert whole != (holder in inside_named), (texts_written, question.message)
                    assert bool(whole) is _alone_in(texts.text_of(holder), value), (
                        texts_written,
                        value,
                        question.message,
                    )
                checked += 1
        assert checked > 50
