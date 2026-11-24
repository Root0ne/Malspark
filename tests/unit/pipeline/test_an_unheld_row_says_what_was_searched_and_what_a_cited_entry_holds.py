"""A row the stated-value or cited-id check asks about says what was searched and what a cited
entry holds.

Per row and per span, the stated-value question says what the search found,
never that a span is in none of the cited entries where one holds it in any
reading: a span not found says it was not found as a whole value in the cited
entries, read as written, and as the bytes their texts write where the byte
reading takes the span (no number alone, nothing under three characters) and a
byte run had a place to hold it, the two kinds said apart where a row holds
both; bytes writing it whole only where chance explains it say so; a span a
cited entry holds only inside a longer run says so with the run, whatever its
length, spans beyond the listed ones counted, and the question then offers
three ends (keep the row where the value is one of several strings joined in
the run, write the token where the longer token is the value, otherwise cite an
entry that holds it or leave the row out); a span of one or two characters the
check reads as a number, and never as a value of its own, is said to be one,
with what that reading takes. The code and the mark of the row stay. Several
rows and several spans are said one by one. The cited-id question names the
byte reading, says a by-chance holding as such, and says of an id read as a
number that none of the cited entries writes it as a compared operand.
"""

from __future__ import annotations

import json
import random
import re
from typing import Any

from malspark.pipeline.validation import (
    BYTES_HELD_BY_CHANCE,
    ID_NOT_IN_CITED_ENTRY_CODE,
    INSIDE_A_TOKEN_ENDS,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    cited_id_violations,
    stated_value_violations,
)
from malspark.schemas.evidence import LedgerEntry

ASK = (
    "A value in this table is one an entry records as written. Cite an entry that holds each "
    "value the row states, or leave the row out."
)
ASK_WITH_A_RUN = (
    "A value in this table is one an entry records as written. "
    f"{INSIDE_A_TOKEN_ENDS} Otherwise, cite an entry that holds each value the row states, or "
    "leave the row out."
)


# What the questions say of a span the check reads as a short number.
SHORT_NUMBER = (
    "is one or two characters this check reads as a number (hex digits with a decimal digit "
    "among them, or a decimal digit then '.', ',' or ':'), which it does not read as a value "
    "of its own"
)
SHORT_NUMBERS = (
    "are each one or two characters this check reads as a number (hex digits with a decimal "
    "digit among them, or a decimal digit then '.', ',' or ':'), which it does not read as "
    "values of their own"
)


def _entry(entry_id: str, answer: Any) -> LedgerEntry:
    output = answer if isinstance(answer, str) else json.dumps(answer)
    return LedgerEntry(id=entry_id, agent="static", server="static", tool="t", output=output)


def _texts(*entries: tuple[str, Any]) -> EntryTexts:
    return EntryTexts.from_ledger([_entry(*entry) for entry in entries])


def _identifiers(*rows: tuple[str, str]) -> dict[str, Any]:
    return {
        "identifiers": [
            {"kind": kind, "value": value, "evidence_refs": ["ev_0001"]} for kind, value in rows
        ]
    }


def _item(value: str) -> dict[str, Any]:
    return {
        "items": [
            {
                "key": "Port",
                "value": value,
                "how_obtained": "decrypted",
                "evidence_refs": ["ev_0001"],
            }
        ]
    }


def _one(payload: dict[str, Any], *entries: tuple[str, Any]) -> Any:
    (found,) = stated_value_violations(payload, _texts(*entries))
    assert found.code == STATED_VALUE_UNHELD_CODE
    return found


class TestAWholeValue:
    def test_not_found_says_what_was_read(self) -> None:
        found = _one(_identifiers(("Mutex", "ExampleMutex")), ("ev_0001", {"strings": ["other"]}))

        assert found.message == (
            "identifier 1 (Mutex: 'ExampleMutex') was not found as a whole value in the answer "
            f"of ev_0001 (t), read as written. {ASK}"
        )

    def test_the_bytes_are_named_where_a_run_had_a_place(self) -> None:
        found = _one(
            _identifiers(("Mutex", "ExampleMutex")),
            ("ev_0001", {"hex": "00112233445566778899aabbccddeeff"}),
        )

        assert "read as written, and as the bytes its text writes." in found.message

    def test_bytes_holding_it_by_chance_say_so(self) -> None:
        rng = random.Random(8961)
        dump = bytearray(rng.randrange(256) for _ in range(80_000))
        dump[40_000:40_005] = b"\x00cmd\x00"

        found = _one(_identifiers(("Mutex", "cmd")), ("ev_0001", {"hex": dump.hex()}))

        assert "the bytes the text of ev_0001 (t) writes hold it whole" in found.message
        assert BYTES_HELD_BY_CHANCE in found.message

    def test_a_value_under_the_floor_inside_a_run_shows_the_run(self) -> None:
        found = _one(
            _identifiers(("Service", "SyncSvc")),
            ("ev_0001", {"strings": ["launcherSyncSvcHelper"]}),
        )

        assert found.message == (
            "identifier 1 (Service: 'SyncSvc') stands in ev_0001 (t) only inside a longer run "
            f"of text: 'launcherSyncSvcHelper'. {ASK_WITH_A_RUN}"
        )

    def test_five_characters_inside_a_run_stay_under_the_floor(self) -> None:
        found = _one(
            _identifiers(("Service", "GxSvc")), ("ev_0001", {"strings": ["poolGxSvcpool"]})
        )

        assert "only inside a longer run of text: 'poolGxSvcpool'" in found.message


class TestSpans:
    def test_a_short_number_span_is_said_for_what_it_is(self) -> None:
        found = _one(_item("80, 4431"), ("ev_0001", "listening on port 80"))

        assert found.message == (
            "configuration item 1 (Port: '80, 4431'): '4431' was not found as a whole value in "
            f"the answer of ev_0001 (t), read as written; '80' {SHORT_NUMBER}. {ASK}"
        )

    def test_spans_are_said_together_by_what_was_found(self) -> None:
        found = _one(
            _item("alpha7, beta7, 8, 24, SyncSvc"),
            ("ev_0001", {"strings": ["launcherSyncSvcHelper", "port 8 and 24"]}),
        )

        assert found.message == (
            "configuration item 1 (Port: 'alpha7, beta7, 8, 24, SyncSvc'): 'alpha7', 'beta7' "
            "were not found as whole values in the answer of ev_0001 (t), read as written; "
            "'SyncSvc' stands in ev_0001 (t) only inside a longer run of text: "
            f"'launcherSyncSvcHelper'; '8', '24' {SHORT_NUMBERS}. {ASK_WITH_A_RUN}"
        )

    def test_a_span_written_twice_is_said_once(self) -> None:
        found = _one(_item("alpha7; alpha7; SyncSvc"), ("ev_0001", {"strings": ["other"]}))

        assert found.message.count("'alpha7'") == 1

    def test_no_span_a_cited_entry_holds_is_said_not_found(self) -> None:
        texts = _texts(("ev_0001", {"strings": ["launcherSyncSvcHelper", "port 8 and 24"]}))
        (found,) = stated_value_violations(_item("alpha7, 8, 24, SyncSvc"), texts)

        said_missing = re.findall(
            r"'([^']+)'(?:, '[^']+')* were not found|'([^']+)' was not", found.message
        )
        for span in [part for pair in said_missing for part in pair if part]:
            assert not texts.holds("ev_0001", span, fields=True), span
        assert "none of the entries" not in found.message
        assert "in none of" not in found.message


class TestSeveralRows:
    def test_each_row_is_said_for_itself(self) -> None:
        found = _one(
            _identifiers(("Mutex", "ExampleMutex"), ("Service", "SyncSvc")),
            ("ev_0001", {"strings": ["launcherSyncSvcHelper"]}),
        )

        assert found.message == (
            "identifiers 1, 2 cite ev_0001 (t). identifier 1 (Mutex: 'ExampleMutex') was not "
            "found as a whole value in the answer of ev_0001 (t), read as written. identifier 2 "
            "(Service: 'SyncSvc') stands in ev_0001 (t) only inside a longer run of text: "
            f"'launcherSyncSvcHelper'. {ASK_WITH_A_RUN}"
        )


class TestTheCitedIdQuestion:
    @staticmethod
    def _found(cited: Any) -> Any:
        texts = _texts(("ev_0001", cited), ("ev_0002", {"strings": ["--sync-now"]}))
        (found,) = cited_id_violations(
            {"commands": [{"id": "--sync-now", "evidence_refs": ["ev_0001"]}]}, texts
        )
        assert found.code == ID_NOT_IN_CITED_ENTRY_CODE
        return found

    def test_it_says_what_was_searched(self) -> None:
        found = self._found({"strings": ["other"]})

        assert found.message == (
            "Row 1 of commands states the id '--sync-now'; it was not found as a whole value in "
            "the answer of ev_0001 (t), which the row cites, read as written. This run's evidence "
            "holds it in ev_0002 (t). A number is held where an entry's code compares it with the "
            "value it chooses by, any other id where an entry's text writes it whole, or a cited "
            "entry's text writes it as bytes chance does not explain. Cite the entry that holds "
            "each row's id."
        )

    def test_it_names_the_byte_reading(self) -> None:
        found = self._found({"hex": "00112233445566778899aabbccddeeff"})

        assert "read as written, and as the bytes its text writes." in found.message
        assert "none of the entries" not in found.message


BYTE_RUNS = ("ev_0001", {"hex": "00112233445566778899aabbccddeeff"})


class TestTheBytesAreNamedOnlyForValuesTheByteReadingTakes:
    def test_a_number_only_value_is_read_as_written_and_no_more(self) -> None:
        found = _one(_item("700"), BYTE_RUNS)

        assert found.message == (
            "configuration item 1 (Port: '700') was not found as a whole value in the answer "
            f"of ev_0001 (t), read as written. {ASK}"
        )

    def test_a_row_holding_both_kinds_says_each_group_once(self) -> None:
        found = _one(_item("alpha7, 4431, zq"), BYTE_RUNS)

        assert found.message == (
            "configuration item 1 (Port: 'alpha7, 4431, zq'): 'alpha7' was not found as a "
            "whole value in the answer of ev_0001 (t), read as written, and as the bytes its "
            "text writes; '4431', 'zq' were not found as whole values in the answer of ev_0001 "
            f"(t), read as written. {ASK}"
        )


class TestAShortNumberSpan:
    def test_the_words_name_what_the_check_reads_as_a_number(self) -> None:
        found = _one(_item("a1, alpha7"), ("ev_0001", "listening on port 80"))

        assert found.message == (
            "configuration item 1 (Port: 'a1, alpha7'): 'alpha7' was not found as a whole value "
            f"in the answer of ev_0001 (t), read as written; 'a1' {SHORT_NUMBER}. {ASK}"
        )

    def test_several_are_said_together(self) -> None:
        found = _one(_item("e5, 9f, alpha7"), ("ev_0001", "listening on port 80"))

        assert f"'e5', '9f' {SHORT_NUMBERS}." in found.message


class TestSpansInsideRuns:
    def test_spans_beyond_the_listed_ones_are_counted(self) -> None:
        spans = [f"Ab{n}cd" for n in range(1, 9)]
        found = _one(
            _item(", ".join(["alpha7", *spans])),
            ("ev_0001", {"strings": [f"pool{span}pool" for span in spans]}),
        )

        assert "'Ab6cd' stands in ev_0001 (t) only inside a longer run" in found.message
        assert "'Ab7cd' stands" not in found.message
        assert "; and 2 more spans stand only inside longer runs of text" in found.message

    def test_one_more_span_is_said_as_one(self) -> None:
        spans = [f"Ab{n}cd" for n in range(1, 8)]
        found = _one(
            _item(", ".join(["alpha7", *spans])),
            ("ev_0001", {"strings": [f"pool{span}pool" for span in spans]}),
        )

        assert "; and 1 more span stands only inside a longer run of text" in found.message


class TestANumberOnlyIdSaysWhatTheCheckTests:
    # A dispatcher comparing the table's numbers, and an entry writing two of them
    # whole as call arguments, never as compared operands.
    DISPATCHER = (
        "void dispatch(int c) {\n  switch (c) {\n  case 0x5e: a(); break;\n"
        "  case 0x6b: b(); break;\n  case 0x71: d(); break;\n  case 0x7d: e(); break;\n  }\n}\n"
    )
    CALLER = "int f(void) {\n  g(0x5e);\n  return g(0x6b);\n}\n"

    def _found(self, *rows: tuple[str, str]) -> Any:
        texts = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0001", agent="static", server="static", tool="decompile",
                    output=json.dumps({"code": self.DISPATCHER}),
                ),
                LedgerEntry(
                    id="ev_0002", agent="static", server="static", tool="decompile",
                    output=json.dumps({"code": self.CALLER}),
                ),
            ]
        )  # fmt: skip
        assert "0x6b" in texts.text_of("ev_0002")
        payload = {
            "commands": [
                {"id": written, "name": f"command {written}", "evidence_refs": [cited]}
                for written, cited in (*rows, ("0x71", "ev_0001"), ("0x7d", "ev_0001"))
            ]
        }
        (found,) = cited_id_violations(payload, texts)
        return found

    def test_one_row(self) -> None:
        found = self._found(("0x6b", "ev_0002"), ("0x5e", "ev_0001"))

        assert found.message.startswith(
            "Row 1 of commands states the id '0x6b', read as a number none of the entries it "
            "cites writes as a compared operand: ev_0002 (decompile). This run's evidence holds "
            "it in ev_0001 (decompile)."
        )
        assert "holds:" not in found.message

    def test_several_rows(self) -> None:
        found = self._found(("0x5e", "ev_0002"), ("0x6b", "ev_0002"))

        assert found.message.startswith(
            "Rows 1, 2 of commands each state an id read as a number none of the entries the "
            "row cites writes as a compared operand: 1: '0x5e'; 2: '0x6b'. This run's evidence "
            "holds them in ev_0001 (decompile)."
        )

    def test_a_number_beside_a_name_is_said_as_read_as_a_number(self) -> None:
        # One holder for both rows: the dispatcher's entry also lists the name.
        texts = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0001", agent="static", server="static", tool="decompile",
                    output=json.dumps({"code": self.DISPATCHER, "names": ["relay_open"]}),
                ),
                LedgerEntry(
                    id="ev_0002", agent="static", server="static", tool="decompile",
                    output=json.dumps({"code": self.CALLER}),
                ),
            ]
        )  # fmt: skip
        rows = (
            ("0x6b", "ev_0002"),
            ("relay_open", "ev_0002"),
            ("0x5e", "ev_0001"),
            ("0x71", "ev_0001"),
            ("0x7d", "ev_0001"),
        )
        payload = {
            "commands": [
                {"id": written, "name": f"command {written}", "evidence_refs": [cited]}
                for written, cited in rows
            ]
        }
        (found,) = cited_id_violations(payload, texts)

        assert found.message.startswith(
            "Rows 1, 2 of commands each state an id this check did not find in the entries the "
            "row cites: 1: '0x6b' (read as a number none of the entries the row cites writes as "
            "a compared operand); 2: 'relay_open' (was not found as a whole value in the answer "
            "of ev_0002 (decompile), which the row cites, read as written). This run's evidence "
            "holds them in ev_0001 (decompile)."
        )
