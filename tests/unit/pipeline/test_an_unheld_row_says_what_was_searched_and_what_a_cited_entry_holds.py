"""A row the stated-value or cited-id check asks about says what was searched and what a cited
entry holds.

Per row and per span, the stated-value question says what the search found,
never that a span is in none of the cited entries where one holds it in any
reading: a span not found says it was not found as a whole value in the cited
entries, read as written, and as the bytes their texts write where a byte run
had a place to hold it; bytes writing it whole only where chance explains it
say so; a span a cited entry holds only inside a longer run says so with the
run, whatever its length, and the question then offers three ends (keep the row
where the value is one of several strings joined in the run, write the token
where the longer token is the value, otherwise cite an entry that holds it or
leave the row out); a span that is a number of one or two characters, which the
check never reads as a value of its own, is said to be that. The code and the
mark of the row stay. Several rows and several spans are said one by one. The
cited-id question names the byte reading, and says a by-chance holding as such.
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
            "the answer of ev_0001 (t), read as written; '80' is a number of one or two "
            f"characters, which this check does not read as a value of its own. {ASK}"
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
            "'launcherSyncSvcHelper'; '8', '24' are numbers of one or two characters, which "
            f"this check does not read as values of their own. {ASK_WITH_A_RUN}"
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
