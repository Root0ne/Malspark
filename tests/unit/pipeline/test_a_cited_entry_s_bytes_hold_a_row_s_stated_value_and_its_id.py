"""A cited entry holds a table row's stated value, and a row's id, that its text writes as bytes.

The stated-value check asks about a configuration or identifier row whose value
none of the entries it cites holds; the cited-id check about a row whose id
none of them holds while another entry does. Each reads every cited entry also
as the bytes its text writes — the citation check's one byte reading: the text
outside the echo of the entry's own call, decoded as UTF-8 or UTF-16LE, holding
the value whole, under the platform's one chance bound — asked of each cited
entry directly, so an entry that writes the value only as bytes is never left
unread. A read that returns the first bytes of a longer string holds what it
returned, as a text a tool cut at a chosen length does. A run equal to the bytes
of the call's own argument followed only by NUL bytes is the call's echo, in the
single-byte and the two-byte spelling and as a list of numbers. The decoded
readings of an entry's byte runs are read once per entry.
"""

from __future__ import annotations

import json
import random
from typing import Any

from malspark.pipeline.validation import (
    ID_NOT_IN_CITED_ENTRY_CODE,
    STATED_VALUE_UNHELD_CODE,
    EntryTexts,
    cited_id_violations,
    stated_value_violations,
)
from malspark.schemas.evidence import LedgerEntry
from malspark.utils.written_bytes import byte_runs
from tests.linear_cost import assert_under

MUTEX = "Global\\ExampleMutex"
SWITCH = "/Apply"
FLAG = "--sync-now"


def _entry(entry_id: str, answer: Any, args: dict[str, Any] | None = None) -> LedgerEntry:
    output = answer if isinstance(answer, str) else json.dumps(answer)
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool="t", output=output, args=args or {}
    )


def _read(entry_id: str, data: bytes, *, as_list: bool = False) -> LedgerEntry:
    """A memory read: the call names an address and a length, the answer the bytes."""
    answer: dict[str, Any] = {"address": "0x401000", "length": len(data)}
    answer["data" if as_list else "hex"] = list(data) if as_list else data.hex()
    return _entry(entry_id, answer, {"address": "0x401000", "length": len(data)})


def _identifier(value: str, *refs: str) -> dict[str, Any]:
    return {"identifiers": [{"kind": "Mutex", "value": value, "evidence_refs": list(refs)}]}


def _item(value: str, *refs: str) -> dict[str, Any]:
    return {
        "items": [
            {
                "key": "Marker",
                "value": value,
                "how_obtained": "decrypted",
                "evidence_refs": list(refs),
            }
        ]
    }


class TestTheStatedValue:
    def test_an_identifier_a_cited_read_writes_as_bytes_is_held(self) -> None:
        texts = EntryTexts.from_ledger([_read("ev_0001", MUTEX.encode())])

        assert stated_value_violations(_identifier(MUTEX, "ev_0001"), texts) == []

    def test_a_configuration_value_written_as_a_list_of_numbers_is_held(self) -> None:
        texts = EntryTexts.from_ledger([_read("ev_0001", SWITCH.encode(), as_list=True)])

        assert stated_value_violations(_item(SWITCH, "ev_0001"), texts) == []

    def test_a_value_written_as_utf16le_bytes_is_held(self) -> None:
        texts = EntryTexts.from_ledger([_read("ev_0001", MUTEX.encode("utf-16-le"))])

        assert stated_value_violations(_identifier(MUTEX, "ev_0001"), texts) == []

    def test_a_cell_of_three_spans_each_held_by_another_read_is_held(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _read("ev_0001", SWITCH.encode()),
                _read("ev_0002", FLAG.encode()),
                _read("ev_0003", b"tasks.cfg"),
            ]
        )
        cell = f"{SWITCH}; {FLAG}; tasks.cfg"

        assert stated_value_violations(_item(cell, "ev_0001", "ev_0002", "ev_0003"), texts) == []

    def test_the_same_read_without_the_value_is_asked(self) -> None:
        texts = EntryTexts.from_ledger([_read("ev_0001", b"\x00\x11\x22\x33\x44\x55")])

        (found,) = stated_value_violations(_identifier(MUTEX, "ev_0001"), texts)
        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_cut_read_holds_what_it_returned(self) -> None:
        # Six bytes of a longer string: the read's end bounds what it returned.
        texts = EntryTexts.from_ledger([_read("ev_0001", b"ExampleMutexLonger"[:12])])

        assert stated_value_violations(_identifier("ExampleMutex", "ev_0001"), texts) == []

    def test_a_short_value_in_a_large_random_dump_is_still_asked(self) -> None:
        rng = random.Random(896)
        dump = bytearray(rng.randrange(256) for _ in range(80_000))
        dump[40_000:40_005] = b"\x00cmd\x00"
        texts = EntryTexts.from_ledger([_entry("ev_0001", {"hex": dump.hex()})])

        (found,) = stated_value_violations(_identifier("cmd", "ev_0001"), texts)
        assert found.code == STATED_VALUE_UNHELD_CODE


class TestTheCallsOwnBytesFollowedByNulsAreItsEcho:
    @staticmethod
    def _asked(answer: dict[str, Any], args: dict[str, Any]) -> list[Any]:
        texts = EntryTexts.from_ledger([_entry("ev_0001", answer, args)])
        return stated_value_violations(_identifier(MUTEX, "ev_0001"), texts)

    def test_the_single_byte_spelling(self) -> None:
        answer = {"pattern_hex": (MUTEX.encode() + b"\x00").hex(), "hits": []}

        (found,) = self._asked(answer, {"pattern": MUTEX})
        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_the_two_byte_spelling(self) -> None:
        answer = {"pattern_hex": (MUTEX.encode("utf-16-le") + b"\x00\x00").hex(), "hits": []}

        (found,) = self._asked(answer, {"pattern": MUTEX})
        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_hex_argument_echoed_as_a_list_of_numbers(self) -> None:
        answer = {"pattern_bytes": [*MUTEX.encode(), 0], "hits": []}

        (found,) = self._asked(answer, {"pattern": MUTEX.encode().hex()})
        assert found.code == STATED_VALUE_UNHELD_CODE

    def test_a_run_holding_more_than_the_argument_and_nuls_is_data(self) -> None:
        answer = {"hits": [{"hex": (b"\x00" + MUTEX.encode() + b"\x00").hex()}]}

        assert self._asked(answer, {"pattern": MUTEX}) == []

    def test_the_echo_rule_is_the_one_byte_reading_s(self) -> None:
        texts = EntryTexts.from_ledger(
            [_entry("ev_0001", {"hex": (SWITCH.encode() + b"\x00\x00").hex()}, {"p": SWITCH})]
        )

        assert texts.byte_runs_of("ev_0001") == ()
        assert byte_runs(json.dumps({"hex": (SWITCH.encode() + b"\x00\x00").hex()}))


class TestTheRowsId:
    @staticmethod
    def _payload(identifier: str, *refs: str) -> dict[str, Any]:
        return {"commands": [{"id": identifier, "evidence_refs": list(refs)}]}

    def test_an_id_a_cited_read_writes_as_bytes_is_held(self) -> None:
        texts = EntryTexts.from_ledger(
            [_read("ev_0001", FLAG.encode()), _entry("ev_0002", {"strings": [FLAG]})]
        )

        assert cited_id_violations(self._payload(FLAG, "ev_0001"), texts) == []

    def test_an_id_held_as_text_only_elsewhere_is_asked(self) -> None:
        texts = EntryTexts.from_ledger(
            [_read("ev_0001", b"\x00\x11\x22\x33\x44"), _entry("ev_0002", {"strings": [FLAG]})]
        )

        (found,) = cited_id_violations(self._payload(FLAG, "ev_0001"), texts)
        assert found.code == ID_NOT_IN_CITED_ENTRY_CODE


class TestTheCost:
    def test_rows_by_spans_by_a_byte_dense_megabyte_stay_bounded(self) -> None:
        rng = random.Random(8960)
        dense = bytes(rng.randrange(256) for _ in range(500_000)).hex()
        entry = _entry("ev_0001", {"hex": dense})
        rows = [
            {
                "key": f"k{row}",
                "value": "; ".join(f"span{row}x{span}" for span in range(10)),
                "how_obtained": "decrypted",
                "evidence_refs": ["ev_0001"],
            }
            for row in range(30)
        ]

        # A fresh reading per call: nothing read before the call is reused.
        assert_under(
            lambda: stated_value_violations({"items": rows}, EntryTexts.from_ledger([entry])),
            20.0,
        )
