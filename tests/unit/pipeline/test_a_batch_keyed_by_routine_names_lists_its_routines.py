"""A batch decompile keyed by the decompiler's own routine names lists its routines (T-707).

A batch call may be given its functions by the names the decompiler printed
for them (``FUN_<address>``) and answer under those names. Such a key carries
the routine's address as a generic name does everywhere else
(``generic_function_name``, from the declared auto-name prefixes), so the
batch lists each routine under its address: the routines it lists are read,
their callees are known, and the limitations count them. A key that is a plain
symbol the call asked for carries no address: it keeps its name and invents
none. Every address and tool name here is a neutral synthetic value, read by
the tools' declared kinds.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from malspark.agents.function_callees import call_edges, unread_callees
from malspark.pipeline.validation import _batch_listings, _entry_functions, decompiled_functions
from malspark.reporting.agreement_facts import ledger_facts
from malspark.reporting.limitation_inventory import build_inventory
from malspark.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from malspark.schemas.evidence import LedgerEntry

_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_BATCH = {"v": 1, "kind": "decompile_batch", "reader": "listing"}

GATE, FIRST, SECOND, THIRD = 0x4F9EA0, 0x4B6BA0, 0x4F9020, 0x4F9FC0


def _listing(address: int, body: str = "") -> str:
    return f"void FUN_{address:08x}(void)\n{{\n{body}\n}}\n"


def _lifted(entry_id: str, address: int, body: str = "") -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=_listing(address, body),
        facts=_DECOMPILE,
    )


def _batch(entry_id: str, answer: dict[str, str], asked: str | None = None) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_many",
        args={"functions": asked if asked is not None else ",".join(answer)},
        output=json.dumps(answer),
        facts=_BATCH,
    )


def _by_name(*addresses: int) -> dict[str, str]:
    return {f"FUN_{a:08x}": _listing(a, "  return;") for a in addresses}


def test_a_batch_answer_keyed_by_generic_names_is_one_listing_per_routine() -> None:
    shown, listings = _batch_listings(json.dumps(_by_name(FIRST, SECOND, THIRD)))
    assert shown is True
    assert sorted(listings) == [FIRST, SECOND, THIRD]
    assert listings[SECOND].startswith(f"void FUN_{SECOND:08x}")


def test_the_entry_holds_each_routine_it_was_asked_for_by_name() -> None:
    entry = _batch("ev_0155", _by_name(FIRST, SECOND, THIRD))
    assert [address for address, _names in _entry_functions(entry)] == [FIRST, SECOND, THIRD]
    assert {f.address for f in decompiled_functions([entry])} == {FIRST, SECOND, THIRD}


def test_a_list_of_generic_names_is_read_as_their_addresses_when_the_answer_is_no_batch() -> None:
    asked = f"FUN_{FIRST:08x},FUN_{SECOND:08x}"
    entry = LedgerEntry(
        id="ev_0150", tool="lift_many", args={"functions": asked}, output="", facts=_BATCH
    )
    assert [address for address, _names in _entry_functions(entry)] == [FIRST, SECOND]


def test_a_callee_a_name_keyed_batch_lists_is_read_not_unread() -> None:
    ledger = [
        _lifted("ev_0154", GATE, f"  FUN_{SECOND:08x}();\n  FUN_{THIRD:08x}();"),
        _batch("ev_0155", _by_name(FIRST, SECOND, THIRD)),
    ]
    assert unread_callees(ledger) == []
    assert {SECOND, THIRD} <= set(call_edges(ledger).listed)


def test_the_limitations_count_the_routines_a_name_keyed_batch_lists() -> None:
    ledger = [
        _lifted("ev_0154", GATE, f"  FUN_{SECOND:08x}();"),
        _batch("ev_0155", _by_name(FIRST, SECOND, THIRD)),
    ]
    found = ledger_facts(ledger)
    assert {routine.address for routine in found.listed} == {GATE, FIRST, SECOND, THIRD}
    assert found.unread == ()
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64), file_type="PE32"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        dynamic=DynamicBehavior(),
    )
    inventory = build_inventory(report, ledger)
    assert (inventory.listed, inventory.unread) == (4, 0)


def test_an_error_key_beside_a_name_key_keeps_the_readable_one() -> None:
    answer = {
        f"FUN_{FIRST:08x}": _listing(FIRST, "  return;"),
        f"FUN_{SECOND:08x}": "Error: no function at this address",
    }
    shown, listings = _batch_listings(json.dumps(answer))
    assert (shown, sorted(listings)) == (True, [FIRST])
    assert [a for a, _n in _entry_functions(_batch("ev_0156", answer))] == [FIRST]


def test_a_plain_symbol_the_call_asked_for_keeps_its_name_and_no_address() -> None:
    answer: dict[str, Any] = {
        "parse_config": "int parse_config(char *p)\n{\n  return 0;\n}\n",
        f"FUN_{FIRST:08x}": _listing(FIRST, "  return;"),
    }
    entry = _batch("ev_0157", answer)
    functions = _entry_functions(entry)
    assert (None, ["parse_config"]) in functions
    assert (FIRST, [f"FUN_{FIRST:08x}"]) in functions
    assert {f.names for f in decompiled_functions([entry]) if f.address is None} == {
        ("parse_config",)
    }


def test_a_key_the_call_never_asked_for_is_no_batch_member() -> None:
    # One function's answer as an object: its keys are fields, not routines.
    answer = {"name": "parse_config", "code": "int parse_config(char *p) { return 0; }"}
    entry = LedgerEntry(
        id="ev_0158",
        tool="lift_routine",
        args={"function": "parse_config"},
        output=json.dumps(answer),
        facts=_DECOMPILE,
    )
    assert _batch_listings(entry.output) == (False, {})
    assert _entry_functions(entry) == [(None, ["parse_config"])]


def test_a_batch_keyed_by_addresses_reads_as_it_did() -> None:
    answer = {hex(FIRST): _listing(FIRST), f"{SECOND:x}": _listing(SECOND)}
    shown, listings = _batch_listings(json.dumps(answer))
    assert (shown, sorted(listings)) == (True, [FIRST, SECOND])


def test_a_key_that_is_no_routine_beside_an_address_key_is_no_batch() -> None:
    answer = {hex(FIRST): _listing(FIRST), "note": "the second function was skipped"}
    assert _batch_listings(json.dumps(answer)) == (False, {})


def _asked(args: dict[str, Any], answer: dict[str, str]) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0160", tool="lift_many", args=args, output=json.dumps(answer), facts=_BATCH
    )


def test_a_name_keyed_answer_to_one_address_names_the_routine_at_that_address() -> None:
    entry = _asked({"address": hex(FIRST)}, {"main": "int main(void)\n{ }"})
    assert _entry_functions(entry) == [(FIRST, ["main"])]


def test_a_name_keyed_answer_to_several_addresses_keeps_the_call_s_addresses() -> None:
    answer = {"main": "int main(void)\n{ helper(); }", "helper": "void helper(void)\n{}"}
    entry = _asked({"addresses": [hex(FIRST), hex(SECOND)]}, answer)
    assert _entry_functions(entry) == [(FIRST, []), (SECOND, [])]


def test_a_name_keyed_answer_to_a_call_that_gave_no_address_keeps_its_names() -> None:
    answer = {"main": "int main(void)\n{ }", "helper": "void helper(void)\n{}"}
    entry = _asked({"functions": "main,helper"}, answer)
    assert _entry_functions(entry) == [(None, ["main"]), (None, ["helper"])]
