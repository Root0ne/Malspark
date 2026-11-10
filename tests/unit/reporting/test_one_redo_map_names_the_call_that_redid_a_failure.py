"""The agreement round and the run summary name the same call as a failure's redo.

The run summary names the call that redid a failed call (``redone_calls``),
while the agreement round's answered facts linked the failure to the first
later call that answered for its address: a few instructions read from the
address before the call that asked the same question again. The round was
shown a later call that redid nothing, and the limitations paragraph was held
to the one the summary named (T-600). One redo map is read now, and every
reader names the call that redid the failure. Every address, entry and tool
name here is a neutral synthetic value, read by declared kinds.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from malspark.reporting.agreement_facts import answered_later, ledger_facts
from malspark.reporting.limitation_facts import failed_calls
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.redone_calls import redo_map, redone_failures
from malspark.reporting.section_agreement import FACT, passages_of, prompt_text
from malspark.schemas.evidence import LedgerEntry

GATE, OTHER = 0x2475A10, 0x2475B20
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
# Instructions read from an address: a listing of code, never the whole function.
_BYTES = {"v": 1, "kind": "byte_disassembly", "reader": "listing"}


def _failed(entry_id: str, *addresses: int) -> LedgerEntry:
    asked = {"address": hex(addresses[0])} if len(addresses) == 1 else {}
    if len(addresses) > 1:
        asked = {"functions": ",".join(hex(a) for a in addresses)}
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args=asked,
        ok=False,
        error="no function there",
        facts=_DECOMPILE,
    )


def _lifted(entry_id: str, address: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n  return a;\n}}\n",
        facts=_DECOMPILE,
    )


def _some_instructions(entry_id: str, address: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="read_instructions",
        args={"address": hex(address), "count": 3},
        output=f"{address:x}: push rbp\n{address + 1:x}: mov rbp, rsp\n",
        facts=_BYTES,
    )


def _ledger() -> list[LedgerEntry]:
    return [
        _failed("ev_0001", GATE),
        _some_instructions("ev_0002", GATE),
        _lifted("ev_0003", GATE),
    ]


def test_a_failed_call_is_linked_to_the_call_that_redid_it_not_the_first_later_answer() -> None:
    ledger = _ledger()
    assert [row["answered_by"] for row in redone_failures(ledger)] == [["ev_0003"]]
    links = answered_later(ledger)
    assert [(a.failed, a.answered, a.redone) for a in links] == [("ev_0001", "ev_0003", True)]


def test_a_failed_call_no_later_call_redid_keeps_its_first_later_answer() -> None:
    # A few instructions answer for the address, and nothing asked the same question.
    ledger = _ledger()[:2]
    assert redone_failures(ledger) == []
    links = answered_later(ledger)
    assert [(a.failed, a.answered, a.redone) for a in links] == [("ev_0001", "ev_0002", False)]


def test_each_address_of_a_redone_call_is_linked_to_the_call_that_redid_it_there() -> None:
    ledger = [_failed("ev_0001", GATE, OTHER), _lifted("ev_0002", OTHER), _lifted("ev_0003", GATE)]
    (redo,) = redo_map(ledger)
    assert redo.answered_by == ("ev_0002", "ev_0003")
    assert dict(redo.by_address) == {GATE: "ev_0003", OTHER: "ev_0002"}
    links = answered_later(ledger)
    # In the answering calls' ledger order.
    assert [(a.address, a.answered) for a in links] == [(OTHER, "ev_0002"), (GATE, "ev_0003")]


def test_the_redo_map_is_read_once_and_every_reader_names_the_same_call() -> None:
    ledger = _ledger()
    found = ledger_facts(ledger)
    assert found.redone is not None
    assert [(r.entry_id, r.answered_by) for r in found.redone] == [("ev_0001", ("ev_0003",))]
    (call,) = failed_calls(ledger, found.answered, found.image_bases, found.redone)
    assert call.redone_by == ("ev_0003",)
    assert dict(call.answered) == {GATE: "ev_0003"}
    # The rows the run summary prints are the map's own.
    assert redone_failures(ledger) == [
        {"entry_id": "ev_0001", "tool": "lift_routine", "answered_by": ["ev_0003"]}
    ]


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            string_resolution=TechnicalSubsection(
                title="API and String Resolution",
                body="The listing of 0x5a10 failed once [ev_0001].",
            ),
        ),
    )


def test_the_round_is_shown_the_call_that_redid_the_failure() -> None:
    passages: list[Any] = passages_of(_report(), entries=_ledger())
    facts = {p.id: p for p in passages if p.kind == FACT}
    assert facts["answered.1"].cites == frozenset({"ev_0001", "ev_0003"})
    text = prompt_text(passages)
    assert (
        'ev_0001 ("lift_routine") for 0x2475a10 failed; the later call ev_0003 '
        '("lift_routine") for the same address answered, asking the same question again'
    ) in text
    assert "ev_0002" not in facts["answered.1"].text
