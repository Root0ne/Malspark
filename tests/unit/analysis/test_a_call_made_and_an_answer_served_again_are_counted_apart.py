"""A call whose tool ran and an answer served again are counted apart, by one definition.

The run's finished events hold one event per ledger entry, an answer served
again from an earlier entry included; the disclosure block, its effects part
and the per-agent latency table counted only the calls that ran, and none of
them said so. One predicate (``schemas.evidence.call_state``) now decides for
every reader, and each count carries the calls made and, apart, the answers
without a run and the steps never run. The recorder states "no run" on the
entry at the only places that file one; a call that ran and whose answer an
earlier entry holds (a decompile answered with a function already read) is a
call made, its time counted. Every entry is counted once, a call that stayed
on this machine in a line of its own, so the block's lines sum to the finished
events per source. A block, a latency row or an entry stored before these
counts existed reads as it did.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from malspark.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from malspark.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from malspark.analysis.disclosure import (
    DISCLOSURE_VERSION,
    PLATFORM_SOURCE,
    disclosure_lines,
    disclosure_record,
)
from malspark.analysis.run_summary import RunSummaryBuilder, tool_latency_lines
from malspark.analysis.tool_effects import effects_part
from malspark.pipeline.events import TOOL_CALL_FINISHED
from malspark.pipeline.triage_pack import NOT_RUN_PREFIX
from malspark.schemas.evidence import (
    MADE,
    NOT_RUN,
    SERVED,
    EvidenceCounter,
    LedgerEntry,
    call_counts,
    call_state,
    call_was_made,
)

FAR = {"mcp.servers.far.transport": "http", "mcp.servers.far.url": "https://far.example"}
INTEL = {"mcp.servers.intel.transport": "http", "mcp.servers.intel.url": "https://intel.example"}
NEAR = {"mcp.servers.near.transport": "stdio", "mcp.servers.near.url": ""}
SNAPSHOT = {"memory.backend": "memory", **FAR, **INTEL, **NEAR}
LOOKUP_FACTS = {"v": 1, "kind": "reputation", "arguments": {"hash": "sha256"}}
CLOSED_FACTS = {
    "v": 1,
    "kind": "strings",
    "effects": {"executes": "no", "network": False, "third_party": "no"},
}


def _ledger() -> tuple[list[LedgerEntry], list[dict[str, Any]]]:
    """A run's ledger with answers served again on every kind of source, and its finished events.

    The read of an entry again (``read_evidence``) runs its tool and names the
    entry it reads: a call made.
    """
    events: list[dict[str, Any]] = []
    counter = EvidenceCounter()

    def _sink(kind: str, data: dict[str, Any]) -> None:
        if kind == TOOL_CALL_FINISHED:
            events.append(dict(data))

    triage = EvidenceRecorder("triage", counter=counter, sink=_sink)
    static = EvidenceRecorder("static", counter=counter, sink=_sink)
    judge = EvidenceRecorder("judge", counter=counter, sink=_sink)

    def _call(recorder: EvidenceRecorder, source: str, tool: str, ms: int, **over: Any) -> Any:
        server = source.partition(":")[2] or None
        entry = recorder.record(
            tool=tool,
            args={"q": tool},
            server=server,
            source=source,
            output="answer",
            duration_ms=ms,
        )
        for name, value in over.items():
            setattr(entry, name, value)
        return entry

    def _served(recorder: EvidenceRecorder, held: Any, **over: Any) -> Any:
        entry = recorder.record_repeat(
            tool=held.tool,
            args=held.args,
            server=held.server,
            source=held.source,
            first=held.id,
            said="answered from the ledger",
        )
        for name, value in over.items():
            setattr(entry, name, value)
        return entry

    report = _call(triage, "mcp:intel", "file_report", 300, facts=LOOKUP_FACTS)
    _served(static, report, facts=LOOKUP_FACTS)
    _served(static, report, facts=LOOKUP_FACTS)
    listing = _call(static, "mcp:far", "decompile", 900)
    _call(static, "mcp:far", "imports", 100)
    _served(static, listing)
    strings = _call(static, "mcp:near", "strings", 50, facts=CLOSED_FACTS)
    _served(static, strings, facts=CLOSED_FACTS)
    _call(triage, "pack", "yara_scan", 20)
    read = judge.record(
        tool="read_evidence",
        args={"evidence_id": listing.id},
        server=None,
        output="read again",
        repeated_of=listing.id,
    )
    assert read.source is None
    entries = [*triage.entries, *static.entries, *judge.entries]
    entries.sort(key=lambda entry: entry.id)
    return entries, events


def _by_source(entry: Any) -> str:
    return str(entry.source or entry.server or PLATFORM_SOURCE)


def _block_counts(record: dict[str, Any]) -> Counter[tuple[str, str]]:
    """``(source, made|served)`` over every row of the block and its stayed line."""
    out: Counter[tuple[str, str]] = Counter()
    for part in ("lookups", "uploads", "servers", "undeclared"):
        for row in record[part]:
            out[(row["source"], MADE)] += row["calls"]
            out[(row["source"], SERVED)] += row["served"]
    for row in record["stayed"]:
        out[(row["source"], MADE)] += row[MADE]
        out[(row["source"], SERVED)] += row[SERVED]
    return +out


class TestTheOneDefinition:
    def test_an_entry_stored_without_the_field_reads_as_it_did(self) -> None:
        ran = LedgerEntry(id="ev_0001", tool="t")
        again = LedgerEntry(id="ev_0002", tool="t", repeated_of="ev_0001")
        guard = LedgerEntry(id="ev_0003", tool="t", repeated_of="ev_0003")

        assert call_was_made(ran) and call_was_made({"id": "ev_0001"})
        assert not call_was_made(again) and not call_was_made({"repeated_of": "ev_0001"})
        assert not call_was_made(guard)
        assert call_counts([ran, again, guard]) == {MADE: 1, SERVED: 2, NOT_RUN: 0}

    def test_the_stated_field_decides_over_repeated_of(self) -> None:
        held = {"id": "ev_0002", "tool": "t", "repeated_of": "ev_0001", "ran": True}

        assert call_was_made(held) and call_was_made(LedgerEntry(**held))
        assert call_state({"id": "ev_0003", "tool": "t", "ran": False}) == SERVED

    def test_a_served_repeat_and_a_guard_answer_state_no_run(self) -> None:
        recorder = EvidenceRecorder("static", counter=EvidenceCounter())
        first = recorder.record(tool="t", args={}, server=None, output="answer")
        again = recorder.record_repeat(tool="t", args={}, server=None, first=first.id, said="s")
        guard = recorder.record_guard_answer(tool="t", args={}, server=None, said="no")

        assert (again.ran, guard.ran) == (False, False)
        assert call_state(again) == call_state(guard) == SERVED
        assert json.loads(again.model_dump_json())["ran"] is False
        assert call_state(json.loads(guard.model_dump_json())) == SERVED

    def test_a_step_never_run_is_neither_made_nor_served(self) -> None:
        step = LedgerEntry(id="ev_0004", tool="t", ok=False, error=f"{NOT_RUN_PREFIX} no input")

        assert call_state(step) == NOT_RUN and not call_was_made(step)
        assert call_counts([step]) == {MADE: 0, SERVED: 0, NOT_RUN: 1}


class TestTheStoredBytes:
    # An entry as a ledger stored it before ``ran`` existed.
    STORED = (
        '{"id":"ev_0001","stage":"analysis","agent":"static","server":"far","tool":"t",'
        '"args":{},"symbol":null,"ok":true,"error":null,"remediation":null,"output":"a",'
        '"structured":null,"function_ranges":null,"truncated":false,"chars_dropped":0,'
        '"repeated_of":null,"args_repaired":false,"args_raw":null,"model":null,'
        '"started_at":0.0,"duration_ms":5,"seq":1}'
    )

    def test_a_stored_entry_dumps_byte_for_byte(self) -> None:
        assert LedgerEntry.model_validate_json(self.STORED).model_dump_json() == self.STORED

    def test_a_call_that_ran_dumps_no_field(self) -> None:
        recorder = EvidenceRecorder("static", counter=EvidenceCounter())
        entry = recorder.record(tool="t", args={}, server="far", output="a", duration_ms=5)

        assert entry.ran is None and "ran" not in entry.model_dump()
        assert entry.model_dump_json() == self.STORED


class _Address(BaseModel):
    address: str = ""


LISTING = "\nundefined8 FUN_1360bc0ae78(void)\n\n{\n  FUN_1360bc09040(0);\n  return 0;\n}\n\n"


def _held_decompile() -> list[LedgerEntry]:
    """A decompile that runs at an address inside a function an earlier call read."""

    def _run(address: str = "") -> str:
        return LISTING

    tool = StructuredTool.from_function(
        func=_run,
        name="decompile_function",
        description="d",
        args_schema=_Address,
        infer_schema=False,
    )
    (stamped,) = stamp_source([tool], PROVIDER_FAMILY, declared="provider:ghidra")
    recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
    (wrapped,) = record_tools([stamped], recorder, RepeatGuard())
    wrapped.invoke({"address": "0x1360bc0ae78"})
    wrapped.invoke({"address": "0x1360bc0ae80"})
    first, held = recorder.entries
    assert held.repeated_of == first.id, "answered with the function the first call read"
    # As long as a decompiler takes: the time the call ran is what is counted.
    return [first, held.model_copy(update={"duration_ms": 1500})]


class TestARunWhoseAnswerAnEarlierEntryHolds:
    def test_it_is_a_call_made(self) -> None:
        first, held = _held_decompile()

        assert held.ran is True and call_was_made(held)
        assert call_state(json.loads(held.model_dump_json())) == MADE

    def test_the_latency_table_counts_its_time(self) -> None:
        entries = _held_decompile()
        latency = RunSummaryBuilder(start_time=0.0).set_tool_latency(entries)._tool_latency

        assert latency is not None
        row = latency["reverser"]
        assert (row["calls"], row["served"]) == (2, 0)
        assert row["total_ms"] == entries[0].duration_ms + 1500
        assert row["slowest"]["id"] == entries[1].id

    def test_the_block_and_the_effects_part_count_it_made(self) -> None:
        entries = _held_decompile()
        record = disclosure_record({"memory.backend": "memory"}, entries=entries)
        rows = [
            row for part in ("lookups", "uploads", "servers", "undeclared") for row in record[part]
        ] + record["stayed"]

        assert sum(row.get("calls", row.get(MADE, 0)) for row in rows) == 2
        assert sum(row.get(SERVED, 0) for row in rows) == 0
        assert not any("answered without a run" in line for line in disclosure_lines(record))
        (effects,) = effects_part(entries)["tools"]
        assert (effects["calls"], effects["served"]) == (2, 0)


class TestTheStayedLine:
    def test_with_no_call_made_only_the_answers_without_a_run_are_said(self) -> None:
        recorder = EvidenceRecorder("static", counter=EvidenceCounter())
        first = recorder.record(tool="t", args={}, server="near", source="mcp:near", output="a")
        recorder.record_repeat(tool="read", args={}, server=None, first=first.id, said="s")
        lines = disclosure_lines(disclosure_record(SNAPSHOT, entries=recorder.entries))

        (stayed,) = [line for line in lines if "stayed on this machine" in line]
        assert "the platform's own tools 1 answered without a run" in stayed
        assert " 0 (" not in stayed and "0 calls" not in stayed

    def test_a_step_never_run_is_said_apart_and_never_among_the_calls(self) -> None:
        step = LedgerEntry(
            id="ev_0001",
            agent="pipeline",
            tool="capa",
            source="pack",
            ok=False,
            error=f"{NOT_RUN_PREFIX} no rules",
        )
        ran = LedgerEntry(id="ev_0002", agent="pipeline", tool="yara", source="pack", duration_ms=7)
        record = disclosure_record(SNAPSHOT, entries=[step, ran])

        (stayed,) = [line for line in disclosure_lines(record) if "stayed on this machine" in line]
        assert "1 call (+1 not run)" in stayed
        latency = RunSummaryBuilder(start_time=0.0).set_tool_latency([step, ran])._tool_latency
        assert latency is not None
        assert (latency["pipeline"]["calls"], latency["pipeline"][NOT_RUN]) == (1, 1)
        (line,) = tool_latency_lines(latency)
        assert "pipeline 1 calls (+1 not run) in" in line
        rows = {row["tool"]: row for row in effects_part([step, ran])["tools"]}
        assert (rows["capa"]["calls"], rows["capa"][NOT_RUN]) == (0, 1)


class TestTheRecordsAgree:
    def test_the_finished_events_are_the_calls_made_and_served_per_source(self) -> None:
        entries, events = _ledger()
        record = disclosure_record(SNAPSHOT, entries=entries)

        by_id = {entry.id: entry for entry in entries}
        expected: Counter[tuple[str, str]] = Counter()
        for event in events:
            entry = by_id[event["evidence_id"]]
            served = event.get("repeated_of") and entry.tool != "read_evidence"
            expected[(_by_source(entry), SERVED if served else MADE)] += 1

        assert len(events) == len(entries)
        assert _block_counts(record) == +expected
        assert record["v"] == DISCLOSURE_VERSION == 5

    def test_the_block_states_both_totals(self) -> None:
        entries, _events = _ledger()
        lines = disclosure_lines(disclosure_record(SNAPSHOT, entries=entries))

        assert any(
            "`intel.example`" in line and "was asked once (+2 answered without a run)" in line
            for line in lines
        )
        assert any(
            line.startswith("Tool calls: tool server `far`")
            and "2 calls (+1 answered without a run)" in line
            for line in lines
        )
        (stayed,) = [line for line in lines if "stayed on this machine" in line]
        assert "3 calls (+1 answered without a run)" in stayed
        assert "tool server `near` 1 (+1 answered without a run)" in stayed
        assert "the platform's own tools 1" in stayed

    def test_the_effects_part_counts_the_same(self) -> None:
        entries, _events = _ledger()
        part = effects_part(entries)

        rows = {(row["source"], row["tool"]): row for row in part["tools"]}
        assert (
            rows[("mcp:intel", "file_report")]["calls"],
            rows[("mcp:intel", "file_report")]["served"],
        ) == (1, 2)
        assert (
            rows[("mcp:far", "decompile")]["calls"],
            rows[("mcp:far", "decompile")]["served"],
        ) == (1, 1)
        assert sum(row["calls"] + row["served"] for row in part["tools"]) == len(
            [entry for entry in entries if entry.source]
        )

    def test_the_latency_table_agrees(self) -> None:
        entries, events = _ledger()
        latency = RunSummaryBuilder(start_time=0.0).set_tool_latency(entries)._tool_latency

        assert latency is not None
        assert sum(row["calls"] for row in latency.values()) == call_counts(entries)[MADE]
        assert sum(row["calls"] + row["served"] for row in latency.values()) == len(events)
        assert latency["static"]["served"] == 4
        (line,) = tool_latency_lines(latency)
        assert "static 3 calls (+4 answered without a run) in" in line


class TestAnOlderBlock:
    def test_a_block_stored_before_the_served_counts_reads_as_it_did(self) -> None:
        stored = {
            "v": 4,
            "nothing_left": False,
            "partial_reason": "",
            "models": [],
            "lookups": [],
            "uploads": [],
            "servers": [
                {
                    "source": "mcp:far",
                    "transport": "http",
                    "host": "far.example",
                    "where": "remote",
                    "calls": 40,
                    "why": "",
                }
            ],
            "undeclared": [],
            "local_servers": [],
            "stores": [],
            "tracing": False,
            "unreadable_entries": 0,
        }

        assert disclosure_lines(stored) == [
            "Tool calls: tool server `far` over http at `far.example` (outside this machine): "
            "40 calls."
        ]

    def test_an_older_latency_row_reads_as_it_did(self) -> None:
        row = {"calls": 3, "total_ms": 3_000, "slowest": {"tool": "t", "ms": 2_000}}

        assert tool_latency_lines({"static": row}) == [
            "**Tool calls**: static 3 calls in 3.0s, slowest `t` 2.0s  "
        ]


class TestTheEfficiencyRecord:
    def test_a_run_whose_answer_an_earlier_entry_holds_is_no_repeat_and_no_uncited_entry(
        self,
    ) -> None:
        from malspark.analysis.efficiency import calls_record, uncited_record

        first, held = _held_decompile()
        served = LedgerEntry(
            id="ev_0009", agent="reverser", tool=first.tool, repeated_of=first.id, ran=False
        )

        calls = calls_record([first, held, served])
        assert calls is not None and calls["repeated"] == 1, "only the served answer"
        uncited = uncited_record([first, held, served], {})
        assert uncited is not None and uncited["entries"] == 1


class _EvidenceId(BaseModel):
    evidence_id: str = ""


def _read_again_ledger() -> list[LedgerEntry]:
    """An answer of a tool with no server, then a read of it again by its id."""
    from malspark.agents.tool_answer_clearing import READS_EVIDENCE

    recorder = EvidenceRecorder("static", counter=EvidenceCounter())
    first = recorder.record(tool="t", args={}, server=None, output="answer")
    reader = StructuredTool.from_function(
        func=lambda evidence_id="": "answer",
        name="read_again",
        description="d",
        args_schema=_EvidenceId,
        infer_schema=False,
        metadata={READS_EVIDENCE: True},
    )
    (wrapped,) = record_tools([reader], recorder, RepeatGuard())
    wrapped.invoke({"evidence_id": first.id})
    _first, read = recorder.entries
    assert read.repeated_of == first.id
    return list(recorder.entries)


class TestAReadAgain:
    def test_it_is_served_and_reads_the_same_from_an_old_ledger(self) -> None:
        _first, read = _read_again_ledger()
        stored = json.loads(read.model_dump_json())
        old = {key: value for key, value in stored.items() if key != "ran"}

        assert read.ran is False
        assert call_state(read) == call_state(stored) == call_state(old) == SERVED

    def test_the_evidence_summary_counts_it_a_repeat(self) -> None:
        from malspark.pipeline.nodes import evidence_summary

        summary = evidence_summary(_read_again_ledger())

        assert (summary["ok"], summary.get("repeats")) == (1, 1)

    def test_it_makes_no_server_stale(self) -> None:
        from types import SimpleNamespace

        from malspark.agents.base_agent import _stale_after

        agent = SimpleNamespace(run_state_source={"evidence_ledger": _read_again_ledger()})

        assert _stale_after(agent, set()) == set()


class TestAnOldHeldDecompile:
    def test_it_keeps_its_milliseconds_and_an_old_served_repeat_stays_served(self) -> None:
        first, held = _held_decompile()
        old_held = {k: v for k, v in json.loads(held.model_dump_json()).items() if k != "ran"}
        old_served = {"id": "ev_0009", "agent": "reverser", "tool": first.tool}
        old_served |= {"repeated_of": first.id, "duration_ms": 0}
        entries = [json.loads(first.model_dump_json()), old_held, old_served]
        latency = RunSummaryBuilder(start_time=0.0).set_tool_latency(entries)._tool_latency

        assert latency is not None
        row = latency["reverser"]
        assert (row["calls"], row["served"]) == (2, 1)
        assert row["total_ms"] == first.duration_ms + 1500
