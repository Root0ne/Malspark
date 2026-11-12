"""A call whose tool ran and an answer served again are counted apart, by one definition.

The run's finished events hold one event per ledger entry, an answer served
again from an earlier entry included; the disclosure block, its effects part
and the per-agent latency table counted only the calls that ran, and none of
them said so. One predicate (``schemas.evidence.call_was_made``) now decides
for every reader, and each count carries both totals: the calls made and the
answers without a run. Every entry is counted once, a call that stayed on this
machine in a line of its own, so the block's lines sum to the finished events
per source. A block stored before the served counts existed reads as it did.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from malspark.agents.evidence_recorder import EvidenceRecorder
from malspark.analysis.disclosure import (
    DISCLOSURE_VERSION,
    PLATFORM_SOURCE,
    disclosure_lines,
    disclosure_record,
)
from malspark.analysis.run_summary import RunSummaryBuilder, tool_latency_lines
from malspark.analysis.tool_effects import effects_part
from malspark.pipeline.events import TOOL_CALL_FINISHED
from malspark.schemas.evidence import (
    MADE,
    SERVED,
    EvidenceCounter,
    LedgerEntry,
    call_counts,
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
    """A run's ledger with answers served again on every kind of source, and its finished events."""
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
    def test_a_call_that_ran_is_made_and_any_answer_without_a_run_is_not(self) -> None:
        ran = LedgerEntry(id="ev_0001", tool="t")
        again = LedgerEntry(id="ev_0002", tool="t", repeated_of="ev_0001")
        guard = LedgerEntry(id="ev_0003", tool="t", repeated_of="ev_0003")

        assert call_was_made(ran) and call_was_made({"id": "ev_0001"})
        assert not call_was_made(again) and not call_was_made({"repeated_of": "ev_0001"})
        assert not call_was_made(guard)
        assert call_counts([ran, again, guard]) == {MADE: 1, SERVED: 2}


class TestTheRecordsAgree:
    def test_the_finished_events_are_the_calls_made_and_served_per_source(self) -> None:
        entries, events = _ledger()
        record = disclosure_record(SNAPSHOT, entries=entries)

        by_id = {entry.id: entry for entry in entries}
        expected: Counter[tuple[str, str]] = Counter()
        for event in events:
            entry = by_id[event["evidence_id"]]
            expected[(_by_source(entry), SERVED if event.get("repeated_of") else MADE)] += 1

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
        assert "2 calls (+2 answered without a run)" in stayed
        assert "tool server `near` 1 (+1 answered without a run)" in stayed
        assert "the platform's own tools 0 (+1 answered without a run)" in stayed

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
