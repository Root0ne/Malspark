"""An effect the platform read of a tool's listing or program is said as taken, never declared.

What the platform reads of a listed tool (a reputation service's lookup, the
cautious reading kept of a tool its block removed, a program-analysis
server's reading) is laid under the declarations and is in force as any of
them. Which fields of each tool's effects only that reading gave is recorded
where it is laid (``Declared.read_fields``), stored with each entry
(``core.declared_reading.READ_KEY``) and carried to the effects row
(``network_from``, ``third_party_from``, ``executes_from``, ``why_from``), so
the tool-effects part says each such effect as taken; what a declaration
states stays declared. The record is read by no model: every rendering of a
tool's declaration a model reads is the same with and without it (T-820).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from malspark.analysis import tool_effects
from malspark.analysis.disclosure import _stayed_line
from malspark.analysis.tool_effects import effects_lines, effects_part
from malspark.core import served_declarations as sd
from malspark.core.config import Settings
from malspark.core.declared_reading import READ_KEY, facts_record
from malspark.core.derived_declarations import derived_tool_facts, program_readings_of
from malspark.core.tool_declarations import ToolDeclarations, launch_identity

CODE = tool_effects._code

# A reputation service's lookup: read-only, requires a hash, gives no openWorldHint.
LOOKUP = {
    "name": "lookup_hash",
    "description": "Look up a file report",
    "inputSchema": {
        "type": "object",
        "properties": {"sha256": {"type": "string"}},
        "required": ["sha256"],
    },
    "annotations": {"readOnlyHint": True},
}
# A tool that takes the file's content, which its block removed.
UPLOAD = {
    "name": "removed_upload",
    "description": "Upload a file",
    "inputSchema": {
        "type": "object",
        "properties": {"file": {"type": "string", "contentEncoding": "base64"}},
        "required": ["file"],
    },
}
# A program-analysis server's tool that says it sends what a path names.
SEND = {
    "name": "send_program",
    "description": "Sends the program file to the remote service",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
# A program-analysis server's tool read as emulating.
EMULATE = {
    "name": "emulate_function",
    "description": "Emulate a function of the program",
    "inputSchema": {
        "type": "object",
        "properties": {"address": {"type": "string"}},
        "required": ["address"],
    },
}
SERVICE = {
    "transport": "streamable-http",
    "url": "https://intel.example.invalid/mcp",
    "roles": ["reputation"],
    "enabled": True,
}
PROGRAM = {
    "transport": "streamable-http",
    "url": "https://dis.example.invalid/mcp",
    "roles": ["disassembler"],
    "enabled": True,
}


@pytest.fixture
def nothing_kept() -> Iterator[None]:
    sd.forget_served()
    sd._UNSAVED.clear()
    yield
    sd.forget_served()
    sd._UNSAVED.clear()


def _declarations(**blocks: dict[str, Any]) -> ToolDeclarations:
    """The declarations in force once each block's server listed what the test lists."""
    settings = Settings.model_validate({"mcp": {"servers": blocks}})
    for key, block in blocks.items():
        listing = block["listing"]
        launch = launch_identity(settings.mcp.servers[key])
        program = program_readings_of(listing) if "disassembler" in block["roles"] else None
        sd.register_served(f"mcp:{key}", {}, launch, derived_tool_facts(listing), None, program)
    return ToolDeclarations.from_settings(settings)


def _entries(held: ToolDeclarations, *called: tuple[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "id": f"ev_{n:04d}",
            "source": f"mcp:{key}",
            "server": key,
            "tool": tool,
            "ok": True,
            "args": {},
            "facts": facts_record(f"mcp:{key}", tool, declared=held),
        }
        for n, (key, tool) in enumerate(called, 1)
    ]


def test_a_reputation_lookup_read_from_its_listing_is_taken(nothing_kept: None) -> None:
    held = _declarations(svc={**SERVICE, "listing": [LOOKUP]})
    (entry,) = _entries(held, ("svc", "lookup_hash"))
    assert entry["facts"]["effects"] == {"executes": "no", "network": True, "third_party": "hash"}
    assert entry["facts"][READ_KEY] == [
        "effects.executes",
        "effects.network",
        "effects.third_party",
    ]
    part = effects_part([entry])
    (row,) = part["tools"]
    assert (row["network_from"], row["third_party_from"], row["executes_from"]) == (
        "read",
        "read",
        "read",
    )
    assert effects_lines(part) == [
        "Taken as reaching the network: `lookup_hash` on tool server `svc`.",
        "Taken as sending the sample's hash to a third party: `lookup_hash` on tool server `svc`.",
    ]


def test_a_removed_tool_still_read_as_sending_is_taken(nothing_kept: None) -> None:
    held = _declarations(
        svc={**SERVICE, "tool_facts": {"removed_upload": None}, "listing": [LOOKUP, UPLOAD]}
    )
    (entry,) = _entries(held, ("svc", "removed_upload"))
    assert entry["facts"][READ_KEY] == [
        "discloses_sample",
        "effects.network",
        "effects.third_party",
    ]
    assert effects_lines(effects_part([entry])) == [
        "Taken as reaching the network: `removed_upload` on tool server `svc`.",
        "Taken as sending the sample's file out of the deployment: `removed_upload` on tool "
        "server `svc`; the upload rows of the disclosure above say what is known of where each "
        "call sent it.",
        "Undeclared whether it may run the sample's code, so not taken as safe: "
        "`removed_upload` on tool server `svc`.",
    ]


def test_a_program_reading_is_taken(nothing_kept: None) -> None:
    held = _declarations(dis={**PROGRAM, "listing": [SEND, EMULATE]})
    entries = _entries(held, ("dis", "send_program"), ("dis", "emulate_function"))
    assert entries[1]["facts"]["effects"] == {"executes": "emulation"}
    assert entries[1]["facts"][READ_KEY] == ["effects.executes"]
    lines = effects_lines(effects_part(entries))
    assert lines[:3] == [
        "Taken as running the sample's code under emulation: `emulate_function` on tool server "
        "`dis`, the isolation part records no read of the sample by its source.",
        "Taken as reaching the network: `send_program` on tool server `dis`.",
        "Taken as sending the sample's file out of the deployment: `send_program` on tool server "
        "`dis`; the upload rows of the disclosure above say what is known of where each call "
        "sent it.",
    ]
    assert not any(line.startswith(("Ran ", "Declared ")) for line in lines)


def test_what_the_block_declares_stays_declared_over_a_reading(nothing_kept: None) -> None:
    declared = {"effects": {"executes": "no", "network": True, "third_party": "hash"}}
    held = _declarations(
        svc={**SERVICE, "tool_facts": {"lookup_hash": declared}, "listing": [LOOKUP]}
    )
    (entry,) = _entries(held, ("svc", "lookup_hash"))
    assert READ_KEY not in entry["facts"]
    assert effects_lines(effects_part([entry])) == [
        "Declared to reach the network: `lookup_hash` on tool server `svc`.",
        "Declared to send the sample's hash to a third party: `lookup_hash` on tool server `svc`.",
    ]


def test_the_block_s_statement_of_its_tools_as_a_whole_is_declared(nothing_kept: None) -> None:
    whole = {"executes": "no", "network": False, "third_party": "no"}
    held = _declarations(dis={**PROGRAM, "default_effects": whole, "listing": [EMULATE]})
    (entry,) = _entries(held, ("dis", "emulate_function"))
    # The network and the third party are the block's own word; the run is the reading's.
    assert entry["facts"][READ_KEY] == ["effects.executes"]
    assert effects_lines(effects_part([entry]))[0].startswith(
        "Taken as running the sample's code under emulation: `emulate_function`"
    )


# ---------------------------------------------------------------------------
# No model reads the record
# ---------------------------------------------------------------------------


def test_every_rendering_of_a_declaration_a_model_reads_is_the_same_without_the_record(
    nothing_kept: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malspark.core import declared_reading as dr
    from malspark.core.reputation import record_at_write
    from malspark.core.undeclared_tools import categories_of
    from malspark.pipeline.triage_pack import _render_entries
    from malspark.schemas.evidence import LedgerEntry, stored_bytes

    blocks = {
        "svc": {
            **SERVICE,
            "tool_facts": {"removed_upload": None},
            "listing": [LOOKUP, UPLOAD],
        },
        "dis": {**PROGRAM, "listing": [SEND, EMULATE]},
    }
    with_record = _declarations(**blocks)
    sd.forget_served()
    monkeypatch.setattr(sd, "_read_fields", lambda *args, **kwargs: {})
    without = _declarations(**blocks)
    for source in ("mcp:svc", "mcp:dis"):
        kept, bare = with_record.source(source), without.source(source)
        assert kept is not None and bare is not None
        assert kept.read_fields and not bare.read_fields
        # The tools in force, and the description tags each tool is offered under.
        assert dict(kept.tools) == dict(bare.tools)
        assert categories_of(kept.tools) == categories_of(bare.tools)
    called = (("svc", "lookup_hash"), ("svc", "removed_upload"), ("dis", "send_program"))
    marked = _entries(with_record, *called)
    plain = [
        {**entry, "facts": {k: v for k, v in entry["facts"].items() if k != READ_KEY}}
        for entry in marked
    ]
    assert all(READ_KEY in entry["facts"] for entry in marked)
    for one, other in zip(marked, plain, strict=True):
        for reader in (
            dr.facts_of,
            dr.kind_free_facts,
            dr.kind_of,
            dr.named_facts,
            dr.served_statement,
            dr.server_hints,
            dr.declared_name,
        ):
            assert reader(one) == reader(other), reader.__name__
        assert record_at_write(one["facts"], ok=True, output="{}") == record_at_write(
            other["facts"], ok=True, output="{}"
        )
    # The pack's lines and an answer's cost, as a model is handed and charged them.
    ledger = [LedgerEntry(**{**entry, "output": "answer"}) for entry in marked]
    bare_ledger = [LedgerEntry(**{**entry, "output": "answer"}) for entry in plain]
    assert _render_entries(ledger, 4000) == _render_entries(bare_ledger, 4000)
    assert [stored_bytes(e) for e in ledger] == [stored_bytes(e) for e in bare_ledger]


# ---------------------------------------------------------------------------
# Stored rows, and the rows' joins
# ---------------------------------------------------------------------------


def _row(**over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "source": "mcp:svc",
        "server": "",
        "tool": "t",
        "calls": 1,
        "completed": 1,
        "executes": "no",
        "network": True,
        "network_by": "declared",
        "third_party": "no",
    }
    row.update(over)
    return row


def test_a_row_that_records_no_origin_says_a_network_a_hash_and_bytes_as_taken() -> None:
    stored = [
        _row(tool="reach"),
        _row(tool="hashed", third_party="hash"),
        _row(tool="sent", third_party="bytes"),
    ]
    assert effects_lines({"tools": stored}) == [
        "Taken as reaching the network: `reach`, `hashed` and `sent` on tool server `svc`.",
        "Taken as sending the sample's hash to a third party: `hashed` on tool server `svc`.",
        "Taken as sending the sample's file out of the deployment: `sent` on tool server `svc`; "
        "the upload rows of the disclosure above say what is known of where each call sent it.",
    ]


def test_an_origin_this_code_does_not_know_is_taken() -> None:
    odd = _row(network_from="elsewhere", third_party_from="elsewhere", third_party="hash")
    assert effects_lines({"tools": [odd]}) == [
        "Taken as reaching the network: `t` on tool server `svc`.",
        "Taken as sending the sample's hash to a third party: `t` on tool server `svc`.",
    ]
    sent = _row(network_from="sends", third_party="bytes", third_party_from="elsewhere")
    assert effects_lines({"tools": [sent]})[0] == (
        "Taken as reaching the network, as a tool taken to send the sample's file out: `t` on "
        "tool server `svc`."
    )


def test_the_case_store_a_tool_reaches_is_placed_only_where_the_case_memory_row_places_it() -> None:
    reach = {"tools": [_row(tool="recall", network="case_store")]}
    lead = "Declared to reach the configured case-memory store"
    placed = [{"backend": "qdrant", "host": "127.0.0.1", "where": "local"}]
    unplaced = [{"backend": "qdrant", "host": "", "where": "unknown", "why": "no address"}]
    named = [{"backend": "qdrant", "host": "10.0.0.5", "where": "unknown", "why": "a gateway"}]
    assert effects_lines(reach, stores=placed) == [
        f"{lead}, which the disclosure's case-memory row places: `recall` on tool server `svc`."
    ]
    for rows in (unplaced, named):
        assert effects_lines(reach, stores=rows) == [
            f"{lead}, of which the disclosure's case-memory row cannot tell where it runs: "
            "`recall` on tool server `svc`."
        ]
    assert effects_lines(reach, stores=[]) == [
        f"{lead}, which the disclosure records as kept in the process or not configured: "
        "`recall` on tool server `svc`."
    ]
    read = {"tools": [_row(tool="recall", network="case_store", network_from="read")]}
    assert effects_lines(read, stores=placed) == [
        "Taken as reaching the configured case-memory store, which the disclosure's case-memory "
        "row places: `recall` on tool server `svc`."
    ]


def test_the_calls_made_here_place_the_store_only_where_the_case_memory_line_does() -> None:
    stayed = [{"source": "mcp:svc", "made": 1, "served": 0, "not_run": 0}]
    effects = {"tools": [_row(tool="recall", network="case_store")]}
    head = (
        "Tool calls made on this machine: 1 call (tool server `svc` 1); of the tools called "
        "through these sources, `recall` on tool server `svc` is declared to read the "
        "case-memory store, "
    )
    unplaced = [{"backend": "qdrant", "host": "", "where": "unknown", "why": "no address"}]
    assert _stayed_line(stayed, CODE, {"effects": effects, "stores": unplaced}) == (
        f"{head}of which the case-memory line cannot tell where it runs."
    )
    named = [{"backend": "qdrant", "host": "10.0.0.5", "where": "unknown", "why": "a gateway"}]
    assert _stayed_line(stayed, CODE, {"effects": effects, "stores": named}) == (
        f"{head}of which the case-memory line cannot tell where it runs."
    )
    placed = [{"backend": "qdrant", "host": "127.0.0.1", "where": "local"}]
    assert _stayed_line(stayed, CODE, {"effects": effects, "stores": placed}) == (
        f"{head}which the case-memory line places."
    )


def test_an_effects_row_with_no_source_is_joined_to_its_stayed_row_by_its_server() -> None:
    stayed = [{"source": "refs", "made": 1, "served": 0, "not_run": 0}]
    row = _row(source="", server="refs", tool="refresh", network="on_refresh")
    assert _stayed_line(stayed, CODE, {"effects": {"tools": [row]}}) == (
        "Tool calls made on this machine: 1 call (tool server `refs` 1); of the tools called "
        "through these sources, `refresh` on tool server `refs` is declared to reach the "
        "network only to fetch or refresh reference data, sending nothing of the sample "
        "(whether a call did is not recorded in this report)."
    )
