"""The tool effects part says each tool's effects in whole sentences, from its row.

Every sentence the part prints is pinned here word for word under the row
that prints it: where a tool was called through, where a tool that ran the
sample's code read it, a network reached by a server's own word, the sandbox
service a server fronts as the disclosure placed it, the calls that ended
without completing, and the questions a declaration leaves open. A tool with
no completed call is said only by how its calls ended (T-770).
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.analysis import tool_effects
from malspark.analysis.isolation import (
    BY_DECLARATION,
    BY_MEASUREMENT,
    CHILD,
    IN_PROCESS,
    LOCAL_SERVICE,
    REMOTE_SERVICE,
    UNPLACED,
)
from malspark.analysis.tool_effects import (
    DECLARED,
    FAILED,
    NOT_RUN,
    REFUSED,
    SERVER_HINT,
    SERVER_STATED,
    effects_lines,
)

CODE = tool_effects._code


def _tool(source: str, tool: str, **over: Any) -> dict[str, Any]:
    """A row of one tool with one completed call, declared to do none of the three.

    Built with where each answer came from: each a declaration's, a network a server's own
    word or hint by ``network_by``, unless the row says otherwise.
    """
    row: dict[str, Any] = {
        "source": source,
        "server": "",
        "tool": tool,
        "calls": 1,
        "served": 0,
        "executes": "no",
        "network": False,
        "network_by": DECLARED,
        "third_party": "no",
        "why_undeclared": "",
        "when": "",
        "completed": 1,
        "failed": 0,
        "not_run": 0,
        "refused": 0,
    }
    row.update(over)
    origin = {DECLARED: "declared", SERVER_HINT: "hint", SERVER_STATED: "server"}
    row.setdefault(
        "network_from", origin.get(row["network_by"], "") if row["network"] is not None else ""
    )
    row.setdefault("third_party_from", "declared" if row["third_party"] else "")
    row.setdefault("executes_from", "declared" if row["executes"] else "")
    row.setdefault("why_from", "declared" if row["why_undeclared"] else "")
    return row


def _stored(row: dict[str, Any]) -> dict[str, Any]:
    """The row as a record stored before it recorded where its answers came from."""
    return {key: value for key, value in row.items() if not key.endswith("_from")}


def test_each_place_a_tool_was_called_through_is_named_by_its_kind() -> None:
    assert tool_effects._label({"source": "", "server": "s"}, CODE) == (
        "tool server `s`, which recorded no source"
    )
    assert tool_effects._label({"source": "", "server": ""}, CODE) == (
        "the platform's own tools, which record no source"
    )
    assert tool_effects._label({"source": "pack"}, CODE) == "Triage pack (`pack`)"
    assert tool_effects._label({"source": "mcp:analysis"}, CODE) == "tool server `analysis`"
    assert tool_effects._label({"source": "provider:vt"}, CODE) == (
        "the `vt` provider's tool server"
    )
    assert tool_effects._label({"source": "odd"}, CODE) == "source `odd`"


def test_an_in_process_source_with_no_label_is_named_as_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tool_effects, "_in_process_labels", lambda: {"x": ""})
    assert tool_effects._label({"source": "x"}, CODE) == "the in-process source (`x`)"


def test_where_a_tool_that_ran_the_sample_read_it_is_said_as_isolation_placed_it() -> None:
    note = tool_effects._read_note
    assert note({"read_where": None}) == (
        "the isolation part records no read of the sample by its source"
    )
    assert note({"read_where": IN_PROCESS}) == "read in the worker process itself"
    kept = {"read_where": CHILD, "read_isolated": True, "read_isolated_by": BY_MEASUREMENT}
    assert note(kept) == "read in a process the worker started, measured as kept from the worker"
    assert note({**kept, "read_isolated": False}) == (
        "read in a process the worker started, not shown to be kept from the worker"
    )
    assert note({**kept, "read_isolated_by": BY_DECLARATION}) == (
        "read in a process the worker started, kept from the worker as its block's declaration "
        "of a launcher says"
    )
    assert note({"read_where": LOCAL_SERVICE}) == "read at a local server this run does not measure"
    assert note({"read_where": REMOTE_SERVICE}) == "read outside this machine"
    assert note({"read_where": UNPLACED}) == "where it read the sample cannot be told"


def test_a_network_answer_is_said_in_the_voice_of_where_it_came_from() -> None:
    network_from = tool_effects.network_from
    # A row built with the field says it.
    for held in ("declared", "sends", "server", "hint", "read", ""):
        assert network_from({"network_from": held, "network_by": DECLARED}) == held
    # A row stored before it cannot tell a declaration from the platform's reading: its
    # network is taken, whatever is sent beside it, a named mode and a closed one alike.
    assert network_from({"network_by": SERVER_STATED, "network": True}) == "server"
    assert network_from({"network_by": SERVER_HINT, "network": True}) == "hint"
    for sent in ("no", "hash", "bytes"):
        assert network_from({"network_by": DECLARED, "network": True, "third_party": sent}) == (
            "taken"
        )
    assert network_from({"network_by": DECLARED, "network": "case_store"}) == "taken"
    assert network_from({"network_by": DECLARED, "network": False}) == "taken"
    assert network_from({"network_by": ""}) == ""
    assert tool_effects._hint_closed({"hints": {"openWorldHint": False}}) == (
        "though its server's own hint says it does not reach outside its server"
    )
    assert tool_effects._hint_closed({"hints": {"openWorldHint": True}}) == ""
    assert tool_effects._hint_closed({}) == ""
    assert tool_effects._offline({"offline_without_credentials": True}) == (
        "declared to answer offline when it is given no credentials"
    )
    assert tool_effects._offline({"offline_without_credentials": False}) == ""
    assert tool_effects._offline({}) == ""


def test_a_call_to_the_sandbox_a_server_fronts_is_said_where_the_disclosure_placed_it() -> None:
    note = tool_effects._sandbox_place(CODE)
    local = {"placed_where": "local", "placed_host": "127.0.0.1:8000", "placed_why": ""}
    assert note(local) == (
        "at `127.0.0.1:8000`, which the disclosure places on this machine, so the operator's "
        "own and not a third party"
    )
    assert note({**local, "placed_where": "remote", "placed_host": "sandbox.example.org"}) == (
        "at `sandbox.example.org`, outside this machine; whether it is the operator's own the "
        "settings do not say"
    )
    assert note({**local, "placed_why": "its block names no host"}) == (
        "where it went cannot be told: its block names no host"
    )
    assert note({"placed_where": "", "placed_host": "", "placed_why": ""}) == (
        "where it went cannot be told: the record does not say"
    )


def test_a_share_of_calls_is_said_only_where_it_is_not_every_call() -> None:
    assert tool_effects._of_calls(FAILED)({"calls": 3, "served": 1, "not_run": 1, "failed": 2}) == (
        "2 of 4 calls"
    )
    assert tool_effects._of_calls(REFUSED)({"calls": 2, "served": 2, "refused": 2}) == (
        "2 of 4 calls"
    )
    # A row stored before ``served`` was counted holds a step never run in ``calls``.
    assert tool_effects._of_calls(NOT_RUN)({"calls": 3, "not_run": 1}) == "1 of 3 calls"
    assert tool_effects._of_calls(FAILED)({"calls": 2, "failed": 2}) == ""


def test_every_line_of_the_part_is_said_whole_under_the_rows_that_print_it() -> None:
    rows = [
        _tool(
            "mcp:analysis",
            "emu",
            executes="native",
            read_where=CHILD,
            read_isolated=False,
            read_isolated_by="",
        ),
        _tool(
            "mcp:analysis",
            "emulate_function",
            executes="emulation",
            when="at analysis level 2 and above",
            read_where=None,
        ),
        _tool(
            "mcp:detonator",
            "submit",
            executes="sandbox",
            network="operator_sandbox",
            third_party="bytes",
            placed_where="local",
            placed_host="127.0.0.1:8000",
            placed_why="",
        ),
        _tool("provider:remote", "detonate", executes="sandbox", network=True, third_party="bytes"),
        _tool("mcp:intel", "lookup", network=True, third_party="hash"),
        _tool(
            "mcp:other", "fetch", executes="", network=True, network_by=SERVER_HINT, third_party=""
        ),
        _tool(
            "mcp:other",
            "pull",
            network=True,
            network_by=SERVER_STATED,
            server_states={"effects.executes": "no"},
        ),
        _tool("mcp:memory", "recall", network="case_store"),
        _tool("mcp:knowledge", "techniques", network="on_refresh"),
        _tool("mcp:analysis", "pe_info"),
        _tool("pack", "strings"),
        _tool("mcp:other", "peek", network_by=SERVER_HINT),
        _tool(
            "mcp:analysis",
            "capabilities",
            executes="",
            network=None,
            third_party="",
            calls=0,
            completed=0,
            not_run=1,
        ),
        _tool(
            "mcp:intel",
            "submit_file",
            network=True,
            third_party="bytes",
            calls=0,
            completed=0,
            served=1,
            refused=1,
        ),
        _tool("mcp:analysis", "rule_scan", third_party="", calls=3, completed=1, failed=2),
        _tool(
            "mcp:x",
            "run_script",
            executes="",
            network=None,
            third_party="",
            why_undeclared="it runs whatever script it is given",
        ),
        # Answered again from an earlier entry: no call, said nowhere.
        _tool("mcp:analysis", "again", calls=0, completed=0, served=2),
    ]
    part = {"partial_reason": "the job was stopped part way", "tools": rows}
    placed = [{"backend": "qdrant", "host": "127.0.0.1", "where": "local"}]
    assert effects_lines(part, stores=placed) == [
        "This part may be incomplete: the job was stopped part way, and a call made in the "
        "step it stopped in may not be recorded.",
        "Ran the sample's code natively: `emu` on tool server `analysis`, read in a process "
        "the worker started, not shown to be kept from the worker.",
        "Declared to run the sample's code under emulation: `emulate_function` on tool server"
        " `analysis`, at analysis level 2 and above, the isolation part records no read of "
        "the sample by its source.",
        "Declared to have the sample run in the sandbox service its server fronts: `submit` "
        "on tool server `detonator`, at `127.0.0.1:8000`, which the disclosure places on this"
        " machine, so the operator's own and not a third party.",
        "Declared to run the sample in a sandbox its server does not front, which may be a "
        "third party's: `detonate` on the `remote` provider's tool server.",
        "Declared to reach the network: `detonate` on the `remote` provider's tool server; "
        "`lookup` on tool server `intel`.",
        "Stated by its own server, in a declaration its block does not trust, to reach the "
        "network: `pull` on tool server `other`.",
        "Said by its server's own hint to reach outside its server: `fetch` on tool server "
        "`other`.",
        "Declared to reach the sandbox service its server fronts: `submit` on tool server "
        "`detonator`, at `127.0.0.1:8000`, which the disclosure places on this machine, so "
        "the operator's own and not a third party.",
        "Declared to reach the configured case-memory store, which the disclosure's "
        "case-memory row places: `recall` on tool server `memory`.",
        "Declared to reach the network only to fetch or refresh reference data they keep, "
        "sending nothing of the sample: `techniques` on tool server `knowledge`.",
        "Declared to send the sample's hash to a third party: `lookup` on tool server `intel`.",
        "Declared to hand the sample's bytes to the sandbox service its server fronts: "
        "`submit` on tool server `detonator`, at `127.0.0.1:8000`, which the disclosure "
        "places on this machine, so the operator's own and not a third party; where each call"
        " sent them is in the upload rows of the disclosure above.",
        "Declared to send the sample's bytes to a third party: `detonate` on the `remote` "
        "provider's tool server; where each call sent them is in the upload rows of the "
        "disclosure above.",
        "Declared to do none of these: 2 tools, on tool server `analysis` and Triage pack "
        "(`pack`).",
        "Said not to reach the network by its server's own hint (openWorldHint false), which "
        "no declaration says: `peek` on tool server `other`.",
        "Said of itself by its own server, which no declaration the operator trusts says: "
        "`pull` on tool server `other`, effects.executes no.",
        "Was not run, so none of the effects listed for it happened: `capabilities` on tool "
        "server `analysis`.",
        "Was refused, so nothing was sent: `submit_file` on tool server `intel`.",
        "Failed, so whether the effects listed for it happened cannot be told: `rule_scan` on"
        " tool server `analysis`, 2 of 3 calls.",
        "Undeclared whether it may run the sample's code or send the sample's hash or bytes "
        "to a third party, so not taken as safe: `fetch` on tool server `other`.",
        "Undeclared whether it may send the sample's hash or bytes to a third party, so not "
        "taken as safe: `rule_scan` on tool server `analysis`.",
        "Undeclared whether it may run the sample's code, reach the network or send the "
        "sample's hash or bytes to a third party, so not taken as safe: `run_script` on tool "
        "server `x`; its declaration says why: it runs whatever script it is given.",
    ]
    # The same rows stored before they recorded where each answer came from: every
    # effect is taken, a server's own word and hint stay its own.
    stored = {**part, "tools": [_stored(row) for row in rows]}
    assert effects_lines(stored, stores=placed) == [
        "This part may be incomplete: the job was stopped part way, and a call made in the "
        "step it stopped in may not be recorded.",
        "Taken as running the sample's code natively: `emu` on tool server `analysis`, read "
        "in a process the worker started, not shown to be kept from the worker.",
        "Taken as running the sample's code under emulation: `emulate_function` on tool "
        "server `analysis`, at analysis level 2 and above, the isolation part records no read"
        " of the sample by its source.",
        "Taken as having the sample run in the sandbox service its server fronts: `submit` on"
        " tool server `detonator`, at `127.0.0.1:8000`, which the disclosure places on this "
        "machine, so the operator's own and not a third party.",
        "Taken as running the sample in a sandbox its server does not front, which may be a "
        "third party's: `detonate` on the `remote` provider's tool server.",
        "Taken as reaching the network: `detonate` on the `remote` provider's tool server; "
        "`lookup` on tool server `intel`.",
        "Stated by its own server, in a declaration its block does not trust, to reach the "
        "network: `pull` on tool server `other`.",
        "Said by its server's own hint to reach outside its server: `fetch` on tool server "
        "`other`.",
        "Taken as reaching the sandbox service its server fronts: `submit` on tool server "
        "`detonator`, at `127.0.0.1:8000`, which the disclosure places on this machine, so "
        "the operator's own and not a third party.",
        "Taken as reaching the configured case-memory store, which the disclosure's "
        "case-memory row places: `recall` on tool server `memory`.",
        "Taken as reaching the network only to fetch or refresh reference data they keep, "
        "sending nothing of the sample: `techniques` on tool server `knowledge`.",
        "Taken as sending the sample's hash to a third party: `lookup` on tool server `intel`.",
        "Taken as handing the sample's file to the sandbox service its server fronts: "
        "`submit` on tool server `detonator`, at `127.0.0.1:8000`, which the disclosure "
        "places on this machine, so the operator's own and not a third party; the upload rows"
        " of the disclosure above say what is known of where each call sent it.",
        "Taken as sending the sample's file out of the deployment: `detonate` on the `remote`"
        " provider's tool server; the upload rows of the disclosure above say what is known "
        "of where each call sent it.",
        "Taken as doing none of these: 2 tools, on tool server `analysis` and Triage pack "
        "(`pack`).",
        "Said not to reach the network by its server's own hint (openWorldHint false), which "
        "no declaration says: `peek` on tool server `other`.",
        "Said of itself by its own server, which no declaration the operator trusts says: "
        "`pull` on tool server `other`, effects.executes no.",
        "Was not run, so none of the effects listed for it happened: `capabilities` on tool "
        "server `analysis`.",
        "Was refused, so nothing was sent: `submit_file` on tool server `intel`.",
        "Failed, so whether the effects listed for it happened cannot be told: `rule_scan` on"
        " tool server `analysis`, 2 of 3 calls.",
        "Undeclared whether it may run the sample's code or send the sample's hash or bytes "
        "to a third party, so not taken as safe: `fetch` on tool server `other`.",
        "Undeclared whether it may send the sample's hash or bytes to a third party, so not "
        "taken as safe: `rule_scan` on tool server `analysis`.",
        "Undeclared whether it may run the sample's code, reach the network or send the "
        "sample's hash or bytes to a third party, so not taken as safe: `run_script` on tool "
        "server `x`; its declaration says why: it runs whatever script it is given.",
    ]


def test_a_part_with_no_call_says_so_and_a_record_without_the_part_says_nothing() -> None:
    assert effects_lines({"partial_reason": "", "tools": []}) == [
        "This run recorded no tool call, so no tool's effects are said."
    ]
    served_only = _tool("mcp:analysis", "again", calls=0, completed=0, served=2)
    assert effects_lines({"tools": [served_only]}) == [
        "This run recorded no tool call, so no tool's effects are said."
    ]
    assert effects_lines({"partial_reason": ""}) == []
    assert effects_lines(None) == []


def test_one_tool_declared_to_do_none_is_counted_in_the_singular() -> None:
    assert effects_lines({"tools": [_tool("mcp:analysis", "pe_info")]}) == [
        "Declared to do none of these: 1 tool, on tool server `analysis`."
    ]


def test_the_report_heads_the_part_with_its_lead_sentence_after_the_isolation_part() -> None:
    from malspark.analysis.disclosure import disclosure_record
    from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    record = disclosure_record({}, entries=[], worker={"uid": 1000})
    record["effects"] = {"partial_reason": "", "tools": [_tool("mcp:analysis", "pe_info")]}

    def rendered(held: dict[str, Any]) -> str:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"final_decision": "Malware", "disclosure": held},
        )
        return str(MarkdownRenderer().render(report))

    text = rendered(record)
    assert (
        "\n\n**Tool effects:** what is listed of each tool this run called beyond answering: "
        "whether it runs the sample's code, reaches the network, or sends the sample's hash or "
        "bytes to a third party, each said as declared or as taken by where it came from. "
        "Where the sample's bytes were read is the isolation part above, and where they were "
        "sent the upload rows of the disclosure; an answer nothing gives is listed as "
        "undeclared for that tool, and is not taken as safe.\n\n"
        "- Declared to do none of these: 1 tool, on tool server `analysis`.\n"
    ) in text
    # A record stored before the part existed prints no lead sentence.
    old = {key: value for key, value in record.items() if key != "effects"}
    assert "**Tool effects:**" not in rendered(old)


def test_every_lead_of_a_row_built_with_where_its_network_came_from_is_said_whole() -> None:
    def built(source: str, tool: str, **over: Any) -> dict[str, Any]:
        return _tool(
            source,
            tool,
            **{
                "network_from": "declared",
                "third_party_from": "declared",
                "executes_from": "declared",
                "why_from": "",
                "offline_without_credentials": None,
                **over,
            },
        )

    sandbox = {"placed_where": "local", "placed_host": "127.0.0.1:8000", "placed_why": ""}
    rows = [
        built(
            "mcp:intel",
            "lookup",
            network=True,
            third_party="hash",
            when="only at analysis level 2",
            offline_without_credentials=True,
        ),
        built("mcp:intel", "whois", network=True, third_party="no", when="on a domain only"),
        # Declared to send the hash, its network not declared: taken as reaching it.
        built("mcp:rep", "hash_only", network=True, third_party="hash", network_from="sends"),
        built(
            "mcp:analysis",
            "unpack",
            network=True,
            third_party="bytes",
            network_from="sends",
            third_party_from="discloses",
            hints={"openWorldHint": False},
        ),
        built("mcp:other", "pull", network=True, network_by=SERVER_STATED, network_from="server"),
        built("mcp:other", "fetch", network=True, network_by=SERVER_HINT, network_from="hint"),
        built(
            "mcp:detonator",
            "submit",
            executes="sandbox",
            network="operator_sandbox",
            third_party="bytes",
            third_party_from="discloses",
            when="at analysis level 3",
            **sandbox,
        ),
        built("mcp:detonator", "status", network="operator_sandbox", when="hourly", **sandbox),
        built("mcp:memory", "recall", network="case_store", when="when memory is on"),
        built("mcp:knowledge", "techniques", network="on_refresh", when="once a day"),
        built("provider:remote", "detonate", executes="sandbox", network=True, when="on request"),
    ]
    at = (
        "at `127.0.0.1:8000`, which the disclosure places on this machine, so the operator's own "
        "and not a third party"
    )
    placed = [{"backend": "qdrant", "host": "127.0.0.1", "where": "local"}]
    assert effects_lines({"tools": rows}, stores=placed) == [
        f"Declared to have the sample run in the sandbox service its server fronts: `submit` on "
        f"tool server `detonator`, at analysis level 3, {at}.",
        "Declared to run the sample in a sandbox its server does not front, which may be a third "
        "party's: `detonate` on the `remote` provider's tool server, on request.",
        "Declared to reach the network: `lookup` on tool server `intel`, only at analysis level "
        "2, declared to answer offline when it is given no credentials; `whois` on tool server "
        "`intel`, on a domain only; `detonate` on the `remote` provider's tool server, on "
        "request.",
        "Taken as reaching the network, as a tool declared to send the sample's hash out: "
        "`hash_only` on tool server `rep`.",
        "Taken as reaching the network, as a tool taken to send the sample's file out: `unpack` "
        "on tool server `analysis`, though its server's own hint says it does not reach outside "
        "its server.",
        "Stated by its own server, in a declaration its block does not trust, to reach the "
        "network: `pull` on tool server `other`.",
        "Said by its server's own hint to reach outside its server: `fetch` on tool server "
        "`other`.",
        f"Declared to reach the sandbox service its server fronts: `submit` on tool server "
        f"`detonator`, at analysis level 3, {at}; `status` on tool server `detonator`, hourly, "
        f"{at}.",
        "Declared to reach the configured case-memory store, which the disclosure's case-memory "
        "row places: `recall` on tool server `memory`, when memory is on.",
        "Declared to reach the network only to fetch or refresh reference data they keep, "
        "sending nothing of the sample: `techniques` on tool server `knowledge`, once a day.",
        "Declared to send the sample's hash to a third party: `lookup` on tool server `intel`, "
        "only at analysis level 2, declared to answer offline when it is given no credentials; "
        "`hash_only` on tool server `rep`.",
        f"Taken as handing the sample's file to the sandbox service its server fronts: `submit` "
        f"on tool server `detonator`, at analysis level 3, {at}; the upload rows of the "
        "disclosure above say what is known of where each call sent it.",
        "Taken as sending the sample's file out of the deployment: `unpack` on tool server "
        "`analysis`; the upload rows of the disclosure above say what is known of where each "
        "call sent it.",
    ]
    # A row taken to reach the network is never said to have reached it, nor declared to.
    taken = [line for line in effects_lines({"tools": rows}) if "`unpack`" in line]
    assert not any(line.startswith(("Declared", "Reached")) for line in taken)


def test_a_row_reaching_the_network_with_no_recorded_origin_is_taken() -> None:
    row = _tool("mcp:old", "t", network=True, network_by="", third_party="")
    assert tool_effects.network_from(row) == ""
    assert (
        effects_lines({"tools": [row]})[0]
        == "Taken as reaching the network: `t` on tool server `old`."
    )


def test_where_a_network_answer_came_from_and_the_offline_condition_are_built_from_the_entry() -> (
    None
):
    from malspark.analysis.tool_effects import effects_part, entry_effects
    from malspark.schemas.evidence import LedgerEntry

    def entry(tool: str, facts: dict[str, Any]) -> LedgerEntry:
        return LedgerEntry(
            id="ev_0001",
            tool=tool,
            source="mcp:svc",
            server="svc",
            agent="static",
            facts={"v": 1, "kind": "", "platform_read": [], **facts},
        )

    # A hash-only third party with no network declared: taken as reaching it, as a tool
    # declared to send the hash out, never "declared to reach the network".
    hashed = entry("hash_only", {"effects": {"executes": "no", "third_party": "hash"}})
    assert (entry_effects(hashed).network, entry_effects(hashed).network_from) == (True, "sends")
    offline = entry(
        "lookup",
        {
            "effects": {
                "executes": "no",
                "network": True,
                "third_party": "hash",
                "offline_without_credentials": True,
            }
        },
    )
    effects = entry_effects(offline)
    assert (effects.network_from, effects.offline_without_credentials) == ("declared", True)
    sent = entry("push", {"discloses_sample": True})
    assert (entry_effects(sent).third_party, entry_effects(sent).network_from) == ("bytes", "sends")
    part = effects_part([hashed, offline, sent])
    assert [
        (row["tool"], row["network_from"], row["offline_without_credentials"])
        for row in part["tools"]
    ] == [
        ("hash_only", "sends", None),
        ("lookup", "declared", True),
        ("push", "sends", None),
    ]
    lines = effects_lines(part)
    assert lines[:3] == [
        "Declared to reach the network: `lookup` on tool server `svc`, declared to answer "
        "offline when it is given no credentials.",
        "Taken as reaching the network, as a tool declared to send the sample's hash out: "
        "`hash_only` on tool server `svc`.",
        "Taken as reaching the network, as a tool taken to send the sample's file out: `push` "
        "on tool server `svc`.",
    ]


def test_bytes_a_declaration_states_are_declared_and_bytes_read_cautiously_are_taken() -> None:
    from malspark.analysis.tool_effects import effects_part, entry_effects
    from malspark.schemas.evidence import LedgerEntry

    def entry(tool: str, facts: dict[str, Any]) -> LedgerEntry:
        return LedgerEntry(
            id="ev_0001",
            tool=tool,
            source="mcp:svc",
            server="svc",
            agent="static",
            facts={"v": 1, "kind": "", "platform_read": [], **facts},
        )

    stated = entry("push", {"effects": {"executes": "no", "network": True, "third_party": "bytes"}})
    cautious = entry("upload", {"discloses_sample": True})
    assert entry_effects(stated).third_party_from == "declared"
    assert entry_effects(cautious).third_party_from == "discloses"
    part = effects_part([stated, cautious])
    assert [(row["tool"], row["third_party_from"]) for row in part["tools"]] == [
        ("push", "declared"),
        ("upload", "discloses"),
    ]
    lines = effects_lines(part)
    assert (
        "Taken as reaching the network, as a tool taken to send the sample's file out: `upload` "
        "on tool server `svc`." in lines
    )
    sent = [line for line in lines if "sample's bytes" in line or "sample's file out of" in line]
    assert sent == [
        "Declared to send the sample's bytes to a third party: `push` on tool server `svc`; where "
        "each call sent them is in the upload rows of the disclosure above.",
        "Taken as sending the sample's file out of the deployment: `upload` on tool server "
        "`svc`; the upload rows of the disclosure above say what is known of where each call "
        "sent it.",
    ]
    # Declared to send the bytes, its network not declared: the sends clause says so.
    quiet = entry("drop", {"effects": {"executes": "no", "third_party": "bytes"}})
    assert effects_lines(effects_part([quiet]))[0] == (
        "Taken as reaching the network, as a tool declared to send the sample's bytes to a third "
        "party: `drop` on tool server `svc`."
    )
    # A row stored before ``third_party_from``, of either origin: its fields hold no
    # declared value for the bytes, so they are taken.
    for row in part["tools"]:
        stored = {key: value for key, value in row.items() if key != "third_party_from"}
        assert tool_effects.third_party_from(stored) == "discloses"
        assert any(
            line.startswith("Taken as sending the sample's file out of the deployment: ")
            for line in effects_lines({"tools": [stored]})
        )
    # A sent hash of a row stored before the field is taken too, and so is sending nothing.
    assert tool_effects.third_party_from({"third_party": "hash"}) == "taken"
    assert tool_effects.third_party_from({"third_party": "no"}) == "taken"
    assert tool_effects.third_party_from({}) == ""


def test_a_run_of_the_sample_s_code_is_said_only_where_a_counted_call_completed_unconditioned() -> (
    None
):
    ran = _tool("mcp:analysis", "emu", executes="emulation")
    assert effects_lines({"tools": [ran]})[0].startswith(
        "Ran the sample's code under emulation: `emu` on tool server `analysis`"
    )
    conditioned = {**ran, "when": "at analysis level 2"}
    legacy = {key: value for key, value in ran.items() if key != "completed"}
    for row in (conditioned, legacy):
        assert effects_lines({"tools": [row]})[0].startswith(
            "Declared to run the sample's code under emulation: `emu` on tool server `analysis`"
        )
    # Only failed: said by how it ended, never as a run.
    failed = {**ran, "completed": 0, "failed": 1}
    assert not any(
        line.startswith(("Ran ", "Declared to run")) for line in effects_lines({"tools": [failed]})
    )
