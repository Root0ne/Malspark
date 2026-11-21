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
    """A row of one tool with one completed call, declared to do none of the three."""
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
    return row


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


def test_a_network_answered_by_the_server_s_own_word_says_whose_word_it_is() -> None:
    assert tool_effects._by_hint_only({"network_by": SERVER_STATED}) == (
        "by its server's own declaration, which its block does not trust"
    )
    assert tool_effects._by_hint_only({"network_by": SERVER_HINT}) == "by its server's own hint"
    assert tool_effects._by_hint_only({"network_by": DECLARED}) == ""


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
    fronted = (
        "`submit` on tool server `detonator`, at `127.0.0.1:8000`, which the disclosure places "
        "on this machine, so the operator's own and not a third party"
    )
    assert effects_lines(part) == [
        "This part may be incomplete: the job was stopped part way, and a call made in the step "
        "it stopped in may not be recorded.",
        "Ran the sample's code natively: `emu` on tool server `analysis`, read in a process the "
        "worker started, not shown to be kept from the worker.",
        "Ran the sample's code under emulation: `emulate_function` on tool server `analysis`, at "
        "analysis level 2 and above, the isolation part records no read of the sample by its "
        "source.",
        f"Had the sample run in the sandbox service its server fronts: {fronted}.",
        "Handed the sample to a third party's sandbox, which may run it: `detonate` on the "
        "`remote` provider's tool server.",
        "Reached the network: `detonate` on the `remote` provider's tool server; `lookup` on tool "
        "server `intel`; `fetch` on tool server `other`, by its server's own hint; `pull` on "
        "tool server `other`, by its server's own declaration, which its block does not trust.",
        f"Reached the sandbox service its server fronts: {fronted}.",
        "Reached the configured case-memory store, which the disclosure's case-memory row "
        "places: `recall` on tool server `memory`.",
        "Reach the network only to fetch or refresh reference data they keep, sending nothing "
        "of the sample: `techniques` on tool server `knowledge`.",
        "Sent the sample's hash to a third party: `lookup` on tool server `intel`.",
        f"Handed the sample's bytes to the sandbox service its server fronts: {fronted}; where "
        "each call sent them is in the upload rows of the disclosure above.",
        "Sent the sample's bytes to a third party: `detonate` on the `remote` provider's tool "
        "server; where each call sent them is in the upload rows of the disclosure above.",
        "Declared to do none of these: 2 tools, on tool server `analysis` and Triage pack "
        "(`pack`).",
        "Said not to reach the network by its server's own hint (openWorldHint false), which no "
        "declaration says: `peek` on tool server `other`.",
        "Said of itself by its own server, which no declaration the operator trusts says: "
        "`pull` on tool server `other`, effects.executes no.",
        "Was not run, so none of its declared effects happened: `capabilities` on tool server "
        "`analysis`.",
        "Was refused, so nothing was sent: `submit_file` on tool server `intel`.",
        "Failed, so whether its declared effects happened cannot be told: `rule_scan` on tool "
        "server `analysis`, 2 of 3 calls.",
        "Undeclared whether it may run the sample's code or send the sample's hash or bytes to "
        "a third party, so not taken as safe: `fetch` on tool server `other`.",
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
        "\n\n**Tool effects:** what each tool this run called is declared to do beyond "
        "answering: run the sample's code, reach the network, or send the sample's hash or "
        "bytes to a third party. Where the sample's bytes were read is the isolation part "
        "above, and where they were sent the upload rows of the disclosure; a tool whose "
        "declaration does not say is listed as undeclared, and is not taken as safe.\n\n"
        "- Declared to do none of these: 1 tool, on tool server `analysis`.\n"
    ) in text
    # A record stored before the part existed prints no lead sentence.
    old = {key: value for key, value in record.items() if key != "effects"}
    assert "**Tool effects:**" not in rendered(old)
