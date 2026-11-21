"""The calls made on this machine and the case-memory line say only what the run recorded.

A tool called on this machine whose declared network is a named mode (to refresh its
reference data, or the case-memory store) is said with that declaration wherever its calls
are counted, read by joining the stayed row's source with the effects part's rows, never by
a tool's name (T-815). Every value here is made up.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.disclosure import (
    _nothing_sentence,
    _stayed_line,
    disclosure_lines,
    disclosure_record,
)
from malspark.analysis.tool_effects import effects_lines

LOCAL_LLM = {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"}
RUNTIME = {"http://127.0.0.1:8080": "llama.cpp /props"}
TOKENS = {
    "llm_calls": 1,
    "per_agent": {"static": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}},
}
STDIO = {"mcp.servers.refs.transport": "stdio", "mcp.servers.refs.url": ""}
QDRANT = {"qdrant": {"address_leaf": "url"}}
WORKER = {"uid": 1000, "platform_names_in_env": []}
REFRESH = {
    "v": 1,
    "kind": "capability_rules",
    "effects": {"executes": "no", "network": "on_refresh", "third_party": "no"},
}
CASES = {
    "v": 1,
    "kind": "",
    "effects": {"executes": "no", "network": "case_store", "third_party": "no"},
}


def _code(text: str) -> str:
    return f"`{text}`"


def _entry(source: str, tool: str, facts: dict[str, Any], **over: Any) -> dict[str, Any]:
    server = source.partition(":")[2] if source.startswith("mcp:") else "pipeline"
    return {
        "id": "ev_0001",
        "tool": tool,
        "args": {},
        "ok": True,
        "source": source,
        "server": server,
        "facts": facts,
        **over,
    }


def _record(store_url: str, *entries: dict[str, Any], **over: Any) -> dict[str, Any]:
    snapshot = {
        **LOCAL_LLM,
        **STDIO,
        "memory.backend": "qdrant",
        "memory.qdrant.url": store_url,
    }
    return disclosure_record(
        snapshot,
        entries=list(entries),
        tokens=TOKENS,
        agents=["static"],
        runtimes=RUNTIME,
        backends=QDRANT,
        worker=WORKER,
        **over,
    )


# ---------------------------------------------------------------------------
# The calls made here, and "nothing left"
# ---------------------------------------------------------------------------


def test_a_local_tool_declared_to_refresh_its_data_is_named_where_nothing_is_said_left() -> None:
    record = _record("http://localhost:6333", _entry("mcp:refs", "refresh_catalogue", REFRESH))

    assert record["nothing_left"] is True
    lines = disclosure_lines(record)
    assert lines[0] == (
        "Nothing of the sample left this machine, as the declarations count it. This rests on: "
        "every model endpoint in this run's settings is a local address that answered as a "
        "model runtime: `127.0.0.1` (llama.cpp /props) (a local address that answered as a "
        "model runtime is taken as running here, and a tunnel or proxy to a remote runtime "
        "cannot be told apart); the local tool servers called (tool server `refs`) were taken "
        "as local by their tools' declarations; `refresh_catalogue` on tool server `refs` is "
        "declared to reach the network only to fetch or refresh reference data, sending "
        "nothing of the sample (whether a call did is not recorded in this report); the "
        "case-memory store is at a local address; no lookup was asked, and tracing is off."
    )
    assert lines[-1] == (
        "Tool calls made on this machine: 1 call (tool server `refs` 1); of the tools called "
        "through these sources, `refresh_catalogue` on tool server `refs` is declared to "
        "reach the network only to fetch or refresh reference data, sending nothing of the "
        "sample (whether a call did is not recorded in this report)."
    )
    assert not any("stayed on this machine" in line for line in lines)


def test_an_in_process_tool_declared_to_read_the_case_store_is_said_so_where_it_is_counted() -> (
    None
):
    record = _record(
        "http://cases.example.org:6333",
        _entry("pack", "function_matches", CASES),
        _entry("pack", "pe_info", {"v": 1, "kind": "", "effects": {"network": False}}),
    )

    assert record["stayed"] == [{"source": "pack", "made": 2, "served": 0, "not_run": 0}]
    (row,) = [row for row in record["effects"]["tools"] if row["tool"] == "function_matches"]
    assert row["network"] == "case_store"
    # No line places that call without its declaration.
    lines = [*disclosure_lines(record), *effects_lines(record["effects"])]
    assert [line for line in lines if "function_matches" in line] == [
        "Tool calls made on this machine: 2 calls (the platform's in-process source `pack` 2); "
        "of the tools called through these sources, `function_matches` on the platform's "
        "in-process source `pack` is declared to read the case-memory store, which the "
        "case-memory line places.",
        "Reached the configured case-memory store, which the disclosure's case-memory row "
        "places: `function_matches` on Triage pack (`pack`).",
    ]


def test_the_calls_made_here_name_each_named_mode_and_the_store_s_place() -> None:
    rows = [{"source": "mcp:refs", "made": 2, "served": 0, "not_run": 0}]
    tool = {"source": "mcp:refs", "server": "", "calls": 2}
    both = {
        "effects": {
            "tools": [
                {**tool, "tool": "a", "network": "on_refresh"},
                {**tool, "tool": "b", "network": "on_refresh"},
                {**tool, "tool": "c", "network": "case_store"},
                # Not called, or not through these sources: never named.
                {**tool, "tool": "d", "network": "on_refresh", "calls": 0},
                {**tool, "tool": "e", "network": "on_refresh", "source": "mcp:other"},
                {**tool, "tool": "f", "network": False},
            ]
        },
        "stores": [{"backend": "qdrant", "where": "local", "host": "127.0.0.1"}],
    }
    assert _stayed_line(rows, _code, both) == (
        "Tool calls made on this machine: 2 calls (tool server `refs` 2); of the tools called "
        "through these sources, `a` and `b` on tool server `refs` are declared to reach the "
        "network only to fetch or refresh reference data, sending nothing of the sample "
        "(whether a call did is not recorded in this report); `c` on tool server `refs` is "
        "declared to read the case-memory store, which the case-memory line places."
    )
    only_store = {"effects": {"tools": [{**tool, "tool": "c", "network": "case_store"}]}}
    assert _stayed_line(rows, _code, only_store) == (
        "Tool calls made on this machine: 2 calls (tool server `refs` 2); of the tools called "
        "through these sources, `c` on tool server `refs` is declared to read the case-memory "
        "store, which is kept in the process or not configured."
    )
    # Without such a tool, or without the effects part: the calls stayed.
    plain = "Tool calls that stayed on this machine: 2 calls (tool server `refs` 2)."
    assert _stayed_line(rows, _code, {"effects": {"tools": [{**tool, "tool": "f"}]}}) == plain
    assert _stayed_line(rows, _code, {}) == plain
    assert _stayed_line(rows, _code) == plain


def test_nothing_left_names_a_refreshing_tool_only_when_one_was_called_here() -> None:
    record = {
        "stayed": [{"source": "pack", "made": 1, "served": 0, "not_run": 0}],
        "effects": {
            "tools": [
                {"source": "pack", "server": "", "tool": "t", "calls": 1, "network": "on_refresh"}
            ]
        },
    }
    assert _nothing_sentence(record, _code) == (
        "Nothing of the sample left this machine, as the declarations count it. This rests on: "
        "`t` on the platform's in-process source `pack` is declared to reach the network only "
        "to fetch or refresh reference data, sending nothing of the sample (whether a call did is "
        "not recorded in this report); the case-memory store is kept in the process or not "
        "configured; no lookup was asked, and tracing is off."
    )
    assert _nothing_sentence({**record, "stayed": []}, _code).startswith(
        "Nothing left this machine. This rests on: "
    )
