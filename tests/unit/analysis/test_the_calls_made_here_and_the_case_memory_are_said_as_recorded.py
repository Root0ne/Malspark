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
    lines = [
        *disclosure_lines(record),
        *effects_lines(record["effects"], stores=record["stores"]),
    ]
    assert [line for line in lines if "function_matches" in line] == [
        "Tool calls made on this machine: 2 calls (the platform's in-process source `pack` 2); "
        "of the tools called through these sources, `function_matches` on the platform's "
        "in-process source `pack` is declared to read the case-memory store, which the "
        "case-memory line places.",
        "Declared to reach the configured case-memory store, which the disclosure's case-memory "
        "row places: `function_matches` on Triage pack (`pack`).",
    ]


def test_the_calls_made_here_name_each_named_mode_and_the_store_s_place() -> None:
    rows = [{"source": "mcp:refs", "made": 2, "served": 0, "not_run": 0}]
    tool = {"source": "mcp:refs", "server": "", "calls": 2, "network_by": "declared"}
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
                {
                    "source": "pack",
                    "server": "",
                    "tool": "t",
                    "calls": 1,
                    "network": "on_refresh",
                    "network_by": "declared",
                }
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


# ---------------------------------------------------------------------------
# The case-memory line: the configuration, then what the run recorded
# ---------------------------------------------------------------------------

SHA = "ab" * 32
OTHER = "cd" * 32
CONFIGURED = (
    "Case memory: the `qdrant` case-memory store at `localhost` (local), configured as this "
    "job's case memory."
)


def _store_line_of(record: dict[str, Any]) -> str:
    (line,) = [line for line in disclosure_lines(record) if line.startswith("Case memory:")]
    return line


class _Container:
    """A job's container as the judge and the disclosure read it."""

    def __init__(self) -> None:
        self.memory_owner = None
        self.similar_cases: dict[str, Any] = {}
        self.similar_case_read: Any = None
        self.memory_case: Any = None
        self.pending_memory_case: Any = None


def _case(sample: str, techniques: list[str]) -> Any:
    from datetime import UTC, datetime

    from malspark.memory.long_term_memory import StoredCase

    return StoredCase(
        sample_id=sample,
        summary_text="[STATIC] injects into explorer.exe [ev_0007] T1055",
        technique_ids=techniques,
        malware_category="RAT",
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        corroborated_count=2,
        total_techniques=len(techniques),
    )


def _verdict(container: _Container, store: Any, seen: list[str]) -> Any:
    import asyncio

    from tests.unit.agents.test_the_judge_prompt_is_sized_from_its_window import _judge

    from malspark.schemas.isr_models import AgentISR, ClaimEvidence

    judge = _judge(seen, window_tokens=None)
    judge._container = container
    claim = ClaimEvidence(
        claim="injects into explorer.exe", evidence_ref="[ev_0001]", confidence=0.7
    )
    claim.technique_id = "T1055"
    asyncio.run(
        judge.give_verdict(
            reports={"static": "It injects."},
            history=[],
            isr_reports={"static": AgentISR(agent_id="static", domain="static", claims=[claim])},
            evidence_summary="",
            memory_store=store,
            current_sample_id=SHA,
        )
    )
    return judge


def _built(container: _Container, **over: Any) -> dict[str, Any]:
    from malspark.analysis.disclosure import memory_facts

    return _record("http://localhost:6333", memory=memory_facts(container), **over)


def test_a_store_holding_a_case_of_another_sample_that_shares_a_technique_says_it_was_shown(
    monkeypatch: Any,
) -> None:
    from malspark.memory import embeddings
    from malspark.memory.in_memory_store import InMemoryStore

    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)
    store = InMemoryStore()
    store.store(_case(OTHER, ["T1055"]))
    container = _Container()
    seen: list[str] = []

    judge = _verdict(container, store, seen)

    assert "Past techniques: T1055" in seen[0]
    assert container.similar_case_read == judge.similar_case_read == {"read": "shown", "shown": 1}
    container.pending_memory_case = _case(SHA, ["T1055"])
    assert _store_line_of(_built(container)) == (
        f"{CONFIGURED} The run held its case to file there once the job completes; whether it "
        "was filed is not recorded in this report. The judge's last verdict prompt was given 1 "
        "similar case of another sample read from it."
    )


def test_a_store_that_holds_no_other_case_or_was_down_says_how_the_read_ended(
    monkeypatch: Any,
) -> None:
    from malspark.memory import embeddings
    from malspark.memory.in_memory_store import InMemoryStore

    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)
    container = _Container()
    _verdict(container, InMemoryStore(), [])
    assert container.similar_case_read == {"read": "none_shown", "shown": 0}

    class _Down:
        def retrieve(self, *_a: Any, **_k: Any) -> Any:
            raise ConnectionError("the store is down")

    down = _Container()
    seen: list[str] = []
    _verdict(down, _Down(), seen)
    assert "LONG-TERM MEMORY: unavailable" in seen[0]
    assert down.similar_case_read == {"read": "failed", "shown": 0}
    assert _store_line_of(_built(down)).endswith(
        " The run held no case to file there. The judge's read of similar cases from it "
        "failed, so the judge's last verdict prompt was given none."
    )


def test_the_judge_s_verdict_prompt_is_the_same_whether_or_not_the_read_is_noted(
    monkeypatch: Any,
) -> None:
    from malspark.memory import embeddings
    from malspark.memory.in_memory_store import InMemoryStore

    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)

    class _KeepsNoNotes:
        __slots__ = ("memory_owner", "similar_cases")

        def __init__(self) -> None:
            self.memory_owner = None
            self.similar_cases: dict[str, Any] = {}

    def _prompt(container: Any) -> str:
        store = InMemoryStore()
        store.store(_case(OTHER, ["T1055"]))
        seen: list[str] = []
        _verdict(container, store, seen)
        return seen[0]

    noted = _Container()
    assert _prompt(noted) == _prompt(_KeepsNoNotes())
    assert noted.similar_case_read == {"read": "shown", "shown": 1}


def test_a_store_that_could_not_be_opened_is_noted_where_the_judge_node_opens_it() -> None:
    import asyncio
    from unittest.mock import AsyncMock

    from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container as _Base
    from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _state

    from malspark.agents.judge_agent import JudgeVerdict
    from malspark.pipeline.nodes import make_judge_node
    from malspark.schemas.evidence import EvidenceCounter
    from malspark.schemas.stix_models import Bundle

    class _StoreDown(_Base):
        memory_owner = None

        def __init__(self) -> None:
            super().__init__(EvidenceCounter())
            self.earlier_cases: dict[str, Any] = {}

        def get_memory_store(self) -> Any:
            raise ConnectionError("the store is down")

    container = _StoreDown()
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})
    )
    judge.decide_techniques = AsyncMock(return_value=None)
    asyncio.run(make_judge_node(container)({**_state([]), "file_hash": SHA}))

    assert container.similar_case_read == {"read": "not_opened", "shown": 0}
    assert container.memory_case == {
        "case": "none",
        "why": "the store could not be opened when the judge ran",
    }
    assert _store_line_of(_built(container)) == (  # type: ignore[arg-type]
        f"{CONFIGURED} The run held no case to file there (the store could not be opened when "
        "the judge ran). The store could not be opened when the judge was to read similar cases "
        "from it, so the judge's last verdict prompt was given none."
    )


def test_a_case_withheld_where_the_report_node_decides_says_why() -> None:
    from types import SimpleNamespace

    from malspark.pipeline.nodes import _remember_the_published_techniques

    container = _Container()
    container.pending_memory_case = _case(SHA, ["T1055"])
    container.similar_case_read = {"read": "none_shown", "shown": 0}
    report = SimpleNamespace(ttp_mappings=[])

    _remember_the_published_techniques(container, report, {}, {})

    assert container.pending_memory_case is None
    assert container.memory_case == {
        "case": "withheld",
        "why": "its published evidence was too thin to keep: 0 corroborated techniques, 0 "
        "published techniques",
    }
    assert _store_line_of(_built(container)) == (
        f"{CONFIGURED} The run held no case to file there (its published evidence was too thin "
        "to keep: 0 corroborated techniques, 0 published techniques). The judge read it for "
        "similar cases of other samples, and its last verdict prompt was given none."
    )


def test_a_cancelled_run_files_no_case_and_says_whether_its_judge_was_reached() -> None:
    from malspark.analysis.disclosure import STOPPED_PART_WAY

    container = _Container()
    container.pending_memory_case = _case(SHA, ["T1055"])
    container.similar_case_read = {"read": "shown", "shown": 2}
    assert _store_line_of(_built(container, partial_reason=STOPPED_PART_WAY)) == (
        f"{CONFIGURED} The run stopped part-way, and a job that does not complete files no "
        "case. The judge's last verdict prompt was given 2 similar cases of other samples read "
        "from it."
    )
    early = _Container()
    assert _store_line_of(_built(early, partial_reason=STOPPED_PART_WAY)) == (
        f"{CONFIGURED} The run stopped part-way, and a job that does not complete files no "
        "case. The run did not reach the judge's read of similar cases from it."
    )
    assert "stores its case in" not in _store_line_of(_built(early))


def test_what_the_job_recorded_of_its_case_memory_is_read_off_its_container() -> None:
    from malspark.analysis.disclosure import memory_facts

    container = _Container()
    assert memory_facts(container) == {
        "case": "none",
        "case_why": "",
        "similar_read": "not_reached",
        "similar_shown": 0,
    }
    container.memory_case = {"case": "withheld", "why": "analysts failed: static"}
    container.similar_case_read = {"read": "nothing_to_search", "shown": 0}
    assert memory_facts(container) == {
        "case": "withheld",
        "case_why": "analysts failed: static",
        "similar_read": "nothing_to_search",
        "similar_shown": 0,
    }
    # A held case is what the job holds to file, whatever was noted before.
    container.pending_memory_case = _case(SHA, ["T1055"])
    assert memory_facts(container)["case"] == "held"
    # Anything else noted is not read as a decision or a read.
    junk = _Container()
    junk.memory_case = {"case": "filed"}
    junk.similar_case_read = {"read": "read", "shown": True}
    assert memory_facts(junk)["case"] == "none"
    assert memory_facts(junk)["similar_read"] == "not_reached"
    assert memory_facts(object()) == memory_facts(_Container())
