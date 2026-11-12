"""A finished run records the environment it ran in (``run_summary.environment``).

The host the worker read, and per agent what each model sent with every
request — the sampling parameters or the statement that none was sent, the
effort with the setting it came from or why none was — and which models the
provider's answers named. Each fact only where it is known; a summary without
the block reads as it always has.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage

from malspark.analysis import run_environment
from malspark.analysis.run_environment import (
    ENVIRONMENT_VERSION,
    agents_record,
    environment_record,
    host_facts,
)
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.core.config import Settings
from malspark.core.token_ledger import TokenLedger, record_response_usage, response_model_of
from malspark.llm.registry import LLMProviderRegistry
from malspark.llm.sent_request import NO_SAMPLING_SENT, SentRequest, sampling_sent


@pytest.fixture(autouse=True)
def _fresh_host() -> Any:
    host_facts.cache_clear()
    yield
    host_facts.cache_clear()


# ---------------------------------------------------------------------------
# The host


class TestTheHost:
    def test_this_host_gives_its_facts_and_nothing_empty(self) -> None:
        facts = host_facts()
        assert facts.get("os")
        assert all(value for value in facts.values())
        assert set(facts) <= {
            "os",
            "os_release",
            "os_version",
            "machine",
            "cpu_model",
            "logical_cpus",
            "memory_bytes",
        }

    def test_a_host_that_gives_nothing_records_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("system", "release", "version", "machine", "processor"):
            monkeypatch.setattr(run_environment.platform, name, lambda: "")
        monkeypatch.setattr(run_environment.os, "cpu_count", lambda: None)
        monkeypatch.setattr(run_environment.sys, "platform", "plan9")
        monkeypatch.setattr(run_environment, "_posix_memory_bytes", lambda: None)
        assert host_facts() == {}

    def test_a_host_that_fails_to_read_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken() -> str:
            raise OSError("unreadable")

        monkeypatch.setattr(run_environment.platform, "system", broken)
        assert host_facts() == {}

    def test_macos_is_read_from_sysctl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = {"machdep.cpu.brand_string": "Apple M9", "hw.memsize": "68719476736"}
        monkeypatch.setattr(run_environment.sys, "platform", "darwin")
        monkeypatch.setattr(run_environment, "_sysctl", lambda key: answers.get(key, ""))
        monkeypatch.setattr(run_environment.platform, "mac_ver", lambda: ("16.1", ("", "", ""), ""))
        facts = host_facts()
        assert facts["cpu_model"] == "Apple M9"
        assert facts["memory_bytes"] == 68719476736
        assert facts["os_release"] == "16.1"

    def test_windows_is_read_from_its_own_sources(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(run_environment.sys, "platform", "win32")
        monkeypatch.setattr(run_environment, "_windows_cpu_model", lambda: "Some CPU @ 3.0GHz")
        monkeypatch.setattr(run_environment, "_windows_memory_bytes", lambda: 17179869184)
        facts = host_facts()
        assert facts["cpu_model"] == "Some CPU @ 3.0GHz"
        assert facts["memory_bytes"] == 17179869184

    def test_an_unread_memory_is_left_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(run_environment.sys, "platform", "darwin")
        monkeypatch.setattr(run_environment, "_sysctl", lambda key: "")
        facts = host_facts()
        assert "memory_bytes" not in facts
        assert "cpu_model" not in facts or facts["cpu_model"]


# ---------------------------------------------------------------------------
# What each model sent


def _record(**fields: Any) -> SentRequest:
    base: dict[str, Any] = {"agent": "static", "position": 0, "provider": "p", "model": "m"}
    return SentRequest(**{**base, **fields})


class TestTheAgents:
    def test_no_sampling_sent_is_said(self) -> None:
        row = _record().as_dict()
        assert row["sampling"] == {}
        assert row["sampling_statement"] == NO_SAMPLING_SENT

    def test_sampling_sent_is_listed_without_the_statement(self) -> None:
        row = _record(sampling={"temperature": 0.1}).as_dict()
        assert row["sampling"] == {"temperature": 0.1}
        assert "sampling_statement" not in row

    def test_an_effort_sent_names_its_setting(self) -> None:
        row = _record(effort="low", effort_setting="llm.agents.static.effort").as_dict()
        assert (row["effort"], row["effort_setting"]) == ("low", "llm.agents.static.effort")
        assert "effort_statement" not in row

    def test_no_effort_sent_says_why(self) -> None:
        row = _record(effort_statement="none for this provider").as_dict()
        assert row["effort"] is None
        assert row["effort_statement"] == "none for this provider"
        assert "effort_setting" not in row

    def test_a_model_built_again_is_listed_once_in_list_order(self) -> None:
        sent = [
            _record(position=1, model="fallback"),
            _record(sampling={"temperature": 0.1}),
            _record(sampling={"temperature": 0.1}),
        ]
        block = agents_record(sent, {})["static"]
        assert [row["model"] for row in block["requests"]] == ["m", "fallback"]
        assert block["response_models"] == {}

    def test_the_answers_models_are_beside_the_requests(self) -> None:
        agents = agents_record([_record()], {"static": {"m-2026": 3}, "judge": {"j-1": 1}})
        assert agents["static"]["response_models"] == {"m-2026": 3}
        assert agents["judge"] == {"requests": [], "response_models": {"j-1": 1}}

    def test_sampling_is_read_from_fields_and_the_passed_through_channels(self) -> None:
        class _Model:
            temperature = 0.2
            top_p = None
            max_tokens = 99
            model_kwargs = {"seed": 7}
            extra_body = {"repeat_penalty": 1.1, "n_predict": 99}

        assert sampling_sent(_Model()) == {"temperature": 0.2, "seed": 7, "repeat_penalty": 1.1}

    def test_a_model_that_sets_nothing_sends_nothing(self) -> None:
        class _Model:
            temperature = None

        assert sampling_sent(_Model()) == {}
        assert sampling_sent(None) == {}


# ---------------------------------------------------------------------------
# The models the answers named


class TestTheAnswersModels:
    def test_the_standard_key_is_read_first(self) -> None:
        answer = AIMessage(content="x", response_metadata={"model_name": "a-1", "model": "b"})
        assert response_model_of(answer) == "a-1"

    def test_an_answer_that_names_none_gives_nothing(self) -> None:
        assert response_model_of(AIMessage(content="x")) == ""
        assert response_model_of(object()) == ""

    def test_the_ledger_counts_each_per_agent_and_keeps_the_token_block(self) -> None:
        ledger = TokenLedger()
        for name in ("m-2026-01", "m-2026-01", ""):
            answer = AIMessage(content="x", response_metadata={"model_name": name} if name else {})
            record_response_usage(ledger, answer, agent="static", model="label")
        assert ledger.response_models() == {"static": {"m-2026-01": 2}}
        assert "response_models" not in json.dumps(ledger.snapshot())


# ---------------------------------------------------------------------------
# The record and the summary


class _Registry:
    def __init__(self, sent: list[SentRequest]) -> None:
        self._sent = sent

    def sent_requests(self) -> list[SentRequest]:
        return list(self._sent)


class _Container:
    def __init__(self, sent: list[SentRequest], ledger: TokenLedger) -> None:
        self._llm_registry = _Registry(sent)
        self._ledger = ledger

    def get_token_ledger(self) -> TokenLedger:
        return self._ledger


class TestTheRecord:
    def test_a_job_s_record_holds_its_host_and_agents(self) -> None:
        ledger = TokenLedger()
        ledger.note_response_model("static", "m-2026")
        record = environment_record(_Container([_record()], ledger))
        assert record is not None
        assert record["v"] == ENVIRONMENT_VERSION
        assert record["host"] == host_facts()
        assert record["agents"]["static"]["response_models"] == {"m-2026": 1}

    def test_nothing_read_is_no_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        assert environment_record(object()) is None

    def test_a_record_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Broken:
            @property
            def _llm_registry(self) -> Any:
                raise RuntimeError("broken")

        assert environment_record(_Broken()) is None

    def test_the_summary_carries_the_block(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_environment({"v": 1, "host": {"os": "Linux"}})
            .build()
            .to_dict()
        )
        assert summary["environment"] == {"v": 1, "host": {"os": "Linux"}}

    def test_a_summary_without_it_reads_as_before(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_environment(None).build().to_dict()
        assert "environment" not in summary


# ---------------------------------------------------------------------------
# The registry records what each model it builds sends


def _openai_settings(agents: dict[str, Any] | None = None, **openai: Any) -> Settings:
    return Settings(
        _env_file=None,
        llm={
            "provider": "openai",
            "openai": {
                "api_key": "sk-test",
                "base_url": "https://api.example.com/v1",
                "compat": "standard",
                "expert_model": "m",
                **openai,
            },
            "agents": agents or {},
        },
    )


def _sent_body(registry: LLMProviderRegistry, agent: str) -> dict[str, Any]:
    bodies: list[dict[str, Any]] = []

    def wire(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "c1",
                "object": "chat.completion",
                "created": 0,
                "model": "m-answered",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 1},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(wire))
    registry.build_model_for_agent(agent, max_tokens=5, http_client=client).invoke(
        [HumanMessage(content="hi")]
    )
    return bodies[0]


class TestTheRegistry:
    def test_an_entry_s_effort_is_recorded_with_its_setting_and_sent(self) -> None:
        registry = LLMProviderRegistry(
            _openai_settings(
                {"static": {"provider": "openai", "model": "m", "effort": "high"}},
                reasoning_effort="low",
            )
        )
        body = _sent_body(registry, "static")
        (record,) = registry.sent_requests()
        assert (record.agent, record.effort, record.effort_setting) == (
            "static",
            "high",
            "llm.agents.static.effort",
        )
        assert body["reasoning_effort"] == record.effort
        assert record.sampling == {"temperature": body["temperature"]}

    def test_the_global_effort_is_recorded_with_its_setting(self) -> None:
        registry = LLMProviderRegistry(_openai_settings(reasoning_effort="low"))
        body = _sent_body(registry, "static")
        (record,) = registry.sent_requests()
        assert (record.effort, record.effort_setting) == ("low", "llm.openai.reasoning_effort")
        assert body["reasoning_effort"] == "low"

    def test_no_effort_is_recorded_as_none_sent(self) -> None:
        registry = LLMProviderRegistry(_openai_settings())
        body = _sent_body(registry, "static")
        (record,) = registry.sent_requests()
        assert record.effort is None and record.effort_setting == ""
        assert record.as_dict()["effort_statement"] == "unset, the provider's default"
        assert "reasoning_effort" not in body

    def test_each_model_of_a_list_is_recorded_in_its_place(self) -> None:
        registry = LLMProviderRegistry(
            _openai_settings(
                {
                    "static": {
                        "provider": "openai",
                        "model": "m",
                        "fallbacks": [
                            {"provider": "openai", "model": "m2", "effort": "low"},
                        ],
                    }
                }
            )
        )
        registry.build_model_for_agent("static", max_tokens=5)
        rows = [(r.position, r.model, r.effort_setting) for r in registry.sent_requests()]
        assert rows == [(0, "m", ""), (1, "m2", "llm.agents.static.fallbacks[0].effort")]

    def test_the_build_line_says_what_is_sent(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = Settings(
            _env_file=None,
            llm={
                "provider": "anthropic",
                "anthropic": {"api_key": "test-value", "expert_model": "claude-haiku-5-5"},
            },
        )
        with caplog.at_level(logging.INFO, logger="malspark"):
            LLMProviderRegistry(settings).build_model_for_agent("static", max_tokens=5)
        lines = [r.getMessage() for r in caplog.records if "claude-haiku-5-5" in r.getMessage()]
        assert any(f"sends sampling: {NO_SAMPLING_SENT}" in line for line in lines), lines
        assert not any("temp=" in line for line in lines)
