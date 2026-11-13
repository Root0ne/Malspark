"""A finished run records the environment it ran in (``run_summary.environment``).

The host the worker read, and per agent what each model was built to send
with every request — the sampling parameters and thinking switches, the
statement that none was sent or that the adapter reported nothing, the effort
with the setting it came from or why none was — how many calls each model
answered, and which models the provider's answers named. Each fact only where
it is known; a summary without the block reads as it always has, and the
report node, a stopped run and a failed verdict each write it.
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
from malspark.llm.sent_request import NO_SAMPLING_SENT, NOT_REPORTED_BY_ADAPTER, SentRequest


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
            "cpus_available",
            "memory_limit_bytes",
        }

    def test_a_host_that_gives_nothing_records_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("system", "release", "version", "machine", "processor"):
            monkeypatch.setattr(run_environment.platform, name, lambda: "")
        monkeypatch.setattr(run_environment.os, "cpu_count", lambda: None)
        monkeypatch.setattr(run_environment.sys, "platform", "plan9")
        monkeypatch.setattr(run_environment, "_posix_memory_bytes", lambda: None)
        monkeypatch.setattr(run_environment, "_cpus_available", lambda: None)
        monkeypatch.setattr(run_environment, "_memory_limit_bytes", lambda: None)
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

    def _groups(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, files: dict[str, str]
    ) -> None:
        """A control-group tree under ``tmp_path``, and ``/proc/self/cgroup`` naming it."""
        proc = files.pop("/proc/self/cgroup")
        for name, text in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        monkeypatch.setattr(run_environment, "_CGROUP_ROOT", str(tmp_path))
        real = run_environment._read_text
        monkeypatch.setattr(
            run_environment,
            "_read_text",
            lambda path: proc if path == "/proc/self/cgroup" else real(path),
        )
        monkeypatch.setattr(run_environment, "_affinity", lambda: 16)

    def test_a_system_without_cpu_affinity_reports_none_of_it_and_never_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # macOS and Windows have no ``os.sched_getaffinity``.
        monkeypatch.delattr(run_environment.os, "sched_getaffinity", raising=False)
        monkeypatch.setattr(run_environment, "_cgroup_dirs", lambda: ([], {}))
        assert run_environment._affinity() is None
        assert run_environment._cpus_available() is None
        assert "cpus_available" not in host_facts()

    def test_a_group_quota_is_read_where_the_system_has_no_cpu_affinity(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._groups(
            tmp_path,
            monkeypatch,
            {"/proc/self/cgroup": "0::/w\n", "w/cpu.max": "200000 100000"},
        )
        monkeypatch.setattr(run_environment, "_affinity", lambda: None)
        assert host_facts()["cpus_available"] == 2

    def test_a_v2_quota_and_limit_beside_the_kernel_s_counts(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The worker's group allows 4 processors and 8 GiB; its parent sets
        # no limit; the kernel still counts the whole machine.
        self._groups(
            tmp_path,
            monkeypatch,
            {
                "/proc/self/cgroup": "0::/job/worker\n",
                "job/worker/cpu.max": "400000 100000",
                "job/worker/memory.max": "8589934592",
                "job/cpu.max": "max 100000",
                "job/memory.max": "max",
            },
        )
        facts = host_facts()
        assert facts["cpus_available"] == 4
        assert facts["memory_limit_bytes"] == 8589934592
        assert facts["logical_cpus"] == run_environment.os.cpu_count()

    def test_a_parent_s_tighter_limit_and_a_fractional_quota(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._groups(
            tmp_path,
            monkeypatch,
            {
                "/proc/self/cgroup": "0::/job/worker\n",
                "job/worker/memory.max": "8589934592",
                "job/memory.max": "4294967296",
                "job/cpu.max": "150000 100000",
            },
        )
        facts = host_facts()
        assert facts["cpus_available"] == 1.5
        assert facts["memory_limit_bytes"] == 4294967296

    def test_v1_limits_are_read_and_its_no_limit_value_is_none(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._groups(
            tmp_path,
            monkeypatch,
            {
                "/proc/self/cgroup": "4:memory:/\n3:cpu,cpuacct:/\n",
                "cpu/cpu.cfs_quota_us": "200000",
                "cpu/cpu.cfs_period_us": "100000",
                "memory/memory.limit_in_bytes": "9223372036854771712",
            },
        )
        facts = host_facts()
        assert facts["cpus_available"] == 2
        assert "memory_limit_bytes" not in facts

    def test_a_v1_parent_s_limit_is_read(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The limits sit on the parent, between the worker's group and the mount.
        self._groups(
            tmp_path,
            monkeypatch,
            {
                "/proc/self/cgroup": "4:memory:/job/worker\n3:cpu,cpuacct:/job/worker\n",
                "memory/job/worker/memory.limit_in_bytes": "9223372036854771712",
                "memory/job/memory.limit_in_bytes": "2147483648",
                "cpu/job/worker/cpu.cfs_quota_us": "-1",
                "cpu/job/worker/cpu.cfs_period_us": "100000",
                "cpu/job/cpu.cfs_quota_us": "50000",
                "cpu/job/cpu.cfs_period_us": "100000",
            },
        )
        facts = host_facts()
        assert facts["cpus_available"] == 0.5
        assert facts["memory_limit_bytes"] == 2147483648

    def test_the_hybrid_layout_s_unified_mount_is_read(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._groups(
            tmp_path,
            monkeypatch,
            {
                "/proc/self/cgroup": "1:name=systemd:/job\n0::/job\n",
                "unified/job/memory.max": "1073741824",
                "unified/job/cpu.max": "300000 100000",
            },
        )
        facts = host_facts()
        assert facts["cpus_available"] == 3
        assert facts["memory_limit_bytes"] == 1073741824

    def test_no_group_limit_leaves_the_affinity_and_no_limit(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._groups(tmp_path, monkeypatch, {"/proc/self/cgroup": "0::/\n"})
        facts = host_facts()
        assert facts["cpus_available"] == 16
        assert "memory_limit_bytes" not in facts

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

    def test_nothing_reported_is_said_and_is_not_none_sent(self) -> None:
        row = _record(sampling=None, thinking=None).as_dict()
        assert row["sampling"] is None and row["thinking"] is None
        assert row["sampling_statement"] == NOT_REPORTED_BY_ADAPTER

    def test_a_configured_path_is_kept_by_its_base_name_and_said(self) -> None:
        # A server with no alias is configured by the file it loads.
        row = _record(model="/home/alice/models/Qwen3.6.gguf").as_dict()
        assert (row["model"], row["model_reduced"]) == ("Qwen3.6.gguf", True)
        row = _record(model="~vendor/model-latest").as_dict()
        assert row["model"] == "~vendor/model-latest" and "model_reduced" not in row

    def test_a_request_whose_thinking_was_changed_is_counted(self) -> None:
        assert "thinking_changed_requests" not in _record().as_dict()
        row = _record(thinking={"thinking.type": "adaptive"}, thinking_changed=2).as_dict()
        assert row["thinking"] == {"thinking.type": "adaptive"}
        assert row["thinking_changed_requests"] == 2

    def test_a_thinking_switch_sent_is_listed(self) -> None:
        row = _record(thinking={"think": False}).as_dict()
        assert row["thinking"] == {"think": False}

    def test_each_row_carries_the_calls_its_model_answered(self) -> None:
        sent = [_record(), _record(position=1, model="fallback")]
        block = agents_record(sent, {}, {"static": {0: 3}})["static"]
        assert [(row["model"], row["answered"]) for row in block["requests"]] == [
            ("m", 3),
            ("fallback", 0),
        ]

    def test_rows_that_share_a_place_each_carry_its_total_and_say_so(self) -> None:
        # The model at place 0 built again with other sampling: an answer
        # names its place, not which of the two gave it.
        sent = [_record(), _record(sampling={"temperature": 0.2}), _record(position=1)]
        rows = agents_record(sent, {}, {"static": {0: 3, 1: 1}})["static"]["requests"]
        assert [(r["position"], r["answered"], r.get("answered_shared")) for r in rows] == [
            (0, 3, True),
            (0, 3, True),
            (1, 1, None),
        ]

    def test_without_the_ledger_s_counts_no_row_claims_a_count(self) -> None:
        (row,) = agents_record([_record()], {})["static"]["requests"]
        assert "answered" not in row

    def test_agent_names_are_keyed_alike_on_both_sides(self) -> None:
        agents = agents_record(
            [_record(agent="MyAgent")], {"MyAgent": {"m-1": 1}}, {"MyAgent": {0: 1}}
        )
        assert list(agents) == ["myagent"]
        assert agents["myagent"]["response_models"] == {"m-1": 1}
        assert agents["myagent"]["requests"][0]["answered"] == 1

    def test_a_reduced_identifier_is_said(self) -> None:
        agents = agents_record([], {"static": {"x.gguf": 2}}, None, {"static": ["x.gguf"]})
        assert agents["static"]["response_models_reduced"] == ["x.gguf"]


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
        # Every answer counts at its place in the list, one naming no model too.
        assert ledger.answers_by_position() == {"static": {0: 3}}
        assert "response_models" not in json.dumps(ledger.snapshot())

    def test_a_fallback_s_answer_counts_at_its_place(self) -> None:
        ledger = TokenLedger()
        answer = AIMessage(
            content="x",
            response_metadata={
                "model_name": "f-1",
                "malspark_model": "p/f",
                "malspark_model_position": 1,
            },
        )
        record_response_usage(ledger, answer, agent="static", model="label")
        assert ledger.answers_by_position() == {"static": {1: 1}}

    def test_the_agent_is_keyed_in_lowercase(self) -> None:
        ledger = TokenLedger()
        ledger.note_response_model("MyAgent", "m-1")
        assert ledger.response_models() == {"myagent": {"m-1": 1}}

    def test_the_mediator_s_answers_are_filed_under_the_mediator_and_charged_to_the_judge(
        self,
    ) -> None:
        ledger = TokenLedger()
        answer = AIMessage(
            content="x",
            response_metadata={"model_name": "mediator-model"},
            usage_metadata={"input_tokens": 3, "output_tokens": 1, "total_tokens": 4},
        )
        record_response_usage(ledger, answer, agent="judge", model="label", runs_on="mediator")
        assert ledger.response_models() == {"mediator": {"mediator-model": 1}}
        assert set(ledger.snapshot()["agents"]) == {"judge"}

    @pytest.mark.parametrize(
        ("served", "kept", "reduced"),
        [
            ("/home/someone/models/Qwen3.6-35B-A3B.gguf", "Qwen3.6-35B-A3B.gguf", True),
            ("C:\\Users\\someone\\m.gguf", "m.gguf", True),
            ("~/models/m.gguf", "m.gguf", True),
            ("./m.gguf", "m.gguf", True),
            ("~\\models\\m.gguf", "m.gguf", True),
            ("~vendor/model-latest", "~vendor/model-latest", False),
            ("x-ai/grok-4.fast", "x-ai/grok-4.fast", False),
            ("models/gemini-2.5-flash", "models/gemini-2.5-flash", False),
            ("deepseek-chat", "deepseek-chat", False),
        ],
    )
    def test_a_path_shaped_identifier_is_kept_by_its_base_name(
        self, served: str, kept: str, reduced: bool
    ) -> None:
        ledger = TokenLedger()
        ledger.note_response_model("static", served)
        assert ledger.response_models() == {"static": {kept: 1}}
        assert ledger.reduced_response_models() == ({"static": [kept]} if reduced else {})


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

    def test_a_configured_path_is_recorded_by_its_base_name(self) -> None:
        registry = LLMProviderRegistry(_openai_settings(expert_model="/home/alice/m/Qwen3.6.gguf"))
        registry.build_model_for_agent("static", max_tokens=5)
        (record,) = registry.sent_requests()
        assert (record.model, record.model_reduced) == ("Qwen3.6.gguf", True)

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


# ---------------------------------------------------------------------------
# Through a job's container: the mediator's answers under the mediator


def test_the_mediator_s_answers_are_filed_under_the_mediator_through_the_container() -> None:
    from malspark.core.container import ServiceContainer

    settings = _openai_settings(
        {"mediator": {"provider": "openai", "model": "m-mediator"}}, expert_max_tokens=64
    )
    container = ServiceContainer(config=settings, mock=True)
    container._llm_registry = LLMProviderRegistry(settings)
    mediator = container.get_judge_agent("mediator")
    mediator._record_usage(AIMessage(content="x", response_metadata={"model_name": "m-med-1"}))
    record = environment_record(container)
    assert record is not None
    agents = record["agents"]
    assert agents["mediator"]["requests"][0]["model"] == "m-mediator"
    assert agents["mediator"]["response_models"] == {"m-med-1": 1}
    assert agents["mediator"]["requests"][0]["answered"] == 1
    assert "judge" not in agents or not agents["judge"]["response_models"]


# ---------------------------------------------------------------------------
# Each writer puts the block on the summary it writes

BLOCK = {"v": ENVIRONMENT_VERSION, "host": {"os": "Linux"}}


class _Recorded:
    """A stand-in for ``environment_record`` that keeps the ledger each call was handed."""

    def __init__(self) -> None:
        self.entries: list[Any] = []

    def __call__(self, container: Any, entries: Any = ()) -> dict[str, Any]:
        self.entries.append(entries)
        return dict(BLOCK)


def _ledger() -> list[Any]:
    """A run's evidence ledger of one entry: the servers a record names are read from it."""
    from malspark.schemas.evidence import LedgerEntry

    return [LedgerEntry(id="ev_0001", agent="static", server="analysis", tool="pe_info")]


def test_a_stopped_run_writes_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from malspark.core.container import ServiceContainer
    from malspark.pipeline.stopped_run import stopped_run_summary

    recorded = _Recorded()
    monkeypatch.setattr(run_environment, "environment_record", recorded)
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    state = {
        "file_hash": "b" * 64,
        "run_started_at": time.time() - 5,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": _ledger(),
        "degradation_reasons": [],
        "stage_results": {},
    }
    summary = stopped_run_summary(state, container, note="stopped")
    assert summary["environment"] == BLOCK
    assert recorded.entries == [state["evidence_ledger"]]
    assert recorded.entries[0] is state["evidence_ledger"]


def test_a_failed_verdict_writes_the_block(monkeypatch: pytest.MonkeyPatch) -> None:
    from malspark.core.container import ServiceContainer
    from malspark.pipeline import nodes

    recorded = _Recorded()
    monkeypatch.setattr(nodes, "environment_record", recorded)
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    state: dict[str, Any] = {
        "file_hash": "b" * 64,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": _ledger(),
        "degradation_reasons": [],
        "stage_results": {},
    }
    summary = nodes._failed_verdict_summary(container, state, None, ["the judge failed"])  # type: ignore[arg-type]
    assert summary is not None
    assert summary["environment"] == BLOCK
    assert recorded.entries and all(e is state["evidence_ledger"] for e in recorded.entries)


def test_the_judge_writes_the_block_with_the_run_s_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from malspark.pipeline import nodes
    from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _run, _state

    recorded = _Recorded()
    monkeypatch.setattr(nodes, "environment_record", recorded)
    state = _state([])
    update = _run(state)
    assert update["run_summary"]["environment"] == BLOCK
    assert recorded.entries and all(e is state["evidence_ledger"] for e in recorded.entries)


@pytest.mark.asyncio
async def test_the_report_node_writes_the_block_once_the_last_call_is_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unittest.mock import MagicMock

    from malspark.pipeline import analyst_mode as analyst_mode_module
    from malspark.pipeline import nodes
    from malspark.pipeline.analyst_mode import ReporterMode
    from tests.stages import paper_profile
    from tests.unit.pipeline.test_the_reporter_follows_the_analyst_mode_decision import _Composer
    from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

    monkeypatch.setattr(
        analyst_mode_module,
        "resolve_reporter_mode",
        lambda settings: ReporterMode(1, "auto", "a stated reason"),
    )
    recorded = _Recorded()
    monkeypatch.setattr(nodes, "environment_record", recorded)
    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = "auto"
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = None
    fake.get_report_composer.return_value = _Composer()
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    stage = next(step for step in fake.active_profile().stages if step.kind == "report")

    state = {**_state(), "evidence_ledger": _ledger()}
    out = await nodes.make_report_node(fake, stage=stage, announces=False)(state)  # type: ignore[arg-type]

    assert out["run_summary"]["environment"] == BLOCK
    assert recorded.entries and all(e is state["evidence_ledger"] for e in recorded.entries)
