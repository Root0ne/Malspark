"""Further detonations are carried out between the graph's steps, and owed analysts get a turn.

An accepted request is carried out on entry of the next step that has an
agent reading the sandbox, before that step's own work; the graph gains no
node. On the debate's first negotiation entry, each analyst that reads the
sandbox and ran before a detonation returned gets one further turn. A step
entered with nothing pending is entered as it always was. Offline: the
detonator and the agents are stand-ins.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.agents.evidence_recorder import holds_a_settled_answer
from malspark.core.config import Settings
from malspark.pipeline import detonations as dt
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import (
    ACCEPTED,
    JOINED,
    REQUEST_KIND,
    REQUEST_TOOL,
    DetonationRequest,
)

REPORTS = {
    "-a": {"behavior": {"processes": [{"pid": 7, "process_name": "x.exe"}]}},
    "-b": {"behavior": {"processes": [{"pid": 9, "process_name": "x.exe"}]}},
}


def _container(**config: Any) -> Any:
    settings = Settings()
    for key, value in config.items():
        setattr(settings, key, value)
    profile = settings.agents.profiles[settings.agents.profile]
    events: list[tuple[str, dict[str, Any]]] = []

    async def _detonate(record: DetonationRecord) -> None:
        if record.arguments == "-boom":
            raise RuntimeError("the sandbox went away")
        record.report = REPORTS.get(record.arguments)
        record.task_id = f"t-{record.name}"

    container = SimpleNamespace(
        config=settings,
        active_profile=lambda: profile,
        _agent_cache={},
        event_sink=lambda kind, data: events.append((kind, data)),
        detonations=[DetonationRecord(report={})],
        detonation_requests=[],
        detonator=_detonate,
        detonations_seen={},
        further_turns=[],
        current_step="",
    )
    container.events = events
    return container


def _request(
    container: Any, number: int, agent: str, arguments: str, detonation: str, state: str
) -> DetonationRequest:
    request = DetonationRequest(
        number=number,
        agent=agent,
        stage="analysis",
        arguments=arguments,
        reason="found",
        cited_entries=["ev_0003"],
        state=state,
        detonation=detonation,
    )
    container.detonation_requests.append(request)
    return request


class TestWhereARequestCanStillRun:
    def test_the_next_step_with_a_sandbox_reader_is_named(self) -> None:
        container = _container()
        # The default team: the debate's mediator (the judge) reads the sandbox.
        assert dt.later_reading_step(container, "dynamic_analyst") == "negotiation"
        assert dt.later_reading_step(container, "revision") == "negotiation"
        assert dt.later_reading_step(container, "negotiation") == "judge"

    def test_after_the_last_reading_step_nothing_can_run(self) -> None:
        container = _container()
        assert dt.later_reading_step(container, "judge") == ""
        assert dt.later_reading_step(container, "report") == ""

    def test_an_agent_built_with_a_sandbox_tool_reads_the_sandbox(self) -> None:
        from langchain_core.tools import StructuredTool

        from malspark.agents.prompt_fragments import SANDBOX_FAMILY, stamp_source

        container = _container()
        tool = StructuredTool.from_function(func=lambda: {}, name="sandbox_items", description="x")
        container._agent_cache["network"] = SimpleNamespace(
            tools=stamp_source([tool], SANDBOX_FAMILY, declared="sandbox")
        )
        assert dt.reads_the_sandbox(container, "network")
        assert dt.later_reading_step(container, "dynamic_analyst") == "network_analyst"

    def test_a_profile_that_withholds_the_sandbox_tools_reads_none(self) -> None:
        container = _container()
        profile = container.active_profile().model_copy(update={"exclude_sandbox_tools": True})
        container.active_profile = lambda: profile
        assert not dt.reads_the_sandbox(container, "judge")


class TestTheExecutor:
    def test_pending_detonations_are_carried_out_once_each_with_who_asked(self) -> None:
        container = _container()
        first = _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)
        _request(container, 2, "judge", "-a", "d2", JOINED)
        _request(container, 3, "dynamic", "-b", "d3", ACCEPTED)
        state = {
            "evidence_ledger": [
                {
                    "id": "ev_0007",
                    "tool": REQUEST_TOOL,
                    "source": "sandbox",
                    "facts": {"v": 1, "kind": REQUEST_KIND},
                    "structured": {"request": "r1"},
                },
                {
                    "id": "ev_0008",
                    "tool": "other",
                    "source": "sandbox",
                    "facts": {"v": 1, "kind": "other"},
                    "structured": {"request": "r3"},
                },
            ]
        }
        made = asyncio.run(dt.carry_out(container, state, "negotiation"))
        assert [r.name for r in made] == ["d2", "d3"]
        d2, d3 = made
        assert [a["agent"] for a in d2.requested_by] == ["dynamic", "judge"]
        assert first.entry_id == "ev_0007" and d2.requested_by[0]["entry_id"] == "ev_0007"
        assert d3.requested_by[0]["entry_id"] == ""
        assert d2.report == REPORTS["-a"] and d2.step == "negotiation"
        assert d2.ended_at >= d2.started_at > 0 and d2.duration_ms >= 0
        assert d2.public()["step"] == "negotiation"
        assert [r.name for r in container.detonations] == ["d1", "d2", "d3"]
        kinds = [kind for kind, _ in container.events]
        assert kinds == [dt.DETONATION_STARTED, dt.DETONATION_FINISHED] * 2
        assert container.events[0][1]["requested_by"] == ["dynamic", "judge"]
        # Nothing is carried out twice.
        assert asyncio.run(dt.carry_out(container, state, "judge")) == []

    def test_no_event_or_log_carries_the_arguments(self, caplog: Any) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)
        asyncio.run(dt.carry_out(container, {}, "negotiation"))
        assert "-a" not in repr(container.events)
        assert "-a" not in caplog.text

    def test_a_failed_detonation_is_recorded_and_never_raises(self) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-boom", "d2", ACCEPTED)
        (record,) = asyncio.run(dt.carry_out(container, {}, "negotiation"))
        assert record.failure == "it failed: RuntimeError"
        assert not record.reported
        assert container.events[-1][1]["reported"] is False

    def test_the_job_s_time_limit_bounds_a_detonation(self) -> None:
        container = _container(job_timeout=60)
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)
        state = {"run_started_at": time.time() - 100}
        (record,) = asyncio.run(dt.carry_out(container, state, "negotiation"))
        assert record.failure.startswith("not run: the job's time limit leaves 0 seconds")
        assert record.report is None


class TestTheEntryOfAStep:
    def test_a_step_with_nothing_pending_is_entered_as_it_always_was(self) -> None:
        container = _container()
        seen: list[Any] = []

        async def node(state: Any) -> dict[str, Any]:
            seen.append(state)
            return {"x": 1}

        entered = dt.on_entry(container, "judge", node, reading_agents=("judge",))
        state = {"reports": {}}
        assert asyncio.run(entered(state)) == {"x": 1}
        assert seen == [state] and seen[0] is state
        assert container.events == [] and container.current_step == "judge"
        assert entered.__wrapped__ is node

    def test_a_pending_request_runs_before_a_reading_step_s_own_work(self) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)
        held: list[list[str]] = []

        async def node(state: Any) -> dict[str, Any]:
            held.append([r.name for r in container.detonations])
            return {}

        asyncio.run(dt.on_entry(container, "judge", node, reading_agents=("judge",))({}))
        assert held == [["d1", "d2"]]

    def test_a_step_without_a_sandbox_reader_carries_nothing_out(self) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)

        def node(state: Any) -> dict[str, Any]:
            return {}

        dt.on_entry(container, "report", node, reading_agents=("reporter",))({})
        assert [r.name for r in container.detonations] == ["d1"]

    def test_a_synchronous_step_beside_a_running_loop_carries_it_out(self) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)

        def node(state: Any) -> dict[str, Any]:
            return {"n": len(container.detonations)}

        entered = dt.on_entry(
            container,
            "dynamic_analyst",
            node,
            reading_agents=("dynamic",),
            analysis_agents=("dynamic",),
        )

        async def main() -> Any:
            return entered({})

        assert asyncio.run(main()) == {"n": 2}
        # The analyst's own turn can read d2.
        assert container.detonations_seen["dynamic"] == {"d1", "d2"}


class _Analyst:
    def __init__(self) -> None:
        self.asked: list[str] = []

    def safe_revise_isr(self, data: str, own: str, peers: Any, feedback: str, rnd: int) -> Any:
        self.asked.append(feedback)
        return "revised with d2", SimpleNamespace(claims=["c"])

    def drain_evidence_entries(self) -> list[Any]:
        return []


@pytest.fixture
def _turns(monkeypatch: pytest.MonkeyPatch) -> _Analyst:
    from malspark.pipeline import nodes

    analyst = _Analyst()
    monkeypatch.setattr(
        nodes, "_revision_input", lambda state, container, name: nodes.RevisionInput(text="raw")
    )
    monkeypatch.setattr(nodes, "brief_agent", lambda agent, state, container: None)
    monkeypatch.setattr(nodes, "_budget_update", lambda agent, name: {})
    monkeypatch.setattr(nodes, "_validation_update", lambda agent, name: {})
    monkeypatch.setattr(nodes, "_nudge_mode", lambda agent: None)
    monkeypatch.setattr(nodes, "revision_decided_nothing", lambda isr: False)
    return analyst


class TestTheFurtherTurn:
    def _ready(self, analyst: _Analyst) -> Any:
        container = _container()
        container.get_agent = lambda name: analyst
        container.detonations.append(
            DetonationRecord(
                ordinal=2,
                origin="agent",
                arguments="-a",
                report=REPORTS["-a"],
                requested_by=[{"agent": "dynamic", "cited_entries": ["ev_0003"]}],
            )
        )
        # The analyst's own turn began before d2 returned.
        container.detonations_seen["dynamic"] = {"d1"}
        return container

    def test_an_analyst_owed_a_detonation_gets_one_turn_at_the_debate_s_start(
        self, _turns: _Analyst
    ) -> None:
        container = self._ready(_turns)
        got: list[Any] = []

        async def negotiation(state: Any) -> dict[str, Any]:
            got.append(state)
            return {"iteration_count": 1}

        entered = dt.on_entry(
            container,
            "negotiation",
            negotiation,
            reading_agents=("judge",),
            first_negotiation=True,
        )
        out = asyncio.run(entered({"reports": {"dynamic": "first answer"}}))
        assert got[0]["revised_reports"] == {"dynamic": "revised with d2"}
        assert out["revised_reports"] == {"dynamic": "revised with d2"}
        assert out["iteration_count"] == 1
        (asked,) = _turns.asked
        assert "detonation d2: launched with '-a', asked for by dynamic citing ev_0003" in asked
        (turn,) = container.further_turns
        assert turn["agent"] == "dynamic" and turn["outcome"] == "revised"
        assert turn["detonations"] == ["d2"] and turn["step"] == "negotiation"
        kinds = [kind for kind, _ in container.events]
        assert kinds == [dt.FURTHER_TURN_STARTED, dt.FURTHER_TURN_FINISHED]
        # A later negotiation entry gives no second turn.
        got.clear()
        asyncio.run(entered({"reports": {"dynamic": "first answer"}}))
        assert len(container.further_turns) == 1 and "revised_reports" not in got[0]

    def test_an_analyst_that_read_every_detonation_gets_none(self, _turns: _Analyst) -> None:
        container = self._ready(_turns)
        container.detonations_seen["dynamic"] = {"d1", "d2"}

        async def negotiation(state: Any) -> dict[str, Any]:
            return {}

        entered = dt.on_entry(
            container, "negotiation", negotiation, reading_agents=("judge",), first_negotiation=True
        )
        asyncio.run(entered({"reports": {"dynamic": "first answer"}}))
        assert container.further_turns == [] and _turns.asked == []


def test_a_read_of_a_detonation_not_held_yet_is_never_served_again() -> None:
    """Its answer carries an error, which is never held for a later call nor seeded in a turn."""
    from malspark.providers.detonation import selected

    _, problem = selected(SimpleNamespace(detonations=[]), "d2")
    entry = SimpleNamespace(
        ok=True, repeated_of=None, output="{}", structured={"error": problem, "tool": "sandbox"}
    )
    assert not holds_a_settled_answer(entry)
    assert not holds_a_settled_answer(entry, deep=True)


class TestAFurtherDetonationThroughTheApp:
    """``MalsparkApp.detonate_further``: the first detonation's path, its own record."""

    def _box(self) -> Any:
        from malspark.schemas.sandbox_report import SandboxRun
        from tests.unit.pipeline.test_a_launcher_run_is_read_as_the_launcher_s import (
            _LauncherBox,
            _overview,
            _report,
        )

        class _Box(_LauncherBox):
            def submit(self, sample_path: str, **kwargs: Any) -> str:
                options = kwargs.get("options")
                self.sent.append(options.launcher if options else None)
                return f"s{len(self.sent)}"

            def fetch(self, task_id: str) -> SandboxRun:
                overview = _overview()
                built = self.sent[-1]
                if built is not None:
                    overview["sample"]["sha256"] = built.record["archive_sha256"]
                report = _report(overview=overview)
                return SandboxRun(task_id=task_id, report=report, raw=overview, status="reported")

        return _Box()

    def test_d1_bare_and_d2_through_a_launcher_are_each_read_by_their_own_launch(
        self, tmp_path: Any
    ) -> None:
        from malspark.pipeline import sandbox_status as status
        from malspark.schemas.sandbox_document import place
        from malspark.schemas.sandbox_report import LINEAGE_KEY
        from tests.unit.pipeline.test_a_launcher_run_is_read_as_the_launcher_s import (
            ARGS,
            INTAKE,
            _sample,
        )
        from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app

        box = self._box()
        app = _app(box)
        sample = _sample(tmp_path)
        first = app._mark_the_launch(
            app._tell_the_target(asyncio.run(app._submit_to_sandbox(sample)), INTAKE)
        )
        assert first is not None and app.container.launch_record is None
        app.container.sample_path = sample
        app.container.sample_sha256 = INTAKE
        record = DetonationRecord(ordinal=2, origin="agent", arguments=ARGS)
        asyncio.run(app.detonate_further(record))

        # d1 went bare: no launcher, no lineage marks, no launch mark.
        assert box.sent[0] is None
        lineage_1 = {
            p["pid"]: p.get("extra", {}).get(LINEAGE_KEY) for p in place(first, "processes")
        }
        assert set(lineage_1.values()) == {None}
        # d2 went through the launcher, read by its own launch record.
        assert box.sent[1] is not None
        assert record.launch["launcher"]["archive_sha256"] == box.sent[1].record["archive_sha256"]
        lineage_2 = {
            p["pid"]: p.get("extra", {}).get(LINEAGE_KEY) for p in place(record.report, "processes")
        }
        assert lineage_2 == {1: "launcher", 4: "launcher", 2: "sample", 3: "sample"}
        # Its own target claim is the archive it submitted, not another target.
        assert record.target_claim["sha256"] == box.sent[1].record["archive_sha256"]
        assert status.TARGET_KEY not in record.report
        assert record.report[status.LAUNCH_KEY]["arguments"] == ARGS
        # The job-level fields stay the first detonation's.
        assert app.container.launch_record is None
        assert app.container.sandbox_target_claim["task_id"] == "s1"
        # Its upload row joins the job's list, naming it.
        rows = app.container.sample_uploads
        assert [row.get("detonation") for row in rows] == [None, "d2"]
        assert rows[1]["launch_arguments"] == ARGS


class TestTheRunsRecord:
    def test_a_job_without_a_request_records_nothing_more(self) -> None:
        container = _container()
        assert dt.recorded_detonations(container) == {}
        assert dt.further_detonation_reasons(container) == []

    def test_the_summary_lists_every_detonation_request_and_turn(self) -> None:
        container = _container()
        _request(container, 1, "dynamic", "-a", "d2", ACCEPTED)
        asyncio.run(dt.carry_out(container, {}, "negotiation"))
        container.further_turns.append({"agent": "dynamic", "detonations": ["d2"]})
        record = dt.recorded_detonations(container)
        first, second = record["detonations"]
        assert first["detonation"] == "d1" and first["origin"] == "job"
        assert second["detonation"] == "d2" and second["origin"] == "agent"
        assert second["arguments"] == "-a" and second["step"] == "negotiation"
        assert second["requested_by"][0]["agent"] == "dynamic"
        assert record["detonation_requests"][0]["state"] == ACCEPTED
        assert record["further_turns"] == [{"agent": "dynamic", "detonations": ["d2"]}]

    def test_a_request_not_carried_out_is_a_limitation(self) -> None:
        from malspark.providers.detonation_requests import NO_LATER_STEP, REFUSED

        container = _container()
        late = _request(container, 1, "judge", "-a", "", REFUSED)
        late.answer = NO_LATER_STEP
        wrong = _request(container, 2, "dynamic", "-x", "", REFUSED)
        wrong.answer = "give the reason the sample should be detonated with these arguments"
        _request(container, 3, "dynamic", "-boom", "d2", ACCEPTED)
        _request(container, 4, "dynamic", "-b", "d3", ACCEPTED)
        asyncio.run(dt.carry_out(container, {}, "negotiation"))
        _request(container, 5, "network", "-c", "d4", ACCEPTED)
        reasons = dt.further_detonation_reasons(container)
        assert reasons == [
            "further detonation asked for by judge (r1) was not carried out: " + NO_LATER_STEP,
            "further detonation d4 asked for by network was accepted and not carried out "
            "before the verdict",
            "further detonation d2 asked for by dynamic returned no sandbox report: "
            "it failed: RuntimeError",
        ]


class TestTheLauncherAttributionIsReadPerDetonation:
    """The launcher review's reading side, on this branch's files (T-674 review round 2)."""

    LAUNCHED = {
        "arguments": "-a",
        "honoured": True,
        "provider": "lab-box",
        "launcher": {
            "launcher_text": "x",
            "script_host": "powershell",
            "sample_member": "sample.exe",
        },
    }

    def _report(self, *, launched: bool) -> dict[str, Any]:
        from malspark.schemas.sandbox_document import LAUNCH_KEY
        from malspark.schemas.sandbox_report import LINEAGE_MARKED_STORED

        report: dict[str, Any] = {
            "behavior": {
                "processes": [
                    # A wrapper the sandbox marked as the sample's.
                    {"pid": 9, "process_name": "cmd.exe", "extra": {LINEAGE_MARKED_STORED: True}},
                    {"pid": 2, "process_name": "sample.exe"},
                ]
            }
        }
        if launched:
            report[LAUNCH_KEY] = dict(self.LAUNCHED)
        return report

    def test_the_sandbox_s_sample_mark_is_set_aside_in_a_launcher_run(self) -> None:
        from malspark.providers.sandbox_tools import sandbox_processes

        rows = sandbox_processes(self._report(launched=True))["processes"]
        assert not any(row.get("marked") for row in rows)

    def test_a_bare_run_keeps_the_sandbox_s_sample_mark(self) -> None:
        from malspark.providers.sandbox_tools import sandbox_processes

        rows = sandbox_processes(self._report(launched=False))["processes"]
        assert [row.get("marked") for row in rows] == [True, None]

    def test_the_statement_follows_the_attribution_mark(self) -> None:
        from malspark.pipeline import sandbox_status as status

        established = status.launch_statement(self.LAUNCHED, "established")
        assert "the sample's own start at the process that runs `sample.exe`" in established
        assert established == status.launch_statement(self.LAUNCHED)
        failed = status.launch_statement(
            self.LAUNCHED, "not established: no listed process runs sample.exe"
        )
        assert "the sample's own start" not in failed
        assert "could not be established (no listed process runs sample.exe)" in failed
        report = {status.LAUNCHER_ATTRIBUTION_KEY: "not established: no listed process runs x"}
        assert status.launcher_attribution_reason(report) == (
            "the launcher's processes could not be told from the sample's in the sandbox "
            "report: no listed process runs x; only the script host's own processes are "
            "marked as the launcher's"
        )
        assert (
            status.launcher_attribution_reason({status.LAUNCHER_ATTRIBUTION_KEY: "established"})
            is None
        )
        assert status.launcher_attribution_reason({}) is None

    def test_a_further_detonation_s_launch_is_said_to_be_asked_by_its_agents(self) -> None:
        from malspark.pipeline import sandbox_status as status

        said = status.launch_statement(
            {**self.LAUNCHED, "detonation": "d2", "requested_by": ["reverser"]}
        )
        assert said.startswith("For detonation 2, reverser asked the sandbox to launch")
        assert status.launch_statement(self.LAUNCHED).startswith("The job asked the sandbox")


class TestTheSubmissionPath:
    """B8 and B9 of the launcher review, per detonation."""

    def test_the_launch_answer_is_built_off_the_event_loop_and_errors_are_logged_masked(
        self, tmp_path: Any, caplog: Any
    ) -> None:
        import threading

        from tests.unit.pipeline.test_a_launcher_run_is_read_as_the_launcher_s import (
            ARGS,
            _LauncherBox,
            _sample,
        )
        from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app

        threads: list[str] = []

        class _Box(_LauncherBox):
            def launch_arguments_answer(self, arguments: str, *, sample_path: Any = None) -> Any:
                threads.append(threading.current_thread().name)
                return super().launch_arguments_answer(arguments, sample_path=sample_path)

            def fetch(self, task_id: str) -> Any:
                run = super().fetch(task_id)
                # A sandbox that echoes what it was sent in its error.
                return run.model_copy(update={"status": "failed", "error": f"bad: {ARGS}"})

        app = _app(_Box())
        app.container.sample_path = _sample(tmp_path)
        record = DetonationRecord(ordinal=2, origin="agent", arguments=ARGS)
        with caplog.at_level("WARNING"):
            asyncio.run(app.detonate_further(record))
        assert threads and threads[0] != threading.main_thread().name
        assert record.submit_returned and record.report is None
        assert "Sandbox task ended with status=failed" in caplog.text
        assert ARGS not in caplog.text
        assert ARGS not in (record.failure or "")


class TestTheBaseMarksAreRead:
    """The launcher round's platform marks, read where this branch's readers stand."""

    def test_a_report_carrying_the_attribution_mark_sets_the_sandbox_s_sample_mark_aside(
        self,
    ) -> None:
        from malspark.providers.sandbox_tools import sandbox_processes
        from malspark.schemas.sandbox_document import LAUNCHER_ATTRIBUTION_KEY
        from malspark.schemas.sandbox_report import (
            LINEAGE_MARKED_STORED,
            PROCESS_TASK_KEY,
            attribution_not_established,
        )

        report = {
            LAUNCHER_ATTRIBUTION_KEY: attribution_not_established("no listed process runs x"),
            "behavior": {
                "processes": [
                    {
                        "pid": 9,
                        "process_name": "cmd.exe",
                        "extra": {LINEAGE_MARKED_STORED: True, PROCESS_TASK_KEY: "behavioral2"},
                    }
                ]
            },
        }
        (row,) = sandbox_processes(report)["processes"]
        assert "marked" not in row
        assert row["task"] == "behavioral2"

    def test_the_archive_s_members_are_listed_apart_from_the_files_the_sample_wrote(
        self,
    ) -> None:
        from malspark.providers.sandbox_tools import sandbox_dropped_files
        from malspark.schemas.sandbox_report import (
            DROPPED_LAUNCHER,
            LINEAGE_KEY,
            LINEAGE_LAUNCHER,
            LINEAGE_REASON_KEY,
        )

        report = {
            "behavior": {"processes": []},
            "dropped": [
                {
                    "name": "launch.ps1",
                    "sha256": "a" * 64,
                    LINEAGE_KEY: LINEAGE_LAUNCHER,
                    LINEAGE_REASON_KEY: DROPPED_LAUNCHER,
                },
                {"name": "ransom.txt", "sha256": "b" * 64},
            ],
        }
        answer = sandbox_dropped_files(report)
        assert [row["name"] for row in answer["dropped"]] == ["ransom.txt"]
        assert answer["total"] == 1
        (apart,) = answer["platform_files"]
        assert apart["name"] == "launch.ps1"
        assert apart[LINEAGE_KEY] == LINEAGE_LAUNCHER
        assert apart[LINEAGE_REASON_KEY] == DROPPED_LAUNCHER

    def test_the_statement_reads_the_top_level_marks(self) -> None:
        from malspark.pipeline import sandbox_status as status
        from malspark.schemas.sandbox_document import (
            LAUNCH_KEY,
            LAUNCHER_ATTRIBUTION_KEY,
            UNATTRIBUTED_SIGNATURES_KEY,
        )
        from malspark.schemas.sandbox_report import ATTRIBUTION_ESTABLISHED

        launched = TestTheLauncherAttributionIsReadPerDetonation.LAUNCHED
        report = {
            "behavior": {"processes": [{"pid": 1}]},
            LAUNCH_KEY: launched,
            LAUNCHER_ATTRIBUTION_KEY: ATTRIBUTION_ESTABLISHED,
            UNATTRIBUTED_SIGNATURES_KEY: 2,
        }
        said = status.sandbox_status(report).statement
        assert "the sample's own start at the process that runs `sample.exe`" in said
        assert "2 sandbox signatures that name no process could not be attributed" in said
        assert status.launcher_attribution_reason(report) is None
        report[UNATTRIBUTED_SIGNATURES_KEY] = 0
        assert "could not be attributed" not in status.sandbox_status(report).statement


def test_the_family_note_is_printed_where_the_family_s_source_is_worded() -> None:
    from malspark.extractors.attribution import SANDBOX_FAMILY_LAUNCHER_NOTE
    from malspark.reporting.renderers.markdown import _family_words

    report = SimpleNamespace(
        attribution=SimpleNamespace(
            family="somefam", family_source="sandbox", family_note=SANDBOX_FAMILY_LAUNCHER_NOTE
        )
    )
    said = _family_words(report)  # type: ignore[arg-type]
    assert said.startswith("somefam (named by the sandbox's own classification")
    assert SANDBOX_FAMILY_LAUNCHER_NOTE in said
    report.attribution.family_note = None
    assert _family_words(report) == (  # type: ignore[arg-type]
        "somefam (named by the sandbox's own classification; the judge named none)"
    )
