"""An answer served from an earlier entry says it may be asked afresh, and asking again runs it.

Three layers answer an identical call from an earlier entry with no tool run:
a whole-function read the loop already holds, the agent's own call of an
earlier round, and an identical call of the job by any agent. Each served
answer ends with one platform sentence saying that asking again with the same
arguments runs the call fresh, and the identical call after it runs the tool
and is recorded as a call that ran. Once per call per loop: the fresh run
counts as a run, so the call after it is refused as after any second run, and
the refusals end the loop as before. The rule reads no tool's name and holds
for a tool nothing declares. The sentence tells what the fresh run does: a call
the layers know to be read-only is read again; any other call runs again and
repeats whatever it does. A call no layer serves keeps the guard's two runs
before its refusal, and its answers carry no such sentence.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from malspark.agents.evidence_recorder import (
    FRESH_RUN_REPEATS_SENTENCE,
    FRESH_RUN_SENTENCE,
    EvidenceRecorder,
    RepeatGuard,
    record_tools,
    seeded_repeat_guard,
)
from malspark.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from malspark.agents.tool_pinning import (
    READ_ONLY_METADATA_KEY,
    SERVER_HINTS_METADATA_KEY,
    SERVER_METADATA_KEY,
)
from malspark.schemas.evidence import EvidenceCounter, LedgerEntry, call_was_made

LISTING = "\nundefined8 FUN_1360bc0ae78(void)\n\n{\n  FUN_1360bc09040(0);\n  return 0;\n}\n\n"
REPORT = json.dumps({"status": "found", "domain": "example.test", "malicious": 3})
BOTH_HINTS = {"readOnlyHint": True, "idempotentHint": True}


class _Single(BaseModel):
    address: str = ""
    program: str | None = None


class _Domain(BaseModel):
    domain: str = ""


def _runs(name: str, answer: str, calls: list[str]) -> Any:
    def _run(**_kwargs: Any) -> str:
        calls.append(name)
        return answer

    return _run


def _declared_read(calls: list[str]) -> Any:
    """A whole-function read a built-in declaration declares read-only."""
    tool = StructuredTool.from_function(
        func=_runs("decompile_function", LISTING, calls),
        name="decompile_function",
        description="d",
        args_schema=_Single,
        infer_schema=False,
    )
    (stamped,) = stamp_source([tool], PROVIDER_FAMILY, declared="provider:ghidra")
    return stamped


def _undeclared(calls: list[str], *, hints: dict[str, bool] | None = BOTH_HINTS) -> Any:
    """A tool of a server nothing declares, with only the hints its server gave it."""
    metadata: dict[str, Any] = {SERVER_METADATA_KEY: "reputation"}
    if hints:
        metadata[SERVER_HINTS_METADATA_KEY] = dict(hints)
        metadata[READ_ONLY_METADATA_KEY] = bool(hints.get("readOnlyHint"))
    return StructuredTool.from_function(
        func=_runs("domain_report", REPORT, calls),
        name="domain_report",
        description="d",
        args_schema=_Domain,
        infer_schema=False,
        metadata=metadata,
    )


def _loop(agent: str, counter: EvidenceCounter, tool: Any, guard: RepeatGuard | None = None):
    recorder = EvidenceRecorder(agent, counter=counter)
    guard = RepeatGuard() if guard is None else guard
    (wrapped,) = record_tools([tool], recorder, guard)
    return wrapped, recorder, guard


def _ran(entry: LedgerEntry) -> bool:
    return call_was_made(entry)


class TestAWholeFunctionReadTheLoopHolds:
    def test_asked_again_after_the_served_answer_it_runs_then_is_refused(self) -> None:
        calls: list[str] = []
        tool, recorder, guard = _loop("reverser", EvidenceCounter(), _declared_read(calls))

        tool.invoke({"address": "0x1360bc0ae78"})
        served = tool.invoke({"address": "0x1360bc0ae78"})
        fresh = tool.invoke({"address": "0x1360bc0ae78"})
        refused = tool.invoke({"address": "0x1360bc0ae78"})

        first, repeat, ran, refusal = recorder.entries
        assert calls == ["decompile_function"] * 2, "the call after the served answer ran"
        assert repeat.repeated_of == first.id
        assert FRESH_RUN_SENTENCE in served and FRESH_RUN_SENTENCE in repeat.output
        assert _ran(ran), "the fresh run is recorded as a call that ran"
        assert fresh.startswith(f"[{ran.id}]\n") and LISTING in fresh
        assert FRESH_RUN_SENTENCE not in fresh
        assert refusal.repeated_of == ran.id, "the refusal names the fresh run's entry"
        assert LISTING not in refused and "Do not call it again" in refused
        assert guard.refused_repeats == 1

    def test_the_served_answer_does_not_say_the_next_call_is_refused(self) -> None:
        calls: list[str] = []
        tool, _recorder, _guard = _loop("reverser", EvidenceCounter(), _declared_read(calls))

        tool.invoke({"address": "0x1360bc0ae78"})
        served = tool.invoke({"address": "0x1360bc0ae78"})

        assert "A third will not be run" not in served
        assert "After that fresh run it will not be run" in served


class TestTheAgentsOwnEarlierRound:
    @staticmethod
    def _seeded(tool_name: str, args: dict[str, Any], output: str) -> RepeatGuard:
        earlier = LedgerEntry(id="ev_0003", tool=tool_name, args=args, output=output)
        return seeded_repeat_guard((), earlier_rounds=[earlier])

    def test_asked_again_after_the_served_answer_it_runs_then_is_refused(self) -> None:
        calls: list[str] = []
        # As the call records them: the schema's default for an argument not given.
        args = {"address": "0x1360bc0ae78", "program": None}
        guard = self._seeded("decompile_function", args, LISTING)
        tool, recorder, _ = _loop("reverser", EvidenceCounter(), _declared_read(calls), guard)

        served = tool.invoke({"address": "0x1360bc0ae78"})
        tool.invoke({"address": "0x1360bc0ae78"})
        refused = tool.invoke({"address": "0x1360bc0ae78"})

        repeat, ran, refusal = recorder.entries
        assert calls == ["decompile_function"]
        assert repeat.repeated_of == "ev_0003" and "earlier round" in served
        assert served.endswith(FRESH_RUN_SENTENCE)
        assert _ran(ran)
        assert refusal.repeated_of == ran.id and "Do not call it again" in refused

    def test_a_tool_nothing_declares_is_treated_the_same(self) -> None:
        calls: list[str] = []
        guard = self._seeded("domain_report", {"domain": "example.test"}, REPORT)
        tool, recorder, _ = _loop("network", EvidenceCounter(), _undeclared(calls), guard)

        served = tool.invoke({"domain": "example.test"})
        tool.invoke({"domain": "example.test"})
        tool.invoke({"domain": "example.test"})

        assert FRESH_RUN_SENTENCE in served
        assert calls == ["domain_report"]
        assert [_ran(entry) for entry in recorder.entries] == [False, True, False]


class TestAnIdenticalCallOfTheJob:
    def test_asked_again_after_the_served_answer_it_runs_then_is_refused(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, held, _ = _loop("triage", counter, _undeclared(calls))
        network, recorder, guard = _loop("network", counter, _undeclared(calls))

        triage.invoke({"domain": "example.test"})
        served = network.invoke({"domain": "example.test"})
        fresh = network.invoke({"domain": "example.test"})
        refused = network.invoke({"domain": "example.test"})

        repeat, ran, refusal = recorder.entries
        assert calls == ["domain_report"] * 2, "an undeclared tool's fresh run ran"
        assert repeat.repeated_of == held.entries[0].id and "by triage" in served
        assert FRESH_RUN_SENTENCE in served and FRESH_RUN_SENTENCE in repeat.output
        assert _ran(ran) and fresh.startswith(f"[{ran.id}]\n")
        assert refusal.repeated_of == ran.id and REPORT not in refused
        assert guard.refused_repeats == 1

    def test_a_tool_recorded_without_a_loop_guard_runs_fresh_too(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, _held, _ = _loop("triage", counter, _undeclared(calls))
        recorder = EvidenceRecorder("network", counter=counter)
        (network,) = record_tools([_undeclared(calls)], recorder)

        triage.invoke({"domain": "example.test"})
        served = network.invoke({"domain": "example.test"})
        network.invoke({"domain": "example.test"})

        assert FRESH_RUN_SENTENCE in served
        assert calls == ["domain_report"] * 2
        assert [_ran(entry) for entry in recorder.entries] == [False, True]


class TestTheBound:
    def test_serving_and_running_never_alternate_and_the_refusals_end_the_loop(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, _held, _ = _loop("triage", counter, _undeclared(calls))
        network, recorder, guard = _loop("network", counter, _undeclared(calls))

        triage.invoke({"domain": "example.test"})
        answers = [network.invoke({"domain": "example.test"}) for _ in range(12)]

        assert calls == ["domain_report"] * 2, "one run for the job, one fresh run for the loop"
        assert sum(FRESH_RUN_SENTENCE in answer for answer in answers) == 1
        assert [_ran(entry) for entry in recorder.entries[:2]] == [False, True]
        assert not any(_ran(entry) for entry in recorder.entries[2:])
        assert guard.refused_repeats == 10
        assert guard.ending_the_loop()

    def test_a_call_gets_one_fresh_run_per_loop(self) -> None:
        guard = RepeatGuard()
        args = {"domain": "example.test"}

        guard.owe_fresh_run("domain_report", args)
        assert guard.takes_fresh_run("domain_report", args)
        assert not guard.may_run_fresh("domain_report", args)
        guard.owe_fresh_run("domain_report", args)
        assert not guard.takes_fresh_run("domain_report", args)

    def test_a_call_no_layer_serves_keeps_two_runs_before_its_refusal(self) -> None:
        calls: list[str] = []
        tool, recorder, _ = _loop("network", EvidenceCounter(), _undeclared(calls, hints=None))

        answers = [tool.invoke({"domain": "example.test"}) for _ in range(3)]

        assert calls == ["domain_report"] * 2
        assert [_ran(entry) for entry in recorder.entries] == [True, True, False]
        assert not any(FRESH_RUN_SENTENCE in answer for answer in answers)

    def test_a_fresh_run_that_fails_is_a_failure_and_the_next_ask_is_refused(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, held, _ = _loop("triage", counter, _undeclared(calls))
        network, recorder, guard = _loop("network", counter, _failing_once(calls))

        triage.invoke({"domain": "example.test"})
        network.invoke({"domain": "example.test"})
        failed = network.invoke({"domain": "example.test"})
        answers = [network.invoke({"domain": "example.test"}) for _ in range(RepeatGuard.ENDS_AT)]

        _repeat, ran, *refusals = recorder.entries
        assert calls == ["domain_report"] * 2, "the failed fresh run is the only second run"
        assert _ran(ran) and ran.ok is False, "recorded as a call that ran and failed"
        assert "server gone" in failed and FRESH_RUN_SENTENCE not in failed
        assert not any(_ran(entry) for entry in refusals), "the next asks run nothing"
        assert {entry.repeated_of for entry in refusals} == {held.entries[0].id}
        assert not any(FRESH_RUN_SENTENCE in answer for answer in answers)
        assert guard.refused_repeats == RepeatGuard.ENDS_AT
        assert guard.ending_the_loop()

    def test_two_identical_calls_of_one_turn_take_one_fresh_run(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, _held, _ = _loop("triage", counter, _undeclared(calls))
        network, recorder, _guard = _loop("network", counter, _undeclared(calls))

        triage.invoke({"domain": "example.test"})
        network.invoke({"domain": "example.test"})

        async def _turn() -> list[str]:
            return await asyncio.gather(
                network.ainvoke({"domain": "example.test"}),
                network.ainvoke({"domain": "example.test"}),
            )

        asyncio.run(_turn())

        assert calls == ["domain_report"] * 2, "one run for the job, one fresh run for the turn"
        assert [_ran(entry) for entry in recorder.entries] == [False, True, False]


def _failing_once(calls: list[str]) -> Any:
    """The undeclared tool, raising on its first run here: the fresh run fails."""
    runs: list[int] = []

    def _run(**_kwargs: Any) -> str:
        calls.append("domain_report")
        runs.append(1)
        if len(runs) == 1:
            raise RuntimeError("server gone")
        return REPORT

    like = _undeclared([])
    return StructuredTool.from_function(
        func=_run,
        name=like.name,
        description="d",
        args_schema=_Domain,
        infer_schema=False,
        metadata=like.metadata,
    )


class TestTheSentence:
    def test_it_names_no_tool_and_is_built_once(self) -> None:
        for sentence in (FRESH_RUN_SENTENCE, FRESH_RUN_REPEATS_SENTENCE):
            assert "decompile_function" not in sentence
            assert "domain_report" not in sentence
            assert sentence.startswith("Asking again with the same arguments")

    def test_a_read_only_call_is_read_again(self) -> None:
        calls: list[str] = []
        tool, _recorder, _guard = _loop("reverser", EvidenceCounter(), _declared_read(calls))

        tool.invoke({"address": "0x1360bc0ae78"})
        served = tool.invoke({"address": "0x1360bc0ae78"})

        assert FRESH_RUN_SENTENCE in served and FRESH_RUN_REPEATS_SENTENCE not in served

    def test_a_call_not_known_to_be_read_only_says_it_repeats_what_it_does(self) -> None:
        calls: list[str] = []
        # A tool nothing declares and whose server gave no hint, settled in an
        # earlier chunk: served, and its fresh run does again what it does.
        guard = seeded_repeat_guard(
            [
                LedgerEntry(
                    id="ev_0003",
                    tool="domain_report",
                    args={"domain": "example.test"},
                    output=REPORT,
                )
            ]
        )
        tool, recorder, _ = _loop(
            "network", EvidenceCounter(), _undeclared(calls, hints=None), guard
        )

        served = tool.invoke({"domain": "example.test"})
        tool.invoke({"domain": "example.test"})

        assert served.endswith(FRESH_RUN_REPEATS_SENTENCE)
        assert FRESH_RUN_SENTENCE not in served
        assert recorder.entries[0].output.endswith(FRESH_RUN_REPEATS_SENTENCE)
        assert calls == ["domain_report"], "the fresh run ran"
        assert [_ran(entry) for entry in recorder.entries] == [False, True]
