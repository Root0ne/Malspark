"""Shapes shared by the tests of an agent holding the platform's request for a further detonation.

A job's container as the request tool reads it, with a stand-in sandbox
provider; the request tool stamped with the source its declaration lives
under, as the sandbox tools are attached; and an analyst on the real
``BaseAnalyst`` whose model answers from a script. Every value is made up.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from malspark.agents.base_agent import BaseAnalyst
from malspark.agents.prompt_fragments import SANDBOX_FAMILY, stamp_source
from malspark.agents.tool_pinning import DECLARED_NAME_METADATA_KEY
from malspark.core.token_ledger import TokenLedger
from malspark.providers.detonation import DetonationRecord
from malspark.providers.detonation_requests import request_tool
from malspark.providers.submission import LaunchArgumentsAnswer
from malspark.schemas.evidence import EvidenceCounter
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, OpenQuestion

TOOLS_STATED = "SYSTEM: your tools are attached"
BRIEFED = "ledger: 3 entries (ev_0001–ev_0003), 2 from the triage pack"
LIMITS = (
    "Limits of the sandbox: at most 4 detonations per job, the job's own included; each one "
    "takes up to 600 seconds of the sbx-any sandbox's time and its quota. Each submission "
    "sends the sample to the sandbox, is disclosed in the run's record, and may be public on "
    "that service. The arguments are handed to the sandbox verbatim as the program's command "
    "line and are never run on this machine."
)


class Provider:
    """A sandbox provider no declaration names, that submits and passes launch arguments."""

    def __init__(self, provider_id: str = "sbx-any", *, submits: bool = True) -> None:
        self.id = provider_id
        self.capabilities = SimpleNamespace(can_submit=submits, can_pass_launch_arguments=True)

    def launch_arguments_answer(self, arguments: str, sample_path: Any = None) -> Any:
        return LaunchArgumentsAnswer(honoured=True, via="arguments=")


def first_detonation() -> DetonationRecord:
    """The job's own detonation, submitted without arguments and reported."""
    record = DetonationRecord(report={}, submit_returned=True)
    record.launch = {"honoured": None}
    return record


def container(
    *,
    ceiling: int = 4,
    mock: bool = False,
    provider: Any = None,
    detonations: list[Any] | None = None,
    job_timeout: int | None = None,
) -> Any:
    """A job's container as the request tool and the run-state line read it."""
    stages = [
        SimpleNamespace(key="reversing", agents=["reverser"]),
        SimpleNamespace(key="dynamic", agents=["dynamic", "network"]),
    ]
    counter = EvidenceCounter()
    for _ in range(5):
        counter.next_id()
    return SimpleNamespace(
        config=SimpleNamespace(
            sandbox=SimpleNamespace(
                provider="sbx-any",
                max_detonations_per_job=ceiling,
                **{"sbx-any": SimpleNamespace(timeout_seconds=600)},
            ),
            job_timeout=job_timeout,
        ),
        is_mock=mock,
        sample_path="/samples/given.bin",
        get_sandbox_provider=lambda: provider or Provider(),
        get_evidence_counter=lambda: counter,
        active_profile=lambda: SimpleNamespace(stages=stages),
        detonations=[first_detonation()] if detonations is None else detonations,
        detonation_requests=[],
    )


def held_tool(job: Any, name: str = "") -> Any:
    """The request tool as an agent holds it: stamped with its source, renamed where ``name``."""
    (tool,) = stamp_source([request_tool(job)], SANDBOX_FAMILY, declared="sandbox")
    if not name:
        return tool
    metadata = {**(tool.metadata or {}), DECLARED_NAME_METADATA_KEY: tool.name}
    return tool.model_copy(update={"name": name, "metadata": metadata})


def a_tool_named(name: str) -> Any:
    """A tool nothing declared, under ``name``."""
    from langchain_core.tools import StructuredTool

    return StructuredTool.from_function(func=lambda: "done", name=name, description="Any tool.")


class Scripted(BaseChatModel):
    """Answers from a script, a tool call or a text per turn; records each request and its tools."""

    script: list = []
    seen: list = []
    bound: list = []

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self.model_copy(update={"bound": [str(getattr(t, "name", "")) for t in tools]})

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        self.seen.append({"tools": list(self.bound), "messages": list(messages)})
        step = self.script.pop(0) if self.script else "Nothing more."
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, dict):
            turn = AIMessage(content="", tool_calls=[step])
        else:
            turn = AIMessage(content=str(step))
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"


class CannotBind(Scripted):
    """A model whose provider takes no tools."""

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        raise NotImplementedError("this provider takes no tools")


class Holder(BaseAnalyst):
    """An analyst on the real base, holding ``tools``, answering from a scripted model."""

    def __init__(self, llm: Any, tools: list[Any], job: Any, name: str = "dynamic") -> None:
        super().__init__(llm=llm, name=name)
        self.tools = tools
        self._container = job
        self.evidence_counter = job.get_evidence_counter()
        self._job_id = "job-1"
        self.run_state_block = BRIEFED
        self.run_state_source = {}
        self.pack_ledger_ids = ["ev_0001", "ev_0002"]
        self.token_ledger = TokenLedger()
        self._budget_records = [{"agent": name, "turn": "loop"}]

    def _system_prompt(self, fallback: Any, tools: Any = None) -> str:
        return TOOLS_STATED

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def call(name: str, arguments: str, *, cited: str = "ev_0002", call_id: str = "c1") -> dict:
    """A tool call of the request tool, as a model writes it."""
    return {
        "name": name,
        "args": {
            "arguments": arguments,
            "reason": "the routine compares the first argument with a stored word",
            "cited_entries": [cited],
        },
        "id": call_id,
    }


def marked(text: str = "Does the sample write its note when started with an argument?") -> Any:
    return OpenQuestion(
        question=text,
        why_open="needs_sandbox_run",
        detail="the run made had no argument",
        would_answer="a sandbox run with the argument",
    )


def answer(*questions: OpenQuestion, claims: bool = True) -> AgentISR:
    """A validated stage answer: one claim, and ``questions`` open."""
    isr = AgentISR(
        agent_id="dynamic",
        domain="dynamic",
        claims=[
            ClaimEvidence(
                claim="the sample starts one child process",
                evidence_ref="ev_0001",
                confidence=0.7,
            )
        ]
        if claims
        else [],
        open_questions=list(questions),
    )
    if claims:
        isr.note_answer_text(
            "CLAIM 1: the sample starts one child process\nEVIDENCE: [ev_0001]\n"
            "CONFIDENCE: 0.7\nTECHNIQUE: NONE\n"
        )
    return isr


def last_question(seen: list[dict[str, Any]]) -> str:
    """The newest human turn of the first request sent, without its run-state block."""
    from malspark.pipeline.run_state import without_run_state_tail

    humans = [m for m in seen[0]["messages"] if isinstance(m, HumanMessage)]
    return without_run_state_tail(str(humans[-1].content))
