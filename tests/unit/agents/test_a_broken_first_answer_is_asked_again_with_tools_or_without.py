"""A first answer no claim can be read from is asked again, with tools or without.

The stub rehearsal's ``schema_break`` left three analysts with no claims on a
stack where every tool server was off, while the same fault passed in process
with tools on. Both paths ask once, in different words: the tool loop asks an
answer written without a tool call whether a tool should be called, the
tools-free single shot is asked for the claim format in the validation turn.
Either way a valid second answer is the analyst's claims; the stub answered
only the loop's question with them.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from malspark.agents.composition import ResolvedAgent
from malspark.agents.configurable_analyst import ConfigurableAnalyst
from malspark.agents.prompt_fragments import no_tool_call_question
from malspark.pipeline.validation import FEEDBACK_PREAMBLE

BROKEN = "The sample looks interesting but I will not list findings."
VALID = (
    "CLAIM: The sample adds a Registry Run key so that it starts at logon.\n"
    "EVIDENCE: RegSetValueExW on CurrentVersion\\Run [ev_0001]\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1547.001\n"
    "---\n"
)


class _Path(BaseModel):
    path: str = ""


def _tool() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda path="": f"strings of {path}: none",
        name="strings",
        description="List the printable strings of a file.",
        args_schema=_Path,
        metadata={"malspark_read_only": True},
    )


class _Scripted(BaseChatModel):
    """Answers each turn from a script, tools bound or not, and records what it was sent."""

    script: list = []
    seen: list = []

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        self.seen.append(list(messages))
        text = self.script.pop(0) if self.script else ""
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    @property
    def _llm_type(self) -> str:
        return "scripted"


@pytest.mark.parametrize(
    ("tools", "question"),
    [([], FEEDBACK_PREAMBLE), ([_tool()], no_tool_call_question(["strings"]))],
    ids=["without_tools", "with_tools"],
)
def test_a_valid_second_answer_is_the_analyst_s_claims(tools: list[Any], question: str) -> None:
    llm = _Scripted(script=[BROKEN, VALID], seen=[])
    resolved = ResolvedAgent(
        key="triage",
        role="generic",
        prompt="You are a triage analyst.",
        tools=tools,
        static_provider_id=None,
        llm=llm,
    )
    analyst = ConfigurableAnalyst("triage", resolved, llm)

    isr = analyst.safe_analyze_isr("Target File: sample.exe")

    assert [(c.technique_id, c.confidence) for c in isr.claims] == [("T1547.001", 0.8)]
    assert isr.status is None
    # Asked exactly once more, its own question, over the broken answer.
    assert len(llm.seen) == 2
    assert any(BROKEN in str(m.content) for m in llm.seen[1])
    assert str(llm.seen[1][-1].content).startswith(question)
