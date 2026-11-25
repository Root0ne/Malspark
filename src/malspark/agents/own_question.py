"""One more question to an analyst about its own open questions, where it holds the tool they name.

An analyst that marked a question of its own answer as needing a sandbox
run, while holding the platform's tool that asks for a further detonation,
filed the question and stopped: nothing put the two side by side. Once its
stage answer is validated and settled, it is put one question over its own
loop conversation, with its tools: its own marked questions as it filed
them, the tool it holds by the name its tool list gives, how many further
detonations the job can still accept and the tool's own limits sentence.

Opened on platform facts only, never on words a model wrote:

* the answer holds an open question of the agent's own (not one a callee
  handed it) whose reason the core relation
  (``core.builtin_declarations.REQUEST_KIND_BY_OPEN_QUESTION_REASON``)
  relates to the declared kind of a tool the agent holds;
* the job's request record holds no request of this agent;
* the answer holds a claim or a written answer;
* not asked before in this job.

Where all of these hold and the job's ceiling is reached, the job's time
limit leaves no room for a detonation, the model cannot bind the tools, or
the loop's steps or time cannot hold a turn, it is not asked and the loop's
record says why. The question says the decision is the agent's and the
platform makes no further detonation of its own; it never says one is
needed. Its reply is recorded and never read as the answer: the answer in
force is the one validated before it. A request filed in it is on the job's
record like any other and takes the route every request takes.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from malspark.pipeline.events import safe_answer_text, safe_finding_value
from malspark.schemas.isr_models import OpenQuestion, open_question_line

# The ``what`` of the question's model calls, logs and records.
OWN_QUESTION_CALL = "own-question turn"
# The key of the loop's record the question's outcome is kept under.
OWN_QUESTION_RECORD = "own_question"

QUESTION_HEAD = "One more question, about your own answer; it is asked once."
QUESTION_MARKED = (
    "Your answer leaves {n} question(s) open that you marked as needing a sandbox run:"
)
QUESTION_HELD = (
    "You hold {tools}, which asks the platform for a further detonation of the sample with "
    "launch arguments; the job's record holds no request of yours. The job can accept {left} "
    "more detonation(s). {limits}"
)
RUN_STATE_LISTS = " The run state lists the job's detonations."
QUESTION_CLOSING = (
    "Whether any of these questions calls for a further detonation, and with which "
    "arguments, is yours to decide; the platform makes no further detonation of its own. "
    "This reply is recorded and is not read as your answer: you need not write your answer "
    "again. The tool's answer says when and how a detonation you request is read. Your tools "
    "are attached to this turn."
)

# Why a question whose opening facts held was not asked, on the loop's record.
NOT_ASKED = "not asked: {why}"
CEILING_REACHED = "the job's ceiling of {ceiling} detonations is reached"
TOOLS_NOT_BOUND = "its model could not bind its tools"
STEPS_SHORT = "{steps} step(s) of its loop were left, and a turn that may call a tool needs three"
TIME_SHORT = "{left:.0f}s of the loop's time were left, and an answer needs {needs:.0f}s"
WINDOW_SHORT = (
    "the conversation the question is sent in and an answer of {cap} tokens do not fit "
    "this model's window"
)
FILED_NONE = "asked; it filed no request"
NO_ANSWER = "asked; no answer came ({why})"


def _relation() -> dict[str, str]:
    from malspark.core.builtin_declarations import REQUEST_KIND_BY_OPEN_QUESTION_REASON

    return dict(REQUEST_KIND_BY_OPEN_QUESTION_REASON)


def marked_questions(questions: Iterable[Any]) -> list[OpenQuestion]:
    """The agent's own open questions whose reason the relation names, once each, in order.

    A question a callee handed over (``source`` set) is not the agent's own.
    """
    relation = _relation()
    out: list[OpenQuestion] = []
    for question in questions:
        if not isinstance(question, OpenQuestion) or question.source:
            continue
        if question.why_open in relation and question not in out:
            out.append(question)
    return out


def declared_kind(tool: Any) -> str:
    """The kind ``tool``'s live declaration states; ``""`` for a tool nothing declared."""
    from malspark.agents.tool_pinning import declared_facts_of

    return str(getattr(declared_facts_of(tool), "kind", "") or "")


def tools_serving(tools: Iterable[Any], questions: Sequence[OpenQuestion]) -> list[Any]:
    """The held tools whose declared kind the relation names for a reason of ``questions``."""
    relation = _relation()
    kinds = {relation[q.why_open] for q in questions if q.why_open in relation}
    return [tool for tool in tools or () if kinds and declared_kind(tool) in kinds]


def requests_of(container: Any, agent: str) -> list[Any]:
    """Every request on the job's record filed by ``agent``, whatever its state."""
    return [
        request
        for request in list(getattr(container, "detonation_requests", ()) or ())
        if str(getattr(request, "agent", "")) == str(agent)
    ]


def question_text(
    questions: Sequence[OpenQuestion],
    tools: Sequence[str],
    left: int,
    limits: str,
    *,
    run_state_lists: bool,
) -> str:
    """The question, built from the agent's own questions and the job's record."""
    lines = [
        QUESTION_HEAD,
        QUESTION_MARKED.format(n=len(questions)),
        *(f"- {open_question_line(q)}" for q in questions),
        QUESTION_HELD.format(tools=" and ".join(tools), left=int(left), limits=limits)
        + (RUN_STATE_LISTS if run_state_lists else ""),
        QUESTION_CLOSING,
    ]
    return "\n".join(lines)


def _filed_words(requests: Sequence[Any]) -> str:
    """``request r2 (accepted as d2)``, ``requests r2 (refused) and r3 (joined to d2)``."""
    named = []
    for request in requests:
        state = str(getattr(request, "state", "") or "")
        detonation = str(getattr(request, "detonation", "") or "")
        if detonation and state == "joined":
            said = f"{state} to {detonation}"
        elif detonation and state == "accepted":
            said = f"{state} as {detonation}"
        else:
            said = state
        named.append(f"{request.name} ({said})")
    noun = "request" if len(named) == 1 else "requests"
    return f"{noun} {' and '.join(named)}"


def outcome_words(filed: Sequence[Any], failed: str = "") -> str:
    """What became of a question that was asked: the requests it filed, and a failure."""
    if filed and failed:
        return f"asked; it filed {_filed_words(filed)}; no answer text came ({failed})"
    if filed:
        return f"asked; it filed {_filed_words(filed)}"
    if failed:
        return NO_ANSWER.format(why=failed)
    return FILED_NONE


def own_question_record(
    *,
    asked: bool,
    questions: int,
    tools: Sequence[str],
    left: int,
    outcome: str,
    requests: Sequence[str] = (),
    calls: int = 0,
    reply: str = "",
) -> dict[str, Any]:
    """The loop's record of the question: whether it was asked, about what, and what came of it.

    Names and counts, the outcome through the row rule and the reply as a
    whole model answer is kept (``events.safe_answer_text``).
    """
    record: dict[str, Any] = {
        "asked": bool(asked),
        "questions": int(questions),
        "tools": [safe_finding_value(name) for name in tools],
        "left": int(left),
        "outcome": safe_finding_value(outcome, whole=True),
        "requests": [safe_finding_value(name) for name in requests],
        "calls": int(calls),
    }
    if reply:
        record["reply"] = safe_answer_text(reply)
    return record
