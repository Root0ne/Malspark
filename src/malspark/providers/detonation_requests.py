"""An agent asks for a further detonation of the sample, with launch arguments it found.

Some samples show their behaviour only when started with an argument an
analyst has to find: a locker's password held in the binary, an installer's
switch. The operator hands the run nothing the agents could find themselves,
so the agent that finds it asks for a further detonation with it, through the
``request_detonation`` tool of the in-process ``sandbox`` source: any agent
whose definition holds that source may ask, and no agent is named here.

The tool detonates nothing. It records the request
(:class:`DetonationRequest`) and answers what will happen: accepted, as which
detonation (``d2``, ``d3``…), carried out by the platform between stages
(``providers.detonation``); joined to an identical one already accepted (one
argument set is one detonation, and its record names every agent that asked);
or refused, with the reason: the job cannot detonate again, the provider
cannot pass the arguments in any way, the value is not one command line, the
reason or the cited entries are missing or name entries the run never issued,
the ceiling is reached, or an identical detonation already exists, which is
named. Every check is code; the words the agent sends are never run here.

The ceiling (``sandbox.max_detonations_per_job``) counts the job's own
detonation, and the tool's description states it, with the time each
detonation takes and that each submission is disclosed to the sandbox, as the
sandbox's physical limits.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from malspark.core.logger import logger
from malspark.providers.detonation import detonation_name

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

REQUEST_TOOL = "request_detonation"
# The kind the tool declares (``core.builtin_declarations``): what its
# entries are read by.
REQUEST_KIND = "detonation_request"

# A request's state as the tool answered it.
ACCEPTED = "accepted"
JOINED = "joined"
REFUSED = "refused"

# What the tool answers, by the check that refused it.
REFUSED_NO_REASON = "give the reason the sample should be detonated with these arguments"
REFUSED_NO_CITATIONS = (
    "cite the ledger entries (ev_…) that led you to these arguments, as cited_entries"
)
REFUSED_UNISSUED = "these cited entries were not issued earlier in this run: {ids}"
REFUSED_NOT_ONE_LINE = "the arguments are not one command line: {problem}"
REFUSED_CEILING = "the job's ceiling of {ceiling} detonations (its own included) is reached: {held}"
NO_LATER_STEP = (
    "it cannot be run at this point of the run: no later step of it has an agent that "
    "reads the sandbox, so nothing after this point could read the detonation"
)
REFUSED_EXISTS = (
    "detonation {name} was already launched with exactly these arguments; read it "
    "with the sandbox tools' detonation argument ({name})"
)

_CITATION_RE = re.compile(r"ev_(\d{1,9})", re.IGNORECASE)

# One lock for every job's requests: a request is filed in microseconds, and
# parallel analysts run their tool calls on threads against one container.
_LOCK = threading.Lock()


@dataclass
class DetonationRequest:
    """One request for a further detonation, as filed and as answered.

    ``number`` counts the job's requests from 1 (``r1``). ``detonation`` is
    the detonation that carries it out (``d2``…), set where it was accepted
    or joined to one; ``state`` is how the tool answered it, ``answer`` its
    words. ``entry_id`` is the ledger entry of the call that filed it, filled
    in once the call is recorded.
    """

    number: int
    agent: str
    stage: str
    arguments: str
    reason: str
    cited_entries: list[str] = field(default_factory=list)
    state: str = REFUSED
    answer: str = ""
    detonation: str = ""
    entry_id: str = ""

    @property
    def name(self) -> str:
        return f"r{self.number}"

    def asker(self) -> dict[str, Any]:
        """Who asked, as a detonation's record names them."""
        return {
            "request": self.name,
            "agent": self.agent,
            "stage": self.stage,
            "entry_id": self.entry_id,
            "cited_entries": list(self.cited_entries),
            "reason": self.reason,
        }

    def public(self) -> dict[str, Any]:
        """The request as the run records it."""
        return {
            "request": self.name,
            "agent": self.agent,
            "stage": self.stage,
            "arguments": self.arguments,
            "reason": self.reason,
            "cited_entries": list(self.cited_entries),
            "state": self.state,
            "detonation": self.detonation,
            "answer": self.answer,
            "entry_id": self.entry_id,
        }


def _cited(value: Any) -> list[str]:
    """The entry ids ``value`` names, in the counter's spelling, once each, in order."""
    text = " ".join(str(v) for v in value) if isinstance(value, list | tuple) else str(value or "")
    return list(dict.fromkeys(f"ev_{int(n):04d}" for n in _CITATION_RE.findall(text)))


def _issued(container: Any) -> int:
    """How many entry ids the job has issued so far; 0 where it cannot say."""
    try:
        return int(container.get_evidence_counter().issued)
    except Exception:  # noqa: BLE001 — an unknown count issues nothing
        return 0


def _unissued(container: Any, cited: list[str]) -> list[str]:
    """The cited ids the job never issued before this call."""
    issued = _issued(container)
    return [i for i in cited if not 1 <= int(i.removeprefix("ev_")) <= issued]


def stage_of(container: Any, agent: str) -> str:
    """The key of the stage ``agent`` runs in, by the job's profile; empty where none lists it."""
    try:
        profile = container.active_profile()
    except Exception:  # noqa: BLE001 — a stage that cannot be named is recorded as unnamed
        return ""
    for stage in getattr(profile, "stages", ()) or ():
        if agent and agent in (getattr(stage, "agents", ()) or ()):
            return str(stage.key)
    return ""


def ceiling_of(container: Any) -> int:
    """The job's ceiling on detonations, its own included."""
    try:
        return int(container.config.sandbox.max_detonations_per_job)
    except (AttributeError, TypeError, ValueError):
        return 4


def _launched_with(record: Any) -> str:
    """The arguments a made detonation carried: its own, where its provider passed them."""
    launch = getattr(record, "launch", None)
    if isinstance(launch, dict) and launch.get("honoured") is True:
        return str(record.arguments or "")
    return ""


def _detonations_held(container: Any) -> list[tuple[str, str]]:
    """``(name, arguments)`` of every detonation the job made or accepted, in order."""
    held = [(r.name, _launched_with(r)) for r in getattr(container, "detonations", ()) or ()]
    if not held:
        # The job's own detonation counts whether or not its record is kept yet.
        held = [("d1", "")]
    names = {name for name, _ in held}
    for request in getattr(container, "detonation_requests", ()) or ():
        if request.state == ACCEPTED and request.detonation not in names:
            held.append((request.detonation, request.arguments))
            names.add(request.detonation)
    return held


def _cannot_detonate(container: Any, arguments: str) -> str:
    """Why the job cannot detonate the sample with ``arguments``; empty where it can."""
    from malspark.providers.submission import answer_of

    if getattr(container, "is_mock", False):
        return "the run is in mock mode and submits nothing to a sandbox"
    sample_path = getattr(container, "sample_path", None)
    if not sample_path:
        return "the job has no sample file to submit"
    try:
        provider = container.get_sandbox_provider()
    except Exception as exc:  # noqa: BLE001 — no provider is a reason, never a failure
        return f"no sandbox provider could be set up ({type(exc).__name__})"
    caps = getattr(provider, "capabilities", None)
    if caps is not None and not getattr(caps, "can_submit", True):
        return f"the {provider.id} provider detonates nothing (it reads an attached report)"
    answer = answer_of(provider, arguments, sample_path)
    if not answer.honoured:
        return answer.note or f"the {provider.id} provider cannot pass launch arguments"
    return ""


def file_request(
    container: Any,
    *,
    agent: str,
    arguments: Any,
    reason: Any,
    cited_entries: Any,
) -> DetonationRequest:
    """Check one request and record it on ``container.detonation_requests``, answered.

    The checks, in order: the value is one command line
    (``launch_arguments_problem``); a reason is given; entries are cited and
    every one was issued earlier in the run; an identical detonation was not
    already made (it is named) and, where one is accepted and pending, the
    request joins it; the job can detonate again and its provider passes the
    arguments; the ceiling is not reached. Never raises.
    """
    from malspark.providers.submission import launch_arguments_problem

    text = arguments if isinstance(arguments, str) else str(arguments or "")
    why = str(reason or "").strip()
    cited = _cited(cited_entries)
    with _LOCK:
        requests: list[DetonationRequest] = container.detonation_requests
        request = DetonationRequest(
            number=len(requests) + 1,
            agent=str(agent or ""),
            stage=stage_of(container, str(agent or "")),
            arguments=text,
            reason=why,
            cited_entries=cited,
        )
        requests.append(request)
        problem = launch_arguments_problem(text)
        unissued = _unissued(container, cited)
        held = _detonations_held(container)
        made = {r.name for r in getattr(container, "detonations", ()) or ()}
        same = next((name for name, args in held if args == text), "")
        if problem:
            request.answer = REFUSED_NOT_ONE_LINE.format(problem=problem)
        elif not why:
            request.answer = REFUSED_NO_REASON
        elif not cited:
            request.answer = REFUSED_NO_CITATIONS
        elif unissued:
            request.answer = REFUSED_UNISSUED.format(ids=", ".join(unissued))
        elif same and same in made:
            request.detonation = same
            request.answer = REFUSED_EXISTS.format(name=same)
        elif same:
            pending = next(r for r in requests if r.state == ACCEPTED and r.detonation == same)
            request.state = JOINED
            request.detonation = same
            request.answer = (
                f"joined to {same}, already accepted with exactly these arguments "
                f"(asked for by {pending.agent or 'another agent'}, {pending.name}); "
                "it is one detonation, and its record names every agent that asked"
            )
        else:
            cannot = _cannot_detonate(container, text)
            ceiling = ceiling_of(container)
            later = _later_step(container)
            if cannot:
                request.answer = f"no further detonation can be made: {cannot}"
            elif not later:
                request.answer = NO_LATER_STEP
            elif len(held) >= ceiling:
                listed = ", ".join(
                    f"{name} ({'with ' + repr(args) if args else 'without arguments'})"
                    for name, args in held
                )
                request.answer = REFUSED_CEILING.format(ceiling=ceiling, held=listed)
            else:
                request.state = ACCEPTED
                request.detonation = detonation_name(len(held) + 1)
                request.answer = (
                    f"accepted as detonation {request.detonation}: the platform submits "
                    "the sample with these arguments on entry of the next step of the run "
                    f"that has an agent reading the sandbox ({later}). An analyst that "
                    "reads the sandbox and had its turn before the detonation returned is "
                    "given one further turn with it when the debate starts. Read it with "
                    f"the sandbox tools' detonation argument ({request.detonation})."
                )
    logger.info(
        "Detonation request %s by %s: %s%s",
        request.name,
        request.agent or "an agent",
        request.state,
        f" ({request.detonation})" if request.detonation else "",
    )
    return request


def _later_step(container: Any) -> str:
    """The next step after the one running that can carry a request out; empty where none."""
    from malspark.pipeline.detonations import later_reading_step

    try:
        return later_reading_step(container, str(getattr(container, "current_step", "") or ""))
    except Exception as exc:  # noqa: BLE001 — a step that cannot be read carries nothing
        logger.warning("No later step could be read for a detonation request (%s).", exc)
        return ""


def _limits(container: Any) -> str:
    """The physical limits the tool's description states, from the job's settings."""
    ceiling = ceiling_of(container)
    sandbox = getattr(getattr(container, "config", None), "sandbox", None)
    provider = str(getattr(sandbox, "provider", "") or "")
    block = getattr(sandbox, provider, None) if provider else None
    timeout = getattr(block, "timeout_seconds", None)
    took = (
        f"each one takes up to {int(timeout)} seconds of the {provider} sandbox's time"
        if isinstance(timeout, int | float) and not isinstance(timeout, bool)
        else "each one takes the sandbox's own detonation time, minutes"
    )
    return (
        f"Limits of the sandbox: at most {ceiling} detonations per job, the job's own "
        f"included; {took} and its quota. Each submission sends the sample to the "
        "sandbox, is disclosed in the run's record, and may be public on that service. "
        "The arguments are handed to the sandbox verbatim as the program's command "
        "line and are never run on this machine."
    )


def offered(container: Any) -> bool:
    """Whether the job can ever carry a request out, so the tool is handed to agents at all.

    Not in mock mode, not without a sample file, and only where the job's
    provider detonates and can pass launch arguments in some way (a field of
    its own, or a generated launcher). A job whose sandbox cannot is handed
    no tool that could only refuse.
    """
    if getattr(container, "is_mock", False) or not getattr(container, "sample_path", None):
        return False
    try:
        caps = container.get_sandbox_provider().capabilities
    except Exception:  # noqa: BLE001 — no provider offers nothing
        return False
    if not getattr(caps, "can_submit", False):
        return False
    passes = getattr(caps, "can_pass_launch_arguments", False)
    return bool(passes or getattr(caps, "launcher", None))


def request_tool(container: Any) -> BaseTool:
    """The ``request_detonation`` tool, filing requests on ``container``."""
    from langchain_core.tools import StructuredTool

    def _request(
        arguments: str, reason: str, cited_entries: list[str] | str | None = None
    ) -> dict[str, Any]:
        from malspark.llm.context_window import current_agent

        request = file_request(
            container,
            agent=current_agent(),
            arguments=arguments,
            reason=reason,
            cited_entries=cited_entries,
        )
        answer: dict[str, Any] = {
            "request": request.name,
            "state": request.state,
            "answer": request.answer,
        }
        if request.detonation:
            answer["detonation"] = request.detonation
        return answer

    description = (
        "Ask for a further detonation of the sample, started with launch arguments you "
        "found by your own analysis (a password the sample checks, an installer switch). "
        "``arguments`` is one command line as typed after the program's name; "
        "``reason`` says why; ``cited_entries`` are the ledger entries (ev_…) that led "
        "you to the arguments. The tool detonates nothing itself: it answers whether the "
        "request is accepted, as which detonation (d2, d3…) and when it will be run, "
        "joined to an identical pending one, or refused and why. A request is carried out "
        "on entry of the next step of the run that has an agent reading the sandbox, so it "
        "can be made while such a step is still ahead (during the analysis and the debate); "
        "one made after the last of them began is refused as too late. " + _limits(container)
    )
    return StructuredTool.from_function(func=_request, name=REQUEST_TOOL, description=description)
