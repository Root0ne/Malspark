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

from pydantic import BaseModel, model_validator

from malspark.core.logger import logger
from malspark.providers.detonation import detonation_name
from malspark.schemas.evidence import unissued_ids
from malspark.utils.written_forms import pack_escaped

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
    "cite as cited_entries the ledger entries (ev_…) these arguments rest on, whichever call "
    "filed them (yours, another agent's or the platform's): at least one, each issued earlier "
    "in this run"
)
REFUSED_UNISSUED = "these cited entries were not issued earlier in this run: {ids}"
REFUSED_NOT_ONE_LINE = "the arguments are not one command line: {problem}"
REFUSED_CEILING = "the job's ceiling of {ceiling} detonations (its own included) is reached: {held}"
NO_LATER_STEP = (
    "it cannot be run at this point of the run: no later step of it has an agent that "
    "reads the sandbox, so nothing after this point could read the detonation"
)
# Said in an accepted answer only where a first negotiation, which gives the
# further turns, is still ahead of the step the request was filed in.
FURTHER_TURN_PROMISE = (
    "An analyst that reads the sandbox and had its turn before the detonation returned is "
    "given one further turn with it when the debate starts. "
)
REFUSED_EXISTS = (
    "detonation {name} was already launched with exactly these arguments; read it "
    "with the sandbox tools' detonation argument ({name})"
)

REFUSED_RUNNING = (
    "detonation {name} is being carried out now with exactly these arguments; read it with "
    "the sandbox tools' detonation argument ({name}) once it returns"
)
REFUSED_NO_REPORT = (
    "detonation {name} was already launched with exactly these arguments and returned no "
    "sandbox report, so it is not launched again"
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
    return unissued_ids(cited, _issued(container))


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
    problem = launch_arguments_problem(text)
    # What takes time is read before the lock: whether the provider can pass
    # the arguments (a launcher builds and hashes the sample's archive), the
    # stage, the later step. What other requests change (the detonations
    # held, the ceiling) is read under it.
    stage = stage_of(container, str(agent or ""))
    # Whether the cited ids were issued is decided under the lock alone: an id
    # issued while this request is read must not leave these unread.
    checked = not (problem or not why or not cited)
    cannot = _cannot_detonate(container, text) if checked else ""
    later, turn = _later_step(container) if checked else ("", False)
    # A request joined to an accepted one is promised the further turn only
    # where the asker is one of the agents the turns are given to.
    joiner_turn = turn and _given_further_turns(container, str(agent or ""))
    with _LOCK:
        requests: list[DetonationRequest] = container.detonation_requests
        request = DetonationRequest(
            number=len(requests) + 1,
            agent=str(agent or ""),
            stage=stage,
            arguments=text,
            reason=why,
            cited_entries=cited,
        )
        requests.append(request)
        unissued = _unissued(container, cited)
        held = _detonations_held(container)
        records = {r.name: r for r in getattr(container, "detonations", ()) or ()}
        same = next((name for name, args in held if args == text), "")
        if problem:
            request.answer = REFUSED_NOT_ONE_LINE.format(problem=problem)
        elif not why:
            request.answer = REFUSED_NO_REASON
        elif not cited:
            request.answer = REFUSED_NO_CITATIONS
        elif unissued:
            request.answer = REFUSED_UNISSUED.format(ids=", ".join(unissued))
        elif same and same in records:
            request.detonation = same
            request.answer = _made_answer(records[same])
        elif same:
            pending = next(r for r in requests if r.state == ACCEPTED and r.detonation == same)
            request.state = JOINED
            request.detonation = same
            request.answer = (
                f"joined to {same}, already accepted with exactly these arguments "
                f"(asked for by {pending.agent or 'another agent'}, {pending.name}); "
                "it is one detonation, and its record names every agent that asked; "
                + _carried_out_and_read(same, joiner_turn)
            )
        else:
            ceiling = ceiling_of(container)
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
                    f"that has an agent reading the sandbox ({later}). "
                    + (FURTHER_TURN_PROMISE if turn else "")
                    + _READ_IT.format(name=request.detonation)
                )
    logger.info(
        "Detonation request %s by %s: %s%s",
        request.name,
        request.agent or "an agent",
        request.state,
        f" ({request.detonation})" if request.detonation else "",
    )
    return request


def _made_answer(record: Any) -> str:
    """The answer to a request for a detonation already made with exactly its arguments.

    Worded by how that detonation stands: it returned a report (read it),
    it is being carried out now (read it once it returns), or it returned
    none (it is not launched again).
    """
    name = str(record.name)
    if getattr(record, "reported", False):
        return REFUSED_EXISTS.format(name=name)
    if getattr(record, "running", False):
        return REFUSED_RUNNING.format(name=name)
    failure = str(getattr(record, "failure", "") or "")
    return REFUSED_NO_REPORT.format(name=name) + (f": {failure}" if failure else "")


# How a detonation an answer names is read, as the accepted answer ends.
_READ_IT = "Read it with the sandbox tools' detonation argument ({name})."


def _carried_out_and_read(name: str, turn: bool) -> str:
    """When and how the accepted detonation a joined request names is read, in the accepted
    answer's own clauses: when it is carried out, the further turn where ``turn``, and the
    read. No step is named: on a team whose steps branch, the step the joining agent would
    reach next is not always the one that carries the detonation out.
    """
    return (
        "it is carried out on entry of the next step of the run that has an agent reading "
        "the sandbox. " + (FURTHER_TURN_PROMISE if turn else "") + _READ_IT.format(name=name)
    )


def _given_further_turns(container: Any, agent: str) -> bool:
    """Whether ``agent`` is of the agents the further turns are given to; False where unread."""
    from malspark.pipeline.detonations import given_further_turns

    try:
        return given_further_turns(container, agent)
    except Exception as exc:  # noqa: BLE001 — an agent that cannot be placed is promised nothing
        logger.warning("No further turn could be read for %s (%s).", agent or "an agent", exc)
        return False


def _later_step(container: Any) -> tuple[str, bool]:
    """The next step after the calling one that can carry a request out, and whether a further
    turn is still ahead of it; ``("", False)`` where none can.
    """
    from malspark.pipeline.detonations import current_step, further_turn_ahead, later_reading_step

    try:
        here = current_step(container)
        return later_reading_step(container, here), further_turn_ahead(container, here)
    except Exception as exc:  # noqa: BLE001 — a step that cannot be read carries nothing
        logger.warning("No later step could be read for a detonation request (%s).", exc)
        return "", False


def detonations_left(container: Any) -> int:
    """How many more detonations the job can accept now: its ceiling less every one held."""
    with _LOCK:
        return max(0, ceiling_of(container) - len(_detonations_held(container)))


# The run-state line of the job's detonations (:func:`detonations_line`).
DETONATIONS_LINE = (
    "detonations: the job can accept {left} more (its ceiling is {ceiling}, the job's own "
    "included); {items}"
)
# A further detonation's launch, where the sandbox was handed the sample
# without the arguments asked for.
SUBMITTED_WITHOUT_ARGUMENTS = "submitted without its arguments (the provider did not pass them)"


def _askers(requests: list[Any]) -> str:
    """``dynamic (r1) and network (r3)``: each agent that asked, with its request."""
    named = []
    for asker in requests:
        agent = pack_escaped(str(asker.get("agent") or "an agent"))
        request = pack_escaped(str(asker.get("request") or ""))
        named.append(f"{agent} ({request})" if request else agent)
    return " and ".join(named)


def _asked_with(name: str, askers: list[Any], arguments: str, *, reads: bool) -> str:
    """``asked for by … with `<launch text>```, with the escape hint where it is shown changed.

    The hint names where the exact text is (the ``launched_with`` of a read
    of the detonation), so it is said only where such reads exist.
    """
    from malspark.pipeline.triage_pack import LAUNCH_SHOWN_ESCAPED
    from malspark.reporting.detonation_marks import launch_text

    shown = launch_text(arguments)
    hint = f" {LAUNCH_SHOWN_ESCAPED.format(name=name)}" if reads and shown != arguments else ""
    return f"asked for by {_askers(askers)} with `{shown}`{hint}"


def _state_words(record: Any) -> str:
    """How a detonation with a record stands, from that record alone."""
    failure = str(getattr(record, "failure", "") or "")
    said = f" ({pack_escaped(failure)})" if failure else ""
    if getattr(record, "running", False):
        return "being carried out now"
    if getattr(record, "reported", False):
        return "made, reported"
    if getattr(record, "submit_returned", False):
        return f"submitted, no report{said}"
    return f"not made{said}"


def launch_honoured(record: Any) -> bool:
    """Whether the run records ``record``'s launch as honoured by the sandbox."""
    launch = getattr(record, "launch", None)
    return isinstance(launch, dict) and launch.get("honoured") is True


def launch_words(record: Any, *, reads: bool = False) -> str:
    """How a submitted detonation was launched, from its record; one wording on every surface.

    "launched with" its launch text only where the run records the launch as
    honoured, :data:`SUBMITTED_WITHOUT_ARGUMENTS` where it does not, and
    "launched without arguments" where none were asked. ``reads``: the
    detonation has reads holding its exact text, so an escaped launch text
    carries the pack's hint.
    """
    from malspark.pipeline.triage_pack import LAUNCH_SHOWN_ESCAPED
    from malspark.reporting.detonation_marks import launch_text

    arguments = str(getattr(record, "arguments", "") or "")
    if not arguments:
        return "launched without arguments"
    if not launch_honoured(record):
        return SUBMITTED_WITHOUT_ARGUMENTS
    shown = launch_text(arguments)
    hint = (
        f" {LAUNCH_SHOWN_ESCAPED.format(name=record.name)}" if reads and shown != arguments else ""
    )
    return f"launched with `{shown}`{hint}"


def asked_launch_words(record: Any, *, reads: bool, submitted: bool = True) -> str:
    """``asked for by … with `<launch text>```, then, where ``submitted`` and the run does not
    record the launch as honoured, :data:`SUBMITTED_WITHOUT_ARGUMENTS`: a further detonation's
    launch as the run-state line and a further turn word it. ``reads`` as for
    :func:`launch_words`.
    """
    askers = [a for a in getattr(record, "requested_by", ()) or () if isinstance(a, dict)]
    arguments = str(getattr(record, "arguments", "") or "")
    words = _asked_with(str(record.name), askers, arguments, reads=reads)
    if submitted and not launch_honoured(record):
        words += f", {SUBMITTED_WITHOUT_ARGUMENTS}"
    return words


def _record_item(record: Any) -> str:
    """One detonation the job holds a record of, as the run-state line names it."""
    from malspark.providers.detonation import JOB_ORIGIN

    submitted = bool(getattr(record, "submit_returned", False))
    if getattr(record, "origin", JOB_ORIGIN) == JOB_ORIGIN:
        who = "the job's own"
        if submitted:
            who += f", {launch_words(record)}"
    else:
        reads = bool(getattr(record, "reported", False))
        who = asked_launch_words(record, reads=reads, submitted=submitted)
    return f"{record.name}, {who}: {_state_words(record)}"


def detonations_line(container: Any) -> str:
    """The job's detonations as one run-state line, from its records as they stand now.

    Every detonation the job holds, in order, by the rule the ceiling counts
    them by (:func:`_detonations_held`): each made one by its record (who
    asked for it and with what launch text, and how it stands: made and
    reported, submitted with no report, not made, being carried out now),
    the job's own with no record yet as such, and each accepted one not
    carried out yet with every request it carries out. "launched with" is
    said only where the sandbox honoured the launch. The launch text is
    written as every surface writes it (``detonation_marks.launch_text``).
    States no time, no promise and no instruction.
    """
    with _LOCK:
        records = list(getattr(container, "detonations", ()) or ())
        requests = list(getattr(container, "detonation_requests", ()) or ())
        ceiling = ceiling_of(container)
        held = _detonations_held(container)
    items = [_record_item(record) for record in records]
    if not records:
        items.append("d1, the job's own: no record yet")
    named = {str(record.name) for record in records} | ({"d1"} if not records else set())
    for request in requests:
        name = str(request.detonation or "")
        if request.state != ACCEPTED or not name or name in named:
            continue
        named.add(name)
        askers = [
            r.asker() for r in requests if r.state in (ACCEPTED, JOINED) and r.detonation == name
        ]
        items.append(
            f"{name}, {_asked_with(name, askers, request.arguments, reads=False)}: "
            "accepted, not carried out yet"
        )
    return DETONATIONS_LINE.format(
        left=max(0, ceiling - len(held)), ceiling=ceiling, items="; ".join(items)
    )


def limits_sentence(container: Any) -> str:
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


def offered(container: Any, agent: str | None = None) -> bool:
    """Whether the job can ever carry ``agent``'s request out, so the tool is handed to it at all.

    Not in mock mode, not without a sample file, not where the ceiling is one
    (the job's own detonation fills it), and only where the job's provider
    detonates and can pass launch arguments in some way (a field of its own,
    or a generated launcher). For a named agent, only where a step that
    carries a request out is reachable after its own stage's steps in the
    team (``pipeline.detonations.carrying_steps``): read from the team's
    shape, never from the agent's name. A job whose sandbox cannot, or an
    agent no later step could serve, is handed no tool that could only refuse.
    """
    if getattr(container, "is_mock", False) or not getattr(container, "sample_path", None):
        return False
    if ceiling_of(container) <= 1:
        return False
    if agent and not _served_after(container, agent):
        return False
    try:
        caps = container.get_sandbox_provider().capabilities
    except Exception:  # noqa: BLE001 — no provider offers nothing
        return False
    if not getattr(caps, "can_submit", False):
        return False
    passes = getattr(caps, "can_pass_launch_arguments", False)
    return bool(passes or getattr(caps, "launcher", None))


def _served_after(container: Any, agent: str) -> bool:
    """Whether a step reachable after ``agent``'s own stage can carry its request out."""
    from malspark.pipeline.detonations import carrying_steps, steps_of

    try:
        stage = stage_of(container, agent)
        own = [s for s in steps_of(container) if s.stage == stage]
        mine = [s for s in own if agent in s.agents] or own
        if not mine:
            # An agent no stage of the team lists is placed nowhere: it is
            # served by any carrying step of the run.
            return bool(carrying_steps(container, ""))
        return any(carrying_steps(container, step.name) for step in mine)
    except Exception as exc:  # noqa: BLE001 — a team that cannot be read offers nothing
        logger.warning("No later step could be read for %s's requests (%s).", agent, exc)
        return False


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
        "Ask for a further detonation of the sample, started with launch arguments (a "
        "password the sample checks, an installer switch). "
        "``arguments`` is one command line as typed after the program's name; "
        "``reason`` says why; ``cited_entries`` are the ledger entries (ev_…) the "
        "arguments rest on, whichever call filed them (yours, another agent's or the "
        "platform's): the platform checks that at least one is given and that each was "
        "issued earlier in this run, and nothing else about them. "
        "The tool detonates nothing itself: it answers whether the "
        "request is accepted, as which detonation (d2, d3…) and when it will be run, "
        "joined to an identical pending one, or refused and why. A request is carried out "
        "on entry of the next step of the run that has an agent reading the sandbox, so it "
        "can be made while such a step is still ahead (during the analysis and the debate); "
        "one made after the last of them began is refused as too late. A detonation "
        "already made is compared on its exact launch text: the pack shows a later "
        "detonation's launch text escaped, and the exact text is the launched_with of any "
        "read of that detonation. " + limits_sentence(container)
    )
    return StructuredTool.from_function(
        func=_request,
        name=REQUEST_TOOL,
        description=description,
        args_schema=RequestArguments,
        infer_schema=False,
    )


class RequestArguments(BaseModel):
    """The arguments of one request for a further detonation.

    ``cited_entries`` has no default, so the schema a model reads marks it
    required: a request that cites no entry is refused
    (:data:`REFUSED_NO_CITATIONS`). A call that leaves it out or sends
    ``null`` all the same is read as citing none, so it is refused in the
    tool's own words and filed on the job's record like every other request.
    """

    arguments: str
    reason: str
    cited_entries: list[str] | str

    @model_validator(mode="before")
    @classmethod
    def _none_cited(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("cited_entries") is None:
            return {**data, "cited_entries": ""}
        return data
