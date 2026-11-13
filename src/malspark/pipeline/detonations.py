"""Carrying out the further detonations agents asked for, between the steps of the graph.

An agent asks for a further detonation with ``request_detonation``
(``providers.detonation_requests``); the tool only records the request. This
module carries accepted requests out, deterministically, on the entry of the
next step of the graph that has an agent reading the sandbox: before that
step's own work, through the one path every detonation takes
(``MalsparkApp.detonate_further``, set on the container as ``detonator``).
The graph gains no node: the step a detonation runs on entry of is recorded
on the detonation's record (``step``), with its own start, end and duration,
and announced with events of its own (``detonation_started`` and
``detonation_finished``), so a reader can take the detonation's time out of
the stage it ran inside.

When a detonation's report comes back, the platform reads it as the triage
pack reads the job's first (:func:`platform_reads`): the sandbox views and
the section index, recorded as the pack's entries that state the detonation
and its launch, and returned with the step's update, so what it observed
reaches the report whether or not an agent reads it, its items' ids
(``d2/proc:84``) are known to every citation check, and a stored run holds
them.

A pending detonation is claimed under the job's lock by the step that
carries it out, and its record is kept from that moment, running; a step
that enters while it is in flight waits for it and reads its result, so one
request is never submitted twice.

A detonation made after an analyst that reads the sandbox had its own turn
would never be read by it. So, on the debate's first negotiation entry,
after any request still pending was carried out, each such analyst whose own
turn began before a detonation returned its report gets one further turn
(:func:`further_turns`): its answer in force is revised with the new
detonations named, through the revision call a debate round makes. The turn
is recorded (``container.further_turns``) and announced
(``further_turn_started`` and ``further_turn_finished``).

A job without a request runs exactly as it did: no request is pending on
any entry, so nothing here runs and nothing is recorded or announced. The
step currently running is noted on the container on each entry
(``current_step``), which no output reads; the request tool reads it to say
whether a later step can still carry a request out.

A detonation is bounded by the job's time limit (``job_timeout``) and the
ceiling the tool already applied; one that fails or cannot run is recorded
with its reason, and never fails the run.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
import time
import typing
from dataclasses import dataclass
from typing import Any

from malspark.core.logger import logger
from malspark.pipeline.events import emit
from malspark.providers.detonation import AGENT_ORIGIN, DetonationRecord
from malspark.providers.detonation_requests import ACCEPTED, JOINED, REQUEST_KIND

DETONATION_STARTED = "detonation_started"
DETONATION_FINISHED = "detonation_finished"
FURTHER_TURN_STARTED = "further_turn_started"
FURTHER_TURN_FINISHED = "further_turn_finished"

# ---------------------------------------------------------------------------
# The steps of the run, and which of them read the sandbox
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One node of the graph, the stage it belongs to, and the agents it runs."""

    name: str
    stage: str
    kind: str
    agents: tuple[str, ...]
    parallel: bool = False
    # A debate's negotiation node (its revision node is the other).
    negotiation: bool = False


def steps_of(container: Any) -> list[Step]:
    """The graph's nodes in plan order (``pipeline.topology.plan``), each with its agents.

    An analysis node runs its agent; a debate's negotiation node runs its
    mediator, the verdict stage's agent, and its revision node the analysts
    (it is never where a detonation runs); the verdict and report nodes run
    their stage's agents. Barriers and the triage step run none.
    """
    from malspark.pipeline.topology import JOIN_SUFFIX, debate_nodes, plan

    try:
        profile = container.active_profile()
        reporting = bool(getattr(container.config.reporting, "enabled", True))
    except Exception:  # noqa: BLE001 — no profile read is no step known
        return []
    verdict_agents = tuple(
        agent for stage in profile.stages if stage.kind == "verdict" for agent in stage.agents
    )
    out: list[Step] = []
    for entry in plan(profile, reporting_enabled=reporting):
        stage = entry.stage
        parallel = stage.kind == "analysis" and stage.mode == "parallel"
        for node in entry.nodes:
            if node.endswith(JOIN_SUFFIX) or stage.kind == "triage":
                agents: tuple[str, ...] = ()
            elif stage.kind == "analysis":
                agents = tuple(a for a in stage.agents if node == f"{a}_analyst")
            elif stage.kind == "debate":
                negotiation, _revision = debate_nodes(profile, stage)
                agents = verdict_agents if node == negotiation else ()
            else:
                agents = tuple(stage.agents)
            out.append(
                Step(
                    node,
                    stage.key,
                    stage.kind,
                    agents,
                    parallel,
                    negotiation=stage.kind == "debate" and node == debate_nodes(profile, stage)[0],
                )
            )
    return out


def _stages_after(container: Any, key: str) -> set[str]:
    """The stages reachable from stage ``key`` in the graph (``depends_on``, the triage's roots)."""
    from malspark.pipeline.topology import adopted_roots, dependents

    try:
        profile = container.active_profile()
    except Exception:  # noqa: BLE001 — no profile read reaches nothing
        return set()
    triage, adopted = adopted_roots(list(profile.stages))
    reached: set[str] = set()
    todo = [key]
    while todo:
        here = todo.pop()
        onward = [s.key for s in dependents(profile, here)]
        if here == triage:
            onward += adopted
        for later in onward:
            if later not in reached:
                reached.add(later)
                todo.append(later)
    return reached


def _analysts_read(container: Any) -> bool:
    """Whether an analysis agent of the team reads the sandbox."""
    return any(
        reads_the_sandbox(container, agent)
        for step in steps_of(container)
        if step.kind == "analysis"
        for agent in step.agents
    )


def turns_ahead(container: Any) -> bool:
    """Whether the further turns are still to be given: no first negotiation has been entered."""
    return not getattr(container, "_further_turns_given", False)


def _carries(container: Any, step: Step) -> bool:
    """Whether a pending detonation is carried out on entry of ``step``.

    A step with an agent reading the sandbox; and a debate's negotiation
    while the further turns are still to be given and an analyst reads the
    sandbox, since a detonation carried out there is read in those turns.
    """
    if any(reads_the_sandbox(container, agent) for agent in step.agents):
        return True
    return step.negotiation and turns_ahead(container) and _analysts_read(container)


def carrying_steps(container: Any, current: str) -> list[Step]:
    """The steps reachable after ``current`` that carry a pending detonation out, in plan order.

    "After" is reachability in the graph: the steps of the stages that
    depend on ``current``'s stage, directly or through others; in a
    sequential analysis stage, its own later steps; a sibling of a parallel
    analysis stage runs beside ``current``, never after it. A revision's own
    debate negotiates again after it. An unknown ``current`` (no step noted)
    cannot be placed, and every carrying step of the run is answered.
    """
    steps = steps_of(container)
    at = next((i for i, step in enumerate(steps) if step.name == current), None)
    if at is None:
        candidates = steps
    else:
        here = steps[at]
        onward = _stages_after(container, here.stage)
        candidates = [
            step
            for index, step in enumerate(steps)
            if step.stage in onward
            or (step.stage == here.stage and index > at and not here.parallel)
        ]
        if here.kind == "debate" and not here.negotiation:
            # A revision: its debate's negotiation comes again after it.
            candidates = [s for s in steps if s.stage == here.stage and s.negotiation] + candidates
    return [step for step in candidates if _carries(container, step)]


def reads_the_sandbox(container: Any, agent: str) -> bool:
    """Whether ``agent`` reads the sandbox: by a tool of the sandbox source, or by its definition.

    An agent already built is read by its tools (an analyst may be handed
    the sandbox's item query by its class); one not built yet by whether its
    definition holds the sandbox source. A profile that withholds the
    sandbox tools reads none.
    """
    try:
        profile = container.active_profile()
        if getattr(profile, "exclude_sandbox_tools", False):
            return False
    except Exception:  # noqa: BLE001 — no profile read withholds nothing
        pass
    cache = getattr(container, "_agent_cache", None)
    built = cache.get(agent) if isinstance(cache, dict) else None
    if built is not None:
        from malspark.agents.tool_pinning import declared_source_of

        if any(declared_source_of(t) == "sandbox" for t in getattr(built, "tools", None) or ()):
            return True
    try:
        definition = container.config.agents.definitions.get(agent)
    except Exception:  # noqa: BLE001 — no definition read reads nothing
        return False
    return bool(definition) and any(ref.kind == "sandbox" for ref in definition.tools)


def later_reading_step(container: Any, current: str) -> str:
    """The first step after ``current`` that carries a pending detonation out; empty where none.

    :func:`carrying_steps`'s first.
    """
    found = carrying_steps(container, current)
    return found[0].name if found else ""


def further_turn_ahead(container: Any, current: str) -> bool:
    """Whether a further turn will still be given after ``current``: a first negotiation ahead."""
    return turns_ahead(container) and any(
        step.negotiation for step in carrying_steps(container, current)
    )


# The step the code running now belongs to, set on each node's entry
# (:func:`on_entry`): per context, so steps running at once never overwrite
# each other's, and a tool call made inside a step reads its own.
_CURRENT_STEP: contextvars.ContextVar[str] = contextvars.ContextVar(
    "malspark_detonation_step", default=""
)


def current_step(container: Any) -> str:
    """The step the calling code runs in; the container's note where no step set one here."""
    return _CURRENT_STEP.get() or str(getattr(container, "current_step", "") or "")


# ---------------------------------------------------------------------------
# The executor
# ---------------------------------------------------------------------------


def _pending(container: Any) -> list[tuple[str, list[Any]]]:
    """Each accepted detonation not carried out yet, with every request it carries out."""
    made = {r.name for r in getattr(container, "detonations", None) or ()}
    out: dict[str, list[Any]] = {}
    for request in getattr(container, "detonation_requests", None) or ():
        if request.state == ACCEPTED and request.detonation not in made:
            out.setdefault(request.detonation, [])
    for request in getattr(container, "detonation_requests", None) or ():
        if request.state in (ACCEPTED, JOINED) and request.detonation in out:
            out[request.detonation].append(request)
    return list(out.items())


def _fill_entry_ids(requests: list[Any], state: Any) -> None:
    """The ledger entry of the call that filed each request, located in the run's ledger."""
    import json

    from malspark.core.declared_reading import kind_of

    wanted = {r.name: r for r in requests if not r.entry_id}
    if not wanted:
        return
    for row in (state or {}).get("evidence_ledger") or ():
        if not isinstance(row, dict) or kind_of(row) != REQUEST_KIND:
            continue
        structured = row.get("structured")
        if not isinstance(structured, dict):
            try:
                structured = json.loads(str(row.get("output") or ""))
            except (TypeError, ValueError):
                continue
        name = structured.get("request") if isinstance(structured, dict) else None
        if isinstance(name, str) and name in wanted:
            wanted[name].entry_id = str(row.get("id") or "")


def _seconds_left(container: Any, state: Any) -> float | None:
    """What the job's time limit leaves; ``None`` where it sets none."""
    limit = getattr(getattr(container, "config", None), "job_timeout", None)
    started = (state or {}).get("run_started_at")
    if not isinstance(limit, int | float) or not isinstance(started, int | float):
        return None
    return float(limit) - (time.time() - float(started))


def _needs_seconds(container: Any) -> float | None:
    """How long one detonation may take: the job's provider's own timeout, where it sets one."""
    sandbox = getattr(getattr(container, "config", None), "sandbox", None)
    block = getattr(sandbox, str(getattr(sandbox, "provider", "") or ""), None)
    timeout = getattr(block, "timeout_seconds", None)
    if isinstance(timeout, int | float) and not isinstance(timeout, bool):
        return float(timeout)
    return None


def _stage_of_step(container: Any, step: str) -> str:
    """The key of the stage ``step`` belongs to; empty where no step of the run is named so."""
    return next((s.stage for s in steps_of(container) if s.name == step), "")


def platform_reads(container: Any, record: DetonationRecord, step: str) -> list[dict[str, Any]]:
    """The reads the triage pack makes of the job's first detonation, made of ``record``'s report.

    The pack's own sandbox views (processes, network, signatures, dropped
    files, channels) and the report's section index, each recorded as the
    pack's entry (agent ``pipeline``, so every agent may cite it and the
    report reads it as the pack's), its answer carrying the detonation, the
    launch and who asked (``DetonationRecord.stated``). Returned as ledger
    rows for the step's update, so a stored run holds them. ``[]`` for a
    detonation that returned no report.
    """
    from functools import partial

    from malspark.agents.evidence_recorder import EvidenceRecorder, result_text
    from malspark.analysis.sandbox_sections import SECTIONS_TOOL, section_index
    from malspark.pipeline.triage_pack import _SANDBOX_VIEWS, PACK_SOURCE, PIPELINE

    report = record.report
    if not isinstance(report, dict):
        return []

    def _held(getter: str) -> Any:
        try:
            return getattr(container, getter)()
        except Exception:  # noqa: BLE001 — a container that holds none records without it
            return None

    recorder = EvidenceRecorder(
        PIPELINE,
        counter=_held("get_evidence_counter"),
        stage=_stage_of_step(container, step),
        sink=getattr(container, "event_sink", None),
        corpus=_held("get_evidence_corpus"),
        spill=_held("get_evidence_spill"),
    )
    reads: list[tuple[str, Any]] = [
        *((tool, partial(view, report)) for tool, view in _SANDBOX_VIEWS.items()),
        (SECTIONS_TOOL, partial(section_index, report, record.normalised_by, record.name)),
    ]
    stated = record.stated()
    for tool, call in reads:
        started, wall_clock = time.monotonic(), time.time()
        try:
            value = call()
        except Exception as exc:  # noqa: BLE001 — a failed read is an entry, never a crash
            value = {"error": f"{type(exc).__name__}: {exc}"}
        answer = {**stated, **value} if isinstance(value, dict) else value
        error = answer.get("error") if isinstance(answer, dict) else None
        recorder.record(
            tool=tool,
            args={"detonation": record.name},
            server=PIPELINE,
            source=PACK_SOURCE,
            output=result_text(answer),
            ok=not error,
            error=str(error) if error else None,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
    return [entry.model_dump(mode="json") for entry in recorder.entries]


# One lock per container (``_claims``) guards the claim of a pending
# detonation: whose step carries it out, and which steps wait for it.
_CLAIM_LOCKS = threading.Lock()


def _claims(container: Any) -> tuple[threading.Lock, dict[str, threading.Event]]:
    """The job's claim lock, and its detonations in flight by name with the event their end sets."""
    with _CLAIM_LOCKS:
        lock = getattr(container, "_detonation_lock", None)
        if lock is None:
            lock = threading.Lock()
            container._detonation_lock = lock
        flight = getattr(container, "_detonations_in_flight", None)
        if flight is None:
            flight = {}
            container._detonations_in_flight = flight
    return lock, flight


def in_flight(container: Any) -> bool:
    """Whether a detonation of the job is being carried out now, by another step."""
    return bool(getattr(container, "_detonations_in_flight", None))


def _claim(
    container: Any, state: Any, step: str
) -> tuple[list[tuple[DetonationRecord, threading.Event]], list[tuple[str, threading.Event]]]:
    """Claim every pending detonation for ``step``, and name those another step is carrying out.

    Under the job's claim lock: each pending detonation's record is made and
    added to ``container.detonations`` at once, running, so no other step
    finds it pending; the claimant alone submits it. A detonation already in
    flight is waited for, never submitted again.
    """
    lock, flight = _claims(container)
    claimed: list[tuple[DetonationRecord, threading.Event]] = []
    with lock:
        waiting = list(flight.items())
        for name, requests in _pending(container):
            _fill_entry_ids(requests, state)
            record = DetonationRecord(
                ordinal=int(name[1:]),
                origin=AGENT_ORIGIN,
                arguments=requests[0].arguments,
                requested_by=[r.asker() for r in requests],
            )
            record.step = step
            record.running = True
            done = threading.Event()
            flight[name] = done
            container.detonations.append(record)
            claimed.append((record, done))
    return claimed, waiting


async def _detonate(container: Any, state: Any, step: str, record: DetonationRecord) -> None:
    """Carry ``record`` out through the job's detonator, bounded by the job's time limit."""
    name = record.name
    askers = list(dict.fromkeys(str(a.get("agent") or "") for a in record.requested_by))
    emit(
        container.event_sink,
        DETONATION_STARTED,
        {"detonation": name, "step": step, "requested_by": [a for a in askers if a]},
    )
    record.started_at = time.time()
    began = time.monotonic()
    left, needs = _seconds_left(container, state), _needs_seconds(container)
    detonator = getattr(container, "detonator", None)
    try:
        if left is not None and (left <= 0 or (needs is not None and left < needs)):
            record.failure = (
                "not run: the job's time limit leaves "
                f"{max(0, int(left))} seconds, and a detonation may take "
                f"{int(needs or 0)}"
            )
        elif detonator is None:
            record.failure = "not run: this run has no way to submit the sample again"
        else:
            try:
                await detonator(record)
            except Exception as exc:  # noqa: BLE001 — a failed detonation never fails the run
                logger.error("Further detonation %s failed: %s", name, type(exc).__name__)
                record.failure = record.failure or f"it failed: {type(exc).__name__}"
    finally:
        record.ended_at = time.time()
        record.duration_ms = int((time.monotonic() - began) * 1000)
        record.running = False
    logger.info(
        "Further detonation %s on entry of %s: %s in %d ms.",
        name,
        step,
        "reported" if record.reported else "no report",
        record.duration_ms,
    )
    emit(
        container.event_sink,
        DETONATION_FINISHED,
        {
            "detonation": name,
            "step": step,
            "reported": record.reported,
            "duration_ms": record.duration_ms,
            **({"failure": record.failure} if record.failure else {}),
        },
    )


async def carry_out(
    container: Any,
    state: Any,
    step: str,
    entries: list[dict[str, Any]] | None = None,
    waited: list[DetonationRecord] | None = None,
) -> list[DetonationRecord]:
    """Carry out every accepted detonation still pending, on the entry of ``step``.

    Each is one record, added to ``container.detonations`` in order when it
    is claimed (:func:`_claim`), with the agents that asked, the step, and
    its own start, end and duration. A detonation the job's time limit leaves
    no room for, or that no detonator can make, is recorded with the reason;
    one that fails is recorded with its failure. Never raises for a
    detonation. The platform's reads of each report that came back
    (:func:`platform_reads`) are added to ``entries``. A detonation another
    step is carrying out is waited for, and added to ``waited`` once it
    ended; its claimant returns it and its reads.
    """
    claimed, waiting = _claim(container, state, step)
    made: list[DetonationRecord] = []
    lock, flight = _claims(container)
    for record, done in claimed:
        try:
            await _detonate(container, state, step, record)
            if record.reported:
                record.platform_rows = platform_reads(container, record, step)
        finally:
            with lock:
                flight.pop(record.name, None)
            done.set()
        made.append(record)
        if entries is not None:
            entries.extend(record.platform_rows)
    for name, done in waiting:
        await asyncio.to_thread(done.wait)
        ended = next((r for r in container.detonations if r.name == name), None)
        if ended is not None and waited is not None:
            waited.append(ended)
    return made


# ---------------------------------------------------------------------------
# The further turn
# ---------------------------------------------------------------------------


def _readers_owed(container: Any, state: Any) -> dict[str, list[DetonationRecord]]:
    """Each analysis agent that reads the sandbox, ran, and has detonations it did not read."""
    reported = [r for r in getattr(container, "detonations", None) or () if r.ordinal > 1]
    reported = [r for r in reported if r.reported]
    if not reported:
        return {}
    answered = set((state or {}).get("reports") or {}) | set((state or {}).get("isr_reports") or {})
    owed: dict[str, list[DetonationRecord]] = {}
    for step in steps_of(container):
        if step.kind != "analysis":
            continue
        for agent in step.agents:
            if agent not in answered or not reads_the_sandbox(container, agent):
                continue
            seen = container.detonations_seen.get(agent, set())
            unread = [r for r in reported if r.name not in seen]
            if unread:
                owed[agent] = unread
    return owed


def _asker_words(asker: dict[str, Any]) -> str:
    """One asker as a further turn is told it: the agent, and the entries it cited."""
    cited = ", ".join(asker.get("cited_entries") or [])
    return f"{asker.get('agent') or 'an agent'}" + (f" citing {cited}" if cited else "")


def _directive(records: list[DetonationRecord]) -> str:
    """What a further turn is asked: the new detonations, each with who asked and why."""
    lines = []
    for record in records:
        askers = ", ".join(_asker_words(a) for a in record.requested_by)
        lines.append(
            f"- detonation {record.name}: launched with {record.arguments!r}, asked for by "
            f"{askers or 'an agent'}"
        )
    return (
        "Further detonations of the sample were made after your turn, with launch "
        "arguments an agent found:\n"
        + "\n".join(lines)
        + "\nRead them with the sandbox tools' detonation argument (the item ids of a "
        "later detonation are qualified by it, d2/proc:<pid>), and revise your answer "
        "with what they show. Say under which detonation each observation was made; "
        "keep every claim of your answer that still stands."
    )


def _merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Two updates of the state as one, each key by its channel's own reducer."""
    from malspark.pipeline.state import AnalysisState

    hints = typing.get_type_hints(AnalysisState, include_extras=True)
    out = dict(left)
    for key, value in right.items():
        reducer = None
        hint = hints.get(key)
        if hint is not None and typing.get_origin(hint) is typing.Annotated:
            reducer = next((m for m in hint.__metadata__ if callable(m)), None)
        if reducer is not None and key in out:
            out[key] = reducer(out[key], value)
        else:
            out[key] = value
    return out


async def further_turns(container: Any, state: Any, step: str) -> dict[str, Any]:
    """One further turn for each analyst owed one, as an update of the state; ``{}`` for none.

    The analyst revises its answer in force with the new detonations named
    (``BaseAnalyst.safe_revise_isr``, on the input its first turn read). An
    answer that decided something replaces the one in force
    (``revised_reports``, ``isr_reports``); one that decided nothing leaves it
    standing. The ledger entries, spend and validation rows the turn made are
    carried as a revision round carries them. Each turn is recorded on
    ``container.further_turns``.
    """
    from malspark.pipeline.nodes import (
        _budget_update,
        _merge_validation_update,
        _nudge_mode,
        _revision_input,
        _validation_update,
        brief_agent,
        revision_decided_nothing,
    )

    owed = _readers_owed(container, state)
    if not owed:
        return {}
    update: dict[str, Any] = {}
    reports = {
        **((state or {}).get("reports") or {}),
        **((state or {}).get("revised_reports") or {}),
    }
    for agent_name, records in owed.items():
        names = [r.name for r in records]
        emit(
            container.event_sink,
            FURTHER_TURN_STARTED,
            {"agent": agent_name, "detonations": names, "step": step},
        )
        began, started_at = time.monotonic(), time.time()
        outcome = "revised"
        try:
            got = await asyncio.to_thread(_revision_input, state, container, agent_name)
            if got.absent:
                outcome = f"not given: {got.absent}"
            else:
                agent = container.get_agent(agent_name)
                brief_agent(agent, state, container)
                text, isr = await asyncio.to_thread(
                    agent.safe_revise_isr,
                    got.text,
                    str(reports.get(agent_name, "") or ""),
                    {},
                    _directive(records),
                    0,
                )
                own: dict[str, Any] = {}
                ledger = [entry.model_dump(mode="json") for entry in agent.drain_evidence_entries()]
                if ledger:
                    own["evidence_ledger"] = ledger
                budget = _budget_update(agent, agent_name)
                if budget:
                    own.update(budget)
                validation: dict[str, Any] = {}
                _merge_validation_update(validation, _validation_update(agent, agent_name))
                own.update(validation)
                mode = _nudge_mode(agent)
                if mode:
                    own["nudge_retry_modes"] = {agent_name: mode}
                if not str(text or "").strip():
                    outcome = "no answer was written; the answer in force stands"
                elif revision_decided_nothing(isr):
                    outcome = "it decided nothing; the answer in force stands"
                else:
                    own["revised_reports"] = {agent_name: text}
                    own["isr_reports"] = {agent_name: isr}
                update = _merge(update, own)
        except Exception as exc:  # noqa: BLE001 — a failed turn leaves the answer in force
            logger.error("Further turn of %s failed: %s", agent_name, type(exc).__name__)
            outcome = f"it failed: {type(exc).__name__}; the answer in force stands"
        container.detonations_seen.setdefault(agent_name, set()).update(names)
        duration_ms = int((time.monotonic() - began) * 1000)
        container.further_turns.append(
            {
                "agent": agent_name,
                "detonations": names,
                "step": step,
                "outcome": outcome,
                "started_at": started_at,
                "ended_at": time.time(),
                "duration_ms": duration_ms,
            }
        )
        emit(
            container.event_sink,
            FURTHER_TURN_FINISHED,
            {
                "agent": agent_name,
                "detonations": names,
                "step": step,
                "outcome": outcome,
                "duration_ms": duration_ms,
            },
        )
    return update


# ---------------------------------------------------------------------------
# The entry of a step
# ---------------------------------------------------------------------------


def _note_seen(container: Any, agents: tuple[str, ...]) -> None:
    """The detonations with a report each agent's turn starting now can read."""
    held = {r.name for r in getattr(container, "detonations", None) or () if r.reported}
    for agent in agents:
        container.detonations_seen[agent] = set(held)


def _blocking(coroutine_of: Any) -> Any:
    """Run ``coroutine_of()`` to its end from synchronous code, in this thread's context.

    In a thread with no running loop it runs here; beside a running loop it
    runs on a thread of its own, the context copied, and this thread waits.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine_of())
    context = contextvars.copy_context()
    result: list[Any] = []
    error: list[BaseException] = []

    def _run() -> None:
        try:
            result.append(context.run(asyncio.run, coroutine_of()))
        except BaseException as exc:  # noqa: BLE001 — handed back to the caller
            error.append(exc)

    worker = threading.Thread(target=_run, name="malspark-detonation")
    worker.start()
    worker.join()
    if error:
        raise error[0]
    return result[0] if result else None


def on_entry(
    container: Any,
    name: str,
    fn: Any,
    *,
    analysis_agents: tuple[str, ...] = (),
    reading_agents: tuple[str, ...] = (),
    first_negotiation: bool = False,
) -> Any:
    """``fn``, entered through the detonation steps that belong before it.

    On every entry: the step is noted (``current_step``). Where the step has
    an agent reading the sandbox (``reading_agents``) and a request is
    pending, the pending detonations are carried out first (:func:`carry_out`).
    An analysis step notes what its agents can read. On the debate's first
    negotiation entry, after that, the further turns run (:func:`further_turns`)
    and the step's own work reads the state they updated; their update is
    returned with the step's. With nothing pending and no turn owed, ``fn``
    is called with the state it was given, as it always was.
    """

    def _wanted() -> bool:
        if not (_pending(container) or in_flight(container)):
            return False
        if any(reads_the_sandbox(container, agent) for agent in reading_agents):
            return True
        # A first negotiation still to give the further turns carries one out
        # for them, whether or not its mediator reads the sandbox.
        return first_negotiation and turns_ahead(container) and _analysts_read(container)

    async def _before(state: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        """What the step returns beside its own update, and what it only reads."""
        entries: list[dict[str, Any]] = []
        waited: list[DetonationRecord] = []
        if _wanted():
            await carry_out(container, state, name, entries, waited)
        # The platform's reads of each detonation that came back go out with
        # the step's update, and the step's own work (and a further turn)
        # reads the state holding them. A detonation another step carried
        # out is read here and returned by that step alone.
        extra: dict[str, Any] = {"evidence_ledger": entries} if entries else {}
        rows = [row for record in waited for row in record.platform_rows]
        seen: dict[str, Any] = {"evidence_ledger": rows} if rows else {}
        if first_negotiation and not getattr(container, "_further_turns_given", False):
            container._further_turns_given = True
            read = _merge(_merge(dict(state or {}), seen), extra)
            extra = _merge(extra, await further_turns(container, read, name))
        return extra, seen

    def _owed(state: Any) -> bool:
        return (
            first_negotiation
            and not getattr(container, "_further_turns_given", False)
            and bool(_readers_owed(container, state))
        )

    def _read(state: Any, extra: dict[str, Any], seen: dict[str, Any]) -> Any:
        return _merge(_merge(dict(state), seen), extra) if (extra or seen) else state

    if asyncio.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_entry(state: Any, *args: Any, **kwargs: Any) -> Any:
            container.current_step = name
            token = _CURRENT_STEP.set(name)
            try:
                return await _async_entry(state, *args, **kwargs)
            finally:
                _CURRENT_STEP.reset(token)

        async def _async_entry(state: Any, *args: Any, **kwargs: Any) -> Any:
            if not (_wanted() or _owed(state)):
                _note_seen(container, analysis_agents)
                return await fn(state, *args, **kwargs)
            extra, seen = await _before(state)
            _note_seen(container, analysis_agents)
            out = await fn(_read(state, extra, seen), *args, **kwargs)
            if not extra:
                return out
            return _merge(extra, out if isinstance(out, dict) else {})

        return async_entry

    @functools.wraps(fn)
    def sync_entry(state: Any, *args: Any, **kwargs: Any) -> Any:
        container.current_step = name
        token = _CURRENT_STEP.set(name)
        try:
            return _sync_entry(state, *args, **kwargs)
        finally:
            _CURRENT_STEP.reset(token)

    def _sync_entry(state: Any, *args: Any, **kwargs: Any) -> Any:
        if not (_wanted() or _owed(state)):
            _note_seen(container, analysis_agents)
            return fn(state, *args, **kwargs)
        extra, seen = _blocking(lambda: _before(state))
        _note_seen(container, analysis_agents)
        out = fn(_read(state, extra, seen), *args, **kwargs)
        if not extra:
            return out
        return _merge(extra, out if isinstance(out, dict) else {})

    return sync_entry


# ---------------------------------------------------------------------------
# The run's limitations
# ---------------------------------------------------------------------------


def further_detonation_reasons(container: Any) -> list[str]:
    """Each further detonation an agent asked for that was not carried out, or returned nothing.

    A request refused because no later step could read it, because the
    ceiling was reached, or because the job's sandbox could not detonate with
    it; an accepted one still pending when the verdict began; a detonation
    that returned no report, with why. A request the agent wrote wrongly (no
    reason, no cited entries, not one command line) or that names a
    detonation already made is its own answer, not a limitation. They are the
    run's limitations, never a reason to call the verdict tentative: the
    job's own detonation is what the run was asked for.
    """
    from malspark.providers.detonation_requests import REFUSED

    out: list[str] = []
    for request in getattr(container, "detonation_requests", None) or ():
        who = f"{request.agent or 'an agent'} ({request.name})"
        answer = str(request.answer or "")
        if request.state == REFUSED and (
            answer.startswith("it cannot be run at this point")
            or answer.startswith("the job's ceiling")
            or answer.startswith("no further detonation can be made")
        ):
            out.append(f"further detonation asked for by {who} was not carried out: {answer}")
    made = {r.name: r for r in getattr(container, "detonations", None) or () if r.ordinal > 1}
    for name, _requests in _pending(container):
        askers = ", ".join(dict.fromkeys(r.agent for r in _requests if r.agent)) or "an agent"
        out.append(
            f"further detonation {name} asked for by {askers} was accepted and not carried out "
            "before the verdict"
        )
    for record in made.values():
        if record.reported:
            continue
        askers = ", ".join(
            dict.fromkeys(str(a.get("agent") or "") for a in record.requested_by if a.get("agent"))
        )
        out.append(
            f"further detonation {record.name} asked for by {askers or 'an agent'} returned "
            "no sandbox report" + (f": {record.failure}" if record.failure else "")
        )
    return list(dict.fromkeys(out))


def later_sections(container: Any) -> dict[str, Any]:
    """Each later detonation's report read into sections, by its name: what a cited ``d2/…`` reads.

    A detonation that returned no report has none. ``{}`` for a job with only its own.
    """
    from malspark.analysis.sandbox_sections import Sections

    return {
        record.name: Sections(record.report, record.normalised_by, record.name)
        for record in getattr(container, "detonations", None) or ()
        if record.ordinal > 1 and record.reported
    }


def recorded_detonations(container: Any) -> dict[str, Any]:
    """What the run summary records of the job's further detonations; ``{}`` where none was asked.

    Every detonation (the job's own first, then each further one with who
    asked, at which step, citing what, and its start, end and duration),
    every request with its answer, and every further turn. A job in which no
    agent asked records nothing here, so its summary is the one it was.
    """
    requests = list(getattr(container, "detonation_requests", None) or ())
    if not requests:
        return {}
    return {
        "detonations": [r.public() for r in getattr(container, "detonations", None) or ()],
        "detonation_requests": [r.public() for r in requests],
        "further_turns": [dict(t) for t in getattr(container, "further_turns", None) or ()],
    }
