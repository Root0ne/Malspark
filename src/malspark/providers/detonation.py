"""One detonation of the job's sample: what was asked, what was sent, and what came back.

A job's sample is detonated once before the agents start (the job's own
detonation, ``d1``), through ``MalsparkApp.detonate``. Every detonation is
made through that one path and kept as one :class:`DetonationRecord`: its
ordinal, the launch arguments it asked for and what became of them, the
upload rows the disclosure block reads, the task the sandbox gave it, the
report it returned or why it returned none, the reader that read the report
and the target the report names.

The job-level fields the run has always read (``container.sandbox_report``,
``launch_record``, ``sandbox_failure``, ``sandbox_normalised`` and the rest)
are the first detonation's, copied from its record as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from malspark.core.logger import logger

# Who asked for a detonation: the job (its first, with the job's own launch
# arguments) or an agent (a further one, by the request tool).
JOB_ORIGIN = "job"
AGENT_ORIGIN = "agent"


def detonation_name(ordinal: int) -> str:
    """The name a detonation is selected and qualified by: ``d1`` for the job's first."""
    return f"d{int(ordinal)}"


@dataclass
class DetonationRecord:
    """One detonation of the job's sample, as it was asked for and as it ended.

    ``uploads`` and ``artefact_fetch_failures`` are the rows this detonation
    added; for the job's first they are the container's own lists, so a run
    stopped part-way still discloses an upload made before it stopped.
    ``requested_by`` names each request a further detonation carries out
    (empty for the job's first).
    """

    ordinal: int = 1
    origin: str = JOB_ORIGIN
    arguments: str = ""
    requested_by: list[dict[str, Any]] = field(default_factory=list)
    provider: str = ""
    task_id: str = ""
    report: dict[str, Any] | None = None
    launch: dict[str, Any] | None = None
    failure: str | None = None
    uploads: list[dict[str, Any]] = field(default_factory=list)
    artefact_fetch_failures: list[dict[str, str]] = field(default_factory=list)
    normalised_by: tuple[str, str, str] | None = None
    signature_scale: dict[str, Any] | None = None
    target_claim: dict[str, str] | None = None
    attached_target_claim: dict[str, str] | None = None
    # Whether the provider's submit call returned: only then were the launch
    # arguments sent.
    submit_returned: bool = False
    # The step of the graph a further detonation was carried out on entry of,
    # and when: its own start and end (Unix time) and duration, so a reader can
    # take its time out of the stage it ran inside. Empty and zero for the
    # job's first, made before the graph.
    step: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    duration_ms: int = 0
    # Whether a further detonation is being carried out now: set when a step
    # claims it (``pipeline.detonations``), cleared however it ends.
    running: bool = False
    # The platform's reads of its report, as ledger rows
    # (``pipeline.detonations.platform_reads``): what a step that waited for
    # it reads beside its claimant's update. Never stated.
    platform_rows: list[dict[str, Any]] = field(default_factory=list, repr=False)
    # What the provider stated about the sandbox run behind the report, asked
    # once the report was read (:func:`stated_by`); ``None`` where it stated
    # nothing or no report was read. Read by the run's environment record.
    sandbox_facts: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        """``d<ordinal>``."""
        return detonation_name(self.ordinal)

    @property
    def reported(self) -> bool:
        """Whether this detonation returned a report."""
        return isinstance(self.report, dict)

    def stated(self) -> dict[str, Any]:
        """What a read of this detonation answers beside its rows: which, launched how, by whom.

        Carried on every sandbox read of a later detonation, so the entry alone
        says under which launch its observations were made.
        """
        return {
            "detonation": self.name,
            "launched_with": self.arguments,
            "requested_by": [
                {
                    "agent": str(a.get("agent") or ""),
                    "cited_entries": list(a.get("cited_entries") or []),
                }
                for a in self.requested_by
            ],
        }

    def public(self) -> dict[str, Any]:
        """The record as the run states it: everything but the report itself."""
        out: dict[str, Any] = {
            "detonation": self.name,
            "origin": self.origin,
            "arguments": self.arguments,
            "provider": self.provider,
            "task_id": self.task_id,
            "reported": self.reported,
        }
        if self.requested_by:
            out["requested_by"] = [dict(row) for row in self.requested_by]
        if self.launch is not None:
            out["launch"] = dict(self.launch)
        if self.failure:
            out["failure"] = self.failure
        if self.step:
            out["step"] = self.step
            out["started_at"] = self.started_at
            out["ended_at"] = self.ended_at
            out["duration_ms"] = self.duration_ms
        return out


def stated_by(provider: Any, run: Any) -> dict[str, Any] | None:
    """What ``provider`` states about the sandbox run behind ``run``, or ``None``. Never raises.

    The one question every provider is asked
    (``SandboxProvider.detonation_facts``); a provider that does not answer
    it, answers something that is not a mapping, or fails, states nothing.
    """
    ask = getattr(provider, "detonation_facts", None)
    try:
        held = ask(run) if callable(ask) else None
    except Exception as exc:  # noqa: BLE001 — a provider that cannot say states nothing
        logger.debug("the sandbox provider stated nothing of its run (%s).", type(exc).__name__)
        return None
    return dict(held) if isinstance(held, dict) else None


def report_facts(run: Any, *, detonated: bool) -> dict[str, Any]:
    """A built-in provider's answer to ``detonation_facts``: the report's own facts and parts.

    What the report's parts state of the run: as the provider read them while
    it held them (``SandboxRun.run_facts``), else as the reader of the
    report's format reads them off the raw report with the shipped
    declaration of its id (``ReportReader.run_facts``); the parts the
    provider read (``SandboxRun.report_parts``) and whether it ran the sample.
    """
    from malspark.providers.sandbox.readers import report_reader, run_facts_of

    held = getattr(run, "run_facts", None)
    if isinstance(held, dict):
        facts = dict(held)
    else:
        report = getattr(run, "report", None)
        reader = report_reader(str(getattr(report, "source_format", "") or ""))
        raw = getattr(run, "raw", None)
        read = run_facts_of(reader, raw) if reader is not None and isinstance(raw, dict) else None
        facts = read or {}
    facts["detonated"] = bool(detonated)
    facts["report_parts"] = [dict(part) for part in getattr(run, "report_parts", None) or ()]
    return facts


# What a sandbox reader answers for a detonation selector it cannot read.
NO_SUCH_DETONATION = "no detonation {name!r} in this job"
NOT_A_DETONATION = "the detonation is named d1, d2 and so on (d1 is the job's own)"


def selected(container: Any, selector: Any) -> tuple[DetonationRecord | None, str]:
    """The later detonation ``selector`` names, and the problem where it names none.

    ``(None, "")`` where ``selector`` is empty or ``d1``: the job's first,
    which every reader reads as it always did. A later
    detonation (``d2``…) is looked up in ``container.detonations``; one the
    job does not hold, or that returned no report, is answered as a problem
    naming the detonations it holds.
    """
    text = str(selector or "").strip().lower()
    if text in ("", "d1"):
        return None, ""
    digits = text[1:] if text.startswith("d") else ""
    if not digits.isdigit() or int(digits) < 1:
        return None, NOT_A_DETONATION
    records = [r for r in getattr(container, "detonations", None) or () if r.ordinal > 1]
    found = next((r for r in records if r.ordinal == int(digits)), None)
    held = ", ".join(["d1", *(r.name for r in records)])
    if found is None:
        return None, f"{NO_SUCH_DETONATION.format(name=text)}; it holds {held}"
    if not found.reported:
        why = f": {found.failure}" if found.failure else ""
        return None, f"detonation {found.name} returned no sandbox report{why}"
    return found, ""
