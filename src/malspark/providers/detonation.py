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

    @property
    def name(self) -> str:
        """``d<ordinal>``."""
        return detonation_name(self.ordinal)

    @property
    def reported(self) -> bool:
        """Whether this detonation returned a report."""
        return isinstance(self.report, dict)

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
        return out


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
