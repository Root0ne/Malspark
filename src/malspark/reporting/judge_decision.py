"""The judge's decision as the run recorded it, read off the report in one place.

The agreement round (``reporting.section_agreement``) shows it as passages of their own
kind, the source of a sentence's drop and of nothing else (T-717). It is read, never decided
here:

- the verdict and the overall confidence, with the word its band reads as
  (``renderers.markdown.confidence_word``), where the judge assessed one: a verdict with no
  confidence is the pipeline's own, written where the judge never answered, and a report
  whose verdict was not assessed carries none;
- the family the judge named, or none: a family the sandbox supplied where the judge
  abstained (``FamilyAttribution.family_source``) is no family of the judge's;
- each technique published (``ttp_mappings``), and each the judge dropped, which the
  capability matrix keeps out of that list with the judge's reason in its own words
  (``CapabilityCell.not_published``, ``isr_models.judge_dropped_reason``). The judge's
  technique answer itself (``x_malspark_technique_review``) is read once, where the matrix
  is built, and kept by no other stored record; a technique the judge declined to map
  was carried by nothing and has no row.

No sentence is read here for what it asserts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from malspark.schemas.isr_models import is_judge_dropped

if TYPE_CHECKING:
    from malspark.reporting.models import MalwareReport


@dataclass(frozen=True)
class DecidedTechnique:
    """One technique the decision speaks of: published, or dropped with the judge's words."""

    technique_id: str
    # The catalogue's own name, else the record's.
    name: str
    published: bool
    # A dropped technique's record, the judge's reason in its own words; "" when published.
    said: str = ""


@dataclass(frozen=True)
class JudgeDecision:
    """The judge's decision as the run recorded it (module docstring)."""

    verdict: str | None = None
    confidence: float | None = None
    band: str = ""
    # Whether the judge's verdict stands in the record, so its family (or none) does too.
    assessed: bool = False
    family: str | None = None
    techniques: tuple[DecidedTechnique, ...] = ()


def judge_decision(report: MalwareReport) -> JudgeDecision:
    """The judge's decision read off ``report`` (module docstring)."""
    from malspark.memory.attck_loader import technique_entry
    from malspark.reporting.renderers.markdown import confidence_word

    def _name(tid: str, recorded: str) -> str:
        entry = technique_entry(tid)
        return entry.name if entry is not None and entry.name else str(recorded or "").strip()

    techniques: list[DecidedTechnique] = []
    seen: set[str] = set()
    for mapping in report.ttp_mappings:
        tid = str(mapping.technique_id or "").strip().upper()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        techniques.append(
            DecidedTechnique(
                technique_id=tid,
                name=_name(tid, mapping.technique_name),
                published=True,
            )
        )
    for cell in report.capability_matrix:
        tid = str(cell.technique_id or "").strip().upper()
        if not tid or tid in seen or not is_judge_dropped(cell.not_published):
            continue
        seen.add(tid)
        techniques.append(
            DecidedTechnique(
                technique_id=tid,
                name=_name(tid, cell.technique_name),
                published=False,
                said=cell.not_published.strip(),
            )
        )
    assessed = report.verdict_not_assessed is None and report.overall_confidence is not None
    attribution = report.attribution
    named = str(attribution.family or "").strip()
    family = named if named and attribution.family_source != "sandbox" else None
    return JudgeDecision(
        verdict=report.verdict if assessed else None,
        confidence=report.overall_confidence if assessed else None,
        band=confidence_word(report.overall_confidence) if assessed else "",
        assessed=assessed,
        family=family if assessed else None,
        techniques=tuple(techniques),
    )
