"""The judge's decision as the run recorded it, read off the report in one place.

The agreement round (``reporting.section_agreement``) shows it as passages of their own
kind, a source of every passage it may rewrite (T-717). It is read, never decided here:

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

Beside it, the family names the run's own records hold that the judge did not name (the
sandbox's, a similar sample's, a function-hash match's): a sentence writing one is held
to the decision. No list of names is kept here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from malspark.schemas.isr_models import is_judge_dropped

if TYPE_CHECKING:
    from malspark.reporting.models import MalwareReport

# The words each verdict is written in: its own label, and for a malicious file the
# adjective. A sentence writing one of another verdict's words is held (T-717).
VERDICT_WORDS: dict[str, tuple[str, ...]] = {
    "Malware": ("malware", "malicious"),
    "Suspicious": ("suspicious",),
    "Benign": ("benign",),
}
# A family name shorter than this is part of too many words to be read as one.
_FAMILY_FLOOR = 3


@dataclass(frozen=True)
class DecidedTechnique:
    """One technique the decision speaks of: published, or dropped with the judge's words."""

    technique_id: str
    # The catalogue's own name, else the record's.
    name: str
    published: bool
    # A dropped technique's record, the judge's reason in its own words; "" when published.
    said: str = ""
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class JudgeDecision:
    """The judge's decision as the run recorded it (module docstring)."""

    verdict: str | None = None
    confidence: float | None = None
    band: str = ""
    # Whether the judge's verdict stands in the record, so its family (or none) does too.
    assessed: bool = False
    family: str | None = None
    family_ids: tuple[str, ...] = ()
    techniques: tuple[DecidedTechnique, ...] = ()
    # Family names the run's records hold that the judge did not name.
    other_families: tuple[str, ...] = ()

    @property
    def dropped(self) -> tuple[DecidedTechnique, ...]:
        return tuple(t for t in self.techniques if not t.published)

    @property
    def empty(self) -> bool:
        return not self.assessed and not self.techniques


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
                evidence_ids=tuple(mapping.evidence_ids or mapping.sources or ()),
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
                evidence_ids=tuple(cell.evidence_ids or cell.sources or ()),
            )
        )
    assessed = report.verdict_not_assessed is None and report.overall_confidence is not None
    attribution = report.attribution
    named = str(attribution.family or "").strip()
    judges = bool(named) and attribution.family_source != "sandbox"
    family = named if judges else None
    others = _family_names(
        [
            *([] if judges else [named]),
            *(str(row.get("family") or "") for row in attribution.similar_samples),
            *(str(row.get("family") or "") for row in attribution.function_hash_matches),
        ],
        family,
    )
    return JudgeDecision(
        verdict=report.verdict if assessed else None,
        confidence=report.overall_confidence if assessed else None,
        band=confidence_word(report.overall_confidence) if assessed else "",
        assessed=assessed,
        family=family if assessed else None,
        family_ids=tuple(attribution.family_evidence_ids) if family and assessed else (),
        techniques=tuple(techniques),
        other_families=others if assessed else (),
    )


def _family_names(names: Iterable[str], family: str | None) -> tuple[str, ...]:
    """Each name once, as first written, but the judge's own and one too short to read."""
    own = (family or "").casefold()
    out: dict[str, str] = {}
    for name in names:
        said = " ".join(str(name or "").split())
        if len(said) < _FAMILY_FLOOR or said.casefold() == own:
            continue
        out.setdefault(said.casefold(), said)
    return tuple(out.values())


def words_pattern(words: str) -> re.Pattern[str] | None:
    """A name written whole as prose words, without case, any run of spaces or punctuation
    between them ("Dynamic API Resolution", "dynamic-API resolution"); never inside an
    identifier ("process_injection", "suspicious_instruction"). ``None`` for no words."""
    parts = re.findall(r"[a-z0-9]+", str(words or "").lower())
    if not parts:
        return None
    return re.compile(
        r"(?<!\w)" + r"\W+".join(re.escape(p) for p in parts) + r"(?!\w)", re.IGNORECASE
    )


# A span the sentence quotes: a tool's or a rule's own label, not the writer's words.
_QUOTED_SPAN = re.compile(r'"[^"]*"|`[^`]*`|\u201c[^\u201d]*\u201d|(?<!\w)\'[^\']*\'(?!\w)')


def quoted_spans(text: str) -> list[tuple[int, int]]:
    """Where ``text`` quotes something, in order."""
    return [found.span() for found in _QUOTED_SPAN.finditer(text)]


def id_pattern(technique_id: str) -> re.Pattern[str]:
    """A technique id written whole: never a part of a longer id or a sub-technique's."""
    return re.compile(
        r"(?<![A-Za-z0-9.])" + re.escape(technique_id) + r"(?![0-9]|\.\d)", re.IGNORECASE
    )
