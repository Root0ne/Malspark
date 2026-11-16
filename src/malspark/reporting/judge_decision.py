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
sandbox's, a similar sample's, a function-hash match's). No list of names is kept here.

What the decision denies is read off the model's own new words alone (:func:`denied_in`): a
rewrite resting on the decision that writes, in a clause denying nothing, a technique the
judge dropped, another verdict or a family the judge did not name is refused. No sentence of
the report is picked by these names.
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
# adjective. A rewrite writing one of another verdict's words is refused (T-717).
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


def words_pattern(words: str, *, compound: bool = True) -> re.Pattern[str] | None:
    """A name written whole as prose words, without case, any run of spaces or punctuation
    between them ("Dynamic API Resolution", "dynamic-API resolution"); never inside an
    identifier ("process_injection", "suspicious_instruction"), nor, with ``compound`` off, a
    part of a hyphened word ("suspicious-instruction"). ``None`` for no words."""
    parts = re.findall(r"[a-z0-9]+", str(words or "").lower())
    if not parts:
        return None
    edge = r"\w" if compound else r"[\w-]"
    return re.compile(
        rf"(?<!{edge})" + r"\W+".join(re.escape(p) for p in parts) + rf"(?!{edge})",
        re.IGNORECASE,
    )


# A span the text quotes: a tool's or a rule's own label, not the writer's words.
_QUOTED_SPAN = re.compile(r'"[^"]*"|`[^`]*`|\u201c[^\u201d]*\u201d|(?<!\w)\'[^\']*\'(?!\w)')
# A technique id written whole, a sub-technique's included; never inside an identifier.
_TECHNIQUE_ID = re.compile(r"(?<![\w.])(T\d{4}(?:\.\d{3})?)(?!\w|\.\d)", re.IGNORECASE)
_ID = r"T\d{4}(?:\.\d{3})?"
# A tag list: two or more technique ids in a row, as a tool or a rule lists them.
_TAG_LIST = re.compile(
    rf"(?<![\w.]){_ID}(?:\s*(?:,|/|&|\band\b|\bor\b)\s*(?:and\s+|or\s+)?{_ID})+(?!\w|\.\d)",
    re.IGNORECASE,
)
# A heading: a line a Markdown heading mark opens.
_HEADING = re.compile(r"^\s*#")
# What denies in a clause besides a negation ("not", "no", "without"...).
_DENIES = re.compile(r"\b(?:absent|ruled\s+out|rather\s+than|instead\s+of|dropped)\b", re.I)


def _blanked(text: str, pattern: re.Pattern[str]) -> str:
    """``text`` with every span ``pattern`` finds turned to spaces, so no name is read in it."""
    return pattern.sub(lambda found: " " * len(found.group(0)), text)


def denied_in(text: str, decision: JudgeDecision) -> tuple[str, ...]:
    """What ``text`` writes, in a clause no denial stands in, that ``decision`` denies, each
    once as written: the id or the catalogue name of a technique the judge dropped (a
    sub-technique of a dropped parent included, but one the judge published), a verdict word
    other than the judge's, a family name the run's records hold that the judge did not name
    (T-717). A quoted label, a heading and a tag list write none; "absent", "ruled out",
    "rather than", "dropped" and every negation deny."""
    from malspark.memory.attck_loader import sub_technique_entries
    from malspark.reporting.absence_answers import carries_negation, clauses_of

    published = {t.technique_id for t in decision.techniques if t.published}
    dropped = {t.technique_id for t in decision.dropped}
    names = [t.name for t in decision.dropped]
    for technique in decision.dropped:
        if "." not in technique.technique_id:
            names.extend(
                entry.name
                for entry in sub_technique_entries(technique.technique_id)
                if entry.technique_id not in published and entry.technique_id not in dropped
            )
    patterns = [found for name in dict.fromkeys(names) if (found := words_pattern(name))]
    # Another verdict's words, where the judge gave one; the families the record holds that
    # the judge did not name, which it holds only where the judge assessed the verdict.
    patterns.extend(
        found
        for verdict, words in VERDICT_WORDS.items()
        if decision.verdict is not None and verdict != decision.verdict
        for word in words
        if (found := words_pattern(word, compound=False))
    )
    patterns.extend(
        found for name in decision.other_families if (found := words_pattern(name, compound=False))
    )

    def _denied_id(tid: str) -> bool:
        parent = tid.split(".")[0]
        return tid in dropped or (tid not in published and "." in tid and parent in dropped)

    out: dict[str, str] = {}
    for line in str(text or "").splitlines():
        if _HEADING.match(line):
            continue
        for clause in clauses_of(_blanked(_blanked(line, _QUOTED_SPAN), _TAG_LIST)):
            if carries_negation(clause) or _DENIES.search(clause):
                continue
            for written in _TECHNIQUE_ID.finditer(clause):
                if _denied_id(written.group(1).upper()):
                    out.setdefault(written.group(1).casefold(), written.group(1))
            for pattern in patterns:
                for written in pattern.finditer(clause):
                    out.setdefault(written.group(0).casefold(), written.group(0))
    return tuple(out.values())
