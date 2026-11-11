"""What the analyst report asks of the composer: its own sections, its style and its channels.

The analyst report (``renderers/analyst.py``) reads like a professional malware
report: a short executive summary of the key capabilities, the findings in a
fixed order, a conclusion of a few paragraphs, one scoped limitations
paragraph and an ATT&CK table with one sentence of procedure per technique.
This module holds what the composer (``reporting.composer``) needs for it:

* four sections the composer writes beside the technical spine, with the
  object each answers with and the evidence each is shown
  (:func:`analyst_bundle`): the summary's capability bullets, the conclusion,
  the limitations paragraph and the procedure of each published technique.
  Each reads only what the report held before the composer ran, as every
  section does, so the sections still run at once;
* the style every section's prose is held to (:func:`style_violations`): no
  confidence written as a number and no word of how the report was made. A
  finding is shown to the model once and, if the sentence stays, marked where
  it stands; the words are never rewritten;
* the shape of the four sections (:func:`summary_shape_violations` and the
  rest): at most eight bullets, two or three paragraphs of conclusion, one
  paragraph of limitations, one sentence per published technique;
* the channel check (:func:`channel_binding_violations`): a value a channel
  row gives — an endpoint, a quoted verb — is held in the run's entries
  beside the code that uses it, and a row naming other code is asked about;
* the analyst statements only the ATT&CK section holds
  (:func:`statements_to_fold`), given to the functionality and
  command-and-control sections so each fact is written where it belongs.

Every rule reads the report's own fields and the entries' text, never a tool's
or a family's name.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from malspark.analysis.technique_ids import ID_BODY, is_technique_id
from malspark.memory.attck_loader import TACTIC_ID_RE
from malspark.pipeline.events import safe_finding_value
from malspark.pipeline.validation import (
    CHANNEL_BINDING_CODE,
    NUMERIC_CONFIDENCE_CODE,
    PROCESS_WORDS_CODE,
    PROSE_SHAPE_CODE,
    VALUE_NOT_CARRIED_CODE,
    EntryTexts,
    Violation,
    image_bases_in,
)
from malspark.reporting.evidence_bundles import (
    LISTED_QUESTIONS_FACT,
    MEASURED_LIST_FACT,
    NOT_PRINTED_FACT,
    OTHER_QUESTIONS_FACT,
)
from malspark.reporting.models import CapabilityBullet, MalwareReport, TechniqueProcedure

# ---------------------------------------------------------------------------
# The four sections and the objects they answer with
# ---------------------------------------------------------------------------


class SummaryOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bullets: list[CapabilityBullet] = Field(default_factory=list)


class ConclusionOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("")
    evidence_refs: list[str] = Field(default_factory=list)


class LimitationsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("")
    evidence_refs: list[str] = Field(default_factory=list)


class ProceduresOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    procedures: list[TechniqueProcedure] = Field(default_factory=list)


# The sections, in the order the composer asks for them after the spine.
ANALYST_SECTIONS: dict[str, type[BaseModel]] = {
    "summary": SummaryOut,
    "conclusion": ConclusionOut,
    "limitations": LimitationsOut,
    "attack_procedures": ProceduresOut,
}

# How many capability bullets the executive summary holds, and how many
# paragraphs the conclusion is.
MAX_SUMMARY_BULLETS = 8
CONCLUSION_PARAGRAPHS = (2, 3)
# How many sentences one summary bullet may run to: one line, its subject first.
_BULLET_SENTENCES = 2

# ---------------------------------------------------------------------------
# What each section is shown
# ---------------------------------------------------------------------------

# The heading the analyst statements a section folds in are shown under, as a
# label of each (``[T1234 statement]``).
STATEMENT_LABEL = "{technique} statement"
# The label of a key finding the summary is shown, and of the verdict's own
# rationale the conclusion is shown.
FINDING_LABEL = "summary finding {number}"
OVERVIEW_LABEL = "capability overview {number}"
PARAGRAPH_LABEL = "summary paragraph"
# How many of a published technique's claims its procedure is written from.
_PROCEDURE_CLAIMS = 2
RATIONALE_LABEL = "verdict rationale"


def _confidence_words(value: float | None) -> str:
    from malspark.reporting.renderers.markdown import confidence_word

    return confidence_word(value) if value is not None else ""


def _assessment_facts(report: MalwareReport) -> dict[str, Any]:
    """The verdict, the family and the severity, each confidence in words."""
    attr = report.attribution
    family = str(attr.family or "").strip()
    facts: dict[str, Any] = {
        "verdict": (
            f"not assessed ({report.verdict_not_assessed})"
            if report.verdict_not_assessed
            else report.verdict
        ),
        "verdict_confidence": _confidence_words(report.overall_confidence),
        "family": family if family.lower() not in ("", "unknown") else "",
        "family_confidence": _confidence_words(attr.family_confidence) if family else "",
        "category": report.malware_category if report.malware_category != "unknown" else "",
        "severity": report.severity.rating if report.severity else "",
    }
    return {key: value for key, value in facts.items() if value}


def _claim(text: str, refs: Sequence[Any] = (), label: str = "") -> dict[str, str]:
    return {
        "claim": str(text or ""),
        "evidence_ref": ", ".join(str(r) for r in refs if str(r).strip()),
        "agent": "",
        "label": label,
    }


def published_techniques(report: MalwareReport) -> dict[str, tuple[str, list[str], list[str]]]:
    """Each technique the ATT&CK table publishes: its name, its claims and the ids they cite.

    The same rows, in the same order, as the analyst report's table
    (``renderers.analyst._Analyst.attack``): a valid, published, non-MBC cell
    of the capability matrix, then a published mapping the matrix lacks.
    """
    from malspark.reporting.renderers.markdown import _EV_RE, _is_mbc_id, _tactic_key

    out: dict[str, tuple[str, list[str], list[str]]] = {}
    seen: set[str] = set()
    for cell in sorted(report.capability_matrix, key=_tactic_key):
        if _is_mbc_id(cell.technique_id) or cell.technique_id in seen:
            continue
        seen.add(cell.technique_id)
        if cell.not_published or not cell.technique_id_valid:
            continue
        claims = [str(c) for c in cell.evidence if str(c).strip()]
        out[cell.technique_id] = (
            cell.technique_name,
            claims,
            list(dict.fromkeys(_EV_RE.findall(" ".join(claims)))),
        )
    for mapping in report.ttp_mappings:
        tid = mapping.technique_id
        if not tid or tid in seen:
            continue
        seen.add(tid)
        claims = [str(q) for q in mapping.evidence_quotes if str(q).strip()]
        out[tid] = (
            mapping.technique_name,
            claims,
            list(dict.fromkeys(_EV_RE.findall(" ".join(claims)))),
        )
    return out


def _open_questions(report: MalwareReport) -> list[str]:
    """The questions the run left open, as its own table lists them."""
    for section in report.sections:
        if section.key != "open_questions" or "Question" not in section.columns:
            continue
        at = section.columns.index("Question")
        return list(dict.fromkeys(str(row[at]).strip() for row in section.rows if len(row) > at))
    return []


def _redone_calls(report: MalwareReport) -> list[str]:
    """Each failed call a later call redid, as the run's bounds hold it (``evidence.redone``).

    Shown readable as the platform's citations, so only the ids, each of an
    entry id's shape; the tool's name, a server's word, is not repeated here.
    """
    from malspark.reporting.redone_calls import ENTRY_ID

    evidence = (report.run_summary or {}).get("evidence") or {}
    said: list[str] = []
    for row in evidence.get("redone") or []:
        if not isinstance(row, dict):
            continue
        failed = str(row.get("entry_id") or "")
        by = [str(i) for i in row.get("answered_by") or [] if ENTRY_ID.fullmatch(str(i))]
        if ENTRY_ID.fullmatch(failed) and by:
            said.append(
                f"{failed} failed and was redone: {', '.join(by)} answered for the same "
                "address, so it left no gap"
            )
    return said


# The keys the limitations' writer is shown the inventory under, where the report holds one
# (``evidence_bundles``, which shows them readable).


def measured_limitation_facts(report: MalwareReport) -> dict[str, Any]:
    """What the limitations' writer is shown of a report holding the limitations inventory:
    the rows section 11 prints above the paragraph, in the words it prints them; every
    other row, which the evidence bundle prints, but the marked questions' row, whose
    questions are shown once, under their own key; the open questions, those every routine
    of which has listed code apart, each with its analyst, its reason and its citations;
    and the verdict and degraded-run facts as before."""
    from malspark.reporting.limitation_inventory import (
        MARKS,
        inventory_rows,
        question_lines,
        reason_label,
    )

    inventory = report.limitation_inventory
    if inventory is None:
        return {}
    from malspark.utils.written_forms import ids_written_out

    # The rows are the platform's words and citations, shown readable; a tool's name, a
    # reason it recorded and an analyst's question have every ledger id in them written
    # out, so none reads as a citation (``evidence_bundles.PLATFORM_CITED_FACTS``).
    def _quoted(text: str) -> str:
        return f'"{" ".join(ids_written_out(str(text)).split())}"'

    rows = inventory_rows(inventory, quote=_quoted, name=ids_written_out, reason_as=reason_label)
    listed, other = question_lines(inventory, quote=_quoted, name=ids_written_out)
    return {
        MEASURED_LIST_FACT: [row.text for row in rows if row.printed],
        NOT_PRINTED_FACT: [row.text for row in rows if not row.printed and row.part != MARKS],
        LISTED_QUESTIONS_FACT: listed,
        OTHER_QUESTIONS_FACT: other,
        "degraded_run": bool(report.degraded_mode),
        "verdict_not_assessed": report.verdict_not_assessed or "",
    }


def analyst_bundle(
    section: str,
    report: MalwareReport,
    technical_evidence: Any = None,
    isr_reports: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The evidence one of :data:`ANALYST_SECTIONS` is shown, in a section bundle's shape.

    Each reads what the report held before the composer ran, and no more than
    it needs: the summary and the conclusion the key findings and the
    capability overview the narrative wrote, each citing its entries, with the
    verdict in words (and the verdict's rationale for the conclusion); the
    limitations the run's recorded limitations and open questions; the
    procedures the published techniques with their first claims. The claims in
    force are not shown again: the findings were written from them, and every
    claim beside them would put each of these calls over a price tier.
    """
    from malspark.reporting.evidence_bundles import (
        REDONE_CALLS_FACT,
        binary_facts,
        sandbox_entry_ids,
    )

    binary = binary_facts(report)
    findings = [
        _claim(f.text, f.evidence_ids, FINDING_LABEL.format(number=n))
        for n, f in enumerate(report.key_findings, 1)
        if f.text.strip()
    ] + [
        _claim(p, (), OVERVIEW_LABEL.format(number=n))
        for n, p in enumerate(report.capabilities_narrative, 1)
        if str(p).strip()
    ]
    if report.executive_summary.strip():
        findings.insert(0, _claim(report.executive_summary, (), PARAGRAPH_LABEL))
    if section == "summary":
        return {
            "claims": findings,
            "tool_outputs": [],
            "binary": binary,
            "facts": _assessment_facts(report),
        }
    if section == "conclusion":
        facts = _assessment_facts(report)
        severity = report.severity
        if severity is not None and severity.business_impact.strip():
            facts["business_impact"] = severity.business_impact.strip()
        if severity is not None and severity.likely_targets:
            facts["likely_targets"] = list(severity.likely_targets)
        stored = report.conclusion
        rationale = (
            [_claim(stored.text, (), RATIONALE_LABEL)]
            if stored is not None and stored.text.strip()
            else []
        )
        return {
            "claims": [*rationale, *findings],
            "tool_outputs": [],
            "binary": binary,
            "facts": facts,
        }
    if section == "limitations" and report.limitation_inventory is not None:
        return {
            "claims": [],
            "tool_outputs": [],
            "binary": binary,
            "facts": measured_limitation_facts(report),
        }
    if section == "limitations":
        facts = {
            "limitations_recorded": list(report.degradation_reasons),
            "open_questions": _open_questions(report),
            # Said only when it is a limitation: a fact that is false is no gap.
            "no_sandbox_observation": not sandbox_entry_ids(report),
            "degraded_run": bool(report.degraded_mode),
            "verdict_not_assessed": report.verdict_not_assessed or "",
        }
        # A failed call a later call redid is no gap, said so beside the open
        # questions an analyst may have filed on it (T-494 D6); none, no key.
        redone = _redone_calls(report)
        if redone:
            facts[REDONE_CALLS_FACT] = redone
        return {"claims": [], "tool_outputs": [], "binary": binary, "facts": facts}
    if section == "attack_procedures":
        published = published_techniques(report)
        technique_claims = [
            _claim(text, refs, tid)
            for tid, (_name, texts, refs) in published.items()
            for text in texts[:_PROCEDURE_CLAIMS]
        ]
        return {
            "claims": technique_claims,
            "tool_outputs": [],
            "binary": binary,
            "facts": {
                "published_techniques": [
                    f"{tid} {name}".strip() for tid, (name, _t, _r) in published.items()
                ]
            },
        }
    raise KeyError(section)


# The ATT&CK tactic a statement's technique sits under, and the section of the
# functionality or command-and-control part that owns its facts.
_TACTIC_SECTIONS: dict[str, str] = {
    "TA0003": "persistence_detail",
    "TA0004": "evasion_antiforensics",
    "TA0005": "evasion_antiforensics",
    "TA0007": "discovery",
    "TA0010": "command_and_control",
    "TA0011": "command_and_control",
}
# The section a statement whose tactic names none of the above is folded into.
_FOLD_DEFAULT = "payloads"
_LAYER_LABEL = re.compile(r"^\s*[\w.-]+:\s+")


def statements_to_fold(report: MalwareReport) -> dict[str, list[dict[str, str]]]:
    """The analyst statements only the ATT&CK section holds, by the section that owns them.

    The statements of a technique a rule matched only on names resolved at
    runtime (the ones the analyst report's appendix prints where they name a
    value printed nowhere else): each statement is given to one section, by its
    technique's tactic, so the section states its facts once, in their place.
    """
    from malspark.reporting.renderers.markdown import _is_mbc_id, _resolved_only, _tactic_key

    static = report.static
    hits = list(static.api_technique_hits) if static else []
    by_tid: dict[str, list[dict[str, Any]]] = {}
    for hit in hits:
        by_tid.setdefault(str(hit.get("technique_id") or ""), []).append(hit)
    out: dict[str, list[dict[str, str]]] = {}
    seen: set[str] = set()
    for cell in sorted(report.capability_matrix, key=_tactic_key):
        rules = by_tid.get(cell.technique_id) or []
        if _is_mbc_id(cell.technique_id) or not rules:
            continue
        if not all(_resolved_only(hit) for hit in rules):
            continue
        section = _TACTIC_SECTIONS.get(str(cell.tactic or "").upper(), _FOLD_DEFAULT)
        for statement in cell.statements:
            text = _LAYER_LABEL.sub("", str(statement), count=1).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.setdefault(section, []).append(
                _claim(text, (), STATEMENT_LABEL.format(technique=cell.technique_id))
            )
    return out


def code_around_values(report: MalwareReport) -> dict[str, list[str]]:
    """Each recovered network value and the functions the recovering tools name around it.

    Read from the report's record of what each recovering tool read and where
    (``EmulatedStrings.recovered_by``): the functions around the code that
    uses or decodes the text, as each tool named them — which of them uses it
    is the section's to read from the entries. A value no tool placed is left
    out.
    """
    record = report.emulated_strings
    if record is None:
        return {}
    out: dict[str, list[str]] = {}
    for value, rows in record.recovered_by.items():
        functions = list(dict.fromkeys(f for row in rows for f in row.functions if f))
        if functions:
            out[record.spelled.get(value, value)] = functions
    return out


# ---------------------------------------------------------------------------
# The style every section's prose is held to
# ---------------------------------------------------------------------------

# A confidence written as a number: beside the word ("confidence 0.85",
# "0.35 confidence", "85% confidence") or a bare one in parentheses ("(0.60)").
_A_CONFIDENCE = r"(?<![\w.])(?:0?\.\d{1,3}|1\.0{1,3}|\d{1,3}(?:\.\d+)?\s?%)(?![\w.]*\d)"
_NUMERIC_CONFIDENCE = re.compile(
    # The number attached to the word: "confidence 0.85", "confidence of 0.6",
    # "confidence: 85%", "(confidence 0.60)" ...
    r"\bconfidence\b\s*(?:(?:of|is|was|at|level|score)\s*)?[:=]?\s*\(?"
    + _A_CONFIDENCE
    # ... or the word attached to the number: "0.35 confidence", "85% confidence".
    + r"|"
    + _A_CONFIDENCE
    + r"\)?\s+(?:overall\s+)?confidence\b",
    re.IGNORECASE,
)
# The phrasings of how the report was produced, never of what the sample does:
# a word alone ("ledger", "producer", "model", "tool") is a sample's term as
# often, so only the phrasings that name the run's own record are read. The
# debate's own words count too: a claim by its number ("Claim 44 is refuted",
# "claims 12 and 13", "claim no. 44"), never a quantity a sample claims ("claims
# 4 GB"), and the analysis the report revised ("the earlier analysis"), never
# one by or from another party (T-555).
_PROCESS_WORDS = re.compile(
    r"\b(?:(?:the|this run's|the run's) ledger(?!\s+of\b)|ledger entr(?:y|ies)"
    r"|per the judge|the judge (?:kept|ruled|stated|said|found|accepted|rejected|dropped|named)"
    r"|tool calls?|claim numbers?|analyst claims?|language models?|report models?"
    r"|claims?\s+(?:no\.?\s*|#)?\d+(?:\s*(?:,|and|to)\s*#?\d+)*"
    # ... never a quantity: "claims 4 and 8 GB", "claims 3, 5 or 7 days", "Claim 1 BTC".
    r"(?![\s,#\d]*(?:(?:or|and|to)\s*[#\d][\s,#\d]*)?"
    r"(?:(?:[KMGT]i?B|bytes?|days?|hours?|minutes?|seconds?|times|USD|EUR|BTC|prizes?)\b|%))"
    r"|(?:the|this) earlier analys[ie]s(?!\s+(?:by|from)\b))\b",
    re.IGNORECASE,
)
# An agent's name is a process word where it is an identifier ("static_r2"):
# a name that is also an English word ("dynamic") is not told from one.
_DISTINCT_NAME = re.compile(r"[_\d]")
# The fields of an answer whose strings are the sample's values, not prose.
_VALUE_FIELDS = frozenset(
    {
        "value",
        "endpoints",
        "evidence_refs",
        "evidence_ref",
        "id",
        "key",
        "flag",
        "technique_id",
        "verbatim_content",
        "filename",
        "company_id_hash",
        "iv",
        "file_marker",
        "extension",
        "how_obtained",
        "voice",
        "kind",
    }
)
# A number after "no." numbers what stands before it ("claim no. 44"): no end.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z(\"'\[])|(?<=[.!?])(?<!\b[Nn]o\.)\s+(?=[0-9])")


def agent_names(report: MalwareReport) -> list[str]:
    """The run's analysts' names that are identifiers, as the run summary lists them."""
    profile = (report.run_summary or {}).get("profile") or {}
    names = [str(a) for a in profile.get("analysts") or [] if str(a).strip()]
    return [name for name in names if _DISTINCT_NAME.search(name)]


def _prose_strings(payload: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """Every prose string of an answer with its path; the sample's values are left out."""
    if depth > 5:
        return
    if isinstance(payload, str):
        yield path, payload
    elif isinstance(payload, Mapping):
        for key, value in payload.items():
            if str(key) in _VALUE_FIELDS:
                continue
            yield from _prose_strings(value, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(payload, list | tuple):
        for index, value in enumerate(payload):
            yield from _prose_strings(value, f"{path}[{index}]", depth + 1)


def sentences(text: str) -> list[str]:
    """``text``'s sentences, each as written."""
    return [part.strip() for part in _SENTENCE_END.split(str(text or "").strip()) if part.strip()]


def _found_in(text: str, pattern: re.Pattern[str]) -> list[tuple[str, list[str]]]:
    """Each sentence of ``text`` that ``pattern`` finds something in, with what it found."""
    out: list[tuple[str, list[str]]] = []
    for sentence in sentences(text):
        found = [m.group(0).strip() for m in pattern.finditer(sentence)]
        if found:
            out.append((sentence, list(dict.fromkeys(found))))
    return out


def style_violations(
    payload: Any, names: Sequence[str] = (), evidence: str = ""
) -> list[Violation]:
    """The prose of an answer that writes a confidence as a number or names how it was made.

    One finding per field and kind, naming every sentence; each sentence is
    marked where it stands if it stays (``validation.MARKED_IN_PLACE``).
    ``names`` are the run's agents' identifier names (:func:`agent_names`);
    ``evidence`` is the text the section was shown: a phrasing it holds is the
    sample's or a tool's term there, and is not asked about.
    """
    if payload is None:
        return []
    process = _PROCESS_WORDS
    if names:
        process = re.compile(
            _PROCESS_WORDS.pattern
            + "|"
            + "|".join(rf"(?<![\w]){re.escape(name)}(?![\w])" for name in names),
            re.IGNORECASE,
        )
    out: list[Violation] = []
    for path, text in _prose_strings(payload):
        numbers = _found_in(text, _NUMERIC_CONFIDENCE)
        if numbers:
            said = ", ".join(dict.fromkeys(f for _s, found in numbers for f in found))
            out.append(
                Violation(
                    code=NUMERIC_CONFIDENCE_CODE,
                    message=(
                        f"{safe_finding_value(path)} writes a confidence as a number "
                        f"({safe_finding_value(said)}). Say how confident the assessment is in "
                        "words (high, moderate, low), never as a number."
                    ),
                    path=path,
                    quoted=tuple(s for s, _f in numbers),
                    labels=tuple(", ".join(f) for _s, f in numbers),
                )
            )
        shown = evidence.lower()
        words = [
            (sentence, kept)
            for sentence, found in _found_in(text, process)
            if (kept := [f for f in found if f.lower() not in shown])
        ]
        if words:
            said = ", ".join(dict.fromkeys(f for _s, found in words for f in found))
            out.append(
                Violation(
                    code=PROCESS_WORDS_CODE,
                    message=(
                        f"{safe_finding_value(path)} names how this report was made "
                        f"({safe_finding_value(said)}). State the finding itself, in the "
                        "sample's terms: no ledger, judge, mediator, producer, "
                        "model, agent or tool call, and no analyst's name, claim number or "
                        "earlier analysis."
                    ),
                    path=path,
                    quoted=tuple(s for s, _f in words),
                    labels=tuple(", ".join(f) for _s, f in words),
                )
            )
    return out


# ---------------------------------------------------------------------------
# The shape of the four sections
# ---------------------------------------------------------------------------


def _rows(payload: Any, key: str) -> list[Mapping[str, Any]]:
    rows = payload.get(key) if isinstance(payload, Mapping) else None
    return [row for row in rows or [] if isinstance(row, Mapping)]


def summary_shape_violations(payload: Any) -> list[Violation]:
    """A summary of more than eight bullets, or a bullet longer than one line."""
    bullets = [row for row in _rows(payload, "bullets") if str(row.get("text") or "").strip()]
    out: list[Violation] = []
    if len(bullets) > MAX_SUMMARY_BULLETS:
        out.append(
            Violation(
                code=PROSE_SHAPE_CODE,
                path="bullets",
                message=(
                    f"The summary has {len(bullets)} bullets; it holds at most "
                    f"{MAX_SUMMARY_BULLETS}. Keep the most actionable capabilities, one bullet "
                    "each, and leave the rest to the sections that describe them."
                ),
            )
        )
    for index, row in enumerate(bullets):
        if len(sentences(str(row.get("text") or ""))) > _BULLET_SENTENCES:
            number = index + 1
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"bullets[{index}].text",
                    message=(
                        f"Bullet {number} runs to more than {_BULLET_SENTENCES} sentences. "
                        "Write each capability on one line, its subject first."
                    ),
                )
            )
    return out


def _paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", str(text or "").strip()) if p.strip()]


def conclusion_shape_violations(payload: Any) -> list[Violation]:
    """A conclusion that is not two or three paragraphs."""
    body = str(payload.get("body") or "") if isinstance(payload, Mapping) else ""
    count = len(_paragraphs(body))
    low, high = CONCLUSION_PARAGRAPHS
    if not body.strip() or low <= count <= high:
        return []
    return [
        Violation(
            code=PROSE_SHAPE_CODE,
            path="body",
            message=(
                f"The conclusion is {count} paragraph{'s' if count != 1 else ''}; write "
                f"{low} or {high} short paragraphs, separated by a blank line."
            ),
        )
    ]


def limitations_shape_violations(payload: Any) -> list[Violation]:
    """Limitations written as more than one paragraph."""
    body = str(payload.get("body") or "") if isinstance(payload, Mapping) else ""
    count = len(_paragraphs(body))
    if count <= 1:
        return []
    return [
        Violation(
            code=PROSE_SHAPE_CODE,
            path="body",
            message=(
                f"The limitations are {count} paragraphs; write one short paragraph of "
                "scoped sentences."
            ),
        )
    ]


def procedure_violations(payload: Any, published: Sequence[str]) -> list[Violation]:
    """A procedure for a technique the report does not publish, or longer than one sentence."""
    known = {str(t).strip().upper() for t in published}
    out: list[Violation] = []
    for index, row in enumerate(_rows(payload, "procedures")):
        tid = str(row.get("technique_id") or "").strip().upper()
        if tid not in known:
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"procedures[{index}].technique_id",
                    message=(
                        f"{safe_finding_value(tid) or 'A procedure'} is not a technique this "
                        "report publishes; write a procedure only for a technique listed in the "
                        "evidence."
                    ),
                )
            )
        if len(sentences(str(row.get("procedure") or ""))) > 1:
            out.append(
                Violation(
                    code=PROSE_SHAPE_CODE,
                    path=f"procedures[{index}].procedure",
                    message=(
                        f"The procedure for {safe_finding_value(tid) or 'this technique'} is "
                        "more than one sentence; write one sentence saying how the sample "
                        "carries it out."
                    ),
                )
            )
    return out


# ---------------------------------------------------------------------------
# The channel check
# ---------------------------------------------------------------------------

_ADDRESS = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-f]{3,16})(?![0-9a-z_])", re.IGNORECASE)
_WHOLE_ADDRESS = re.compile(r"0x[0-9a-f]{3,16}", re.IGNORECASE)
_QUOTED = re.compile(r"\"([^\"\n]{2,80})\"")
# How far after a quoted value an address is the value's own place ('"X" string
# at 0x1f00'), not the code the row names.
_PLACE_AFTER = 40
# Above this an address is read with its image base folded out where none is known.
_LOW_ADDRESS = 0xFFFFFFFF
_ALIGNMENT = 0x10000
_CHANNEL_TEXT_FIELDS = ("name", "protocol", "encryption", "packet_layout", "beacon_format")


def _forms(address: int, bases: Sequence[int]) -> set[int]:
    forms = {address}
    forms.update(address - base for base in bases if address >= base)
    if not bases and address > _LOW_ADDRESS:
        forms.add(address % _ALIGNMENT)
    return forms


def _addresses_in(node: Any, *, deep: bool) -> list[str]:
    """The address strings ``node`` holds: its own fields, and every nested one when ``deep``."""
    found: list[str] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _WHOLE_ADDRESS.fullmatch(item.strip()):
                found.append(item.strip())
        elif isinstance(item, Mapping):
            for value in item.values():
                if isinstance(value, str) or deep:
                    stack.append(value)
        elif isinstance(item, list | tuple) and (deep or item is node):
            stack.extend(item)
    return found


def _records_beside(node: Any, wanted: str) -> list[str]:
    """The addresses of each record of a JSON answer that holds ``wanted`` as a whole value.

    The record is the object that holds the value, with everything nested in
    it; where that object holds no address, the nearest object above it that
    holds one of its own (a row whose list of texts holds the value).
    """
    out: list[str] = []
    stack: list[tuple[Any, tuple[Mapping[str, Any], ...]]] = [(node, ())]
    while stack:
        item, above = stack.pop()
        if isinstance(item, Mapping):
            holds = any(isinstance(v, str) and v.strip().lower() == wanted for v in item.values())
            if holds:
                found = _addresses_in(item, deep=True)
                if not found:
                    for parent in reversed(above):
                        found = _addresses_in(parent, deep=False)
                        if found:
                            break
                out.extend(found)
            for value in item.values():
                if isinstance(value, Mapping | list):
                    stack.append((value, (*above, item)))
        elif isinstance(item, list):
            in_list = any(isinstance(v, str) and v.strip().lower() == wanted for v in item)
            if in_list:
                for parent in reversed(above):
                    found = _addresses_in(parent, deep=False)
                    if found:
                        out.extend(found)
                        break
            stack.extend((value, above) for value in item if isinstance(value, Mapping | list))
    return out


class _Beside:
    """What the run's entries hold beside each value: the code addresses of its records."""

    def __init__(self, entries: EntryTexts) -> None:
        self.entries = entries
        self.bases = image_bases_in(entries.entries.values())
        self._parsed: dict[str, Any] = {}
        self._held: dict[str, tuple[set[int], list[str], list[str]]] = {}

    def _json(self, entry_id: str) -> Any:
        if entry_id not in self._parsed:
            output = str(getattr(self.entries.entries.get(entry_id), "output", "") or "")
            parsed: Any = None
            if output.lstrip().startswith(("{", "[")):
                try:
                    parsed = json.loads(output)
                except (TypeError, ValueError):
                    parsed = None
            self._parsed[entry_id] = parsed
        return self._parsed[entry_id]

    def held(self, value: str) -> tuple[set[int], list[str], list[str]]:
        """The address forms beside ``value``, the addresses as written, and the entries."""
        key = value.strip().lower()
        if key not in self._held:
            forms: set[int] = set()
            written: list[str] = []
            holders: list[str] = []
            for entry_id in self.entries.holding(value):
                parsed = self._json(entry_id)
                if parsed is None:
                    continue
                found = _records_beside(parsed, key)
                if found:
                    holders.append(entry_id)
                for address in found:
                    written.append(address)
                    forms |= _forms(int(address, 16), self.bases)
            self._held[key] = (forms, list(dict.fromkeys(written)), holders)
        return self._held[key]


def _channel_code(channel: Mapping[str, Any]) -> tuple[list[int], dict[str, set[int]], list[str]]:
    """The addresses a channel row names, each quoted value's own place, and its quoted values."""
    text = " ".join(str(channel.get(f) or "") for f in _CHANNEL_TEXT_FIELDS)
    named = [int(m.group(1), 16) for m in _ADDRESS.finditer(text)]
    places: dict[str, set[int]] = {}
    quoted: list[str] = []
    for match in _QUOTED.finditer(text):
        value = match.group(1).strip()
        quoted.append(value)
        after = text[match.end() : match.end() + _PLACE_AFTER]
        places.setdefault(value.lower(), set()).update(
            int(m.group(1), 16) for m in _ADDRESS.finditer(after)
        )
    return named, places, list(dict.fromkeys(quoted))


def channel_binding_violations(payload: Any, entries: EntryTexts | None) -> list[Violation]:
    """Channel rows given a value the entries hold beside another row's code, or beside neither.

    Each row names the code its traffic runs through (its addresses). A value
    the row gives — a quoted verb or string, an endpoint — is looked for in the
    run's entries, and the code addresses of each record holding it are read
    (:class:`_Beside`). Asked once, with those records' addresses and entries:

    * a value whose records hold another row's code and none of this row's
      (the address right after a quoted value is its own place, not code);
    * an endpoint two rows naming different code both give, whose records
      hold the code of neither.

    A row that names no address, or a value no record of an entry holds, is
    not asked: nothing binds it either way.
    """
    channels = _rows(payload, "channels")
    if entries is None or len(channels) < 2:
        return []
    beside = _Beside(entries)
    code = [_channel_code(ch) for ch in channels]

    def own(index: int, value: str) -> set[int]:
        named, places, _quoted = code[index]
        skip = places.get(value.lower(), set())
        return {f for a in named if a not in skip for f in _forms(a, beside.bases)}

    def label(index: int) -> str:
        return f"channel {index + 1} ({str(channels[index].get('name') or '').strip()})"

    out: list[Violation] = []
    for index, channel in enumerate(channels):
        values = [
            *code[index][2],
            *(str(e) for e in channel.get("endpoints") or [] if str(e).strip()),
        ]
        for value in dict.fromkeys(values):
            forms, written, holders = beside.held(value)
            mine = own(index, value)
            if not forms or not mine or forms & mine:
                continue
            others = [d for d in range(len(channels)) if d != index and forms & own(d, value)]
            if not others:
                continue
            theirs = {f for d in others for f in own(d, value)}
            # The addresses the other rows name first: they are what binds the value.
            written = sorted(written, key=lambda a: not (_forms(int(a, 16), beside.bases) & theirs))
            out.append(
                Violation(
                    code=CHANNEL_BINDING_CODE,
                    message=(
                        f"{safe_finding_value(label(index))} gives "
                        f"{safe_finding_value(json.dumps(value))}, held in "
                        f"{safe_finding_value(', '.join(holders[:3]))} beside the code at "
                        f"{safe_finding_value(', '.join(written[:4]))}: the code "
                        f"{safe_finding_value(' and '.join(label(d) for d in others))} names, "
                        "not this row's. Give a value only to the channel whose code uses it, "
                        "and name that code."
                    ),
                    path=f"channels[{index}]",
                    values=(value,),
                )
            )
    # An endpoint two rows naming different code both give, bound to neither.
    rows_of: dict[str, list[int]] = {}
    for index, channel in enumerate(channels):
        for endpoint in channel.get("endpoints") or []:
            if str(endpoint).strip():
                rows_of.setdefault(str(endpoint).strip(), []).append(index)
    grouped: dict[tuple[int, ...], list[str]] = {}
    for endpoint, indexes in rows_of.items():
        rows = tuple(dict.fromkeys(indexes))
        if len(rows) < 2 or any(not own(i, endpoint) for i in rows):
            continue
        if len({frozenset(own(i, endpoint)) for i in rows}) < len(rows):
            continue
        forms, _written, _holders = beside.held(endpoint)
        if not forms or any(forms & own(i, endpoint) for i in rows):
            continue
        grouped.setdefault(rows, []).append(endpoint)
    for rows, endpoints in grouped.items():
        forms, written, holders = beside.held(endpoints[0])
        out.append(
            Violation(
                code=CHANNEL_BINDING_CODE,
                message=(
                    f"{safe_finding_value(' and '.join(label(i) for i in rows))} name "
                    "different code and both give "
                    f"{safe_finding_value(', '.join(json.dumps(e) for e in endpoints))}, held in "
                    f"{safe_finding_value(', '.join(holders[:3]))} beside the code at "
                    f"{safe_finding_value(', '.join(written[:4]))}, code neither row names. "
                    "Give an endpoint only to the channel whose code uses it; a channel whose "
                    "endpoints the "
                    "evidence does not name lists none."
                ),
                path="channels",
                values=tuple(endpoints),
            )
        )
    return out


# ---------------------------------------------------------------------------
# The values a composed section must carry
# ---------------------------------------------------------------------------

_CODE_SPAN = re.compile(r"`([^`\n]{2,120})`")
_ADDRESS_VALUE = re.compile(r"(?<![\w])0x[0-9a-fA-F]{2,16}(?![\w])")
_PATH_VALUE = re.compile(
    r"(?:[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\)[^\s\"'`,;()]+|(?<![\w.:/])/(?:[\w.-]+/)+[\w.-]*"
)
_REGISTRY_VALUE = re.compile(r"(?<![\w])HK(?:LM|CU|CR|U|CC|EY_[A-Z_]+)\\[^\s\"'`,;()]+")
_FILE_NAME = re.compile(
    r"(?<![\w.-])[\w.-]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|lnk|msi"
    r"|com|cpl|ocx|py|sh|elf|so|dylib|jar|apk)(?![\w-])",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_ORDINAL_CALL = re.compile(r"[^\s\"'`]+,#\d+")
_QUOTED_VALUE = re.compile(
    r"[\"\u201c]([^\"\u201d\n]{2,80})[\"\u201d]|(?<![\w])'([^'\n]{2,80})'(?![\w])"
)
# An identifier with a digit or an underscore in it (a mutex, an export, a
# routine's name), or an API-style name of two or more humps (CreateMutexW);
# an evidence id is a citation, not a value.
_IDENTIFIER_VALUE = re.compile(
    r"(?<![\w])(?!ev_\d)(?=[A-Za-z0-9_]*[_\d])(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z_][A-Za-z0-9_]{3,}(?![\w])"
    r"|(?<![\w])[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*){2,}[A-Za-z0-9]*(?![\w])"
)
# A quoted ordinary word ('sample', "Marks") is no value.
_ORDINARY_WORD = re.compile(r"^[A-Za-z][a-z]+$")
# Algorithm, encoding and platform names that are no value of the sample's own.
_GENERIC_TOKENS = frozenset(
    {
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "md5",
        "crc32",
        "base64",
        "base32",
        "base85",
        "win32",
        "win64",
        "x86_64",
        "x86",
        "x64",
        "amd64",
        "arm64",
        "aes128",
        "aes192",
        "aes256",
        "rc4",
        "utf8",
        "utf_8",
        "utf16",
        "utf_16",
        "ipv4",
        "ipv6",
    }
)
# A run of citations with the space before each. The space opens a match only where no
# space stands before it, so a long run of spaces is walked once, not from each of them.
_CITATIONS = re.compile(r"(?:(?<!\s)\s*[\[(]\s*ev_\d+(?:\s*[,;]\s*ev_\d+)*\s*[\])])+")


@dataclass(frozen=True)
class ValueReader:
    """What counts as a value of the sample's own in a text, for one report.

    ``sample`` is the run's entry texts in :func:`carrying_form` (the tool
    outputs and the evidence tables the report holds); an identifier or a quoted
    string is a value only where it occurs there, and with no entry text at
    all every one is. ``family`` is the family the report attributes, a value
    wherever the text names it.
    """

    sample: str = ""
    family: str = ""

    @classmethod
    def of(cls, report: MalwareReport) -> ValueReader:
        return cls(sample=carrying_form(sample_text(report)), family=attributed_family(report))

    def __call__(self, text: str) -> list[str]:
        return carried_values(text, self)


def attributed_family(report: MalwareReport) -> str:
    """The family the report attributes, or ``""``."""
    family = str(getattr(report.attribution, "family", "") or "").strip()
    return family if family.lower() not in ("", "unknown", "none") else ""


def sample_text(report: MalwareReport) -> str:
    """The run's entry texts as the report holds them: every tool output and evidence table."""
    parts: list[str] = []
    for rows in (report.technical_evidence or {}).values():
        for row in rows or []:
            if isinstance(row, Mapping):
                parts.append(str(row.get("output") or ""))
    for section in report.sections:
        parts.extend(" ".join(str(cell) for cell in row) for row in section.rows)
    record = report.emulated_strings
    if record is not None:
        parts.extend([*record.values, *record.plain, *record.spelled.values()])
    return "\n".join(parts)


def carried_values(text: str, reader: ValueReader | None = None) -> list[str]:
    """The values ``text`` names, once each, in order: what a sentence that replaces it carries.

    Always a value: the hosts and addresses the unpublished-value check reads
    (``validation.network_values_in``), each email and its domain, code span,
    routine address, file path, registry key, file name with an executable or
    script extension, ordinal call (``x.dll,#1``), and the attributed family
    the text names. A value where the run's entries hold it (``reader``): a
    quoted string that is no ordinary word, and an identifier with a digit or
    an underscore or of two or more humps. Never: an ATT&CK id, or a generic
    algorithm, encoding or platform name (``SHA256``, ``Win32``).
    """
    from malspark.pipeline.validation import network_values_in

    reader = reader or ValueReader()
    plain = _CITATIONS.sub("", str(text or ""))
    found: list[str] = [value for _kind, value in network_values_in(plain)]
    for match in _EMAIL.finditer(plain):
        found.extend([match.group(0), match.group(1)])
    for pattern in (
        _CODE_SPAN,
        _ADDRESS_VALUE,
        _PATH_VALUE,
        _REGISTRY_VALUE,
        _FILE_NAME,
        _ORDINAL_CALL,
    ):
        for match in pattern.finditer(plain):
            value = (match.group(1) if match.groups() else match.group(0)).strip()
            # A sentence's own stop is no part of a path, key or file name.
            if pattern in (_PATH_VALUE, _REGISTRY_VALUE, _FILE_NAME):
                value = value.rstrip(".,:;")
            found.append(value)
    if reader.family and re.search(rf"(?i)(?<![\w]){re.escape(reader.family)}(?![\w])", plain):
        found.append(reader.family)
    sampled: list[str] = []
    for match in _QUOTED_VALUE.finditer(plain):
        quoted = (match.group(1) or match.group(2) or "").strip()
        # An ordinary word quoted is no value, unless the run's entries hold it
        # (a key or a password literal the sample carries).
        ordinary = bool(_ORDINARY_WORD.match(quoted)) and not (
            reader.sample and carrying_form(quoted) in reader.sample
        )
        if quoted and not ordinary:
            sampled.append(quoted)
    sampled.extend(m.group(0) for m in _IDENTIFIER_VALUE.finditer(plain))
    for value in sampled:
        if reader.sample and carrying_form(value) not in reader.sample:
            continue
        found.append(value)
    return [
        value
        for value in dict.fromkeys(found)
        if len(value) >= 2 and not _is_attack_id(value) and value.lower() not in _GENERIC_TOKENS
    ]


def _is_attack_id(value: str) -> bool:
    """Whether ``value`` is an ATT&CK technique or tactic id, in either case: no value."""
    upper = value.upper()
    return is_technique_id(upper) or TACTIC_ID_RE.match(upper) is not None


def carrying_form(text: str) -> str:
    """``text`` as values are looked for in it: refanged, unescaped, without marks, lower case."""
    plain = str(text or "")
    for written, value in (("[.]", "."), ("[@]", "@"), ("[:]", ":"), ("hxxp", "http")):
        plain = plain.replace(written, value)
    return re.sub(r"[`*\\]", "", plain).lower()


def values_not_carried(values: Sequence[str], text: str, *, formed: bool = False) -> list[str]:
    """The values of ``values`` that ``text`` does not hold, compared as :func:`carrying_form`.

    ``formed`` says ``text`` is in that form already, read once by its caller.
    """
    held = text if formed else carrying_form(text)
    return [value for value in values if carrying_form(value) not in held]


def evidence_text(bundle: Mapping[str, Any]) -> str:
    """The sample's own evidence a section is shown: its tool outputs and its functions' code.

    What the style check exempts a phrasing by (a sample's or a tool's term):
    never the headings, the instructions, the facts, the run state or a claim.
    """
    parts = [str(t.get("output") or "") for t in bundle.get("tool_outputs") or []]
    parts.extend(str(row.get("output") or "") for row in bundle.get("function_code") or [])
    return "\n".join(parts)


def summary_value_violations(
    payload: Any, findings: str, held: str, reader: ValueReader | None = None
) -> list[Violation]:
    """Values the key findings and the summary paragraph name that the bullets carry not, nor
    anything else the report held before the composer ran (``held``)."""
    bullets = " ".join(str(row.get("text") or "") for row in _rows(payload, "bullets"))
    if not bullets.strip():
        return []
    named = carried_values(findings, reader)
    dropped = values_not_carried(values_not_carried(named, bullets), held)
    if not dropped:
        return []
    return [
        Violation(
            code=VALUE_NOT_CARRIED_CODE,
            message=(
                "The key findings name "
                f"{safe_finding_value(', '.join(dropped[:8]))}, which no bullet carries and "
                "the report states nowhere else. Carry each in the bullet of its capability."
            ),
            path="bullets",
            values=tuple(dropped),
        )
    ]


def procedure_value_violations(
    payload: Any,
    firsts: Mapping[str, str | BehaviourUnits],
    reader: ValueReader | None = None,
) -> list[Violation]:
    """A procedure that carries the identifying values of none of its technique's claims.

    ``firsts`` holds, for each published technique, the units of each of its
    claims that name the technique's behaviour (:func:`first_claim_sentences`;
    a plain text is one claim of one unit). Each claim is read as the unit that
    shares the most identifying values with the procedure, then names most of
    the technique, then says it is so, then stands first. The procedure stands when it carries every
    identifying value (:func:`identifying_values`) of one claim's unit; else it
    is asked for what it drops of the unit it shares the most with, the
    earliest claim on a tie. A claim whose unit names no identifying value
    grounds nothing, unless no claim's unit names one.
    """
    out: list[Violation] = []
    for index, row in enumerate(_rows(payload, "procedures")):
        tid = str(row.get("technique_id") or "").strip().upper()
        units = firsts.get(tid, "")
        claims = units.claims if isinstance(units, BehaviourUnits) else ((_Unit(units),),)
        held = carrying_form(str(row.get("procedure") or ""))
        read: list[tuple[list[str], list[str]]] = []
        for candidates in claims:
            best: tuple[tuple[int, int, int, int], list[str], list[str]] | None = None
            for unit in candidates:
                named = identifying_values(carried_values(unit.text, reader))
                dropped = values_not_carried(named, held, formed=True)
                # A part that says the behaviour is not so loses a tie, never
                # a procedure that carries its values.
                rank = (len(named) - len(dropped), not unit.negated, unit.score, -unit.index)
                if best is None or rank > best[0]:
                    best = (rank, named, dropped)
            if best is not None:
                read.append((best[1], best[2]))
        grounded = [(named, dropped) for named, dropped in read if named]
        if not grounded or any(not dropped for _named, dropped in grounded):
            continue
        _named, dropped = max(grounded, key=lambda pair: len(pair[0]) - len(pair[1]))
        out.append(
            Violation(
                code=VALUE_NOT_CARRIED_CODE,
                message=(
                    f"The procedure for {safe_finding_value(tid)} drops "
                    f"{safe_finding_value(', '.join(dropped[:6]))}, which its claim names "
                    "of the technique's behaviour. Carry the value that shows the procedure."
                ),
                path=f"procedures[{index}].procedure",
                values=tuple(dropped),
            )
        )
    return out


_NUMBER_WORDS = {
    word: value
    for value, word in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve".split()
    )
}
_NUMBER = r"-?(?:0x[0-9a-f]+|\d+)\b|\b(?:" + "|".join(_NUMBER_WORDS) + r")\b"
# The numbers a check compares with: after a comparison word or sign, an
# equality ("equals", "is not", "returns"), before an "or higher"-like close,
# and a record field's offset written "+0x194". A number joined to a word by a
# hyphen ("is 32-bit") is part of that word.
_COMPARED = r"(" + _NUMBER + r")(?!-\w)"
_COMPARED_NUMBER = re.compile(
    r"\b(?:below|above|under|over|exceeds?|exceeding|(?:less|more|greater|fewer|longer|shorter"
    r"|larger|smaller|higher|lower)\s+than|at\s+(?:least|most)|up\s+to|equals?|equal\s+to)\s+"
    + _COMPARED
    + r"|(?:[<>]=?)\s*"
    + _COMPARED
    + r"|\b"
    + _COMPARED
    + r"\s+or\s+(?:higher|more|greater|above|later|lower|less|fewer|below)\b"
    r"|\+\s*(0x[0-9a-f]+)\b"
    # The bare forms last, as their own groups: a 0, 1 or -1 they compare with is a
    # truth value or a status unless a counted noun stands before them.
    r"|((?:\b(?:is(?:\s+not)?|returns?)\s+|[!=]=\s*))" + _COMPARED,
    re.IGNORECASE,
)
# The last two groups of :data:`_COMPARED_NUMBER`: a bare comparison and its number.
_BARE_GROUP = 5
# A noun that counts what it is compared with, alone or with what it counts
# ("the processor count is 1", "the number of monitors is 1").
_COUNTED_NOUN = re.compile(
    r"\b(?:count|number|total|size|length|amount|quantity)(?:\s+of\s+\w+)?\s*$",
    re.IGNORECASE,
)
_TRUTH_VALUES = frozenset({-1, 0, 1})
_ANY_NUMBER = re.compile(r"(?<![\w.])(?:" + _NUMBER + r")", re.IGNORECASE)
# A claim clause that states a check: the code fails, exits, aborts, stalls,
# terminates, quits, halts, stops or bails out, returns failure, a null or a
# number, or calls an API whose name says it ends a process or a thread (a
# name that opens on Exit or Terminate, after a native prefix: ExitProcess,
# NtTerminateProcess; never GetExitCodeThread), on a condition;
# or, the condition first, a condition comparing with a number and then such an
# outcome. A condition that is itself a failure ("returns 0 if an append
# fails") is an error path, not a check.
_OUTCOME = (
    r"(?:\b(?:fail(?:s|ed|ure)?|exit(?:s|ed)?|abort(?:s|ed)?|stall(?:s|ed)?"
    r"|terminat(?:e|es|ed)|quit(?:s)?|halt(?:s|ed)?|stop(?:s|ped)?|bail(?:s|ed)?"
    r"|return(?:s|ed)?\s+(?:failure|false|null|zero|nonzero|-?(?:0x[0-9a-f]+|\d+)))(?![\w-])"
    r"|(?-i:\b(?:Nt|Zw|Rtl)?(?:Exit|Terminate)[A-Z]\w*))"
)
_CONDITION = r"\b(?:when|whenever|if|unless)\b"
_OUTCOME_FIRST = re.compile(_OUTCOME + r"[^.;]{0,160}?" + _CONDITION, re.IGNORECASE)
_FAILURE_WORD = re.compile(r"\bfail", re.IGNORECASE)
_CONDITION_FIRST = re.compile(_CONDITION + r"([^.;]{0,160}?)(" + _OUTCOME + ")", re.IGNORECASE)
# Where a claim's clause ends: a semicolon, or a step of a chain (", then").
_CLAUSE_END = re.compile(r";|,\s+(?:and\s+)?then\b", re.IGNORECASE)
# A clause that opens on a word pointing back takes the code of the sentence before it.
_POINTS_BACK = re.compile(r"^(?:it|its|this|that|these|they|their|the\s+routine)\b", re.IGNORECASE)
# The words before an address that make it a value, not code: a slot, a size, a
# flag or another datum ("slot 0x10c38", "size 0x130"), past a determiner; and a
# value written in brackets after a constant's name ("GENERIC_WRITE (0x40000000)").
_VALUE_NOUNS = frozenset(
    {
        "slot",
        "slots",
        "size",
        "length",
        "flag",
        "flags",
        "value",
        "values",
        "constant",
        "mask",
        "key",
        "seed",
        "id",
        "ordinal",
        "field",
        "option",
        "options",
        "access",
        "disposition",
        "mode",
        "type",
        "class",
        "magic",
    }
)
_DETERMINERS = frozenset({"the", "a", "an", "its", "this", "that"})
_WORD_BEFORE = re.compile(r"([A-Za-z_][\w]*)\W*$")
_CONSTANT_NAME = re.compile(r"^[A-Z][A-Z0-9]*_[A-Z0-9_]+$")


def _number_value(text: str) -> int | None:
    word = text.strip().lower()
    if word in _NUMBER_WORDS:
        return _NUMBER_WORDS[word]
    negative = word.startswith("-")
    digits = word.lstrip("-")
    try:
        value = int(digits, 16) if digits.startswith("0x") else int(digits)
    except ValueError:
        return None
    return -value if negative else value


@dataclass(frozen=True)
class _Check:
    """What one claim states of a check: the code it names, and the values it tests."""

    places: frozenset[int]
    names: tuple[str, ...]
    numbers: tuple[tuple[str, int], ...]
    said: str


@dataclass(frozen=True)
class _Clause:
    """One check clause of a claim: its words from its subject on, its condition,
    and the code it is about."""

    text: str
    condition: str
    places: frozenset[int]
    # The words of the sentence before that a clause pointing back reads its
    # called functions from.
    borrowed: str = ""


def _check_clauses(text: str) -> list[_Clause]:
    """The clauses of ``text`` that state a check.

    A clause is a sentence's part up to a semicolon or a chain's ", then". It
    states a check when the code fails, exits or ends on a condition
    (:data:`_OUTCOME_FIRST`), or on a condition that compares with a number
    (:data:`_CONDITION_FIRST`). Its subject is the last code it names before the
    outcome (:func:`_code_places`), and it is read from there on, so another
    routine the clause names first is not its code ("0x401a00 decrypts the
    configuration and 0x402b10 exits if …"); the code its condition names is its
    code too. A check written in brackets is an aside of the clause, and is read
    alone; a clause naming no code before its outcome that opens on a word
    pointing back ("It returns failure when …") takes the code the sentence before
    it names and the functions it calls (:func:`_called_names`), nothing else.
    """
    out: list[_Clause] = []
    previous = ""
    for sentence in sentences(text):
        for clause in _CLAUSE_END.split(sentence):
            clause = clause.strip(" ,")
            found = None
            condition = ""
            for m in _OUTCOME_FIRST.finditer(clause):
                if not _FAILURE_WORD.search(clause, m.end()):
                    found, condition = m, clause[m.end() :]
                    break
            if found is None:
                for m in _CONDITION_FIRST.finditer(clause):
                    if _COMPARED_NUMBER.search(m.group(1)):
                        found, condition = m, m.group(1)
                        break
            if found is None:
                continue
            start, stop = 0, len(clause)
            opened = clause.rfind("(", 0, found.start())
            if opened > clause.rfind(")", 0, found.start()):
                closed = clause.find(")", found.end())
                start, stop = opened + 1, closed if closed != -1 else len(clause)
                condition = condition[: max(0, stop - found.end())]
            outcome_at = found.start() if found.re is _OUTCOME_FIRST else found.start(2)
            subject = _last_code_place(clause[start:outcome_at])
            places = _code_places(condition)
            if subject is not None:
                places.add(subject[0])
                start += subject[1]
            elif _POINTS_BACK.match(clause[start:]) and previous:
                places |= _code_places(previous)
                out.append(_Clause(clause[start:stop], condition, frozenset(places), previous))
                continue
            out.append(_Clause(clause[start:stop], condition, frozenset(places)))
        previous = sentence
    return out


def _check_of(claim: str) -> _Check | None:
    """The check ``claim`` states, or ``None`` for a claim that states none.

    Read from its check clauses (:func:`_check_clauses`) alone: the code they are
    about, or, where no clause names any, the code the claim names; the functions
    the clauses call from their subject on, and those of the sentence before a
    clause pointing back (:func:`_called_names`); and the numbers their conditions
    compare with. A claim that names no code, or whose check clauses carry no such
    value, states none.
    """
    text = _CITATIONS.sub("", str(claim or ""))
    # The claim's own words, not the evidence it lists after its dash.
    text = re.split(r"\s+—\s+", text, maxsplit=1)[0]
    clauses = _check_clauses(text)
    if not clauses:
        return None
    said = " ".join(clause.text for clause in clauses)
    # A condition written before the subject ("If GetSystemInfo reports …, 0x5500
    # exits") is read for names too.
    named = " ".join(
        [said, *(c.condition for c in clauses if c.condition and c.condition not in c.text)]
    )
    places: set[int] = set().union(*(clause.places for clause in clauses))
    if not places:
        places = _code_places(text)
    if not places:
        return None
    names = tuple(
        dict.fromkeys(
            [
                *_called_names(named),
                *(
                    _called_names(clause.borrowed)[-1]
                    for clause in clauses
                    if clause.borrowed and _called_names(clause.borrowed)
                ),
            ]
        )
    )
    numbers: dict[int, str] = {}
    for clause in clauses:
        for match in _COMPARED_NUMBER.finditer(clause.condition):
            bare = match.group(_BARE_GROUP) is not None
            written = (
                match.group(_BARE_GROUP + 1)
                if bare
                else next(group for group in match.groups()[: _BARE_GROUP - 1] if group)
            )
            value = _number_value(written)
            if value is None:
                continue
            # A 0, 1 or -1 a bare "is", "returns" or "==" tests is a truth value or
            # a status, which any wording of the branch carries ("returns 0 when …"),
            # unless a counted noun stands before it ("the processor count is 1").
            if (
                bare
                and value in _TRUTH_VALUES
                and not _COUNTED_NOUN.search(clause.condition[: match.start()])
            ):
                continue
            numbers.setdefault(value, written)
    if not names and not numbers:
        return None
    return _Check(
        places=frozenset(places),
        names=names,
        numbers=tuple((written, value) for value, written in numbers.items()),
        said=said,
    )


def _called_names(text: str) -> list[str]:
    """The API-style names ``text`` carries (``claim_coverage.code_names``) that it
    speaks of as functions, in order: not one written only as an argument inside
    another call's brackets (``IsWow64Process(GetCurrentProcess())`` calls
    IsWow64Process, and GetCurrentProcess only supplies its argument)."""
    from malspark.reporting.claim_coverage import code_names

    out: list[str] = []
    for (kind, _value), written in code_names(text).items():
        if kind != "name":
            continue
        spots = [m.start() for m in re.finditer(rf"(?<![\w]){re.escape(written)}(?![\w])", text)]
        if spots and all(_inside_a_call(text, at) for at in spots):
            continue
        out.append(written)
    return out


def _inside_a_call(text: str, at: int) -> bool:
    """Whether ``at`` stands inside the brackets of a call: an open bracket before it,
    not closed before it, written right after a name (no space, no address)."""
    depth = 0
    for index in range(at - 1, -1, -1):
        char = text[index]
        if char == ")":
            depth += 1
        elif char == "(":
            if depth:
                depth -= 1
                continue
            # A call writes its name right before the bracket; a note in brackets
            # after an address or a word ("0x68e8 (GetAdaptersInfo)") is no call.
            name = re.search(r"([A-Za-z_]\w*)$", text[:index])
            return name is not None and not re.fullmatch(r"0x[0-9a-fA-F]+", name.group(1))
    return False


def _places_in(text: str) -> set[int]:
    """The code locations ``text`` names, by value (``claim_coverage``'s reading)."""
    from malspark.reporting.claim_coverage import _address, _address_re

    return {_address(m.group(1)) for m in _address_re().finditer(text)}


def _code_place_matches(text: str) -> Iterator[re.Match[str]]:
    """The address matches of ``text`` that are code (:func:`_code_places`)."""
    from malspark.reporting.claim_coverage import _address_re

    for m in _address_re().finditer(text):
        before = text[: m.start()]
        words = before.split()
        while words and words[-1].lower().strip("(,") in _DETERMINERS:
            words.pop()
        word = _WORD_BEFORE.search(" ".join(words))
        last = word.group(1) if word else ""
        if last.lower() in _VALUE_NOUNS:
            continue
        if before.rstrip().endswith("(") and _CONSTANT_NAME.match(last):
            continue
        yield m


def _code_places(text: str) -> set[int]:
    """The code locations ``text`` names (:func:`_places_in`), but for an address the
    word before it makes a value: a slot, a size, a flag or another datum, past a
    determiner (``slot 0x10c38``), or a constant's name it is written beside in
    brackets (``GENERIC_WRITE (0x40000000)``), as an address another noun governs is
    no routine where the agreement round reads a sentence's subject."""
    from malspark.reporting.claim_coverage import _address

    return {_address(m.group(1)) for m in _code_place_matches(text)}


def _last_code_place(text: str) -> tuple[int, int] | None:
    """The last code location ``text`` names, with where it starts, or ``None``."""
    from malspark.reporting.claim_coverage import _address

    last = None
    for m in _code_place_matches(text):
        last = (_address(m.group(1)), m.start())
    return last


def _names_place(places: set[int], wanted: frozenset[int]) -> bool:
    from malspark.reporting.claim_coverage import _same_place

    return any(_same_place(one, other) for one in places for other in wanted)


def _answer_units(payload: Any) -> list[tuple[str, str, str]]:
    """The answer's texts a check is looked for in: ``(path, text, technique id)``.

    A flow step's action; in a prose body, each sentence that names code with the
    sentences after it up to the next one naming other code ("Routine 0x3868 runs
    the gates. It exits when …"); and each procedure with its technique.
    """
    units: list[tuple[str, str, str]] = []
    for index, row in enumerate(_rows(payload, "steps")):
        units.append((f"steps[{index}].action", str(row.get("action") or ""), ""))
    body = payload.get("body") if isinstance(payload, Mapping) else None
    if isinstance(body, str):
        group: list[str] = []
        named: set[int] = set()
        for sentence in sentences(body):
            places = _places_in(sentence)
            if places and group and not places <= named:
                units.append(("body", " ".join(group), ""))
                group, named = [], set()
            group.append(sentence)
            named |= places
        if group:
            units.append(("body", " ".join(group), ""))
    for index, row in enumerate(_rows(payload, "procedures")):
        tid = str(row.get("technique_id") or "").strip().upper()
        units.append((f"procedures[{index}].procedure", str(row.get("procedure") or ""), tid))
    return units


# How many values one question names; the rest are counted.
_NAMED_VALUES = 8


def check_value_violations(
    payload: Any, claims: Sequence[str] | Mapping[str, Sequence[str]]
) -> list[Violation]:
    """A text that names the code of a check a claim it was shown states, without what it tests.

    ``claims`` are the claims the section was shown, or, for the ATT&CK
    procedures, each published technique's claims by its id (a procedure is
    held to its own technique's claims). A claim that states a check
    (:func:`_check_of`) is read against the texts of the answer that name its
    code (:func:`_answer_units`): each API-style name and compared number it
    states that none of those texts carries is asked for, as one question per
    claim. A number is carried in any base or as a small number word, wherever
    it stands in those texts, so a number the text writes for another reason
    (a step's "flags 6") carries a check's 6 as well; a name in any case. A
    claim whose code the answer does not name is not asked about: where its
    check belongs is the model's to decide, and the report lists a claim the
    body leaves out (``claim_coverage``). A question on the same text and the
    same code that asks for no more than another is asked once.

    Known limitation: a check that compares a string ("exits if the user name
    equals 'sandbox'", "if the MAC prefix matches 08:00:27") carries no API-style
    name or number to read, and is not asked about.
    """
    units = _answer_units(payload)
    if not units:
        return []
    by_technique = isinstance(claims, Mapping)
    read: list[tuple[str, str, set[int], set[int]]] = [
        (
            path,
            carrying_form(text),
            _places_in(text),
            {
                value
                for m in _ANY_NUMBER.finditer(text)
                if (value := _number_value(m.group(0))) is not None
            },
        )
        for path, text, _tid in units
    ]
    groups: list[tuple[list[int], Sequence[str]]]
    if isinstance(claims, Mapping):
        groups = []
        for tid, own in claims.items():
            rows = [i for i, unit in enumerate(units) if unit[2] == str(tid).upper()]
            if rows:
                groups.append((rows, own))
    else:
        groups = [(list(range(len(units))), claims)]
    found: list[tuple[int, str, str, _Check, list[str], frozenset[str | int]]] = []
    for rows, own in groups:
        for claim in own:
            check = _check_of(claim)
            if check is None:
                continue
            naming = [read[i] for i in rows if _names_place(read[i][2], check.places)]
            if not naming:
                continue
            held = " ".join(text for _path, text, _places, _numbers in naming)
            numbers = set().union(*(numbers for *_rest, numbers in naming))
            names = [name for name in check.names if carrying_form(name) not in held]
            dropped = [(written, value) for written, value in check.numbers if value not in numbers]
            if not names and not dropped:
                continue
            found.append(
                (
                    len(found),
                    naming[0][0],
                    ", ".join(dict.fromkeys(path for path, *_rest in naming)),
                    check,
                    [*names, *(written for written, _value in dropped)],
                    frozenset([name.lower() for name in names] + [v for _w, v in dropped]),
                )
            )
    # A claim asking a text for no more than another claim asks of it about the
    # same code is not asked again; the larger question is kept, whichever came first.
    kept: list[tuple[int, str, str, _Check, list[str], frozenset[str | int]]] = []
    for row in sorted(found, key=lambda r: -len(r[5])):
        if not any(
            row[1] == other[1] and row[3].places == other[3].places and row[5] <= other[5]
            for other in kept
        ):
            kept.append(row)
    out: list[Violation] = []
    for _order, path, where, check, missing, _wanted in sorted(kept, key=lambda r: r[0]):
        listed = ", ".join(missing[:_NAMED_VALUES])
        if len(missing) > _NAMED_VALUES:
            listed += f" and {len(missing) - _NAMED_VALUES} more"
        out.append(
            Violation(
                code=VALUE_NOT_CARRIED_CODE,
                message=(
                    f"The text at {safe_finding_value(where)} names code of which a claim you "
                    f"were shown states a check: {safe_finding_value(quoted_claim(check.said))}. "
                    f"It does not carry {safe_finding_value(listed)}, what that check tests. "
                    "Where the text describes that check, carry each value it tests, or say "
                    "why the evidence does not hold it; where it names the code for another "
                    "reason, keep it as it is."
                    + (" Hold each procedure to its own technique." if by_technique else "")
                ),
                path=path,
                values=tuple(missing),
            )
        )
    return out


def shown_claim_texts(bundle: Mapping[str, Any]) -> list[str]:
    """The words of each claim a section's bundle shows it, in order."""
    return [
        str(row.get("claim") or "")
        for row in bundle.get("claims") or []
        if isinstance(row, Mapping) and str(row.get("claim") or "").strip()
    ]


def quoted_claim(text: str, limit: int = 300) -> str:
    """A claim's words as a question quotes them: on one line, cut at ``limit``."""
    flat = " ".join(str(text or "").split())
    if len(flat) > limit:
        flat = flat[: limit - 1].rstrip() + "…"
    return json.dumps(flat, ensure_ascii=False)


@dataclass(frozen=True)
class _Unit:
    """One part of a claim a procedure may be held to: its text, how many words of the
    technique's name it names, and its place in the claim."""

    text: str
    score: int = 0
    index: int = 0
    # Whether its sentences naming the behaviour all say it is not so.
    negated: bool = False


@dataclass(frozen=True)
class BehaviourUnits:
    """A technique's claims, each as the units of it that name the technique's behaviour."""

    claims: tuple[tuple[_Unit, ...], ...]


def first_claim_sentences(report: MalwareReport) -> dict[str, BehaviourUnits]:
    """Each published technique's claims, each as the units that name its behaviour.

    A claim often covers several behaviours, and several techniques can share
    one, so a procedure is held to the part of a claim that is its own
    (:func:`behaviour_units`), never to whatever the claim states first; and a
    procedure may show the technique by any of its claims.
    """
    published = published_techniques(report)
    ids = {tid.upper() for tid in published}
    out: dict[str, BehaviourUnits] = {}
    for tid, (name, claims, _refs) in published.items():
        if claims:
            out[tid.upper()] = BehaviourUnits(
                tuple(behaviour_units(tid, name, claim, ids) for claim in claims)
            )
    return out


# A technique name's words that name no behaviour of their own.
_NAME_FILLER = frozenset(
    {"and", "or", "the", "of", "for", "with", "from", "via", "to", "a", "an", "in", "on", "by"}
    | {"information", "file", "files", "system", "data", "windows", "protocol", "protocols"}
    | {"name", "names", "match", "legitimate", "location", "discovery", "execution"}
)
_BULLET = re.compile(r"^\s*[-*•]\s+")
# The endings a word of a technique's name and a word of a claim may differ by and
# still be one word ("process" and "processes", "deletion" and "deletes").
_ENDINGS = frozenset(
    {"", "s", "es", "d", "ed", "r", "er", "ers", "ing", "ings", "e", "y", "ies", "ied"}
    | {"ion", "ions", "ation", "ations"}
)
# A sentence that says a thing is not so: the behaviour it names is not the
# technique's procedure while another unit names one.
# A verb's negation only: "with no visible window" says how the behaviour is done.
_NEGATION = re.compile(r"\b(?:not|never|cannot)\b|n't\b", re.IGNORECASE)


def _claim_units(claim: str) -> list[str]:
    """``claim``'s units, without citations or its number: each list item whole, the
    text between them by sentence."""
    text = re.sub(r"^\s*\d{1,3}\.\s+", "", _CITATIONS.sub("", str(claim or "")))
    out: list[str] = []
    prose: list[str] = []
    for line in [*text.splitlines(), "- "]:
        if not _BULLET.match(line):
            prose.append(line)
            continue
        out.extend(sentences(" ".join(" ".join(prose).split())))
        prose = []
        # A list item is one behaviour with the words that name it ("... That is T1018.").
        item = " ".join(_BULLET.sub("", line).split())
        if item:
            out.append(item)
    return out


def _words(text: str) -> list[str]:
    """``text``'s words in lower case, an identifier split at its humps (``GetUserNameA``
    is get, user, name, a)."""
    out: list[str] = []
    for token in re.findall(r"[A-Za-z0-9]+", str(text or "")):
        out.extend(part.lower() for part in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", token))
    return out


def _same_word(word: str, other: str) -> bool:
    """Whether a word of a claim is a word of the technique's name: the two agree from
    their first letter on (at least five letters, or the whole of a shorter name word)
    and differ only by an ending ("Toolhelp" is no "tool", "procedure" no "process")."""
    common = 0
    for a, b in zip(word, other, strict=False):
        if a != b:
            break
        common += 1
    if common < min(5, len(word)):
        return False
    return word[common:] in _ENDINGS and other[common:] in _ENDINGS


def _name_words(name: str) -> list[str]:
    return list(dict.fromkeys(w for w in _words(name) if len(w) >= 4 and w not in _NAME_FILLER))


def _name_score(text: str, words: Sequence[str]) -> int:
    """How many of the technique name's ``words`` ``text`` names."""
    said = set(_words(text))
    return sum(1 for word in words if any(_same_word(word, other) for other in said))


def _negated(unit: str, names: Callable[[str], bool]) -> bool:
    """Whether every sentence of ``unit`` that ``names`` the behaviour says it is not so."""
    naming = [s for s in sentences(unit) or [unit] if names(s)]
    return bool(naming) and all(_NEGATION.search(s) for s in naming)


def behaviour_units(
    tid: str, name: str, claim: str, published: Collection[str] = ()
) -> tuple[_Unit, ...]:
    """The units of ``claim`` that name technique ``tid``'s behaviour, best first.

    The units naming ``tid`` itself, unless one names another published
    technique too (``published``): that is a remark on the mapping ("only
    T1027/T1140 are kept"). Else the clauses (:func:`_clauses`) naming words of
    the technique's name (:func:`_same_word`), most first: one item of a list of
    commands, not the list. A unit whose sentences naming the behaviour all say
    it is not so ("does not delete itself", "was not run") is marked
    ``negated``: it stays a candidate, losing a tie to one that says the
    behaviour is so; the units naming ``tid`` stand alone only when one of them
    is not negated. A claim that names neither offers its first sentence, and
    its first sentence that says no "not" where that is another.
    """
    units = _claim_units(claim)
    if not units:
        return ()
    own = tid.upper()
    others = {str(t).upper() for t in published} - {own}

    def _names_id(text: str) -> bool:
        return own in {m.upper() for m in _TECHNIQUE_IN_TEXT.findall(text)}

    by_id = [
        _Unit(unit, 0, at, _negated(unit, _names_id))
        for at, unit in enumerate(units)
        if _names_id(unit) and not {m.upper() for m in _TECHNIQUE_IN_TEXT.findall(unit)} & others
    ]
    words = _name_words(name)
    clauses = [clause for unit in units for clause in _clauses(unit)]
    by_name = [
        _Unit(clause, score, at, _negated(clause, lambda s: _name_score(s, words) > 0))
        for at, clause in enumerate(clauses)
        if (score := _name_score(clause, words))
    ]
    if any(not unit.negated for unit in by_id):
        return tuple(by_id)
    if by_name or by_id:
        return (*by_name, *by_id)
    # The first sentence, and the first saying no "not" where that is another:
    # a "cannot" in a subordinate clause never pushes the first one out.
    first = _Unit(units[0], 0, 0, bool(_NEGATION.search(units[0])))
    plain = next((unit for unit in units if not _NEGATION.search(unit)), None)
    return (first, *([_Unit(plain, 0, 1)] if plain is not None and plain != units[0] else []))


def behaviour_sentence(tid: str, name: str, claim: str, published: Collection[str] = ()) -> str:
    """The unit of ``claim`` :func:`behaviour_units` puts first, read with no procedure:
    one saying the behaviour is so, then most words of the name, then the earliest."""
    units = behaviour_units(tid, name, claim, published)
    if not units:
        return ""
    return max(units, key=lambda unit: (not unit.negated, unit.score, -unit.index)).text


def _clauses(unit: str) -> list[str]:
    """``unit`` split at each semicolon outside parentheses, quotes and code spans."""
    out: list[str] = []
    depth, code, quoted, start = 0, False, False, 0
    for at, char in enumerate(unit):
        if char == "`":
            code = not code
        elif char == '"' and not code:
            quoted = not quoted
        elif char in "([{" and not (code or quoted):
            depth += 1
        elif char in ")]}" and not (code or quoted):
            depth = max(0, depth - 1)
        elif char == ";" and not (depth or code or quoted):
            out.append(unit[start:at])
            start = at + 1
    out.append(unit[start:])
    return [clause.strip() for clause in out if clause.strip()]


_TECHNIQUE_IN_TEXT = re.compile(rf"(?i)(?<![\w.]){ID_BODY}(?![\w]|\.\d)")
_SECTION_NAME = re.compile(r"^\.[A-Za-z0-9_$]{1,8}$")
_ARGUMENT_NAME = re.compile(r"(?i)^(?:arg|param|var|local)_?\d+$")
_BYTE_CONSTANT = re.compile(r"(?i)^0x[0-9a-f]{1,2}$")


def identifying_values(values: Sequence[str]) -> list[str]:
    """The values of ``values`` that identify a behaviour, in order.

    Never a section name or an extension (``.text``, ``.exe``) nor the same name
    without its dot when that is asked too (``UPX0`` beside ``.UPX0``), nor an
    argument name (``arg2``). A one-byte constant (``0x0e``) only where it is the
    unit's one identifying value (an XOR key ``0x5a`` alone stays).
    """
    dotted = {v[1:].lower() for v in values if _SECTION_NAME.match(v)}
    kept = [
        v
        for v in values
        if not _SECTION_NAME.match(v) and not _ARGUMENT_NAME.match(v) and v.lower() not in dotted
    ]
    wide = [v for v in kept if not _BYTE_CONSTANT.match(v)]
    return wide or kept


def held_text(report: MalwareReport) -> str:
    """What the report holds before the composer runs, but for the prose the summary replaces."""
    # The composer's own fields are left out too, so a replay over a stored
    # report reads what the round read before any section was written.
    dumped = report.model_dump(
        mode="json",
        exclude={
            "key_findings",
            "executive_summary",
            "capabilities_narrative",
            "technical_analysis",
            "intro_background",
            "c2_channels",
        },
    )
    return json.dumps(dumped, ensure_ascii=False)
