"""Render a ``MalwareReport`` to GitHub-flavoured markdown.

The renderer is pure-string — no markdown library is pulled in. The layout is
the one a vendor's single-family malware report uses: key findings and the
verdict on the first page, the technical analysis by capability with the
measured tables beside the prose they prove, the ATT&CK table and the
indicators together, and the run's own limitations before the appendices.

Three voices, and every heading says which one is speaking, with one of the
tags in :data:`VOICES`:

* **Measured** — what a tool returned, printed as the tool returned it, and
  what the platform recorded about the run itself.
* **Observed in sandbox** — what the sample did while a sandbox watched.
* **Assessed** — what a model concluded: the judge, an analyst, or the report
  model, each tagged by name. Printed as the model wrote it; the renderer adds
  the voice tag, the citations and a fixed word for a confidence number around
  it, and never rewrites the words. The one exception is how a network
  indicator is written inside prose — defanged — which changes how a value
  reads, never which value.

Every numbered section is printed. One that has nothing in this run says so in
one line, in the platform's voice, so a reader can tell "not found" from "not
looked at" and a citation to a section number always lands.

Severity badge convention: text in square brackets (``[CRITICAL]``,
``[HIGH]``, ...). Emoji are intentionally avoided so the output renders
cleanly on terminals, PDFs and ticket systems alike.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import math
import re
import secrets
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from functools import partial
from html.entities import html5
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel

from malspark.analysis.coverage import ABSENCE_POINTER as COVERAGE_POINTER
from malspark.analysis.coverage import LOOKED_INTRO as COVERAGE_LOOKED_INTRO
from malspark.analysis.coverage import NEGATIVES_INTRO as COVERAGE_NEGATIVES_INTRO
from malspark.analysis.coverage import NOT_ESTABLISHED_INTRO as COVERAGE_MISSING_INTRO
from malspark.analysis.coverage import coverage_lines
from malspark.analysis.disclosure import FOOTNOTE_SENTENCE as DISCLOSURE_FOOTNOTE
from malspark.analysis.disclosure import INTRO_SENTENCE as DISCLOSURE_INTRO
from malspark.analysis.disclosure import disclosure_lines, not_built_line
from malspark.analysis.efficiency import INTRO_SENTENCE as EFFICIENCY_INTRO
from malspark.analysis.efficiency import efficiency_lines
from malspark.analysis.isolation import intro_sentence as isolation_intro
from malspark.analysis.isolation import isolation_lines
from malspark.analysis.run_summary import (
    NEGOTIATION_CONFIDENCE_LABEL,
    NOT_APPLICABLE,
    NOT_APPLICABLE_PHRASE,
    NOT_APPLICABLE_SENTENCE,
    OPERATOR_CHOICES_HEADING,
    bundle_loss_sentence,
    corpus_held_sentence,
    generation_lines,
    server_rest_sentence,
    stage_durations,
    tokens_sentence,
)
from malspark.analysis.technique_ids import ID_BODY
from malspark.analysis.tool_effects import INTRO_SENTENCE as EFFECTS_INTRO
from malspark.analysis.tool_effects import effects_lines
from malspark.core.confidence_words import confidence_word
from malspark.core.logger import logger
from malspark.core.reputation import ReputationRecord, counts_line
from malspark.core.rule_matches import is_rule_fact
from malspark.core.undeclared_tools import (
    CODE_LISTING_KINDS,
    DECOMPILE_KINDS,
    CodePart,
    function_address,
    names_itself,
)
from malspark.reporting import tool_kinds
from malspark.reporting.category_words import category_shown
from malspark.reporting.dedupe import (
    distinct_processes,
    distinct_signatures,
    signature_identity_without_processes,
)
from malspark.reporting.defang import ProseDefanger, defang
from malspark.reporting.judge_reasons import (
    JUDGE_REASON_WIDTH,
    judge_reasons_shown,
    reasons_cut,
    status_cuts,
    status_parts,
)
from malspark.reporting.ledger_projection import (
    FORM_URL,
    NO_HOST_FORMS,
    cell_network_values,
    listing_kind,
    marks_of,
    path_or_host_form,
    stated_marks,
)
from malspark.reporting.ledger_report import (
    ANALYST_SECTION_SOURCES,
    BEHAVIOUR_CODE_PLAIN_WORDS,
    BEHAVIOUR_CODE_SAMPLE_COLUMNS,
    BEHAVIOUR_CODE_SECTION,
    CAPABILITIES_TITLE,
    RULE_TABLES,
    analyst_persistence,
    listed_by,
    rule_table_tools,
    section_key_of_kind,
)
from malspark.reporting.models import (
    CapabilityCell,
    ConsolidatedIOC,
    DetectionRule,
    DraftNotBuilt,
    LimitationInventory,
    MalwareReport,
    ProcessNode,
    RegistryMod,
    SandboxSignature,
    TechnicalSubsection,
    is_open_question_section,
    outcome_words,
    stated_family,
)
from malspark.reporting.prose_decisions import (
    CATEGORY_TYPE_UNSTATED_CODE,
    PUBLISHED_TECHNIQUE_DOUBTED_CODE,
    with_decided_statements,
)
from malspark.reporting.publish_words import NETWORK_INDICATOR_KINDS, PUBLISHED_NETWORK_LABEL
from malspark.reporting.redone_calls import ENTRY_ID
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, BUNDLE_FILES, FULL, checked
from malspark.reporting.renderers.prose_forms import (
    end_references,
    finished,
    references_for_render,
    section_reference,
    tidied,
)
from malspark.reporting.technique_evidence import (
    evidence_words,
    technique_evidence_ids,
    technique_sandbox_items,
)
from malspark.schemas.evidence import is_guard_answer
from malspark.schemas.isr_models import ABSENCE_TECHNIQUE_MARKER, UNVERIFIED_TECHNIQUE_MARKER
from malspark.utils.marked_cut import CUT_MARK

# ---------------------------------------------------------------------------
# Voices
# ---------------------------------------------------------------------------

MEASURED = "Measured"
OBSERVED = "Observed in sandbox"
ASSESSED = "Assessed"
JUDGE = "Assessed by the judge"
# A verdict no stage reached: the run stopped before its verdict stage ran.
NOT_ASSESSED = "Not assessed"
REPORT_MODEL = "Written by the report model"
GENERATED = "Generated by template"
PER_ROW = "Source per row"
PER_SUBSECTION = "Source per subsection"
REFERENCE = "Reference"

# How the one line of a section or subsection with nothing in the run begins.
# The HTML renderer reads it so no figure is placed under such a heading.
ABSENCE_PREFIXES: tuple[str, ...] = (
    "Not written in this run",
    "Not examined in this run",
    "Nothing recorded in this run",
    "Nothing generated in this run",
)

# Every tag a heading may carry. A test reads this and fails any H2 without one.
VOICES: frozenset[str] = frozenset(
    {
        MEASURED,
        OBSERVED,
        ASSESSED,
        JUDGE,
        NOT_ASSESSED,
        REPORT_MODEL,
        GENERATED,
        PER_ROW,
        PER_SUBSECTION,
        REFERENCE,
    }
)

# ---------------------------------------------------------------------------
# Confidence in words
# ---------------------------------------------------------------------------

# The word a number reads as, from the one table the judge is shown too
# (``core.confidence_words``).


def confidence_phrase(value: float | None, producer: str = "") -> str:
    """``high confidence, 0.92, stated by the judge``: the word, the number, the producer."""
    if value is None:
        return "not assessed"
    said = f"{confidence_word(value)}, {float(value):.2f}"
    return f"{said}, stated by {producer}" if producer else said


# Kill-chain order for the ATT&CK table, reconnaissance to impact.
_TACTIC_ORDER: tuple[str, ...] = (
    "TA0043",
    "TA0042",
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0011",
    "TA0010",
    "TA0040",
)

# The tools an absence line names first, as the ones that looked for behaviour:
# the kinds of ``CONSUMER_KINDS``, in this order.
_ANALYSIS_TOOLS = "markdown._ANALYSIS_TOOLS"


def _analysis_rank(row: Any) -> int:
    """Where an absence line names an entry's tool: the analysis kinds first, in order."""
    return tool_kinds.rank_in(row, _ANALYSIS_TOOLS)


def _looked_at_the_file(row: Any) -> bool:
    """Whether an entry's tool looked at the file itself: not a sandbox's, not a lookup.

    A declared tool is a sandbox's by its kind, and reads the sandbox report
    rather than the file when its declaration takes a ``report`` argument; a
    reputation lookup asks about the sample elsewhere. An entry with no
    source is read by its tool's name, as before.
    """
    by_name = tool_kinds.looked_at_the_file_by_name(row)
    if by_name is not None:
        return by_name
    # ``arguments`` is read without a kind: a declaration of no kind keeps it.
    return (
        not tool_kinds.is_of(row, _SANDBOX_TOOLS)
        and not tool_kinds.is_of(row, _REPUTATION_TOOLS)
        and "report" not in tool_kinds.kind_free_facts(row).arguments
    )


def _capability_rule_hit(hit: dict[str, Any]) -> bool:
    """Whether a technique hit came from a capability-rule tool (``capability_rules``).

    A hit carries the corroboration name of the tool that recorded it
    (``ToolFacts.source``); every tool declaring that kind names its own.
    """
    return tool_kinds.hit_of_kind(hit, "capability_rules")


def _is_sandbox_status(row: Any) -> bool:
    """Whether an entry is the pack's sentence about the sandbox rather than a call to one."""
    return tool_kinds.is_kind(row, "sandbox_status")


# What a sandbox signature or a rule has to name to be printed beside the
# anti-analysis prose and the API-resolution prose respectively.
_EVASION_WORDS = ("anti", "evas", "debug", "sandbox", "virtual", "vm")
_RESOLUTION_WORDS = ("hash", "peb", "resolv", "dynamic api")

# No cell of the body is cut: a value is printed whole in its row, and the
# page wraps it (the HTML stylesheet breaks a cell anywhere it must). Only
# Appendix A cuts a one-line value, and says under it where it is whole.

_EV_RE = re.compile(r"\bev_\d+\b")

# The tools whose ledger entries are a sandbox's, by their declared kinds.
_SANDBOX_TOOLS = "markdown._SANDBOX_TOOLS"

# Network indicator kinds, which the IOC section prints in its second table.
_NETWORK_KINDS = NETWORK_INDICATOR_KINDS

# The reputation tools a triage pack may call about the sample itself, by
# their declared kinds.
_REPUTATION_TOOLS = "markdown._REPUTATION_TOOLS"
_REPUTATION_KEYS = (
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "positives",
    "total",
    "popular_threat_label",
    "suggested_threat_label",
)

# What a sentence of the model's prose is said to rest on when it cites nothing.
_NO_CITATION = "_(no evidence cited)_"
_UNCITED_NOTE = (
    "_Written by the report model with no evidence cited; check it against the "
    "measured sections before quoting it._"
)


# The titles of the sections other sections send the reader to
# (``prose_forms.section_reference``): each heading and each reference read
# the one name, and the number is the rendered heading's.
LIMITATIONS_TITLE = "Limitations and analysis notes"
# The heading the bundle's limitations section lists the limitations inventory under.
INVENTORY_HEADING = "Measured limitations"
ANALYST_LIMITATIONS_TITLE = "Limitations"
INDICATORS_TITLE = "Indicators of compromise"
# The §9 table of the rows read from the file's strings that no reader the
# rule checks holds as the network value their form has (``reporting.string_row_form``).
FORM_ROWS_TITLE = "Text with a network value's form, read from the file"
STATIC_TITLE = "Static properties"


# The report model's prose subsections section 5 prints, by the subsection
# that prints them, in order. The one list the single-file report and the
# bundle print section 5's prose from, and the one the analyst report reads to
# know which prose the bundle prints whole (``prose_forms``).
SECTION_5_PROSE: dict[str, tuple[str, ...]] = {
    "5.1": ("packing_obfuscation", "evasion_antiforensics"),
    "5.2": ("string_resolution",),
    "5.4": ("persistence_detail",),
    "5.5": ("discovery",),
    "5.7": ("command_and_control", "message_packet_structure"),
    "5.8": ("payloads",),
}


# The passages the bundle's summary is written in, as the agreement question's records
# name them (``section_agreement.passages_of``): the summary paragraph and each key
# finding. The analyst report's summary also prints each capability bullet
# (:data:`SUMMARY_SUBJECTS`); the bundle prints none, so counts none.
BUNDLE_SUMMARY_SUBJECTS = ("executive_summary", "key_findings.")
SUMMARY_SUBJECTS = (*BUNDLE_SUMMARY_SUBJECTS, "capability_summary.")


def _section_5_prose(ta: Any, number: str) -> list[TechnicalSubsection | None]:
    """The prose subsections section ``number`` prints (:data:`SECTION_5_PROSE`)."""
    return [getattr(ta, name, None) for name in SECTION_5_PROSE[number]] if ta else []


class MarkdownRenderer:
    """Render a complete ``MalwareReport`` as a single markdown string.

    ``layout`` names which report (``renderers/layout.py``): the single-file
    report this renderer has always printed (the default), the analyst report
    (``renderers/analyst.py``) or the evidence bundle behind it
    (``renderers/bundle.py``). The closing defang and escape pass is the same
    for all three.
    """

    # Section order is kept in one place; each ``_section_*`` call returns
    # a block with one heading and its subsections, or "" when it has nothing.

    def __init__(self, *, failed_marker: str = "", layout: str = FULL) -> None:
        # The word a failed section's stub carries (:meth:`_safe_section`);
        # empty for the Markdown export, which prints the stub as it always did.
        self._failed_marker = failed_marker
        self._layout = checked(layout)

    def render(self, report: MalwareReport) -> str:
        return self.render_with_notes(report)[0]

    def render_with_notes(self, report: MalwareReport) -> tuple[str, list[Any]]:
        """The report, and the citation notes the analyst report numbered (none for the others).

        The notes are the analyst report's even when the bundle is rendered:
        the bundle prints them, so its note numbers are the analyst report's.
        """
        markdown, notes, _cited = self.render_with_citations(report)
        return markdown, notes

    def render_with_citations(self, report: MalwareReport) -> tuple[str, list[Any], set[int]]:
        """:meth:`render_with_notes`'s two values, and the numbers of the notes the analyst
        report prints a marker for, read from the markers the platform writes only."""
        # The links this report keeps as links, for the whole of this render.
        token = _KEPT_LINKS.set(_Kept.of(report))
        # The references to other sections this render writes, resolved once
        # its headings are known (``prose_forms``).
        references = references_for_render()
        try:
            return self._render(report)
        finally:
            end_references(references)
            _KEPT_LINKS.reset(token)

    def _render(self, report: MalwareReport) -> tuple[str, list[Any], set[int]]:
        from malspark.reporting.renderers.bundle import marker_numbers

        ctx = _Context.of(report)
        notes: list[Any] = []
        cited: set[int] = set()
        if self._layout == ANALYST:
            from malspark.reporting.renderers.analyst import analyst_sections

            sections, notes = analyst_sections(self, report, ctx)
        else:
            sections = self._full_sections(report, ctx)
            if self._layout == BUNDLE:
                from malspark.reporting.renderers.analyst import analyst_sections
                from malspark.reporting.renderers.bundle import bundle_sections

                # The analyst report's notes, numbered over a context of their
                # own: what it set aside is not this render's to restore. The
                # notes it prints a marker for are read from the markers its
                # own sections set aside, never from text a model wrote.
                own = _Context.of(report)
                written, notes = analyst_sections(self, report, own)
                text = "\n".join(tidied(written, report, analyst=True))
                cited = set(marker_numbers(own.kept_in(text)))
                sections = bundle_sections(self, report, ctx, sections, notes, cited)
        sections = finished(sections, report, analyst=self._layout == ANALYST, keep=ctx.keep)
        if self._layout == ANALYST:
            cited = set(marker_numbers(ctx.kept_in("\n".join(sections))))
        return self._closed(sections, ctx), notes, cited

    def _full_sections(self, report: MalwareReport, ctx: _Context) -> list[str]:
        # Each section is wrapped in _safe_section so a single malformed
        # subtree cannot 500 the whole ``/reports/{id}/markdown`` endpoint.
        sections: list[str] = [
            self._safe_section("title", lambda: self._section_title(report, ctx)),
            self._safe_section("questions", lambda: self._section_questions(report, ctx)),
            self._safe_section("key_findings", lambda: self._section_key_findings(report, ctx)),
            self._safe_section("sample_overview", lambda: self._section_overview(report, ctx)),
            self._safe_section("verdict", lambda: self._section_verdict(report, ctx)),
            self._safe_section("execution_flow", lambda: self._section_flow(report, ctx)),
            self._safe_section("technical_analysis", lambda: self._section_technical(report, ctx)),
            self._safe_section("observed_behaviour", lambda: self._section_observed(report, ctx)),
            self._safe_section("static_properties", lambda: self._section_static(report, ctx)),
            self._safe_section("attack_mapping", lambda: self._section_attack(report, ctx)),
            self._safe_section("indicators", lambda: self._section_indicators(report, ctx)),
            self._safe_section("detection", lambda: self._section_detection(report, ctx)),
            self._safe_section(
                "recommendations", lambda: self._section_recommendations(report, ctx)
            ),
            self._safe_section("attribution", lambda: self._section_attribution(report, ctx)),
            self._safe_section("limitations", lambda: self._section_limitations(report, ctx)),
            self._safe_section("appendix_evidence", lambda: self._appendix_evidence(report, ctx)),
            self._safe_section("appendix_run_summary", lambda: self._appendix_run(report, ctx)),
            self._safe_section(
                "appendix_references", lambda: self._appendix_references(report, ctx)
            ),
            self._safe_section("appendix_methodology", lambda: self._appendix_method(report, ctx)),
        ]
        return sections

    def _closed(self, sections: list[str], ctx: _Context) -> str:
        """The sections joined, after the closing defang and escape pass over each."""
        # Every value a viewer could follow, wherever a section printed it, is
        # read once more by the report's defanger, the run's own values first:
        # a cell or a code span a sandbox, the sample's bytes or a model filled
        # prints defanged even where its section did not pass it through the
        # context, a value the reader of every host would leave as written
        # ("loader.sh", a name under a TLD it does not know) too. What this
        # renderer itself wrote to print as written — each draft rule's body,
        # a configured model endpoint where a rate line names its model — was
        # set aside under a token no text can name, and only that comes back
        # unread. A character reference ("&#58;", "&colon;") is escaped in the
        # same pass: a viewer decodes one after the defanger has read the text,
        # so "https&#58;//evil&#46;example" would become a live link there.
        # A link into the evidence bundle or to a note's anchor the renderer did not set
        # aside prints as its characters: only the platform cites (T-814).
        defanged = [
            _hand_links_unlinked(_defanged_text(text, ctx.run_values), ctx.keep)
            for text in sections
        ]
        # Code is read only where no line may open an HTML block, anywhere in
        # the render; the fences are followed across the sections in order.
        looked = _ReferenceScan()
        for text in defanged:
            looked.read_for_html(text)
        scan = _ReferenceScan(reads_code=looked.reads_code)
        read = [ctx.restore(_escaped_references(text, scan)) for text in defanged]
        return "\n\n".join(text.rstrip() for text in read if text).rstrip() + "\n"

    def _safe_section(self, name: str, fn: Callable[[], str]) -> str:
        """Run a section renderer, return a stub on failure.

        The stub carries the caller's ``failed_marker`` where one was given:
        the HTML renderer draws its callout only for a stub with the marker it
        drew for that render, so no text a sample or a model wrote can fake one.
        """
        try:
            return fn()
        except Exception:  # noqa: BLE001 — markdown is non-critical UX surface
            logger.exception("markdown_renderer: section '%s' raised; substituting stub.", name)
            marker = f" {self._failed_marker}" if self._failed_marker else ""
            return f"<!-- section '{name}' rendering failed{marker} — see server logs -->"

    # ------------------------------------------------------------------
    # 0. Title block
    # ------------------------------------------------------------------

    def _section_title(self, report: MalwareReport, ctx: _Context) -> str:
        ident = report.identity
        sha256 = ident.hashes.sha256 or "unknown"
        lines = [_title_heading(report_title(report, _titled_format(ctx.plain))), ""]
        fm = report.front_matter
        if fm is not None:
            parts = [f"**TLP:{fm.tlp}**"]
            # The operator's configuration, by the inline rule.
            if fm.report_number:
                parts.append(f"Report {ctx.value(fm.report_number, pipes=True)}")
            parts.append(
                ctx.value(fm.report_date, pipes=True) or report.generated_at.date().isoformat()
            )
            parts.append(
                f"{ctx.value(fm.publisher, pipes=True)} report version "
                f"{ctx.value(fm.version, pipes=True)}"
            )
            lines.append(" · ".join(parts) + "  ")
        else:
            lines.append(f"Generated {report.generated_at.isoformat()}  ")
        lines.append(
            f"**Sample:** {_code_span(sha256)} ({_inline_safe(ident.file_type, plain=ctx.plain)}, "
            f"{ident.file_size_bytes:,} bytes)  "
        )
        lines.append(_verdict_line(report))
        for row in ctx.verdict_findings:
            lines.append(
                f"  \n_Unresolved on the verdict: {_code_span(row['code'])}: "
                f"{_one_line(_finding_text(row, ctx.plain))}_"
            )

        if report.verdict_not_assessed:
            # No judge ran: there is no verdict to carry a confidence, and the
            # banner says what happened instead of naming a judge.
            lines.append(
                "\n> **[NO VERDICT]** No verdict and no confidence were assessed: "
                f"{_one_line(report.verdict_not_assessed)}, so no judge ran."
            )
        elif report.overall_confidence is None:
            lines.append(
                "\n> **[NO CONFIDENCE ASSESSED]** This verdict carries no "
                "confidence: the judge assessed none, or never answered at all. "
                "Nothing is substituted for one — the analysts' confidence "
                "belongs to their own claims, and a verdict none of them reached "
                "is not something they rated."
            )
        if report.degraded_mode:
            # One sentence a reader can act on, built from what ran; the reasons
            # themselves, with their operator remedies, are the limitations section's.
            lines.append("\n> **[DEGRADED RUN]** " + _degraded_sentence(report, ctx))
        elif report.degradation_reasons:
            lines.append("\n" + _limitations_note(report))

        evidence = (report.run_summary or {}).get("evidence") or {}
        entries = evidence.get("entries")
        if entries:
            failed = int(evidence.get("failed") or 0)
            said = f"\nEvidence: {entries} tool call(s)"
            said += f", {failed} failed" if failed else ""
            said += (
                _redone_clause(evidence, ids=False, inventory=report.limitation_inventory)
                if failed
                else ""
            )
            repeats = int(evidence.get("repeats") or 0)
            said += f", {repeats} answered from an earlier entry" if repeats else ""
            guarded = int(evidence.get("guard_answers") or 0)
            said += f", {guarded} answered by a guard with no tool run" if guarded else ""
            lines.append(said + f" (see {section_reference(LIMITATIONS_TITLE)}).")
        profile = (report.run_summary or {}).get("profile") or {}
        # A reduced profile changes what evidence backs the verdict, so a
        # non-default one is named; the default keeps the block unchanged.
        if profile.get("name") and profile["name"] != "default":
            analysts = profile.get("analysts") or []
            custom = set(profile.get("custom") or [])
            names = ", ".join(
                f"{ctx.value(a, pipes=True)} (custom)" if a in custom else ctx.value(a, pipes=True)
                for a in analysts
            )
            lines.append(f"\nProfile: {ctx.value(profile['name'], pipes=True)} — analysts: {names}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # The questions the analyst asked of the run
    # ------------------------------------------------------------------

    def _section_questions(self, report: MalwareReport, ctx: _Context) -> str:
        """Each question asked of the run, its outcome, the answer and what it rests on.

        Unnumbered and before §1, so the report leads with what it was asked;
        "" for a job asked nothing, which renders as it always did.
        """
        answers = list(getattr(report, "question_answers", None) or [])
        if not answers:
            return ""
        lines = [_lead_heading("Questions asked of this run", REPORT_MODEL), "", QUESTIONS_NOTE]
        for number, answer in enumerate(answers, 1):
            # The analyst's words: escaped as inline text; the heading escapes
            # each "#", so a trailing run of them cannot close it early.
            asked = ctx.value(answer.question, pipes=True)
            lines.extend(["", _plain_heading(f"Q{number}. {asked}"), ""])
            outcome = f"**Outcome:** {outcome_words(answer.outcome)}"
            if answer.answered:
                outcome += (
                    f" _(the report model answered {outcome_words(answer.answered)}; "
                    "the platform's check refused it)_"
                )
            lines.append(outcome)
            if answer.answer.strip():
                lines.extend(["", _paragraph_line(ctx.inline(answer.answer))])
            facts = [
                ("Evidence", _ids(answer.evidence_ids)),
                ("Looked at", _ids(answer.looked_at)),
                ("Open questions it rests on", "; ".join(answer.open_questions)),
            ]
            said = [_item(f"{label}: {ctx.inline(value)}") for label, value in facts if value]
            # A check is the platform's sentence quoting a model's words or a
            # value, as one string: written whole by the value writer.
            said.extend(
                _item(f"_Platform check:_ {ctx.value(check, pipes=True)}")
                for check in answer.checks
            )
            if said:
                lines.extend(["", *said])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 1. Key findings
    # ------------------------------------------------------------------

    def _section_key_findings(self, report: MalwareReport, ctx: _Context) -> str:
        summary = report.executive_summary.strip()
        # A finding the agreement question left its only sentence out of is no finding written:
        # it prints no empty item, and the validation findings below list it with the reason.
        findings = [f for f in report.key_findings if f.text.strip()]
        written = bool(summary or findings)
        # The platform's fallback below is not the report model's text, and is
        # not headed as if it were: each of its lines names its own voice.
        lines = [_heading(1, "Key findings", REPORT_MODEL if written else PER_ROW), ""]
        for finding in findings:
            lines.append(
                _prose_item(
                    _cited(ctx.line(finding.text), finding.evidence_ids, finding.text)
                    + ctx.cited_row_mark(finding)
                )
            )
        if summary:
            if findings:
                lines.append("")
            lines.append(ctx.prose(summary))
            if not findings and not _EV_RE.search(summary):
                lines.extend(["", _UNCITED_NOTE])
        if written:
            lines.extend(_findings_beside(ctx.narrative_findings, ctx.plain))
            return "\n".join(lines)

        # No summary was written. Said, with the reason, and the verdict's
        # facts listed by the platform with the voice of each.
        why = next(
            (
                reason
                for reason in report.degradation_reasons
                if reason.startswith(_NO_SUMMARY_PREFIX)
            ),
            "",
        )
        reason = why.split(":", 1)[1].strip() if ":" in why else "the report model wrote none"
        written_reason = ctx.value(_one_line(reason), pipes=True)
        left = ctx.left_out_clause(*BUNDLE_SUMMARY_SUBJECTS)
        lines.append(
            f"No summary is printed: {left}. _({MEASURED})_"
            if left
            else f"No summary was written: {written_reason}. _({MEASURED})_"
        )
        if any(r in _INCONCLUSIVE for r in report.degradation_reasons):
            lines.extend(
                [
                    "",
                    "This analysis is inconclusive: nothing about the sample was "
                    "established, and the verdict below is not a finding about it.",
                ]
            )
        lines.append("")
        lines.append(_item(f"Verdict: {_verdict_words(report)} _({_verdict_voice(report)})_"))
        family = report.attribution.family
        lines.append(
            _item(f"Family: {_one_line(family or 'none attributed')} _({_family_voice(report)})_")
        )
        top = sorted(report.ttp_mappings, key=lambda m: -(m.confidence or 0.0))[:3]
        if top:
            named = ", ".join(f"{m.technique_id} {m.technique_name}" for m in top)
            lines.append(_item(f"Top published techniques: {named} _({ASSESSED})_"))
        from malspark.reporting.renderers.stix_renderer import publishes

        published = sum(
            1 for row in ctx.iocs if row.kind in _NETWORK_KINDS and publishes(row.published)
        )
        lines.append(_item(f"{PUBLISHED_NETWORK_LABEL}: {published} _({MEASURED})_"))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 2. Sample overview
    # ------------------------------------------------------------------

    def _section_overview(self, report: MalwareReport, ctx: _Context) -> str:
        ident = report.identity
        hashes = ident.hashes
        lines = [_heading(2, "Sample overview", MEASURED), ""]
        lines.append(_row("Field", "Value"))
        lines.append(_divider(2))
        lines.append(
            _row("File name (as submitted)", _code_span(ctx.plain(ident.file_name or "unknown")))
        )
        lines.append(_row("Size", f"{ident.file_size_bytes:,} bytes"))
        header = _header_facts(report)
        kind = ctx.value(ident.file_type)
        if header["architecture"]:
            kind += f", {ctx.value(header['architecture'])}"
        if header["is_dll"] is not None:
            kind += ", DLL" if header["is_dll"] else ", executable"
        lines.append(_row("Type", kind))
        platforms = [
            p for p in (report.severity.affected_platforms if report.severity else []) if p
        ]
        if platforms and platforms != ["Unknown"]:
            lines.append(_row("Platform", ", ".join(platforms) + " (from the file format)"))
        name = (ident.file_name or "").lower()
        if header["is_dll"] and name.endswith(".exe"):
            lines.append(_row("Name and type", "a DLL submitted under an .exe name"))
        if ident.mime_type:
            lines.append(_row("MIME", ctx.value(ident.mime_type)))
        if ident.magic_bytes:
            lines.append(_row("Magic bytes", _code_span(ctx.plain(str(ident.magic_bytes)))))
        if header["compile_timestamp"]:
            lines.append(
                _row(
                    "Compile timestamp",
                    f"{header['compile_timestamp']} (header value; can be forged)",
                )
            )
        if ident.language_or_compiler:
            lines.append(_row("Compiler / language", ctx.value(ident.language_or_compiler)))
        if header["export_name"]:
            lines.append(
                _row("Export directory name", _code_span(ctx.plain(str(header["export_name"]))))
            )
        if ident.internal_name:
            lines.append(_row("Internal name", _code_span(ctx.plain(str(ident.internal_name)))))
        signing = ident.signing
        cited = f" ({ctx.value(signing.evidence_id)})" if signing.evidence_id else ""
        lines.append(_row("Signed", f"{'yes' if signing.is_signed else 'no'}{cited}"))
        if signing.signer_subject:
            lines.append(_row("Signer", ctx.value(signing.signer_subject)))
        if signing.signer_issuer:
            lines.append(_row("Signer issuer", ctx.value(signing.signer_issuer)))
        if signing.signature_valid is not None:
            lines.append(_row("Signature chain", "valid" if signing.signature_valid else "invalid"))
        static = report.static
        if static is not None and (static.packer_matches or static.packer_hint):
            names = ", ".join(str(m.get("name") or "not recorded") for m in static.packer_matches)
            lines.append(_row("Packer signatures", ctx.value(names or static.packer_hint)))
        lines.append(_row("Reputation", _reputation_line(report)))
        lines.append(_row("Report generated", report.generated_at.isoformat()))
        lines.append("")
        lines.append(_row("Algorithm", "Value"))
        lines.append(_divider(2))
        for algo, value in (
            ("MD5", hashes.md5),
            ("SHA-1", hashes.sha1),
            ("SHA-256", hashes.sha256),
            ("SHA-512", hashes.sha512),
            ("imphash", hashes.imphash),
            ("ssdeep", hashes.ssdeep),
            ("TLSH", hashes.tlsh),
        ):
            if value:
                lines.append(_row(algo, _code_span(str(value))))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 3. Verdict and assessment
    # ------------------------------------------------------------------

    def _section_verdict(self, report: MalwareReport, ctx: _Context) -> str:
        lines = [_heading(3, "Verdict and assessment", _verdict_voice(report)), ""]
        lines.append(f"**Verdict:** {_verdict_words(report)}")
        severity = report.severity
        if severity is None:
            # Said, not defaulted: "Informational" for a rating nobody gave
            # tells a reader something the run never established.
            lines.extend(
                [
                    "",
                    "**Severity:** not assessed — no verdict stage ran."
                    if report.verdict_not_assessed
                    else "**Severity:** not assessed — the judge produced no severity rating.",
                ]
            )
        else:
            lines.extend(["", f"**Severity:** {_code_span(f'[{severity.rating.upper()}]')}"])
            if severity.business_impact:
                lines.extend(["", "**Why, in the judge's words:**", ""])
                quoted = ctx.prose(severity.business_impact).splitlines()
                lines.extend(f"> {line}" if line.strip() else ">" for line in quoted)
            if severity.likely_targets:
                lines.extend(
                    [
                        "",
                        "**Likely targets:** "
                        + ", ".join(_one_line(t) for t in severity.likely_targets),
                    ]
                )
        if category_shown(report.malware_category):
            lines.extend(
                [
                    "",
                    f"**Category:** {category_shown(report.malware_category)} "
                    f"_(a behavioural class, not a family)_{ctx.category_mark}",
                ]
            )
        lines.extend(["", "**Family:** " + _family_words(report)])
        conclusion = report.conclusion
        if conclusion is not None and conclusion.sophistication_rating:
            lines.extend(
                ["", f"**Sophistication:** {conclusion.sophistication_rating} _({REPORT_MODEL})_"]
            )
        negotiation = (report.run_summary or {}).get("negotiation") or report.negotiation_summary
        if isinstance(negotiation, dict) and negotiation.get("rounds_completed") is not None:
            rounds = negotiation.get("rounds_completed")
            reason = str(negotiation.get("termination_reason") or "").strip()
            if reason == NOT_APPLICABLE:
                # No agreement was measured, so none is stated.
                said = NOT_APPLICABLE_PHRASE
            elif reason == "consensus" and ctx.no_analyst_claims:
                # Agreement among analysts that claimed nothing is not agreement.
                said = (
                    f"the negotiation ended by consensus after {rounds} round(s) with no "
                    "analyst claims to agree on"
                )
            elif reason == "consensus":
                said = f"the analysts reached consensus after {rounds} round(s)"
                # Agreement over lines the mediator set aside says so.
                set_aside = int(negotiation.get("not_blocking_at_end") or 0)
                if set_aside:
                    said += (
                        f"; {set_aside} listed line{'s were' if set_aside != 1 else ' was'} "
                        "marked not blocking by the mediator"
                    )
            else:
                said = f"the negotiation ended after {rounds} round(s)" + (
                    f" ({ctx.value(reason, pipes=True)})" if reason and reason != "unknown" else ""
                )
            lines.extend(["", f"**Analyst agreement:** {said} _({MEASURED})_."])
        if ctx.verdict_findings:
            lines.extend(["", "**Unresolved findings on the verdict:**", ""])
            lines.extend(
                _item(f"{_code_span(row['code'])}: {_finding_text(row, ctx.plain)}")
                for row in ctx.verdict_findings
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 4. Execution flow
    # ------------------------------------------------------------------

    def _section_flow(self, report: MalwareReport, ctx: _Context) -> str:
        ta = report.technical_analysis
        steps = list(ta.execution_flow) if ta is not None else []
        if not steps:
            return "\n".join(
                [
                    _heading(4, "Execution flow", MEASURED),
                    "",
                    "Not written in this run: the report model wrote no execution flow.",
                ]
            )
        lines = [_heading(4, "Execution flow", REPORT_MODEL), ""]
        lines.append(
            "_Each step is marked as the report model marked it: observed in the "
            "sandbox, or assessed from the code and the analysts' claims._"
        )
        lines.append("")
        for index, step in enumerate(sorted(steps, key=lambda s: s.order), start=1):
            mark = "observed in sandbox" if step.voice == "observed" else "assessed"
            if str(step.order) in ctx.flow_findings:
                note = " _(unresolved: report.flow_voice)_"
            elif step.voice == "observed" and not ctx.sandbox_observed:
                # The mark is the model's and stays; the platform says beside it
                # that this run holds no observation it could rest on.
                note = " _(unresolved: report.flow_voice; no sandbox observation in this run)_"
            else:
                note = ""
            lines.append(
                _prose_step(
                    index,
                    # A step whose only sentence the agreement question left out reads
                    # "-", as the analyst report prints it (T-600).
                    _cited(
                        f"{ctx.line(step.action) or '-'} ({mark})", step.evidence_refs, step.action
                    )
                    + ctx.cited_row_mark(step)
                    + note,
                )
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 5. Technical analysis
    # ------------------------------------------------------------------

    def _section_technical(self, report: MalwareReport, ctx: _Context) -> str:
        ta = report.technical_analysis
        static = report.static
        dynamic = report.dynamic
        blocks: list[str] = []
        capability = _capability_rules(report)

        if report.capabilities_narrative:
            # A report stored before the composer wrote these subsections
            # carries the old capability paragraphs; they are printed here,
            # under the analysis's lead-in, rather than lost.
            body = [_subheading("", "Overview", REPORT_MODEL), ""]
            for paragraph in report.capabilities_narrative:
                body.extend([ctx.prose(paragraph.strip()), ""])
            body.append(_UNCITED_NOTE)
            blocks.append("\n".join(body))

        # 5.1 Packing, obfuscation and anti-analysis.
        measured: list[str] = []
        if static is not None and static.sections:
            entropies = ", ".join(
                f"{_code_span(ctx.plain(_one_line(sec.name)))} {sec.entropy:.2f}"
                + (" [HIGH]" if sec.entropy > 7.0 else "")
                for sec in _distinct(
                    static.sections, lambda s: (s.name, s.virtual_address, s.raw_offset)
                )
            )
            measured.append(f"_{MEASURED}:_ section entropy {entropies}.")
        if static is not None and static.packer_matches:
            measured.extend(["", f"_{MEASURED}:_ packer signatures", ""])
            # A confidence column only where a match states one: a column of
            # "not recorded" under "Measured" reads as a measurement too.
            rated = any(
                isinstance(pm.get("confidence"), int | float) for pm in static.packer_matches
            )
            head = ["Name", "Kind", *(["Confidence"] if rated else []), "Method", "Evidence"]
            measured.append(_row(*head))
            measured.append(_divider(len(head)))
            for pm in static.packer_matches:
                evidence = ", ".join(
                    _code_span(ctx.plain(str(e))) for e in (pm.get("evidence") or [])
                )
                stated = pm.get("confidence")
                cells = [
                    ctx.value(pm.get("name")) or "not recorded",
                    ctx.value(pm.get("kind")) or "-",
                ]
                if rated:
                    cells.append(
                        f"{float(stated):.2f}" if isinstance(stated, int | float) else "not stated"
                    )
                measured.append(_row(*cells, ctx.value(pm.get("method")) or "-", evidence or "-"))
        elif static is not None and static.packer_hint:
            hint = ctx.value(_one_line(static.packer_hint), pipes=True)
            measured.append(f"_{MEASURED}:_ packer hint {hint}.")
        measured.extend(_capability_table(capability, _is_evasion_rule, _capability_tool(report)))
        # A cipher the model extracted that encrypts no files — a loader's
        # string or traffic cipher — belongs beside the obfuscation prose, not
        # under a ransomware heading.
        enc = ta.encryption_scheme if ta is not None else None
        if enc is not None and not _encrypts_files(enc):
            table = _encryption_table(enc, ctx)
            if table:
                measured.extend(["", *table])
        evasive = [
            sig
            for sig in distinct_signatures(
                dynamic.sandbox_signatures if dynamic else [], signature_identity_without_processes
            )
            if _names_any(sig.name + " " + sig.description, _EVASION_WORDS)
        ]
        if evasive:
            measured.extend(["", f"_{OBSERVED}:_ evasion signatures", ""])
            measured.append(_row("Name", "Severity", "Description"))
            measured.append(_divider(3))
            for sig in evasive[:10]:
                measured.append(
                    _row(
                        ctx.value(sig.name), _severity_cell(sig), ctx.value(_whole(sig.description))
                    )
                )
            measured.extend(_left_out(len(evasive), 10, "evasion signatures"))
        blocks.append(
            _subsection(
                "5.1",
                "Packing, obfuscation and anti-analysis",
                _section_5_prose(ta, "5.1"),
                measured,
                ctx,
                absent=ctx.absence(
                    "packing, obfuscation or anti-analysis",
                    sandbox=False,
                    subjects=SECTION_5_PROSE["5.1"],
                ),
            )
        )

        # 5.2 API and string resolution.
        measured = []
        if static is not None and static.imports:
            imports = _distinct(static.imports, lambda r: (r.dll, r.function))
            libraries = {row.dll.lower() for row in imports if row.dll}
            measured.append(
                f"_{MEASURED}:_ {len(imports)} static imports from "
                f"{len(libraries)} librar{'y' if len(libraries) == 1 else 'ies'}."
            )
        resolving = [
            hit
            for hit in (static.api_technique_hits if static else [])
            if not _capability_rule_hit(hit)
            and _names_any(str(hit.get("name") or ""), _RESOLUTION_WORDS)
        ]
        if resolving:
            names = ", ".join(
                f"{ctx.value(_one_line(h.get('name')), pipes=True)} "
                f"({ctx.value(_one_line(h.get('source')), pipes=True)})"
                for h in resolving
            )
            measured.append(f"_{MEASURED}:_ rule hits {names}.")
        measured.extend(
            _capability_table(capability, _is_resolution_rule, _capability_tool(report))
        )
        blocks.append(
            _subsection(
                "5.2",
                "API and string resolution",
                _section_5_prose(ta, "5.2"),
                measured,
                ctx,
                absent=ctx.absence(
                    "imports or API resolution", sandbox=False, subjects=SECTION_5_PROSE["5.2"]
                ),
            )
        )

        # 5.3 Configuration.
        if ta is not None and ta.configuration:
            body = [_subheading("5.3", "Configuration", REPORT_MODEL), ""]
            body.append(_row("Key", "Value", "How obtained", "Evidence"))
            body.append(_divider(4))
            for index, item in enumerate(ta.configuration):
                how = item.how_obtained + _row_mark(
                    "report.configuration_uncited", ctx.config_findings.get(index + 1)
                )
                cited = ", ".join(item.evidence_refs) or "no evidence cited"
                cited += _row_mark(
                    "report.value_not_in_cited_entry", ctx.config_unheld.get(index + 1)
                )
                cited += _row_mark(
                    _INSIDE_A_TOKEN_CODE,
                    ctx.config_inside.get(index + 1),
                    shown=index + 1 not in ctx.config_run_unshown,
                )
                cited += ctx.cited_row_mark(item)
                value = ctx.cell(item.value) + ctx.publish_state(item.value)
                body.append(_row(ctx.cell(item.key), value, how, cited))
            blocks.append("\n".join(body))
        else:
            blocks.append(
                _absent_subsection(
                    "5.3",
                    "Configuration",
                    "Not written in this run: the report model extracted no configuration.",
                )
            )

        # 5.4 Persistence.
        measured = []
        if report.persistence:
            measured.append(f"_{PER_ROW}:_ persistence mechanisms")
            measured.append("")
            measured.append(_row("Kind", "Target", "Payload", "Technique", "Source", "Evidence"))
            measured.append(_divider(6))
            for mech in report.persistence[:40]:
                measured.append(
                    _row(
                        mech.kind,
                        _code_span(_whole(ctx.plain(mech.target))),
                        _code_span(_whole(ctx.plain(mech.payload))) if mech.payload else "-",
                        mech.technique_id or "-",
                        ctx.source_of(mech.evidence_ref),
                        mech.evidence_ref or "-",
                    )
                )
            measured.extend(_left_out(len(report.persistence), 40, "persistence mechanisms"))
        elif ctx.sandbox_watched_persistence:
            measured.append(f"_{OBSERVED}:_ no persistence observed." + ctx.partial_sentence())
        listed = analyst_persistence(report.sections)
        if listed:
            # What the analysts listed, in their voice and apart from the tools'
            # rows: no count, rule match or detection draft reads it.
            if measured:
                measured.append("")
            measured.extend(
                [
                    f"_{ASSESSED}:_ persistence the analysts listed (not observed; no count, "
                    "rule match or detection draft reads it)",
                    "",
                    _row("Kind", "Target", "Payload", "Listed by", "Evidence"),
                    _divider(5),
                ]
            )
            for listed_row in listed[:40]:
                measured.append(
                    _row(
                        listed_row["kind"] or "-",
                        _code_span(_whole(ctx.plain(listed_row["target"]))),
                        _code_span(_whole(ctx.plain(listed_row["payload"])))
                        if listed_row["payload"]
                        else "-",
                        f"the {listed_row['listed_by']} analyst"
                        if listed_row["listed_by"]
                        else "-",
                        listed_row["evidence"] or "no evidence cited",
                    )
                )
            measured.extend(_left_out(len(listed), 40, "listed persistence rows"))
        blocks.append(
            _subsection(
                "5.4",
                "Persistence",
                _section_5_prose(ta, "5.4"),
                measured,
                ctx,
                absent=ctx.absence(
                    "persistence mechanism", sandbox=True, subjects=SECTION_5_PROSE["5.4"]
                ),
            )
        )

        # 5.5 Discovery.
        measured = []
        commands, others = started_by_the_sample(report)
        if commands:
            measured.extend([f"_{OBSERVED}:_ commands the sample started", ""])
            measured.append(_row("PID", "Command line"))
            measured.append(_divider(2))
            for node in commands[:20]:
                measured.append(_row(node.pid, _code_span(_whole(ctx.plain(node.command_line)))))
            measured.extend(_left_out(len(commands), 20, "commands"))
            measured.extend(not_started_by_the_sample_line(others))
        blocks.append(
            _subsection(
                "5.5",
                "Discovery",
                _section_5_prose(ta, "5.5"),
                measured,
                ctx,
                absent=ctx.absence(
                    "discovery command", sandbox=True, subjects=SECTION_5_PROSE["5.5"]
                ),
            )
        )

        # 5.6 Commands and capabilities.
        if ta is not None and (ta.commands or ta.cli_flags):
            body = [_subheading("5.6", "Commands and capabilities", REPORT_MODEL), ""]
            if ta.commands:
                body.append(_row("ID", "Command", "Description", "Evidence"))
                body.append(_divider(4))
                for cmd in ta.commands:
                    body.append(
                        _row(
                            ctx.cell(cmd.id or "-"),
                            ctx.cell(cmd.name),
                            ctx.cell(cmd.description or "-"),
                            (", ".join(cmd.evidence_refs) or "no evidence cited")
                            + ctx.cited_row_mark(cmd),
                        )
                    )
                body.append("")
            if ta.cli_flags:
                body.append("Command-line flags:")
                body.append("")
                body.append(_row("Flag", "Meaning", "Evidence"))
                body.append(_divider(3))
                for flag in ta.cli_flags:
                    # A flag is the sample's own text, and a URL or host in it
                    # is defanged like every other value the body prints.
                    body.append(
                        _row(
                            _code_span(ctx.plain(flag.flag)),
                            ctx.cell(flag.description or "-"),
                            (flag.evidence_ref or "no evidence cited") + ctx.cited_row_mark(flag),
                        )
                    )
            blocks.append("\n".join(body).rstrip())
        else:
            blocks.append(
                _absent_subsection(
                    "5.6",
                    "Commands and capabilities",
                    "Not written in this run: the report model extracted no command the sample "
                    "accepts and no command-line flag.",
                )
            )

        # 5.7 Command and control.
        measured = []
        if report.c2_channels:
            measured.extend([f"_{REPORT_MODEL}:_ channels", ""])
            measured.append(
                _row(
                    "Channel",
                    "Protocol",
                    "Endpoint(s)",
                    "Encryption",
                    "Beacon/packet format",
                    "Evidence",
                )
            )
            measured.append(_divider(6))
            for ch in report.c2_channels:
                fmt = " / ".join(part for part in (ch.beacon_format, ch.packet_layout) if part)
                refs = list(ch.evidence_refs) + ([ch.evidence_ref] if ch.evidence_ref else [])
                measured.append(
                    _row(
                        ctx.cell(ch.name),
                        ctx.cell(ch.protocol or "-"),
                        "; ".join(_endpoint_with_state(e, ctx) for e in ch.endpoints) or "-",
                        ctx.cell(ch.encryption or "-"),
                        ctx.cell(fmt or "-"),
                        (", ".join(dict.fromkeys(refs)) or "no evidence cited")
                        + ctx.cited_row_mark(ch),
                    )
                )
        net = report.network
        observed_urls = [u for u in (net.urls if net else []) if u.source == "sandbox"]
        if observed_urls:
            measured.extend(["", f"_{OBSERVED}:_ requests", ""])
            measured.append(_row("Method", "URL", "Status", "User-Agent"))
            measured.append(_divider(4))
            for u in observed_urls[:20]:
                measured.append(
                    _row(
                        _inline_safe(u.method or "-", pipes=False, plain=ctx.plain),
                        _code_span(defang(_whole(u.url), "url")),
                        _inline_safe(u.status or "-", pipes=False, plain=ctx.plain),
                        _inline_safe(
                            _whole(u.user_agent or "-"),
                            pipes=False,
                            plain=ctx.plain,
                        ),
                    )
                )
            measured.extend(_left_out(len(observed_urls), 20, "requests"))
        if net is not None and (net.ja3_fingerprints or net.ja3s_fingerprints):
            prints = [f"JA3 {_code_span(_one_line(j))}" for j in net.ja3_fingerprints]
            prints += [f"JA3S {_code_span(_one_line(j))}" for j in net.ja3s_fingerprints]
            measured.extend(["", f"_{OBSERVED}:_ TLS fingerprints " + ", ".join(prints) + "."])
        prose = _section_5_prose(ta, "5.7")
        blocks.append(
            _subsection(
                "5.7",
                "Command and control",
                prose,
                measured,
                ctx,
                absent=ctx.absence(
                    "command-and-control channel", sandbox=True, subjects=SECTION_5_PROSE["5.7"]
                ),
            )
        )

        # 5.8 Payloads and dropped files.
        measured = []
        carved = [r for r in (static.embedded_resources if static else []) if r.get("carved")]
        dropped = [
            op
            for op in (dynamic.file_operations if dynamic else [])
            if isinstance(op, dict) and op.get("operation") == "write"
        ]
        if carved or dropped:
            measured.extend([f"_{PER_ROW}:_ payloads", ""])
            measured.append(_row("Name/offset", "Size", "SHA-256", "Type", "Source"))
            measured.append(_divider(5))
            for res in carved[:10]:
                measured.append(
                    _row(
                        f"{_code_span(ctx.plain(str(res.get('id') or 'not recorded')))} "
                        f"({ctx.plain(str(res.get('source') or '-'))})",
                        dropped_size_cell(res),
                        _code_span(str(res.get("sha256")).lower()) if res.get("sha256") else "-",
                        res.get("type") or "not recorded",
                        "carved (static)",
                    )
                )
            for op in dropped[:20]:
                named = str(op.get("path") or op.get("name") or "not recorded")
                measured.append(
                    _row(
                        _code_span(_whole(ctx.plain(named))),
                        dropped_size_cell(op),
                        _code_span(str(op.get("sha256")).lower()) if op.get("sha256") else "-",
                        op.get("type") or "-",
                        "; ".join(
                            part
                            for part in (
                                "dropped (sandbox)",
                                _observed_cell(op.get("observed_in"), ctx),
                            )
                            if part
                        ),
                    )
                )
            measured.extend(_left_out(len(carved), 10, "carved payloads"))
            measured.extend(_dropped_left_out(dropped, 20))
        # What the carver's own cap left out, stated beside what it carved.
        carve_notes = [r for r in (static.embedded_resources if static else []) if is_carve_note(r)]
        if carve_notes:
            measured.extend(
                ["", *(_item(_inline_safe(str(r["type"]), plain=ctx.plain)) for r in carve_notes)]
            )
        blocks.append(
            _subsection(
                "5.8",
                "Payloads and dropped files",
                _section_5_prose(ta, "5.8"),
                measured,
                ctx,
                absent=ctx.absence(
                    "carved payload or dropped file", sandbox=True, subjects=SECTION_5_PROSE["5.8"]
                ),
            )
        )

        # 5.9 Family-specific behaviour.
        family_block = (
            _ransomware_block(ta, ctx, ransomware=_states_ransomware(report))
            if ta is not None
            else ""
        )
        blocks.append(
            family_block
            or _absent_subsection(
                "5.9",
                "Family-specific behaviour",
                "Not written in this run: the report model described no family-specific behaviour.",
            )
        )
        return "\n\n".join([_heading(5, "Technical analysis", PER_SUBSECTION), *blocks])

    # ------------------------------------------------------------------
    # 6. Observed behaviour
    # ------------------------------------------------------------------

    def _section_observed(self, report: MalwareReport, ctx: _Context) -> str:
        dyn = report.dynamic
        # The sandbox's voice is used only over what a sandbox recorded. A
        # sandbox answer with nothing in it — a mock with no fixture, a call
        # that returned empty lists — is not an execution, and the section
        # says what the run knows about the sandbox in the run's own voice.
        if not ctx.sandbox_observed:
            return "\n".join(
                [_heading(6, "Observed behaviour", MEASURED), "", ctx.sandbox_sentence()]
            )
        lines = [_heading(6, "Observed behaviour", OBSERVED), ""]
        if ctx.sandbox_statement:
            # A recorded fixture is an earlier detonation, not this run's.
            lines.extend([f"_{ctx.sandbox_statement}_", ""])
        lines.append(_environment_line(report))
        lines.append("")
        if dyn is None:
            lines.append(
                "The sandbox recorded network activity only; it is in "
                f"{section_reference('Command and control')} and "
                f"{section_reference(INDICATORS_TITLE)}." + ctx.partial_sentence()
            )
            return "\n".join(lines)
        if dyn.unavailable:
            names = ", ".join(_code_span(ctx.plain(_one_line(name))) for name in dyn.unavailable)
            lines.extend([f"_Not provided by this sandbox: {names}._", ""])

        if dyn.process_tree:
            tree = [
                line
                for root in distinct_processes(dyn.process_tree)
                for line in _process_tree_lines(root, 0, ctx.plain)
            ]
            lines.extend([_plain_heading("Process tree"), "", *_fenced("\n".join(tree)), ""])

        files = [op for op in dyn.file_operations if isinstance(op, dict) and op.get("path")]
        if files:
            lines.extend(
                [
                    _plain_heading("File operations"),
                    "",
                    _row("Path", "Operation", "API"),
                    _divider(3),
                ]
            )
            for op in files[:40]:
                lines.append(
                    _row(
                        _code_span(_whole(ctx.plain(str(op.get("path", ""))))),
                        ctx.value(op.get("operation", "-")),
                        ctx.value(op.get("api", "-")),
                    )
                )
            lines.extend(_left_out(len(files), 40, "file operations"))
            lines.append("")

        if dyn.registry_mods:
            lines.extend(
                [
                    _plain_heading("Registry modifications"),
                    "",
                    _row("Hive", "Key", "Value", "Operation"),
                    _divider(4),
                ]
            )
            lines.extend(_registry_row(reg, ctx.plain) for reg in dyn.registry_mods[:40])
            lines.extend(_left_out(len(dyn.registry_mods), 40, "registry modifications"))
            lines.append("")

        mutexes = [
            str(op.get("name"))
            for op in dyn.file_operations
            if isinstance(op, dict) and op.get("operation") == "mutex" and op.get("name")
        ]
        if mutexes:
            lines.extend([_plain_heading("Mutexes"), ""])
            lines.extend(_item(_code_span(ctx.plain(name))) for name in mutexes[:40])
            lines.extend(_left_out(len(mutexes), 40, "mutexes"))
            lines.append("")

        services = next((s for s in report.sections if s.key == "sandbox_services_and_tasks"), None)
        if services is not None and services.rows:
            lines.extend([_plain_heading("Services and tasks"), ""])
            lines.extend(_evidence_rows(services, ctx.plain))
            if services.evidence_ids:
                lines.extend(["", f"_Evidence: {_ids(services.evidence_ids)}_"])
            lines.append("")

        if dyn.notable_apis:
            lines.extend(
                [_plain_heading("Notable APIs"), "", _row("API", "Process", "Count"), _divider(3)]
            )
            for api in dyn.notable_apis[:20]:
                if isinstance(api, dict):
                    count = api.get("count")
                    lines.append(
                        _row(
                            _code_span(ctx.plain(str(api.get("api", "-")))),
                            _code_span(ctx.plain(str(api.get("process") or "-"))),
                            count if isinstance(count, int) else "not recorded",
                        )
                    )
            lines.extend(_left_out(len(dyn.notable_apis), 20, "notable APIs"))
            lines.append("")

        # Told apart by what the table prints: the processes are not among it.
        signatures = distinct_signatures(
            dyn.sandbox_signatures, signature_identity_without_processes
        )
        if signatures:
            lines.extend(
                [
                    _plain_heading("Sandbox signatures"),
                    "",
                    _row("Name", "Severity", "Techniques", "Description"),
                    _divider(4),
                ]
            )
            # A hit the table prints once carries every detonation it was in.
            marks: dict[tuple[Any, ...], list[Any]] = {}
            for sig in dyn.sandbox_signatures:
                marks.setdefault(signature_identity_without_processes(sig), []).extend(
                    marks_of(sig)
                )
            lines.extend(
                _signature_row(
                    sig,
                    _observed_cell(
                        stated_marks(marks.get(signature_identity_without_processes(sig), [])),
                        ctx,
                    ),
                    ctx.plain,
                )
                for sig in signatures[:30]
            )
            lines.extend(_left_out(len(signatures), 30, "sandbox signatures"))
            lines.append("")

        if len(lines) <= 4:
            lines.append("The sandbox ran and recorded little." + ctx.partial_sentence())
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # 7. Static properties
    # ------------------------------------------------------------------

    def _section_static(self, report: MalwareReport, ctx: _Context) -> str:
        static = report.static
        if static is None:
            lines = [
                _heading(7, STATIC_TITLE, MEASURED),
                "",
                "Not examined in this run: no static tool's answer is recorded in this report.",
            ]
            if report.directed_text:
                lines.extend(["", *_directed_text_lines(report.directed_text, ctx)])
            return "\n".join(lines).rstrip()
        lines = [_heading(7, STATIC_TITLE, MEASURED), ""]

        if static.sections:
            lines.extend([_plain_heading("Sections"), ""])
            lines.append(_row("Name", "VA", "VSize", "Raw offset", "Raw size", "Entropy", "Flags"))
            lines.append(_divider(7))
            for sec in _distinct(
                static.sections, lambda s: (s.name, s.virtual_address, s.raw_offset)
            ):
                flag = "[HIGH ENTROPY]" if sec.entropy > 7.0 else ""
                if sec.is_suspicious and not flag:
                    flag = "[SUSPICIOUS]"
                lines.append(
                    _row(
                        _code_span(ctx.plain(str(sec.name))),
                        ctx.value(sec.virtual_address),
                        sec.virtual_size,
                        f"0x{sec.raw_offset:x}",
                        sec.raw_size,
                        f"{sec.entropy:.2f}",
                        " ".join(part for part in (ctx.value(sec.characteristics), flag) if part)
                        or "-",
                    )
                )
            lines.append("")

        if static.imports or static.api_capabilities:
            lines.extend([_plain_heading("Imports"), ""])
            by_dll: dict[str, list[str]] = {}
            for row in _distinct(static.imports, lambda r: (r.dll, r.function)):
                by_dll.setdefault(row.dll or "not recorded", []).append(row.function)
            if by_dll:
                lines.append(_row("Library", "Functions"))
                lines.append(_divider(2))
                for dll, functions in list(by_dll.items())[:40]:
                    shown = ", ".join(_code_span(ctx.plain(str(f))) for f in functions[:12])
                    more = f" and {len(functions) - 12} more" if len(functions) > 12 else ""
                    lines.append(_row(_code_span(ctx.plain(str(dll))), shown + more))
                lines.extend(_left_out(len(by_dll), 40, "libraries"))
                lines.append("")
            if static.api_capabilities:
                ordered = sorted(static.api_capabilities.items(), key=lambda kv: -kv[1])
                cited = _ids(ctx.value(i, pipes=True) for i in static.api_capabilities_evidence_ids)
                rates = static.api_capability_rates

                def _profile(category: str, count: int) -> str:
                    share = rates.get(category)
                    return f"{ctx.value(_one_line(category), pipes=True)} ×{count}" + (
                        f" ({share:.1f}%)" if share is not None else ""
                    )

                lines.append(
                    "**Import capability profile**"
                    + (f" ({cited})" if cited else "")
                    + ": "
                    + ", ".join(_profile(cat, count) for cat, count in ordered)
                )
                if static.api_capability_corpus:
                    lines.extend(
                        [
                            "",
                            "_The bracketed share is how much of "
                            f"{ctx.value(_one_line(static.api_capability_corpus), pipes=True)} "
                            "the category appears "
                            "on; it says nothing about how likely this sample is to be benign._",
                        ]
                    )
                lines.append("")
        if static.api_capabilities_resolved:
            from malspark.tools.knowledge import RESOLVED_AT_RUNTIME

            ordered = sorted(static.api_capabilities_resolved.items(), key=lambda kv: -kv[1])
            cited = _ids(
                ctx.value(i, pipes=True) for i in static.api_capabilities_resolved_evidence_ids
            )
            lines.append(
                f"**Capability profile of the names {RESOLVED_AT_RUNTIME}** (not imports"
                + (f"; {cited}" if cited else "")
                + "): "
                + ", ".join(
                    f"{ctx.value(_one_line(cat), pipes=True)} ×{count}" for cat, count in ordered
                )
            )
            lines.append("")

        if static.export_rows or static.exports:
            lines.extend([_plain_heading("Exports"), ""])
            lines.append(_row("Name", "Ordinal", "RVA"))
            lines.append(_divider(3))
            if static.export_rows:
                distinct = _distinct(static.export_rows, lambda e: (e.name, e.ordinal, e.rva))
                for exp in distinct[:60]:
                    lines.append(
                        _row(
                            _code_span(ctx.plain(exp.name or "(unnamed)")),
                            exp.ordinal or "-",
                            ctx.value(exp.rva) or "-",
                        )
                    )
                lines.extend(_left_out(len(distinct), 60, "exports"))
                rvas = [
                    exp.rva
                    for exp in _distinct(static.export_rows, lambda e: (e.name, e.ordinal, e.rva))
                    if exp.rva
                ]
                if len(rvas) > 1 and len(set(rvas)) == 1:
                    lines.extend(
                        [
                            "",
                            f"All {len(rvas)} exports share one address, "
                            f"{ctx.value(_one_line(rvas[0]), pipes=True)}.",
                        ]
                    )
            else:
                names = list(dict.fromkeys(static.exports))
                for name in names[:60]:
                    lines.append(_row(_code_span(ctx.plain(str(name))), "-", "-"))
                lines.extend(_left_out(len(names), 60, "exports"))
            lines.append("")

        if static.permissions:
            lines.extend([_plain_heading("Declared permissions"), ""])
            lines.extend(_item(_code_span(ctx.plain(name))) for name in static.permissions)
            lines.append("")

        if static.embedded_resources:
            # The carver's note is stated with the carved payloads (5.8), not
            # here, and does not count toward this list.
            plain = [
                r for r in static.embedded_resources if not r.get("carved") and not is_carve_note(r)
            ]
            if plain:
                lines.extend([_plain_heading("Resources"), ""])
                for res in plain[:20]:
                    kind = res.get("type") or res.get("kind") or "resource"
                    # The size as the size cells read it; none where none is stated.
                    size = dropped_size_cell(res)
                    said = _inline_safe(f"{kind}", plain=ctx.plain)
                    lines.append(_item(said + (f" ({size})" if size != SIZE_NOT_RECORDED else "")))
                lines.extend(_left_out(len(plain), 20, "resources"))
                lines.append("")

        rules = [s for s in report.sections if s.key in _RULE_SECTIONS]
        if rules:
            lines.extend([_plain_heading("Rule hits"), ""])
            for section in rules:
                title = ctx.value(_one_line(section.title), pipes=True)
                lines.extend([_paragraph_line(f"{title}:"), ""])
                lines.extend(_evidence_rows(section, ctx.plain))
                if section.evidence_ids:
                    lines.extend(["", f"_Evidence: {_ids(section.evidence_ids)}_"])
                lines.append("")

        if static.interesting_strings:
            lines.extend([_plain_heading("Strings of note"), ""])
            lines.append(
                "_Values extracted from the file's bytes, printed as they are, network "
                "values defanged. A network-looking string is not an observed endpoint._"
            )
            lines.append("")
            answers = {(row.kind, row.value.lower()): row.published for row in ctx.iocs}
            lines.append(_row("Value", "Kind", "Notes", "Published"))
            lines.append(_divider(4))
            for ioc in static.interesting_strings[:60]:
                published = ctx.value(answers.get((ioc.kind, ioc.value.strip().lower())) or "-")
                value = _whole(_defanged_text(ctx.plain(ioc.value)))
                lines.append(
                    _row(
                        _code_span(value),
                        # A form row of the IOC table prints its form here too.
                        ctx.value(_form_of(ioc, ctx.forms) or ioc.kind),
                        ctx.value(ioc.notes) if ioc.notes else "-",
                        published,
                    )
                )
            lines.extend(_left_out(len(static.interesting_strings), 60, "strings"))
            lines.append("")

        if report.directed_text:
            lines.extend(_directed_text_lines(report.directed_text, ctx))

        if static.pdb_path:
            lines.extend([f"Debug PDB path: {_code_span(_one_line(static.pdb_path))}", ""])
        if static.obfuscation_indicators:
            lines.append(
                "Obfuscation indicators: "
                + ", ".join(
                    _inline_safe(_one_line(x), plain=ctx.plain)
                    for x in static.obfuscation_indicators
                )
            )
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # 8. MITRE ATT&CK mapping
    # ------------------------------------------------------------------

    def _section_attack(self, report: MalwareReport, ctx: _Context) -> str:
        # A Malware Behavior Catalog id is not an ATT&CK technique that failed
        # to resolve; it is listed under the table as the behaviour it is.
        cells = [c for c in report.capability_matrix if not _is_mbc_id(c.technique_id)]
        lines = [_heading(8, "MITRE ATT&CK mapping", PER_ROW), ""]
        mappings = {m.technique_id: m for m in report.ttp_mappings}
        hits = list(report.static.api_technique_hits) if report.static else []
        if not cells and not mappings and not hits:
            lines.append("_No ATT&CK techniques mapped._")
            return "\n".join(
                lines
                + _not_published_lines(report, ctx)[0]
                + _mbc_lines(report)
                + _unmapped_behaviour_lines(report)
            )

        corroboration = (report.run_summary or {}).get("corroboration") or {}
        lines.append(
            _row(
                "Tactic",
                "ID",
                "Technique",
                "Procedure",
                "Source",
                "Confidence",
                "Status",
                "Evidence",
            )
        )
        lines.append(_divider(8))
        # The rules that fired over the binary, by technique. A rule naming a
        # technique a row already holds is folded into that row — its name into
        # the Procedure, its evidence id into the Evidence — so a technique is
        # one row however many producers named it.
        rules_by_tid: dict[str, list[dict[str, Any]]] = {}
        for hit in sorted(
            _distinct(hits, _rule_hit_key),
            key=lambda h: (
                str(h.get("source") or ""),
                str(h.get("technique_id") or ""),
                str(h.get("rule") or ""),
            ),
        ):
            rules_by_tid.setdefault(str(hit.get("technique_id") or ""), []).append(hit)
        capability_ids = _capability_evidence_ids(report)
        seen: set[str] = set()
        # The reasons this section shortens to fit, counted as each is cut.
        cuts = 0
        for cell in sorted(cells, key=_tactic_key):
            seen.add(cell.technique_id)
            row, cut = _attack_row(
                cell,
                mappings.get(cell.technique_id),
                corroboration,
                ctx,
                rules_by_tid.get(cell.technique_id, []),
                capability_ids,
            )
            cuts += cut
            lines.append(row)
        # A published technique the matrix does not hold — a stored report
        # from before every id was collected into it — still gets its row.
        for tid, mapping in mappings.items():
            if tid in seen:
                continue
            seen.add(tid)
            folded = rules_by_tid.get(tid, [])
            procedure = (
                ctx.cell(str(mapping.evidence_quotes[0])) if mapping.evidence_quotes else "-"
            )
            lines.append(
                _row(
                    f"{mapping.tactic_name} ({mapping.tactic})"
                    if mapping.tactic
                    else mapping.tactic_name or "-",
                    tid,
                    mapping.technique_name,
                    _with_rules(procedure, folded),
                    ", ".join(mapping.contributing_layers) or "-",
                    _stated(mapping.confidence, ""),
                    "published"
                    + _corroborated_words(mapping, folded)
                    + (f"; {ctx.rule_only[tid]}" if tid in ctx.rule_only else "")
                    + (
                        f"; {_observed_cell(mapping.observed_in, ctx)}"
                        if mapping.observed_in
                        else ""
                    ),
                    _technique_evidence_cell(mapping, folded, capability_ids),
                )
            )
        # The rules whose technique no row holds, one row per technique.
        for tid, folded in rules_by_tid.items():
            if tid in seen:
                continue
            lines.append(_rule_only_row(tid, folded, mappings, capability_ids))
        lines.extend(_resolved_only_lines(sorted(cells, key=_tactic_key), rules_by_tid, ctx))
        if hits:
            lines.extend(["", _rule_match_note(report, cells, mappings, rules_by_tid, ctx)])
        held, cut = _not_published_lines(report, ctx)
        cuts += cut
        noted = judge_cut_note(cuts, report)
        return "\n".join(
            lines
            + held
            + (["", noted] if noted else [])
            + _mbc_lines(report)
            + _unmapped_behaviour_lines(report)
        ).rstrip()

    # ------------------------------------------------------------------
    # 9. Indicators of compromise
    # ------------------------------------------------------------------

    def _section_indicators(self, report: MalwareReport, ctx: _Context) -> str:
        lines = [_heading(9, INDICATORS_TITLE, PER_ROW), ""]
        host = [row for row in ctx.iocs if row.kind not in _NETWORK_KINDS]
        every_network = [row for row in ctx.iocs if row.kind in _NETWORK_KINDS]
        # A row read from the file's strings that nothing in the run reads as
        # a network value has that value's form only: its own table, after.
        network = [row for row in every_network if not _form_of(row, ctx.forms)]
        formed = [row for row in every_network if _form_of(row, ctx.forms)]
        ta = report.technical_analysis
        identifiers = list(ta.host_identifiers) if ta is not None else []
        if not host and not every_network and not identifiers:
            lines.extend(["No indicator was extracted in this run.", ""])
        if host:
            lines.extend([_subheading("", "File and host indicators", PER_ROW), ""])
            lines.append(_row("Type", "Value", "Context", "Source", "Published"))
            lines.append(_divider(5))
            for row in host:
                lines.append(
                    _row(
                        # A path the extractor took from a longer string says so.
                        ctx.value(_form_of(row, ctx.forms) or row.type),
                        # A file or host value that holds a network value
                        # ("//relay.example.net/path/" read as a path) holds
                        # it defanged; any other is printed as it is.
                        _code_span(ctx.plain(row.value)),
                        "; ".join(
                            part
                            for part in (
                                ctx.context(row),
                                _observed_cell(row.observed_in, ctx),
                            )
                            if part
                        )
                        or "-",
                        ctx.value(row.source) or "-",
                        ctx.value(row.published or "-"),
                    )
                )
            if any(not row.published for row in host):
                lines.extend(
                    [
                        "",
                        "_A dash under Published: the platform's export mints no indicator "
                        "from this row. The judge's own bundle may still carry the value._",
                    ]
                )
            lines.append("")
        if identifiers:
            lines.extend(_host_identifier_table(identifiers, ctx))
        for title, rows_of in (("Network indicators", network), (FORM_ROWS_TITLE, formed)):
            if not rows_of:
                continue
            reputation = ctx.reputations
            lines.extend([_subheading("", title, PER_ROW), ""])
            head = ["Type", "Value (defanged)", "Port/Path", "Context", "Source", "Published"]
            if reputation:
                head.append("Reputation (post-hoc enrichment)")
            lines.append(_row(*head))
            lines.append(_divider(len(head)))
            for row in rows_of:
                cells = [
                    ctx.value(_form_of(row, ctx.forms) or row.type),
                    _code_span(defang(row.value, row.kind or "")),
                    _port_or_path(row, report),
                    "; ".join(
                        part
                        for part in (
                            # "the host of <url>": the URL is defanged too.
                            ctx.context(row),
                            f"recovered by {ctx.recovered(row)}" if row.recovered_by else "",
                            _observed_cell(row.observed_in, ctx),
                        )
                        if part
                    )
                    or "-",
                    ctx.value(row.source) or "-",
                    ctx.value(row.published or "-"),
                ]
                if reputation:
                    cells.append(reputation.get(row.value.strip().lower().rstrip("."), "-"))
                lines.append(_row(*cells))
            lines.append("")
        lines.extend(_enrichment_not_asked_lines(report))
        rid = _one_line(stored_report_id(report) or "{report_id}")
        lines.append(
            "Network values are defanged for reading. The STIX 2.1 bundle "
            f"({_code_span(f'/reports/{rid}/stix')}) and the machine-readable list "
            f"({_code_span(f'/reports/{rid}/iocs')}, see Reports on the documentation's "
            "REST API page) "
            "carry them live."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 10. Detection
    # ------------------------------------------------------------------

    def _section_detection(self, report: MalwareReport, ctx: _Context) -> str:
        blocks: list[str] = []
        rules = [s for s in report.sections if s.key in _RULE_SECTIONS]
        if rules:
            body = [_subheading("10.1", "Rules that matched this sample", MEASURED), ""]
            for section in rules:
                at = section.columns.index("Rule") if "Rule" in section.columns else 0
                every = [_one_line(row[at]) for row in section.rows if len(row) > at]
                names = every[:20]
                ids = f" ({_ids(section.evidence_ids)})" if section.evidence_ids else ""
                more = (
                    f" and {len(every) - 20} more ({section_reference(STATIC_TITLE)})"
                    if len(every) > 20
                    else ""
                )
                body.append(
                    _item(
                        f"{ctx.value(section.title, pipes=True)}{ids}: "
                        + ((", ".join(_code_span(ctx.plain(n)) for n in names) + more) or "none")
                    )
                )
            body.extend(
                [
                    "",
                    "_The rule sets and their licences are the tools' own; see Rule hits in "
                    f"{section_reference(STATIC_TITLE)}._",
                ]
            )
            blocks.append("\n".join(body))
        else:
            blocks.append(
                _absent_subsection(
                    "10.1",
                    "Rules that matched this sample",
                    "Nothing recorded in this run: no rule match is recorded.",
                )
            )
        if report.detection_signatures:
            body = [_subheading("10.2", "Draft detection rules", GENERATED), ""]
            body.append(
                "_Generated from templates over this report's own values and not reviewed "
                "by an analyst. Test before deploying. Each rule's body is printed as "
                "written, its network values not defanged, so it compiles as deployed._"
            )
            body.append("")
            for rule in report.detection_signatures:
                status = (
                    f"compile error: {ctx.value(_one_line(rule.compile_error), pipes=True)}"
                    if rule.compile_error
                    else "compiled"
                )
                # The line naming the values a rule was drafted from is read
                # as prose and defanged; the rule's body is the rule to deploy
                # and is printed as it compiles.
                source = (
                    f"; auto-generated from {ctx.plain(_ids(rule.source_evidence))}"
                    if rule.source_evidence
                    else ""
                )
                kind = _one_line(rule.kind).upper()
                body.append(f"**{kind}** {_code_span(_one_line(rule.name))} — {status}{source}")
                body.append("")
                # What running the draft against its own sample found. A rule
                # stored before the check carries none and renders as it did.
                checked = _sample_check_line(rule, ctx)
                if checked is not None:
                    body.extend([checked, ""])
                fence = rule.kind if rule.kind in {"yara", "sigma"} else ""
                # The rule's body is the rule to deploy: it prints as it
                # compiles, set aside from the closing pass by its own token.
                fenced = _fenced(rule.body.rstrip(), fence)
                fenced[1] = ctx.keep(fenced[1])
                body.extend([*fenced, ""])
            # A format left without a draft says why (``drafts_not_built``).
            body.extend(
                line
                for item in report.drafts_not_built
                for line in (_paragraph_line(_not_drafted(item, ctx)), "")
            )
            blocks.append("\n".join(body).rstrip())
        else:
            blocks.append(
                _absent_subsection(
                    "10.2",
                    "Draft detection rules",
                    "Nothing generated in this run: the verdict is Benign, and a Benign run "
                    "publishes no malicious indicator to draft a rule from."
                    if str(report.verdict or "").strip().lower() == "benign"
                    else "Nothing generated in this run: no draft rule was built from the "
                    "indicators this report publishes."
                    + "".join(" " + _not_drafted(item, ctx) for item in report.drafts_not_built),
                )
            )
        hunting = [rec for rec in report.defensive_recommendations if rec.detection]
        if hunting:
            body = [_subheading("10.3", "Hunting notes", REPORT_MODEL), ""]
            body.extend(
                _prose_item(
                    ctx.line(rec.detection)
                    + (f" ({_one_line(rec.technique_id)})" if rec.technique_id else "")
                )
                for rec in hunting
            )
            blocks.append("\n".join(body))
        else:
            blocks.append(
                _absent_subsection(
                    "10.3",
                    "Hunting notes",
                    "Not written in this run: the report model gave no hunting note.",
                )
            )
        reference = _attck_detection_block(report)
        if reference:
            blocks.append(reference)
        return "\n\n".join([_heading(10, "Detection", PER_SUBSECTION), *blocks])

    # ------------------------------------------------------------------
    # 11. Recommendations
    # ------------------------------------------------------------------

    def _section_recommendations(self, report: MalwareReport, ctx: _Context) -> str:
        recs = report.defensive_recommendations
        mitigations = _attck_mitigation_block(report)
        if not recs:
            lines = [
                _heading(11, "Recommendations", MEASURED),
                "",
                "Not written in this run: the report model gave no recommendation.",
            ]
            if mitigations:
                lines.extend(["", mitigations])
            return "\n".join(lines)
        lines = [_heading(11, "Recommendations", REPORT_MODEL), ""]
        lines.append(_row("Priority", "Category", "Action", "Rationale", "Technique"))
        lines.append(_divider(5))
        order = {"P0": 0, "P1": 1, "P2": 2}
        for rec in sorted(recs, key=lambda r: order.get(r.priority, 9)):
            lines.append(
                _row(
                    rec.priority,
                    rec.category,
                    ctx.cell(rec.action),
                    ctx.cell(rec.rationale),
                    rec.technique_id or "-",
                )
            )
        if mitigations:
            lines.extend(["", mitigations])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 12. Attribution and related activity
    # ------------------------------------------------------------------

    def _section_attribution(self, report: MalwareReport, ctx: _Context) -> str:
        attr = report.attribution
        blocks = [_heading(12, "Attribution and related activity", PER_SUBSECTION)]
        family = [_subheading("12.1", "Family", _family_voice(report)), ""]
        family.append("**Family:** " + _family_words(report))
        if category_shown(report.malware_category):
            family.append("")
            family.append(
                f"**Category:** {category_shown(report.malware_category)} "
                f"_(a behavioural class, not a family)_{ctx.category_mark}"
            )
        blocks.append("\n".join(family))

        similarity: list[str] = []
        if attr.function_hash_matches:
            similarity.extend(
                [
                    "Function-hash matches (exact normalised-opcode hashes shared with "
                    "prior samples):",
                    "",
                    _row("Family", "Confidence", "Shared functions", "Example functions"),
                    _divider(4),
                ]
            )
            for match in attr.function_hash_matches[:10]:
                example_functions = list(match.get("example_functions") or [])
                examples = (
                    ", ".join(_code_span(ctx.plain(str(f))) for f in example_functions[:3]) or "-"
                )
                if len(example_functions) > 3:
                    examples += f" and {len(example_functions) - 3} more"
                stated = match.get("confidence")
                similarity.append(
                    _row(
                        match.get("family") or "not recorded",
                        f"{float(stated):.2f}"
                        if isinstance(stated, int | float)
                        else "not recorded",
                        match.get("shared_functions") or "-",
                        examples,
                    )
                )
            similarity.extend(
                _left_out(len(attr.function_hash_matches), 10, "function-hash matches")
            )
            similarity.append("")
        if attr.family_rag_candidates:
            similarity.extend(
                [
                    "Static-feature similarity to a reference fingerprint catalogue:",
                    "",
                    _row("Family", "Similarity", "Category", "Samples in catalogue"),
                    _divider(4),
                ]
            )
            for cand in attr.family_rag_candidates[:10]:
                score = cand.get("similarity")
                similarity.append(
                    _row(
                        cand.get("family") or "not recorded",
                        f"{float(score):.3f}" if isinstance(score, int | float) else "not recorded",
                        cand.get("malware_category") or "-",
                        cand.get("sample_count") or "-",
                    )
                )
            similarity.extend(_left_out(len(attr.family_rag_candidates), 10, "candidates"))
            similarity.append("")
        # A similar sample is a measurement only with its distance; one the
        # memory returned without a score is counted, not listed as similar.
        scored = [
            sample
            for sample in attr.similar_samples
            if isinstance(sample.get("distance"), int | float)
        ]
        unscored = len(attr.similar_samples) - len(scored)
        if scored:
            similarity.extend(
                [
                    "Nearest previously analysed samples (behavioural distance, lower is "
                    "closer; not a family verdict):",
                    "",
                    _row("Sample", "Category", "Distance", "Source"),
                    _divider(4),
                ]
            )
            for sample in scored[:10]:
                named = sample.get("sha256") or sample.get("sample_id") or "not recorded"
                similarity.append(
                    _row(
                        _code_span(str(named)),
                        sample.get("malware_category") or "-",
                        f"{float(sample['distance']):.3f}",
                        sample.get("source") or "-",
                    )
                )
            similarity.extend(_left_out(len(scored), 10, "similar samples"))
            similarity.append("")
        if unscored:
            similarity.append(
                f"{unscored} previously analysed sample{'s were' if unscored != 1 else ' was'} "
                f"returned by the long-term memory and {'are' if unscored != 1 else 'is'} not "
                "listed. No similarity measure was recorded for "
                f"{'these samples' if unscored != 1 else 'this sample'}."
            )
        blocks.append(
            "\n".join(
                [
                    _subheading("12.2", "Similarity", MEASURED),
                    "",
                    *(
                        similarity
                        or ["Nothing recorded in this run: no similarity search returned a match."]
                    ),
                ]
            ).rstrip()
        )

        if report.intro_background.strip():
            background = [_subheading("12.3", "Background", REPORT_MODEL), ""]
            text = report.intro_background.strip()
            background.append(ctx.prose(text))
            if not _EV_RE.search(text):
                background.extend(["", _UNCITED_NOTE])
            blocks.append("\n".join(background))
        else:
            blocks.append(
                _absent_subsection(
                    "12.3",
                    "Background",
                    f"Not printed in this run: {left}."
                    if (left := ctx.left_out_clause("introduction"))
                    else "Not written in this run: the report model wrote no background.",
                )
            )
        return "\n\n".join(blocks)

    # ------------------------------------------------------------------
    # 13. Limitations and analysis notes
    # ------------------------------------------------------------------

    def _section_limitations(self, report: MalwareReport, ctx: _Context) -> str:
        summary = report.run_summary or {}
        lines = [_heading(13, LIMITATIONS_TITLE, MEASURED), ""]

        ran = [row for row in (summary.get("stages") or []) if isinstance(row, dict)]
        if ran:
            lines.extend(["**What ran:**", ""])
            for row in ran:
                state = "ran" if row.get("ran") else "did not run"
                why = (
                    f": {ctx.value(str(row['reason']), pipes=True)}"
                    if row.get("reason") and not row.get("ran")
                    else ""
                )
                agents = row.get("agent_reasons") or {}
                said = "; ".join(
                    f"{ctx.value(agent, pipes=True)}: {ctx.value(str(reason), pipes=True)}"
                    for agent, reason in agents.items()
                    if reason
                )
                lines.append(
                    _item(
                        f"{_code_span(str(row.get('key', 'stage')))} {state}{why}"
                        + (f"; {said}" if said else "")
                    )
                )
            lines.append("")
        lines.append(ctx.sandbox_sentence())
        lines.append("")
        if report.limitation_inventory is not None:
            # Every row of the inventory the analyst report's section 11 prints
            # from, the ones it leaves to this bundle too, in the same words.
            from malspark.reporting.limitation_inventory import inventory_rows, reason_label

            inventory = report.limitation_inventory

            # Each tool's, sandbox's or entry's name and each recorded reason
            # written by itself by the inline rule, set into the row's own
            # words after they are written (:func:`_placed`).
            def rows_of(word: Callable[[Any], str]) -> list[str]:
                return [
                    row.text
                    for row in inventory_rows(
                        inventory,
                        quote=lambda text: f'"{word(" ".join(str(text).split()))}"',
                        name=word,
                        reason_as=reason_label,
                        entry=word,
                    )
                ]

            rows = _placed(rows_of, ctx.inline, ctx.value, inventory)
            if rows:
                lines.extend([f"**{INVENTORY_HEADING}:**", ""])
                lines.extend(_item(row) for row in rows)
                lines.append("")

        if report.degradation_reasons:
            # Every reason as the run recorded it, with the operator's remedy
            # where the reason carries one: the header says only what they mean
            # for the verdict.
            lines.extend(["**What limited this run:**", ""])
            lines.extend(
                _item(ctx.value(reason, pipes=True)) for reason in report.degradation_reasons
            )
            lines.append("")
        if report.operator_choices:
            # What the operator's configuration left out: listed whole, apart
            # from what limited the run, since it cost no evidence the run's
            # configuration would have given.
            lines.extend([f"**{OPERATOR_CHOICES_HEADING}:**", ""])
            lines.extend(_item(ctx.value(reason, pipes=True)) for reason in report.operator_choices)
            lines.append("")

        evidence = summary.get("evidence") or {}
        if evidence:
            repeats = int(evidence.get("repeats") or 0)
            guarded = int(evidence.get("guard_answers") or 0)
            lines.append(
                f"**Evidence bounds:** {evidence.get('entries', 0)} ledger entries, "
                f"{evidence.get('ok', 0)} ok, {evidence.get('failed', 0)} failed"
                + _redone_clause(evidence, ids=True, inventory=report.limitation_inventory)
                + ", "
                + (f"{repeats} answered from an earlier entry without running, " if repeats else "")
                + (f"{guarded} answered by a guard with no tool run, " if guarded else "")
                + f"{_trimmed(evidence, report.limitation_inventory)} trimmed to the budget"
                + _guardrail_cut_clause(evidence, summary.get("truncation"))
                + "."
            )
            lines.append("")
        failures = [row for row in (evidence.get("failures") or []) if isinstance(row, dict)]
        if failures:
            lines.extend(["**Tool failures:**", ""])
            for row in failures:
                tool = str(row.get("tool") or "tool")
                server = f" ({ctx.value(row['server'], pipes=True)})" if row.get("server") else ""
                count = int(row.get("count") or 1)
                times = f" ×{count}" if count > 1 else ""
                message = ctx.value(str(row.get("error") or "").strip(), pipes=True) or "failed"
                remedy = ctx.value(str(row.get("remediation") or "").strip(), pipes=True)
                lines.append(
                    _item(
                        f"{_code_span(tool)}{server}{times}: {message}"
                        + (f" — {remedy}" if remedy else "")
                    )
                )
            lines.append("")
        truncation = summary.get("truncation")
        if isinstance(truncation, dict):
            trunc = SimpleNamespace(**truncation)
            partial = str(truncation.get("evidence_corpus_partial_reason") or "").strip()
            said_parts = [
                f"Grounding searched less than this run produced ({partial})." if partial else "",
                corpus_held_sentence(trunc),
                bundle_loss_sentence(trunc),
            ]
            said_parts = [s for s in said_parts if s]
            if said_parts:
                lines.extend([_one_line(" ".join(said_parts)), ""])

        validation = summary.get("validation") or {}
        # Each identical finding once, with how many times it was left: a
        # record stored before the run summary folded them is folded here.
        from malspark.pipeline.validation import folded_rows, unresolved_total

        unresolved = folded_rows(
            [row for row in (validation.get("unresolved") or []) if isinstance(row, dict)]
        )
        exports = [row for row in unresolved if str(row.get("code", "")).startswith("stix.")]
        others = [row for row in unresolved if row not in exports]
        # A question the producer answered as it allows is not left unresolved:
        # it is listed after the count, marked, and not counted in it.
        answered = [row for row in others if row.get("answered")]
        others = [row for row in others if row not in answered]
        if validation:
            not_run = validation.get("not_run") or []
            # The advisory rows as one number, so a reader does not count the
            # marks: the platform dropped nothing over any of them.
            advisory_total = unresolved_total([row for row in others if row.get("advisory")])
            lines.append(
                f"**Validation:** {validation.get('retries', 0)} feedback retries, "
                f"{unresolved_total(others)} finding(s) left unresolved"
                + (
                    f", {advisory_total} of them advisory (nothing was dropped over them)"
                    if advisory_total
                    else ""
                )
                + (f"; checks that could not run: {', '.join(not_run)}" if not_run else "")
                + "."
            )
            lines.append("")
            for row in others:
                advisory = " (advisory)" if row.get("advisory") else ""
                lines.append(
                    _item(
                        f"{_code_span(str(row.get('code', '')))} "
                        f"({ctx.value(str(row.get('agent', '')), pipes=True)}){advisory}"
                        f"{_times(row)}: {_finding_text(row, ctx.plain)}"
                    )
                )
            for row in answered:
                lines.append(
                    _item(
                        f"{_code_span(str(row.get('code', '')))} "
                        f"({ctx.value(str(row.get('agent', '')), pipes=True)})"
                        " (answered)"
                        f"{_times(row)}: {_finding_text(row, ctx.plain)}"
                    )
                )
            if others or answered:
                lines.append("")
            # What a kept validation retry left out of an analyst's first
            # answer, and what became of each item when the analyst was asked.
            drops = [row for row in validation.get("retry_drops") or [] if isinstance(row, dict)]
            if drops:
                lines.extend(["**Items a kept validation retry left out:**", ""])
                from malspark.pipeline.validation import retry_drop_sentences

                # The platform's sentence quoting a model's words, as one
                # string: written whole by the value writer.
                lines.extend(
                    _item(ctx.value(sentence, pipes=True))
                    for sentence in retry_drop_sentences(drops)
                )
                lines.append("")
            # What a retry withdrew with a WITHDRAW line, with its reason.
            withdrawn = [
                row for row in validation.get("retry_withdrawals") or [] if isinstance(row, dict)
            ]
            if withdrawn:
                lines.extend(["**Items a validation retry withdrew:**", ""])
                lines.extend(
                    _item(ctx.value(str(row.get("sentence") or ""), pipes=True))
                    for row in withdrawn
                )
                lines.append("")
        if exports:
            lines.extend(["**Export decisions:**", ""])
            for row in exports:
                said = _finding_text(row, ctx.plain)
                lines.append(_item(f"{_code_span(str(row.get('code', '')))}: {said}"))
            lines.append("")
        lines.append(
            "Values in Measured sections come from tools and are reported as the tools "
            "returned them. Assessed sections are the models' conclusions, reported as "
            "they wrote them; the checks above are the platform's comments on them."
        )
        lines.extend(_claims_not_discussed_lines(report, ctx))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Appendices
    # ------------------------------------------------------------------

    def _appendix_evidence(self, report: MalwareReport, ctx: _Context) -> str:
        """The calls behind the report, then everything the tools and agents produced.

        Generic on purpose: a section knows whether it is a table, a key/value
        block, a list or a paragraph, and this renders that, so a tool server
        added tomorrow prints without a renderer change.
        """
        # Each section carries its own voice: a tool's answer is measured, and
        # an analyst's table or finding is the analyst's, never under Measured.
        lines = [_appendix_heading("A", "Evidence index", PER_SUBSECTION), ""]
        lines.extend(_ledger_seal_lines(report))
        if not report.evidence_index and not report.sections:
            lines.append("No tool call is recorded in this report.")
            return "\n".join(lines)
        if report.evidence_index:
            lines.append(_row("ID", "Agent", "Server", "Tool", "OK", "Duration", "Trimmed"))
            lines.append(_divider(7))
            for row in report.evidence_index:
                lines.append(
                    _row(
                        row.id,
                        ctx.value(row.agent) or "-",
                        ctx.value(row.server) or "-",
                        ctx.value(row.tool) or "-",
                        _ran_column(row),
                        f"{row.duration_ms} ms",
                        "yes" if row.truncated else "no",
                    )
                )
            lines.append("")
        for section in report.sections:
            lines.extend([_evidence_heading(section, ctx.plain), ""])
            analysts = listed_by(section)
            if analysts:
                # A model's table, said as one before its rows: nothing in it
                # was measured, and no count, match or profile reads it.
                kind = str(section.key or "").removeprefix("artifact_")
                typed = _typed_values_shown(section, kind, ctx)
                lines.extend([analyst_list_note(analysts, kind, typed), ""])
            elif is_open_question_section(section):
                lines.extend([OPEN_QUESTIONS_NOTE, ""])
            lines.extend(
                _evidence_body(
                    section,
                    ctx.plain,
                    declared_code=declares_code(section.evidence_ids, report.evidence_index),
                    cites_cut=cites_a_cut_entry(section.evidence_ids, report.evidence_index),
                )
            )
            if section.evidence_ids:
                lines.extend(["", f"_Evidence: {_ids(section.evidence_ids)}_"])
            lines.append("")
        return "\n".join(lines).rstrip()

    def _appendix_run(self, report: MalwareReport, ctx: _Context | None = None) -> str:
        run_summary = report.run_summary or {}
        # The platform's own words around values each set in by itself
        # (:func:`_placed`): its spans kept, every other character Markdown
        # reads escaped.
        inline = ctx.inline if ctx is not None else _escaped_spelling
        plain = ctx.plain if ctx is not None else _defanged_text

        def value(text: Any) -> str:
            """A tool's or the operator's name, by the inline rule; the row keeps its separator."""
            return ctx.value(text) if ctx is not None else _inline_safe(text, pipes=False)

        def named(text: Any) -> str:
            """A value, or a sentence quoting a model's words, inside an item, as text."""
            return ctx.value(text, pipes=True) if ctx is not None else _inline_safe(text)

        def spoken(
            build: Callable[[Callable[[Any], str]], list[str]],
            code: Callable[[str], str],
            record: Any,
        ) -> list[str]:
            """A builder's lines, every value it writes as code a span set in after the line.

            ``build`` is handed the writer of a value's code span; every other
            character of each line, a value the builder writes into its words
            included, is written by the inline rule, so no backtick of it opens a
            span, and each span is the one ``code`` writes, read by the defanger.
            """
            return _placed(build, named, lambda text: _emphasis_escaped(plain(code(text))), record)

        lines = [_appendix_heading("B", "Run summary", MEASURED), ""]
        if not run_summary:
            lines.append("No run summary was stored with this report.")
            return "\n".join(lines)
        elapsed = run_summary.get("elapsed_seconds")
        if elapsed is not None:
            lines.append(_item(f"Elapsed: {float(elapsed):.1f}s (the whole run, to this report)"))
        spent_per_stage = ", ".join(
            f"{named(key)} {seconds}" for key, seconds in stage_durations(run_summary.get("stages"))
        )
        if spent_per_stage:
            lines.append(_item(f"Per stage: {spent_per_stage}"))
        verdict = run_summary.get("final_decision")
        if verdict:
            lines.append(_item(f"Verdict: {verdict}"))
        # Said whenever no live sandbox observed the run: a reader of the
        # report's prose has to be able to tell a detonation that did nothing
        # from none at all.
        sandbox = run_summary.get("sandbox")
        if isinstance(sandbox, dict) and sandbox.get("statement"):
            lines.append(_item(f"Sandbox: {sandbox['statement']}"))
        negotiation = run_summary.get("negotiation") or {}
        if negotiation:
            rounds = negotiation.get("rounds_completed")
            reason = negotiation.get("termination_reason")
            final_conf = negotiation.get("final_confidence")
            if rounds is not None:
                lines.append(_item(f"Negotiation rounds: {rounds}"))
            if reason == NOT_APPLICABLE:
                # No agreement was measured, so no final confidence is stored
                # and the one sentence says why.
                lines.append(_item(NOT_APPLICABLE_SENTENCE))
            elif reason:
                lines.append(_item(f"Termination reason: {_code_span(str(reason))}"))
            if final_conf is not None:
                try:
                    lines.append(_item(f"{NEGOTIATION_CONFIDENCE_LABEL}: {float(final_conf):.3f}"))
                except (TypeError, ValueError):
                    pass
            # A sentence of the platform's that quotes the mediator's or an
            # analyst's words, as one string: written whole by the value writer.
            for sentence in negotiation.get("revision_replacements") or []:
                lines.append(_item(named(str(sentence))))
            # A mediation note is the platform's, carrying a provider's or an
            # exception's text and no model's words: by the inline rule.
            for sentence in negotiation.get("mediation_notes") or []:
                lines.append(_item(named(str(sentence))))
            # What the platform recorded of the debate: how many values each
            # revision states nowhere (the claims themselves are in the run
            # summary), the lines the mediator marked not blocking, the marks
            # it wrote that were not read, and the ledger counts. Each
            # sentence is written defanged.
            for row in negotiation.get("dropped_value_counts") or []:
                if isinstance(row, dict):
                    lines.append(
                        _item(
                            f"{named(str(row.get('agent')))}, round {row.get('round')}: "
                            f"{row.get('values')} value{'' if row.get('values') == 1 else 's'} "
                            f"from {row.get('claims')} earlier "
                            f"claim{'' if row.get('claims') == 1 else 's'} "
                            f"{'is' if row.get('values') == 1 else 'are'} no longer stated"
                        )
                    )
            # A line that quotes the mediator's or an analyst's words prints them
            # as text: the quote by the value writer after the platform's words,
            # a sentence that arrives as one string written whole by it.
            for sentence in negotiation.get("not_blocking") or []:
                lines.append(_item(f"Marked not blocking by the mediator: {named(str(sentence))}"))
            for sentence in negotiation.get("unread_marks") or []:
                lines.append(
                    _item(f"A mark that was not read; the line blocked: {named(str(sentence))}")
                )
            for sentence in negotiation.get("ledger_facts") or []:
                # The rule-match fact was the mediator's; the report prints counts.
                if not is_rule_fact(sentence):
                    lines.append(_item(named(str(sentence))))
            for sentence in negotiation.get("ledger_stated") or []:
                lines.append(_item(named(str(sentence))))
            for sentence in negotiation.get("limit_rulings") or []:
                lines.append(_item(named(str(sentence))))
        # A model's configured endpoint prints as configured, set aside where
        # this line writes it and nowhere else.
        model_name = ctx.endpoint_kept if ctx is not None else None
        generation = run_summary.get("generation")
        lines.extend(
            _item(line)
            for line in spoken(
                lambda word: generation_lines(generation, model_name, word),
                _code_span,
                generation,
            )
        )
        ungrounded = run_summary.get("sections_without_evidence")
        if ungrounded:
            lines.append(_item(f"Report sections with no evidence: {ungrounded}"))
        # What the models spent, as the providers reported it, and the turns a
        # fallback model answered because the first one failed as a provider.
        spent = tokens_sentence(run_summary.get("tokens"))
        if spent:
            lines.append(_item(spent))
        for agent, block in sorted((run_summary.get("models") or {}).items()):
            for row in (block or {}).get("fallbacks") or []:
                if isinstance(row, dict):
                    lines.append(
                        _item(
                            f"Model fallback ({named(agent)}): {named(str(row.get('reason', '')))}"
                        )
                    )
        for row in run_summary.get("server_rests") or []:
            if isinstance(row, dict):
                # The server's names and the reason it gave, each by the inline rule.
                lines.extend(
                    _item(line) for line in _placed(partial(_rested, row), inline, value, row)
                )
        corroboration = run_summary.get("corroboration") or {}
        if corroboration:
            from malspark.analysis.corroboration import (
                corroboration_sources,
                published_count,
                technique_label,
            )

            multi = sum(1 for row in corroboration.values() if len(corroboration_sources(row)) > 1)
            asserted = sum(
                1
                for row in corroboration.values()
                if isinstance(row, dict) and row.get("asserted_by")
            )
            lines.append(
                _item(
                    f"TTPs: {len(corroboration)} claimed, {published_count(corroboration)} "
                    f"published, {multi} claimed by more than one source, "
                    f"{asserted} asserted by a deterministic source"
                )
            )
            lines.extend(
                [
                    "",
                    "**Corroboration per technique:**",
                    "",
                    "_Catalogue is the API table's association, shown for reference; "
                    "it is not a rule match and counts for nothing._",
                    "",
                    _row("Technique", "Asserted by", "Claimed by", "Catalogue"),
                    _divider(4),
                ]
            )
            for tid, row in sorted(corroboration.items()):
                if isinstance(row, dict):
                    asserted_by = ", ".join(map(value, row.get("asserted_by") or [])) or "—"
                    claimed_by = ", ".join(map(value, row.get("claimed_by") or [])) or "—"
                    associated = ", ".join(map(value, row.get("associated_by") or [])) or "—"
                else:
                    asserted_by, claimed_by = "—", ", ".join(value(str(s)) for s in row) or "—"
                    associated = "—"
                # A retired id's reason is the catalogue's sentence, written as one.
                if isinstance(row, dict) and row.get("retired_reason"):
                    row = {**row, "retired_reason": inline(str(row["retired_reason"]))}
                # The reason an id was not published, a judge's words among them, is a
                # quote: each sentence a check left standing marked as every other place
                # marks it, every other piece written as text (:func:`_quote_written`).
                if isinstance(row, dict) and row.get("not_published"):
                    quoted = ctx.quoted if ctx is not None else _value_parts
                    reason = _quote_written(quoted(str(row["not_published"])), pipes=False)
                    row = {**row, "not_published": reason}
                label = technique_label(str(tid), row if isinstance(row, dict) else None)
                lines.append(_row(label, asserted_by, claimed_by, associated))
        # What the run sent beyond this machine, where its summary records it
        # (``analysis.disclosure``); a summary stored without the record shows
        # none. A host the settings address prints as configured, set aside
        # here and nowhere else; any other prints defanged.
        code = ctx.host_kept if ctx is not None else _code_span
        held = run_summary.get("disclosure")
        disclosed = spoken(lambda word: disclosure_lines(held, word), code, held)
        if disclosed:
            lines.extend(["", DISCLOSURE_INTRO, ""])
            lines.extend(_item(line) for line in disclosed)
            # Where the sample's bytes were read and what kept each reader
            # from the worker (``analysis.isolation``); a record stored before
            # the part existed shows none.
            part = held.get("isolation") if isinstance(held, dict) else None
            isolated = spoken(lambda word: isolation_lines(part, word), code, part)
            if isolated:
                lines.extend(["", isolation_intro(part), ""])
                lines.extend(_item(line) for line in isolated)
            # What each tool the run called is declared to do beyond answering
            # (``analysis.tool_effects``), the case-memory store a tool reaches
            # placed as the record's case-memory row places it; a record stored
            # before the part existed shows none.
            effects = held.get("effects") if isinstance(held, dict) else None
            stores = held.get("stores") if isinstance(held, dict) else None
            effected = spoken(
                lambda word: effects_lines(effects, word, stores=stores), code, effects
            )
            if effected:
                lines.extend(["", EFFECTS_INTRO, ""])
                lines.extend(_item(line) for line in effected)
            lines.extend(["", DISCLOSURE_FOOTNOTE])
        # What the run spent its input on, where its summary records it
        # (``analysis.efficiency``); a summary stored without it shows none.
        spent_on = run_summary.get("efficiency")
        counted = spoken(
            lambda word: efficiency_lines(spent_on, word),
            lambda text: _code_span(_one_line(text)),
            spent_on,
        )
        if counted:
            lines.extend(["", EFFICIENCY_INTRO, ""])
            lines.extend(_item(line) for line in counted)
        elif unbuilt := not_built_line("efficiency", run_summary.get("efficiency")):
            lines.extend(["", unbuilt])
        # What the run could not establish, what each tool looked for and over
        # which input, and the coverage of each negative claim, where the
        # summary records them (``analysis.coverage``); a summary stored
        # without the record shows none.
        # The analysts are read from the report's own analyst record
        # (``_AnalystStates``), so the block and the rest of the report agree.
        recorded = run_summary.get("coverage")
        states = _AnalystStates(report) if isinstance(recorded, dict) else None
        # A model's claim is quoted by the inline rule and a value the run
        # supplied is a code span, each set into its line after the line's own
        # writing (:func:`spoken`): a value prints its own characters, never
        # another claim's. The first character of what a mark stands for says
        # which of the two it is.
        held = (states.failed, states.skipped, states.silent) if states is not None else None
        blocks: list[list[str]] = [[], [], []]

        def built(word: Callable[[Any], str]) -> list[str]:
            blocks[:] = coverage_lines(
                recorded, lambda text: word(f"c{text}"), lambda text: word(f"q{text}"), held
            )
            return [line for block in blocks for line in block]

        def set_in(text: str) -> str:
            kind, said = text[:1], _one_line(text[1:])
            if kind == "c":
                return _emphasis_escaped(plain(_code_span(said)))
            return _inline_safe(said, plain=plain)

        written = iter(_placed(built, named, set_in, (recorded, held)))
        if unbuilt := not_built_line("coverage", recorded):
            lines.extend(["", unbuilt])
        for intro, block in zip(
            (COVERAGE_MISSING_INTRO, COVERAGE_LOOKED_INTRO, COVERAGE_NEGATIVES_INTRO),
            [len(block) for block in blocks],
            strict=True,
        ):
            if block:
                lines.extend(["", intro, ""])
                lines.extend(_item(next(written)) for _ in range(block))
        return "\n".join(lines)

    def _appendix_references(self, report: MalwareReport, ctx: _Context) -> str:
        lines = [_appendix_heading("C", "References", REFERENCE), ""]
        if not report.references:
            lines.append("_No external references._")
            return "\n".join(lines)
        # The source and the note are a tool's or the operator's words; the link
        # is the platform's, to the target the reference holds.
        for ref in report.references:
            note = f" — {ctx.value(ref.note, pipes=True)}" if ref.note else ""
            source = ctx.value(ref.source, pipes=True)
            lines.append(_item(f"[{source}]({_link_target(ref.url)}){note}"))
        return "\n".join(lines)

    def _appendix_method(self, report: MalwareReport, ctx: _Context) -> str:
        summary = report.run_summary or {}
        lines = [_appendix_heading("D", "Methodology", REFERENCE), ""]
        if report.verdict_not_assessed:
            # Said as it happened: the run stopped before its verdict stage, so
            # no judge stated a verdict or a bundle and no report model wrote.
            lines.append(
                "This report was produced by an automated team of language-model analysts "
                "working over tool servers, and is partial: "
                f"{_one_line(report.verdict_not_assessed)}, so no judge stated a verdict "
                "or a STIX bundle. What the run had produced when it stopped is shown. "
                "Every tool call is in Appendix A. " + CUT_CELL_SENTENCE
            )
        else:
            stated, counted = _judge_bundle(summary)
            lines.append(
                "This report was produced by an automated team of language-model analysts "
                "working over tool servers. The analysts' claims were negotiated, a judge "
                f"stated the verdict{stated}, and a report model wrote the assessed prose."
                f"{counted} Every tool call is in Appendix A. " + CUT_CELL_SENTENCE
            )
        lines.append("")
        profile = summary.get("profile") or {}
        analysts = ", ".join(ctx.value(name, pipes=True) for name in profile.get("analysts") or [])
        if profile.get("name"):
            team = ctx.value(profile["name"], pipes=True) + (f" ({analysts})" if analysts else "")
        else:
            team = "not recorded in this report"
        lines.append(_item(f"Team: {team}"))
        stages = [
            ctx.value(str(row.get("key")), pipes=True)
            for row in (summary.get("stages") or [])
            if isinstance(row, dict) and row.get("ran")
        ]
        if stages:
            lines.append(_item(f"Stages run: {', '.join(stages)}"))
        model = _model_line(summary.get("settings_snapshot"))
        if model:
            lines.append(_item(f"Models: {ctx.value(model, pipes=True)}"))
        servers_line = _servers_line(report, ctx)
        if servers_line:
            lines.append(_item(servers_line))
        sandbox = (
            "; ".join(_sandbox_held(report))
            if ctx.sandbox_state == "observed"
            else _SANDBOX_STATES[ctx.sandbox_state]
        )
        lines.append(_item(f"Sandbox: {sandbox}"))
        lines.append(_item(f"Report generated: {report.generated_at.isoformat()}"))
        if report.version_history:
            lines.extend(["", _row("Version", "Date", "Authors", "Description"), _divider(4)])
            for row in report.version_history:
                cells = (row.version, row.date, row.authors, row.description)
                lines.append(_row(*(ctx.value(cell) for cell in cells)))
        if report.disclaimer:
            lines.extend(["", f"_{_one_line(report.disclaimer)}_"])
        if report.acknowledgements:
            lines.extend(["", _escape_block(report.acknowledgements)])
        for extra in report.appendices:
            lines.extend(["", _escape_block(extra)])
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# What the sections share
# ---------------------------------------------------------------------------

# The evidence sections that are rule hits: the table of each rule kind
# (``ledger_report.RULE_TABLES``), keyed by its kind whichever tool filled it.
_CAPABILITY_SECTION = section_key_of_kind("capability_rules")
_RULE_SECTIONS = tuple(section_key_of_kind(kind) for kind in RULE_TABLES)

# How the report builder begins the reason for an absent summary. Spelled here
# rather than imported so the renderer keeps no import of the builder.
_NO_SUMMARY_PREFIX = "the report model wrote no summary"


def _inconclusive_reasons() -> tuple[str, ...]:
    from malspark.pipeline.outcome import INCONCLUSIVE_REASONS

    return tuple(INCONCLUSIVE_REASONS)


_INCONCLUSIVE = _inconclusive_reasons()


class _Context:
    """What several sections read, computed once per render."""

    def __init__(self, report: MalwareReport) -> None:
        self.report = report
        # What the renderer set aside from the closing defang pass, by token.
        # The token carries a value drawn for this render, so no text a
        # sample, a sandbox or a model wrote can name one.
        self._kept: dict[str, str] = {}
        self._nonce = secrets.token_hex(8)
        self._labels: set[str] | None = None
        self._hosts: set[str] | None = None
        # How a model-written cell writes the citations in it (:meth:`cell`): as
        # written here, where prose prints them so; the layout whose prose moves
        # them to note markers sets its own, so a table and a paragraph cite alike.
        self.cell_citations: Callable[[str], str] | None = None
        summary = report.run_summary or {}
        validation = summary.get("validation") or {}
        self.unresolved = [
            row for row in (validation.get("unresolved") or []) if isinstance(row, dict)
        ]
        self.verdict_findings = [
            {
                "code": str(row.get("code", "")),
                "message": " ".join(str(row.get("message") or "").split()),
            }
            for row in self.unresolved
            if str(row.get("code", "")).startswith("verdict.")
            or row.get("code") == "stix.indicator_type_contradicts_verdict"
        ]
        # The steps and items a survived finding names, read back from its
        # sentence: ``step <order> is marked observed``, ``configuration item <n>``.
        self.flow_findings = _named_in(
            self.unresolved, "report.flow_voice", r"step (\S+) is marked"
        )
        # The report model's own findings the validator kept: printed beside §1.
        self.narrative_findings = [
            {
                "code": str(row.get("code", "")),
                "message": " ".join(str(row.get("message") or "").split()),
            }
            for row in self.unresolved
            if str(row.get("code", "")).startswith("narrative.")
        ]
        # The published techniques only a rule match stands behind, with how
        # much matched: printed beside the row's status.
        from malspark.analysis.corroboration import rule_match_only

        self.rule_only = rule_match_only(report)
        # Each table row a finding names, and whether any finding naming it
        # was asked: a row's mark says when none was (:func:`_row_mark`).
        self.identifier_findings = _numbers_asked(
            self.unresolved, "report.identifier_uncited", r"identifier (\d+)"
        )
        self.config_findings = _numbers_asked(
            self.unresolved, "report.configuration_uncited", r"configuration item (\d+)"
        )
        # The rows whose value is in none of the entries they cite, kept after
        # the question or never asked: marked beside their evidence.
        self.config_unheld = _rows_named_in(
            self.unresolved, "report.value_not_in_cited_entry", "configuration item"
        )
        self.identifier_unheld = _rows_named_in(
            self.unresolved, "report.value_not_in_cited_entry", "identifier"
        )
        # The rows whose value a cited entry holds only inside a longer run of
        # text: recorded, never asked, and marked beside their evidence.
        self.config_inside = _rows_named_in(
            self.unresolved, _INSIDE_A_TOKEN_CODE, "configuration item"
        )
        self.identifier_inside = _rows_named_in(self.unresolved, _INSIDE_A_TOKEN_CODE, "identifier")
        # Of those, the rows whose run the finding could not show.
        from malspark.pipeline.validation import RUN_NOT_SHOWN

        self.config_run_unshown = set(
            _rows_named_in(
                self.unresolved, _INSIDE_A_TOKEN_CODE, "configuration item", saying=RUN_NOT_SHOWN
            )
        )
        self.identifier_run_unshown = set(
            _rows_named_in(
                self.unresolved, _INSIDE_A_TOKEN_CODE, "identifier", saying=RUN_NOT_SHOWN
            )
        )
        # What the run knows about a sandbox, in four answers: it recorded
        # something; its tools were called and returned nothing; none was
        # called; or the report does not say (stored without its index).
        from malspark.reporting.evidence_bundles import sandbox_recorded

        observed = sandbox_recorded(report)
        # The pack's status entry is a sentence about the sandbox, not a call
        # to one, and is read as the statement it is.
        called = any(
            tool_kinds.is_of(row, _SANDBOX_TOOLS) and not _is_sandbox_status(row)
            for row in report.evidence_index
        )
        self.sandbox_statement = _sandbox_statement(report)
        self.sandbox_state = (
            "observed"
            if observed
            else "empty"
            if called
            else "not_called"
            if report.evidence_index
            else "unknown"
        )
        self.sandbox_observed = observed
        self.sandbox_reason = _sandbox_reason(report)
        # "No persistence observed" is a sandbox's to say only when it watched
        # the places persistence is written: a run whose sandbox recorded one
        # URL and nothing about the host looked at none of them.
        from malspark.reporting.evidence_bundles import sandbox_watched_persistence

        self.sandbox_watched_persistence = sandbox_watched_persistence(report)
        self.analysts = _AnalystStates(report)
        team = _team(report)
        self.no_analyst_claims = bool(team) and set(team) <= self.analysts.idle
        self._tools = {row.id: row for row in report.evidence_index}
        # The tools that looked at the file itself, in the order they ran: not
        # a sandbox's, and not a lookup about the sample elsewhere.
        ranked: dict[str, int] = {}
        for row in report.evidence_index:
            if row.tool and str(row.tool) not in ranked and _looked_at_the_file(row):
                ranked[str(row.tool)] = _analysis_rank(row)
        # The analysis tools first, the identity and parsing tools after.
        self.file_tools = sorted(ranked, key=lambda tool: ranked[tool])
        # The table is built once, each value its rows' contexts name marked;
        # the rows read as built, the marks kept for the printed contexts.
        self._row_words = _RowWords(report)
        read = _indicator_rows(report, self._row_words.place)
        self._table_read = read is not None
        self.iocs = self._row_words.rows(read or [])
        # The printed type of each row read from the file's strings that
        # nothing in the run reads as its kind; the kind stays every key.
        self.forms = _string_row_forms(report, self.iocs)
        indicators = run_network_values(report, self.iocs)
        self.indicators = indicators
        run_values = ProseDefanger(indicators)
        # The same pass, for the closing read of every section (``_render``),
        # over each value as written and as an escaped cell writes it
        # ("cdn\_.example.zip"): a section that escaped a value before the
        # run's values were read leaves it for this pass to find.
        self.run_values = ProseDefanger(
            indicators
            + [
                (escaped, kind)
                for value, kind in indicators
                if (escaped := _escaped_spelling(value)) != value
            ]
        )
        # The run's own values first, then every other URL, mailbox, address
        # and host the text names: a model's prose can name one the run never
        # recorded, and it is printed for reading like any other.
        self._defang = lambda text: _defanged_text(run_values(text)) if text else text
        self.reputations = _reputations(report)
        # The report model's sentences a check asked about and the retry left
        # standing, each with the mark printed after it. Longest first, so a
        # sentence that holds another is marked as itself.
        # The statements a check of the finished report finds against what the
        # run published (``prose_decisions``) are marked the same way; the
        # category's row is marked on the category line (``category_mark``),
        # not wherever its word stands in prose.
        marks: dict[str, list[str]] = {}
        # The codes each marked sentence was flagged under, in the order found:
        # what the analyst report reads to rewrite or leave a sentence out (T-555).
        self.flag_codes: dict[str, list[str]] = {}
        self.category_mark = ""
        # The IOC table's answers, read on first use by ``publish_state``.
        self._answers: Any = None
        # Whether this render prints a value's whole answer in an indicator row,
        # given its kind, value and answer: a cell beside the value then prints
        # what refused it, and else the whole answer (``publish_state``). ``None``
        # where the render's indicator section prints every row whole; the
        # analyst layout sets it.
        self.whole_answer_printed: Callable[[str, str, str], bool] | None = None
        stored = list(getattr(report, "flagged_statements", None) or [])
        # The sentences printed in their writer's own words that the agreement question left
        # out (``FlaggedStatement.left_out``), by each place of the analyst report it is left
        # out of: that report leaves it out there, and no render marks it as standing, so the
        # bundle prints it whole beside the round's record (T-613).
        self.verbatim_left: dict[str, list[str]] = {}
        for row in stored:
            for place in row.left_out:
                self.verbatim_left.setdefault(place, []).append(row.sentence)
        stored = [row for row in stored if not row.left_out]
        for read in _joined_marks(with_decided_statements(stored, report)):
            statement = as_rendered(read, self._read_again)
            if statement is None:
                continue
            if statement.sentence.strip():
                try:
                    label = _inline_safe(statement.label, pipes=False, plain=self._defang)
                except Exception as exc:  # noqa: BLE001 — the sentence is marked all the same
                    logger.debug("markdown: a mark's label was not written (%s).", exc)
                    label = STATE_UNKNOWN
                mark = _flag_mark(statement.code, label, asked=statement.asked)
                if statement.code == CATEGORY_TYPE_UNSTATED_CODE:
                    self.category_mark = f" {mark}"
                    continue
                if mark not in marks.setdefault(statement.sentence, []):
                    marks[statement.sentence].append(mark)
                codes = self.flag_codes.setdefault(statement.sentence, [])
                if statement.code not in codes:
                    codes.append(statement.code)
        self.flagged = sorted(
            ((sentence, " ".join(found)) for sentence, found in marks.items()),
            key=lambda pair: -len(pair[0]),
        )
        # The sentences printed in their writer's own words left standing, each found by its
        # words (:meth:`places`, T-613).
        from malspark.reporting.section_agreement import LISTED_CODE

        self._by_words = {
            sentence for sentence, codes in self.flag_codes.items() if LISTED_CODE in codes
        }

    def source_of(self, evidence_id: str) -> str:
        """Who recorded one ledger entry: its agent and its tool, or that it is unknown."""
        row = self._tools.get(str(evidence_id or ""))
        if row is None:
            return "not recorded"
        tool = self.value(row.tool) or "tool"
        return f"{self.value(row.agent)} ({tool})" if row.agent else tool

    def left_out(self, subject: str) -> bool:
        """Whether the agreement question left a sentence of the passage ``subject`` out
        (``section_agreement.LEFT_OUT_CODES``), so an empty field of it was written, not
        missing (T-600)."""
        from malspark.reporting.section_agreement import LEFT_OUT_CODES

        return any(
            row.get("code") in LEFT_OUT_CODES and str(row.get("subject") or "") == subject
            for row in self.unresolved
        )

    def left_out_clause(self, *subjects: str, on: str = "") -> str:
        """The clause a line saying nothing was written for a passage says instead where the
        agreement question left its sentences out (T-600), with their count, naming no one
        as having left them out (its checks or the round's own drop): the records of them
        (``section_agreement.LEFT_OUT_CODES``) whose subject is one of ``subjects``, or, for
        one ending in ".", a record of that list ("key_findings."); ``on`` follows "wrote"
        (" on it"); ``""`` where none was left out."""
        from malspark.reporting.section_agreement import LEFT_OUT_CODES

        whole = {s for s in subjects if not s.endswith(".")}
        lists = tuple(s for s in subjects if s.endswith("."))
        count = sum(
            1
            for row in self.unresolved
            if row.get("code") in LEFT_OUT_CODES
            and (
                (subject := str(row.get("subject") or "")) in whole
                or (bool(lists) and subject.startswith(lists))
            )
        )
        if not count:
            return ""
        one = count == 1
        return (
            f"the {count} sentence{'' if one else 's'} the report model wrote{on} "
            f"{'was' if one else 'were'} left out"
        )

    def no_sandbox_clause(self) -> str:
        """Why no sandbox observation stands behind a subsection, as a clause."""
        if self.sandbox_state == "empty":
            return "the sandbox recorded nothing for this sample"
        if self.sandbox_state == "not_called":
            return "no sandbox ran"
        return "this report records no sandbox observation"

    def absence(self, what: str, *, sandbox: bool, subjects: Sequence[str] = ()) -> str:
        """The one line a capability subsection prints when nothing speaks in it.

        It names what looked: the tools that ran over the file, and the
        sandbox's state where the capability is one a sandbox would see. "Not
        examined" is said only when nothing looked at all. Where the agreement
        question left out what the report model wrote in the passages ``subjects``
        name, it says so, with the count (:meth:`left_out_clause`).
        """
        wrote = (
            self.left_out_clause(*subjects, on=" on it") or "the report model wrote nothing on it"
        )
        tools = self.file_tools
        # A tool's name is the tool's text, by the inline rule.
        named = ", ".join(self.value(tool, pipes=True) for tool in tools[:6]) + (
            f" and {len(tools) - 6} more" if len(tools) > 6 else ""
        )
        blind = sandbox and not self.sandbox_observed
        if not tools:
            said = (
                f"{self.no_sandbox_clause()}, no tool looked at the file"
                if blind
                else ("no tool looked at the file")
            )
            return f"Not examined in this run: {said}, and {wrote}."
        said = f"the tools that ran over the file ({named}) recorded no {what}"
        if blind:
            said += f", and {self.no_sandbox_clause()}"
        line = f"Nothing recorded in this run: {said}; {wrote}."
        # Where the run recorded what each tool looked for and over which
        # input (``analysis.coverage``), the line says where; a report stored
        # without the record prints the line as before.
        held = (self.report.run_summary or {}).get("coverage")
        if isinstance(held, dict) and "v" in held:
            line += f" {COVERAGE_POINTER}"
        return line

    @classmethod
    def of(cls, report: MalwareReport) -> _Context:
        return cls(report)

    def prose(self, text: str) -> str:
        """Model prose, with the run's own network indicators defanged in it.

        A paragraph may keep its line breaks; a line of it may not open a
        heading or a code fence, which would re-section the report or swallow
        everything after it.
        """
        return _escape_block(self._defang(self.marked(text)))

    def marked(self, text: str) -> str:
        """``text`` with each flagged sentence followed by its mark; the words are unchanged."""
        return "".join(piece for piece, _mark in self.marked_parts(text))

    def marked_parts(self, text: str) -> list[tuple[str, bool]]:
        """``text`` as :meth:`marked` prints it, in pieces, each with whether it is a mark."""
        # One pass over positions, keyed by the sentence: every place a flagged
        # sentence stands gets its own mark, the longest sentence first so one
        # inside another is marked as itself, and a place already marked is
        # left alone.
        claimed: list[tuple[int, int]] = []
        inserts: list[tuple[int, str]] = []
        for sentence, mark in self.flagged:
            for start, end in self.places(sentence, text):
                inside = any(a <= start and end <= b for a, b in claimed)
                if not inside and not text.startswith(f" {mark}", end):
                    claimed.append((start, end))
                    inserts.append((end, mark))
        parts: list[tuple[str, bool]] = []
        at = 0
        for end, mark in sorted(inserts):
            parts += [(text[at:end], False), (f" {mark}", True)]
            at = end
        return [*parts, (text[at:], False)]

    def quoted(self, text: str) -> list[tuple[str, bool]]:
        """A platform sentence quoting a model's words, in pieces, before any cut: each
        flagged sentence's mark the platform's, every other piece read as a value is
        (:func:`_value_parts`)."""
        return [
            part
            for piece, mark in self.marked_parts(text)
            for part in ([(piece, True)] if mark else _value_parts(piece, self.plain))
        ]

    def places(self, form: str, text: str, sentence: str | None = None) -> list[tuple[int, int]]:
        """Where ``form`` of the flagged ``sentence`` (``form`` itself where not given) stands
        in ``text``, every place: as written, or, for a sentence printed in its writer's own
        words left standing, by its words, whatever the white space between them (T-613)."""
        if (form if sentence is None else sentence) in self._by_words:
            words = r"\s+".join(re.escape(word) for word in form.split())
            return [(found.start(), found.end()) for found in re.finditer(words, text)]
        out: list[tuple[int, int]] = []
        start = text.find(form)
        while start != -1:
            out.append((start, start + len(form)))
            start = text.find(form, start + 1)
        return out

    def publish_state(self, text: Any) -> str:
        """`` (no: <why>)`` for each value of a table cell this run does not publish, or ``""``.

        The platform states the IOC table's answer beside the value; nothing
        is asked. A reference host no row holds is no indicator and gets
        nothing. The state is what refused the value, every refusing part of
        the answer (``publish_parts.answer_state``), as the prose marks print
        it, where this render prints the whole answer in an indicator row; where
        it prints it in none (:attr:`whole_answer_printed`), the whole answer,
        every part of it (:meth:`_cell_state`). One value
        alone is not named again. Written defanged and
        with Markdown's own characters escaped (:func:`_inline_safe`). Fails
        closed: a table that cannot be read states every value refused for
        that reason, and a lookup that fails says the state is unknown.

        A cell whose whole text is the value of its own indicator row, where
        the reader of its values did not find that row (a URL is read as its
        host), prints that row's own answer (:meth:`_own_row_state`); a cell
        that prints no state otherwise prints none.
        """
        try:
            from malspark.reporting.defang import defang

            unstated = self._unstated(text)
            if not unstated:
                return ""
            own = self._own_row_state(text, unstated)
            if own is not None:
                return own
            found = [
                (kind, value, self._cell_state(kind, value, state))
                for kind, value, state in unstated
            ]
            if len(found) == 1:
                said = found[0][2]
            else:
                said = "; ".join(f"{defang(value, kind)}: {state}" for kind, value, state in found)
            return f" ({_inline_safe(said, pipes=False, plain=self.plain)})"
        except Exception as exc:  # noqa: BLE001 — the cell says what is not known
            logger.debug("markdown: a cell's publish state was not read (%s).", exc)
            return f" ({STATE_UNKNOWN})" if _names_a_network_value(text) else ""

    def _own_row_state(self, text: Any, unstated: list[tuple[str, str, str]]) -> str | None:
        """What a cell prints by its own row's answer, or ``None`` where the reader decides.

        The cell's own row is the indicator row whose value is the cell's whole
        text (one spelling, ``value_key``). Where the reader of the cell's
        values found that row, or no row or rows of more than one answer hold
        the text, or the row has no answer, the reader's values decide
        (``None``). Otherwise the cell
        prints that row's answer: nothing where the row is published, its
        state where it is not (:meth:`_cell_state`).
        """
        from malspark.reporting.ledger_projection import value_key
        from malspark.reporting.publish_parts import answer_state
        from malspark.reporting.renderers.stix_renderer import publishes

        whole = str(text or "").strip()
        kinds = dict.fromkeys(
            str(row.kind)
            for row in self.iocs
            if row.kind and value_key(str(row.kind), row.value) == value_key(str(row.kind), whole)
        )
        if not kinds:
            return None
        found = {(kind, value_key(kind, value)) for kind, value, _state in unstated}
        if any((kind, value_key(kind, whole)) in found for kind in kinds):
            return None
        answers = {kind: self._answers(kind, whole) for kind in kinds}
        if len({str(answer) for answer in answers.values()}) != 1:
            return None
        kind, answer = next(iter(answers.items()))
        if not answer:
            return None
        if publishes(answer):
            return ""
        said = self._cell_state(kind, whole, answer_state(answer))
        return f" ({_inline_safe(said, pipes=False, plain=self.plain)})"

    def _cell_state(self, kind: str, value: str, state: str) -> str:
        """What a cell prints beside one unpublished value: its state, or its whole answer
        where this render prints that in no indicator row (:attr:`whole_answer_printed`).

        The whole answer is printed with no bound: the cell is then its only
        carrier, so every refusing part prints whole and then every fact, as an
        indicator row prints them (the answer's own composition,
        ``publish_parts.PublishAnswer``).
        """
        from malspark.reporting.publish_parts import PublishAnswer

        if self.whole_answer_printed is None:
            return state
        answer = self._answers(kind, value)
        if not isinstance(answer, PublishAnswer) or self.whole_answer_printed(kind, value, answer):
            return state
        return str(answer)

    def _read_again(self, sentence: str) -> list[tuple[str, str, str]] | None:
        """:meth:`_unstated` of a marked sentence, or ``None`` where it cannot be read.

        ``[]``: each unpublished value of ``sentence`` has a state the table
        agrees with. Fails towards the mark: a sentence that cannot be read
        keeps it, with its stored label.
        """
        try:
            return self._unstated(sentence)
        except Exception as exc:  # noqa: BLE001 — the mark is kept
            logger.debug("markdown: a marked sentence was not read again (%s).", exc)
            return None

    def _unstated(self, text: Any) -> list[tuple[str, str, str]]:
        """``(kind, value, state)`` for each value of ``text`` this run does not publish,
        written without a publish state the IOC table agrees with (``_unstated_values``).

        The table's answers are read once, on first use; a table that cannot be
        read refuses every value for that reason.
        """
        from malspark.pipeline.validation import _unstated_values

        if self._answers is None:
            try:
                from malspark.reporting.narrative_agent import published_answers

                if not self._table_read:
                    raise RuntimeError("the IOC table could not be read")
                self._answers = published_answers(self.report, rows=self.iocs)
            except Exception as exc:  # noqa: BLE001 — every value is then refused
                logger.debug("markdown: the IOC table was not read (%s).", exc)
                self._answers = lambda kind, value: TABLE_NOT_READ
        return _unstated_values(str(text or ""), self._answers)

    def cited_row_mark(self, row: Any) -> str:
        """The marks of a table row's wrong citations, printed beside its evidence, or ``""``.

        A wrong citation a row states under its record's citations is recorded
        as one of the row's texts under the ids it cites (``cited_row_text``);
        the row is found by the same text, so the same words in a row citing
        other entries are not marked.
        """
        from malspark.pipeline.validation import cited_row_text

        try:
            cited = row if isinstance(row, dict) else row.model_dump()
            texts = [
                text
                for value in cited.values()
                for text in (value if isinstance(value, list | tuple) else [value])
                if isinstance(text, str) and text.strip()
            ]
            keys = {cited_row_text(text, cited) for text in texts}
        except Exception as exc:  # noqa: BLE001 — a mark is never worth a report
            logger.debug("markdown: a row's citations were not read (%s).", exc)
            return ""
        marks = [mark for sentence, mark in self.flagged if sentence in keys]
        return f" {' '.join(dict.fromkeys(marks))}" if marks else ""

    def plain(self, text: str) -> str:
        """A value with the run's network indicators defanged and nothing else changed."""
        return self._defang(text)

    def inline(self, text: Any) -> str:
        """A sample's, a sandbox's or a tool's text, its Markdown escaped, then defanged.

        Escaped first, so the defanger's own ``[.]`` marks print as written; a
        balanced backtick pair stays a code span (:func:`_escaped_keeping_spans`);
        the table separator is left to the row (:func:`_cell`).
        """
        return _emphasis_escaped(self._defang(_escaped_keeping_spans(text)))

    def context(self, row: Any) -> str:
        """An IOC row's context: the platform's words, each value in it by the inline rule.

        The table is built with each value a context names marked
        (``ioc_table``'s ``word``, :class:`_RowWords`): the context's own words
        are written by their rule and each value by itself by the inline rule,
        set in after (:func:`_placed_with`). A row the build did not mark is
        written by the inline rule whole.
        """
        return self._row_words.written(row, "context", self.inline, self.value)

    def recovered(self, row: Any) -> str:
        """Which tools recovered an IOC row's value, written as :meth:`context` writes."""
        return self._row_words.written(row, "recovered_by", self.inline, self.value)

    def value(self, text: Any, *, pipes: bool = False) -> str:
        """A value of the sample, a sandbox, a tool or the operator, by the inline rule.

        Every character Markdown reads escaped, then the run's own defang
        (:func:`_inline_safe`); no backtick of the value opens a span. A cell
        leaves the table separator to the row; anywhere else ``pipes`` escapes it.
        """
        return _inline_safe(text, pipes=pipes, plain=self.plain)

    def line(self, text: Any) -> str:
        """Model prose that has to stay on one line: a list item, a step."""
        return _one_line(self._defang(self.marked(str(text or ""))))

    def keep(self, text: str) -> str:
        """``text`` set aside from the closing pass: a token now, ``text`` again after it."""
        token = f"\x00{self._nonce}k{len(self._kept)}\x00"
        self._kept[token] = text
        return token

    def kept_in(self, text: str) -> list[str]:
        """What each token :meth:`keep` handed out that stands in ``text`` stands for, in order:
        no text a model or a sample wrote can name a token."""
        return [self._kept[token] for token in _KEPT_TOKEN_RE.findall(text) if token in self._kept]

    def restore(self, text: str) -> str:
        """``text`` with every token :meth:`keep` handed out replaced by what it stands for.

        A link set aside stays the platform's link whatever stands before it: a ``!``
        there, which would make it an image, or a backslash that would escape its
        opening bracket, is escaped and prints as itself.
        """
        if not self._kept or "\x00" not in text:
            return text
        out: list[str] = []
        at = 0
        for found in _KEPT_TOKEN_RE.finditer(text):
            held = self._kept.get(found.group(0))
            if held is None:
                continue
            start = found.start()
            if (
                held.startswith("[")
                and start > at
                and text[start - 1] in "!\\"
                and not _escaped_at(text, start - 1)
            ):
                out += [text[at : start - 1], "\\", text[start - 1]]
            else:
                out.append(text[at:start])
            out.append(held)
            at = found.end()
        out.append(text[at:])
        return "".join(out)

    def endpoint_kept(self, model: str) -> str:
        """A model's recorded name, its endpoint set aside where it is a configured one.

        A run records a model as ``<model> @ <label>``. Only a label equal to
        one the run's own settings configured, as the whole of what follows the
        last `` @ ``, is kept from the closing pass; the same text anywhere else
        in the report is defanged. The labels are the ones the record took from
        the run's snapshot when it was built (``disclosure.endpoint_labels``),
        so a later render prints the same on any machine; a record that holds
        none keeps no endpoint.
        """
        name, sep, label = model.rpartition(" @ ")
        if sep and label in self._endpoint_labels():
            return f"{name} @ {self.keep(label)}"
        return model

    def host_kept(self, host: str) -> str:
        """A host the disclosure block names, as a code span, kept where the run's settings name it.

        Only a host one of the run's own settings addresses names is set aside
        from the closing pass, as :meth:`endpoint_kept` sets a configured model
        endpoint aside; any other host prints defanged. The hosts are the ones
        the record took from the run's snapshot when it was built
        (``disclosure.addressed_hosts``), so a later render prints the same.
        """
        span = _code_span(host)
        return self.keep(span) if host in self._configured_hosts() else span

    def _configured_hosts(self) -> set[str]:
        """The hosts the run's settings addressed, as the disclosure record holds them."""
        if self._hosts is None:
            record = (self.report.run_summary or {}).get("disclosure")
            held = record.get("addressed") if isinstance(record, dict) else None
            self._hosts = {str(h) for h in held} if isinstance(held, list) else set()
        return self._hosts

    def _endpoint_labels(self) -> set[str]:
        """The model endpoints the run's settings configured, as the record holds them."""
        if self._labels is None:
            record = (self.report.run_summary or {}).get("disclosure")
            held = record.get("endpoint_labels") if isinstance(record, dict) else None
            self._labels = {str(label) for label in held} if isinstance(held, list) else set()
        return self._labels

    def cell(self, text: Any) -> str:
        """A model-written table cell: defanged like prose, and whole, as every body cell is;
        its citations written as the layout's prose writes them (``cell_citations``)."""
        raw = str(text or "")
        whole = self._defang(raw)
        if self.cell_citations is not None:
            whole = self.cell_citations(whole)
        marks = self.cell_marks(raw)
        return f"{whole} {' '.join(marks)}" if marks else whole

    def cell_marks(self, text: Any) -> list[str]:
        """The marks :meth:`cell` prints after a cell's text: each flagged sentence's that
        stands in it, once."""
        raw = str(text or "")
        return list(
            dict.fromkeys(mark for sentence, mark in self.flagged if self.places(sentence, raw))
        )

    def sandbox_sentence(self) -> str:
        """What the run knows about a sandbox, as one sentence, in the run's own voice.

        The run's own statement, where the pack wrote one, is the sentence: it
        says whether no sandbox ran or the report is a recorded fixture rather
        than a live detonation.
        """
        why = f" ({self.sandbox_reason})" if self.sandbox_reason else ""
        if self.sandbox_statement:
            return self.sandbox_statement + self.partial_sentence()
        if self.sandbox_state == "observed":
            return _sandbox_held_sentence(self.report) + self.partial_sentence()
        if self.sandbox_state == "empty":
            return (
                "No sandbox observation: the sandbox tools returned nothing for this sample, "
                f"and nothing in this run shows it was executed{why}."
            )
        if self.sandbox_state == "not_called":
            return f"Not run in a sandbox: {self.sandbox_reason or 'no sandbox tool was called'}."
        return "No sandbox observation is recorded in this report."

    def partial_sentence(self) -> str:
        """What made the evidence partial, as a sentence, or ``""``."""
        evidence = (self.report.run_summary or {}).get("evidence") or {}
        inventory = self.report.limitation_inventory
        # A failed call a later call redid left no gap: counted in the run's
        # bounds, not here (T-494 D6). Where the report holds the limitations
        # inventory, its failed calls are the count, as section 11 prints them.
        from malspark.reporting.limitation_inventory import failed_calls_said, trimmed_entries

        if inventory is not None:
            from malspark.reporting.limitation_inventory import failed_counts

            failed, redone = failed_counts(inventory)
            failed -= redone
            entries = inventory.entries
        else:
            redone = len(_redone_rows(evidence))
            failed = max(0, int(evidence.get("failed") or 0) - redone)
            entries = int(evidence.get("entries") or 0)
        trimmed = int(_trimmed(evidence, inventory) or 0)
        parts = []
        if failed:
            parts.append(failed_calls_said(failed, entries, not_redone=bool(redone)))
        if trimmed:
            parts.append(trimmed_entries(trimmed, entries, grouped=False))
        return f" The evidence is partial: {' and '.join(parts)}." if parts else ""


def _trimmed(evidence: dict[str, Any], inventory: LimitationInventory | None) -> Any:
    """The entries trimmed to the budget: the limitations inventory's count, where the report
    holds one, else the run's bounds' (``run_summary.evidence.trimmed``), as held."""
    return inventory.trimmed if inventory is not None else evidence.get("trimmed", 0)


def _limitations_note(report: MalwareReport) -> str:
    """The title block's line on the limitations, counted from what the limitations section
    lists under each of its headings: the measured rows the inventory marks as stating a limit
    (a row it keeps for the record, the operator's choice among them, is not counted) and the
    reasons the run recorded (T-780)."""
    from malspark.reporting.limitation_inventory import inventory_rows

    reasons = len(report.degradation_reasons)
    plural = "" if reasons == 1 else "s"
    where = section_reference(LIMITATIONS_TITLE)
    inventory = report.limitation_inventory
    rows = inventory_rows(inventory) if inventory is not None else []
    limits = sum(1 for row in rows if row.printed)
    if not limits:
        return f"**Notes:** this run recorded {reasons} limitation{plural}; see {where}."
    among = f" (of its {len(rows)} measured rows)" if limits != len(rows) else ""
    return (
        f"**Notes:** {where} states {limits} measured limitation{'' if limits == 1 else 's'} "
        f"of this run{among} and {reasons} limitation{plural} the run recorded."
    )


def _redone_rows(
    evidence: dict[str, Any], inventory: LimitationInventory | None = None
) -> list[dict[str, Any]]:
    """The failed calls a later call redid: the limitations inventory's, where the report
    holds one, else the run's bounds' (``run_summary.evidence.redone``), as held."""
    if inventory is not None:
        from malspark.reporting.limitation_inventory import redone_rows

        return redone_rows(inventory)
    return [row for row in (evidence.get("redone") or []) if isinstance(row, dict)]


def _redone_clause(
    evidence: dict[str, Any], *, ids: bool, inventory: LimitationInventory | None = None
) -> str:
    """``", N of them redone ..."`` after a failed count, or ``""`` when none was redone.

    With ``ids``, in brackets, each redone call and the later calls that
    answered it, as the run's bounds list them (the inventory's, where held).
    """
    rows = _redone_rows(evidence, inventory)
    if not rows:
        return ""
    said = f"{len(rows)} of them redone by a later call for the same address"
    if not ids:
        return f", {said}"
    pairs = []
    for row in rows:
        failed = str(row.get("entry_id") or "")
        by = [str(i) for i in row.get("answered_by") or [] if ENTRY_ID.fullmatch(str(i))]
        if ENTRY_ID.fullmatch(failed) and by:
            pairs.append(f"{failed} by {', '.join(by)}")
    return f" ({said}" + (f": {'; '.join(pairs)}" if pairs else "") + ")"


def _guardrail_cut_clause(evidence: dict[str, Any], truncation: Any) -> str:
    """``", N cut by the tool-output guardrail (X characters dropped)"``, or ``""`` for none.

    Read off the ledger's own count (``run_summary.evidence.cut``). A summary
    written before the ledger counted cuts has the guardrail's count of the
    answers it cut, shortened or summarised, which is the same calls counted
    where they were cut.
    """
    if "cut" in evidence:
        cut = int(evidence.get("cut") or 0)
        dropped = int(evidence.get("chars_dropped") or 0)
    elif isinstance(truncation, dict):
        cut = sum(
            int(truncation.get(key) or 0)
            for key in (
                "tool_output_hard_truncated",
                "tool_output_shortened",
                "tool_output_summarised",
            )
        )
        dropped = int(truncation.get("tool_output_chars_dropped") or 0)
    else:
        return ""
    if cut <= 0:
        return ""
    return f", {cut} cut by the tool-output guardrail ({dropped:,} characters dropped)"


def _servers_line(report: MalwareReport, ctx: _Context) -> str:
    """The methodology's line on the tool servers, read from each index row as the console's
    tab is (``section_servers``): the server it records, else the server or provider its source
    names; the calls whose row records neither are counted, never named (T-780)."""
    from malspark.reporting.section_servers import server_of_row

    named = [server_of_row(row) for row in report.evidence_index]
    servers = sorted({server for server in named if server})
    unnamed = sum(1 for server in named if not server)
    said = ", ".join(ctx.value(server, pipes=True) for server in servers)
    if unnamed:
        calls = f"{unnamed} call{' records' if unnamed == 1 else 's record'} no server"
        said = f"{said}; {calls}" if said else f"none named; {calls}"
    return f"Tool servers called: {said}" if said else ""


def _judge_bundle(summary: Mapping[str, Any]) -> tuple[str, str]:
    """What the methodology says of the judge and the STIX bundle, read from the run's counts of
    the judge's own bundle and the exported one (``run_summary``): the clause after "a judge
    stated the verdict" where the two are the same size, else a sentence giving both counts;
    nothing where the run recorded no count of the judge's (T-780)."""

    def count(key: str) -> int | None:
        held = summary.get(key)
        return held if isinstance(held, int) and not isinstance(held, bool) else None

    judged, exported = count("judge_stix_object_count"), count("stix_object_count")
    if judged is None:
        return "", ""
    if judged and judged == exported:
        return " and the STIX bundle", ""
    said = f" The judge's STIX bundle holds {_objects(judged)}"
    return "", said + (
        f"; the exported one holds {_objects(exported)}." if exported is not None else "."
    )


def _objects(count: int) -> str:
    return "no object" if not count else f"{count} object{'' if count == 1 else 's'}"


def _sandbox_held(report: MalwareReport) -> list[str]:
    """What the report holds from a sandbox, as counts of its rows: the sandbox report's
    processes, signatures, the rows of its dropped-files list and of its mutex list, any other
    file-operation row and its registry rows, and the network rows the sandbox is the source
    of. Each is counted as held, whichever process it names (T-780), and the rows of
    ``file_operations`` by the list each was read from (``operation`` ``write`` or ``mutex``,
    ``ledger_projection``): a row of the dropped-files list is no file operation the record
    shows."""
    out: list[str] = []
    dyn = report.dynamic
    if dyn is not None:

        def processes(nodes: Iterable[ProcessNode]) -> int:
            return sum(1 + processes(node.children) for node in nodes)

        def operations(name: str) -> int:
            return sum(
                1
                for op in dyn.file_operations
                if isinstance(op, dict) and op.get("operation") == name
            )

        dropped, mutexes = operations("write"), operations("mutex")
        counted = (
            (processes(dyn.process_tree), "process", "processes"),
            (len(dyn.sandbox_signatures), "signature", "signatures"),
            (dropped, "row of its dropped-files list", "rows of its dropped-files list"),
            (mutexes, "mutex name", "mutex names"),
            (
                len(dyn.file_operations) - dropped - mutexes,
                "file-operation row",
                "file-operation rows",
            ),
            (len(dyn.registry_mods), "registry row", "registry rows"),
        )
        listed = [f"{n} {one if n == 1 else many}" for n, one, many in counted if n]
        out.append(
            f"a report is held listing {_joined(listed)}"
            if listed
            else "a report is held listing no process, signature, dropped-files row, mutex "
            "name, file-operation row or registry row"
        )
    net = report.network
    rows = [*(net.domains if net else []), *(net.ips if net else []), *(net.urls if net else [])]
    sourced = sum(1 for row in rows if getattr(row, "source", None) == "sandbox")
    if sourced:
        out.append(f"the source of {sourced} network row{'' if sourced == 1 else 's'}")
    return out


def _sandbox_held_sentence(report: MalwareReport) -> str:
    """:func:`_sandbox_held` as a sentence of the sandbox's."""
    held = _sandbox_held(report)
    if not held:
        return "No sandbox observation is recorded in this report."
    if held[0].startswith("a report"):
        said = "A sandbox " + held[0].removeprefix("a ")
        return said + (f", and the sandbox is {held[1]}." if len(held) > 1 else ".")
    return f"The sandbox is {held[0]}."


# How the methodology appendix names each sandbox state; an observed one is counted
# (:func:`_sandbox_held`).
_SANDBOX_STATES = {
    "empty": "called, returned no observation",
    "not_called": "not called",
    "unknown": "not recorded",
}


def _sandbox_statement(report: MalwareReport) -> str:
    """The run's own sentence on its sandbox report, or ``""`` when it wrote none."""
    sandbox = (report.run_summary or {}).get("sandbox")
    if isinstance(sandbox, dict) and str(sandbox.get("statement") or "").strip():
        return _one_line(sandbox["statement"]).strip()
    section = next((s for s in report.sections if s.key == "sandbox_status"), None)
    return _one_line(section.text).strip() if section is not None and section.text else ""


def _sandbox_reason(report: MalwareReport) -> str:
    """Why the run had no sandbox observation, in the words the run recorded, or ``""``."""
    for stage in (report.run_summary or {}).get("stages") or []:
        if not isinstance(stage, dict):
            continue
        for reason in (stage.get("agent_reasons") or {}).values():
            if "sandbox" in str(reason).lower():
                return _one_line(reason)
    for reason in report.degradation_reasons:
        if "sandbox" in reason.lower():
            return _one_line(reason)
    return ""


def _named_in(rows: list[dict[str, Any]], code: str, pattern: str) -> set[str]:
    """What the unresolved rows of one code name, read out of their sentences."""
    found: set[str] = set()
    for row in rows:
        if row.get("code") != code:
            continue
        match = re.search(pattern, str(row.get("message") or ""))
        if match:
            found.add(match.group(1))
    return found


def _rows_named_in(
    rows: list[dict[str, Any]], code: str, noun: str, *, saying: str = ""
) -> dict[int, bool]:
    """The row numbers the unresolved rows of one code name at their start, each with asked.

    ``identifier 3 (…)`` names one row; ``identifiers 3, 4, 9 are …`` names
    several. A row is asked where any finding naming it was (``"asked"`` not
    ``"false"``). With ``saying``, only the findings whose words hold it.
    """
    pattern = re.compile(rf"^{re.escape(noun)}s? (\d+(?:, \d+)*)\b")
    found: dict[int, bool] = {}
    for row in rows:
        if row.get("code") != code or saying not in str(row.get("message") or ""):
            continue
        match = pattern.search(str(row.get("message") or ""))
        if match:
            for number in match.group(1).split(", "):
                try:
                    at = int(number)
                except ValueError:
                    continue
                found[at] = found.get(at, False) or _was_asked(row)
    return found


def _numbers_asked(rows: list[dict[str, Any]], code: str, pattern: str) -> dict[int, bool]:
    """The row number each unresolved row of one code names (:func:`_named_in`), with asked."""
    found: dict[int, bool] = {}
    for row in rows:
        if row.get("code") != code:
            continue
        match = re.search(pattern, str(row.get("message") or ""))
        if match:
            at = int(match.group(1))
            found[at] = found.get(at, False) or _was_asked(row)
    return found


def _was_asked(row: dict[str, Any]) -> bool:
    """Whether a recorded finding was put to the model: a row never asked says ``"false"``."""
    return str(row.get("asked", "")).strip().lower() != "false"


# A table row whose value a cited entry holds only inside a longer run of text
# (``validation.STATED_VALUE_INSIDE_A_TOKEN_CODE``), what its mark says first,
# and what it says of a row kept after the run was shown, in either report.
_INSIDE_A_TOKEN_CODE = "report.value_inside_a_longer_token"
_INSIDE_A_TOKEN_WORDS = "the cited entry holds this text inside a longer run"
INSIDE_A_TOKEN_KEPT = f"{_INSIDE_A_TOKEN_WORDS}; kept after the run was shown"
# What it says of a row kept where the finding could not show the run.
INSIDE_A_TOKEN_KEPT_UNSHOWN = f"{_INSIDE_A_TOKEN_WORDS}; kept"


def inside_a_token_kept(shown: bool) -> str:
    """What a row kept after its inside-a-run question is marked by, as the run was shown."""
    return INSIDE_A_TOKEN_KEPT if shown else INSIDE_A_TOKEN_KEPT_UNSHOWN


def _row_mark(code: str, asked: bool | None, *, shown: bool = True) -> str:
    """The mark a table row carries beside its evidence for one finding naming it, or ``""``.

    ``asked`` is ``None`` where no finding of ``code`` names the row. A finding
    never put to the model says so. A value inside a longer run states that
    fact first, then that it was kept after the run was shown, kept where the
    finding could not show the run (``shown`` false), or not asked.
    """
    if asked is None:
        return ""
    if code == _INSIDE_A_TOKEN_CODE:
        return (
            f" ({inside_a_token_kept(shown)}: {code})"
            if asked
            else f" ({_INSIDE_A_TOKEN_WORDS}; not asked: {code})"
        )
    return f" (unresolved: {code})" if asked else f" (unresolved, not asked: {code})"


class _AnalystStates:
    """What each analyst of the run did, from the stage and agent records.

    ``failed``: the run's failed-analyst list. ``skipped``: an analyst the
    analysis stage records a reason for, or whose own record says it had no
    data, with that reason. ``silent``: an analyst that ran and claimed
    nothing. A report stored before those records falls back to the reasons
    the pipeline writes: ``analyst failures:``, ``analysts skipped (<why>):``
    and ``analysts produced no claims:``.
    """

    def __init__(self, report: MalwareReport) -> None:
        summary = report.run_summary or {}
        failed = [str(a) for a in summary.get("failed_analysts") or [] if a]
        failed += _named_after(report.degradation_reasons, "analyst failures:")
        self.failed = list(dict.fromkeys(failed))
        skipped: dict[str, str] = {}
        for stage in summary.get("stages") or []:
            if not isinstance(stage, dict):
                continue
            for agent, reason in (stage.get("agent_reasons") or {}).items():
                if str(agent) not in self.failed:
                    skipped.setdefault(str(agent), _one_line(reason))
        stats = [row for row in summary.get("agent_stats") or [] if isinstance(row, dict)]
        for row in stats:
            agent = str(row.get("agent_id") or row.get("domain") or "")
            if agent and row.get("no_data") and agent not in self.failed:
                skipped.setdefault(agent, "")
        for why, names in _skipped_after(report.degradation_reasons):
            for agent in names:
                if agent not in self.failed:
                    skipped.setdefault(agent, why)
        self.skipped = skipped
        if stats:
            silent = [
                str(row.get("agent_id") or row.get("domain") or "")
                for row in stats
                if not row.get("claim_count")
            ]
        else:
            silent = _named_after(report.degradation_reasons, "analysts produced no claims:")
        self.silent = [
            name
            for name in dict.fromkeys(silent)
            if name and name not in self.failed and name not in skipped
        ]

    @property
    def idle(self) -> set[str]:
        """Every analyst that produced no claim, whatever the cause."""
        return set(self.failed) | set(self.skipped) | set(self.silent)

    def clauses(self) -> list[str]:
        """``the static analyst failed``, ``the dynamic analyst was skipped (why)``, …"""
        out: list[str] = []
        if self.failed:
            many = len(self.failed) > 1
            out.append(f"the {_joined(self.failed)} analyst{'s' if many else ''} failed")
        if self.skipped:
            names = list(self.skipped)
            many = len(names) > 1
            reasons = {why for why in self.skipped.values() if why}
            why = f" ({next(iter(reasons))})" if len(reasons) == 1 else ""
            out.append(f"the {_joined(names)} analyst{'s were' if many else ' was'} skipped{why}")
        if self.silent:
            many = len(self.silent) > 1
            out.append(
                f"the {_joined(self.silent)} analyst{'s' if many else ''} produced no claims"
            )
        return out


_SKIPPED_REASON_RE = re.compile(r"^analysts skipped \((?P<why>[^)]*)\): (?P<names>.+)$")


def _skipped_after(reasons: list[str]) -> list[tuple[str, list[str]]]:
    """Each ``analysts skipped (<why>): a, b`` reason, as its cause and its names."""
    out: list[tuple[str, list[str]]] = []
    for reason in reasons:
        match = _SKIPPED_REASON_RE.match(str(reason))
        if match:
            names = [n.strip() for n in match.group("names").split(",") if n.strip()]
            out.append((match.group("why").strip(), names))
    return out


def _named_after(reasons: list[str], prefix: str) -> list[str]:
    """The comma-separated names a reason of the given prefix lists."""
    names: list[str] = []
    for reason in reasons:
        if reason.startswith(prefix):
            names.extend(name.strip() for name in reason[len(prefix) :].split(",") if name.strip())
    return names


def _team(report: MalwareReport) -> list[str]:
    """The analysts the run's team had, from its profile or its analysis stage."""
    summary = report.run_summary or {}
    team = [str(a) for a in (summary.get("profile") or {}).get("analysts") or [] if a]
    if team:
        return team
    for stage in summary.get("stages") or []:
        if isinstance(stage, dict) and stage.get("kind") == "analysis":
            return [str(a) for a in stage.get("agents") or [] if a]
    return []


def _joined(names: list[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def lost_tools_sentence(report: MalwareReport, ctx: _Context) -> str:
    """The scope's sentence on what the run went without and why, ``""`` when it says nothing.

    Read from the run summary's ``lost_tools`` (``operator_choice.lost_tool_rows``),
    which the judge node wrote beside the degraded flag: a summary stored
    before it has none and its report renders as it did. Said only of a
    degraded run, as the header's banner is: a rule engine that loaded no
    rule did not run, and the scope says so beside what was examined rather
    than leaving its silence to read as no match. Each name and reason is a
    tool's own text, by the inline rule (``_Context.value``). Its host
    paths were masked when the row was written (``lost_tool_rows``), and
    nothing here reads the rendering host, so a stored run renders the same
    wherever it is rendered.
    """
    rows = (report.run_summary or {}).get("lost_tools")
    if not report.degraded_mode or not isinstance(rows, list):
        return ""
    said: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not str(row.get("tool") or "").strip():
            continue
        name = ctx.value(_one_line(row["tool"]), pipes=True)
        why = ctx.value(_one_line(str(row.get("reason") or "")), pipes=True)
        said.append(f"{name} ({why})" if why else name)
    return f"The run went without {'; '.join(said)}." if said else ""


def _degraded_sentence(report: MalwareReport, ctx: _Context) -> str:
    """The header's one sentence about a degraded run, built from what ran.

    Built from the stage and agent records and the sandbox's state, and from
    the reasons only the bare name of each tool the run went without: the
    reasons are the operator's, carry codes and install commands, and are
    listed whole in the limitations section, which the sentence names by its
    rendered number.
    """
    from malspark.pipeline.operator_choice import facts_from_record, lost_tools

    parts = ctx.analysts.clauses()
    if not ctx.sandbox_observed and ctx.sandbox_state in ("empty", "not_called"):
        parts.append(ctx.no_sandbox_clause())
    # A tool the run went without, by its bare name: capa missing on its host
    # is the run's loss even when nothing else was, and the header says so.
    # The same facts the judge node decided the run degraded on, as the run
    # summary kept them; a summary written before it kept them reads its
    # tool-failure rows and the shipped declarations.
    summary = report.run_summary or {}
    failures = (summary.get("evidence") or {}).get("failures") or []
    facts = facts_from_record(
        summary.get("loss_facts"),
        report.identity.file_type or "",
        [r for r in failures if isinstance(r, dict)],
    )
    lost = lost_tools(report.degradation_reasons, facts)
    if lost:
        parts.append(f"the run went without {_joined(lost)}")
    if not parts:
        parts.append("this run had less evidence than a full analysis")
    said = _joined(parts)
    return (
        f"{said[0].upper()}{said[1:]}; the verdict above is tentative. See "
        f"{section_reference(LIMITATIONS_TITLE, ANALYST_LIMITATIONS_TITLE)} for what this run "
        "could not examine."
    )


# The words of the mark a flagged sentence carries, by the finding's code.
_FLAG_WORDS = {
    "narrative.ungrounded_capability": "not established by this run",
    "report.rule_match_as_action": "a rule match only, stated as an action",
    "report.unpublished_value": "not published by this run",
    "report.citation_wrong_entry": "cited to an entry it was not found whole in",
    "report.value_only_in_call_arguments": "held only in what the call was asked for",
    "report.id_not_in_cited_entry": "an id none of its cited entries holds",
    "report.numeric_confidence": "a confidence written as a number",
    "report.process_words": "names how the report was made",
    PUBLISHED_TECHNIQUE_DOUBTED_CODE: "published by this run",
    CATEGORY_TYPE_UNSTATED_CODE: "not the export's malware type",
}


# What a cell says of a value whose publish state could not be read, and the
# state of every value when the IOC table itself could not be read.
STATE_UNKNOWN = "publish state unknown: the IOC table's answer could not be read"
TABLE_NOT_READ = "no: the IOC table could not be read"
# The table separator, named rather than written: a literal one in this module
# is a table row assembled by hand (``test_a_table_row_is_never_assembled_by_hand``).
_PIPE = chr(124)
# A URL in free text, for telling whether a cell names one. Any scheme a
# viewer may make a link of ("https", "ftp", "sftp", "ws", a defanged "hxxps"),
# wherever it starts: no word boundary before it, since GFM starts a link after
# a digit or "_" as readily as after a space.
_URL_IN_TEXT = re.compile(r"(?i)[a-z][a-z0-9+.-]{0,31}://[^\s<>()\[\]`'\"" + _PIPE + r"]+")
# A host after an "@" no mailbox name stands before.
_BARE_AT_HOST = re.compile(r"(?<![\w.+-])@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# A "www." host, which a forge links whatever its top-level label, after any
# character that is no letter or digit ("_", "*", "~", "(", "/" and the rest).
_WWW_HOST = re.compile(r"(?i)(?<![^\W_])www\.[\w-]+(?:\.[\w-]+)*")
# An IPv6 address written in text: hex groups and colons, read by ``ipaddress``.
_IPV6_CANDIDATE = re.compile(r"(?<![\w:.\]])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# The same with an IPv4 tail read whole ("::ffff:192.0.2.1").
_IPV6_WITH_A_TAIL = re.compile(
    r"(?<![\w:.\]])(?:[0-9A-Fa-f]{0,4}:){2,7}\d{1,3}(?:\.\d{1,3}){3}(?![\w:])(?!\.\d)"
)
# A mailbox: GFM's name characters (``_`` among them) and a dotted domain.
_EMAIL_IN_TEXT = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# The characters that make Markdown of a sample's text: a code span, a link or
# image, an HTML tag, a table cell, emphasis, struck text, and the backslash
# itself. A cell and any other place differ only in the table separator.
_INLINE_META = re.compile(r"([\\`\[\]<>*~" + _PIPE + r"])")
_INLINE_META_NO_PIPE = re.compile(r"([\\`\[\]<>*~])")
# An underscore that can open or close emphasis: one without a letter or digit
# on both sides of it ("FUN_00401310" holds none). Escaped after the defanger
# has read the value (:func:`_emphasis_escaped`), so a host such as
# "_ldap._tcp.example.com" is still read, and defanged, as a host.
_EMPHASIS_UNDERSCORE = re.compile(r"(?<![^\W_])_" + _PIPE + r"_(?![^\W_])")
# A link a reference service may own: https, at no scheme character's end.
_REFERENCE_CANDIDATE = re.compile(r"(?i)(?<![a-z0-9+.-])https://[^\s<>()\[\]`'\"" + _PIPE + r"]+")
# What ends the authority of a URL, or of a "//" target: a separator, a space,
# or a character Markdown or a sentence puts around a link.
_AUTHORITY_END = frozenset("/?#\\<>()[]{}\"'`" + _PIPE)
# The bracketed characters a defanged value is written with.
_DEFANGED_MARKS = ("[.]", "[:]", "[@]")


def _defanged_text(text: str, run_values: Callable[[str], str] | None = None) -> str:
    """``text`` with every network indicator in it defanged, as the report does.

    A URL, a mailbox, a host under a real top-level domain (the string sweep's
    own list, the root zone's) and an address are defanged. What names no
    network value prints as written: a version number ("FileVersion 10.0.0.1",
    "v1.2.3.4"), a .NET name ("ASP.NET"), and a two-label name whose top-level
    label is also a file's extension ("lib.rs", "install.sh"). A reference
    service's own lookup (``_REFERENCE_LOOKUPS``) stays a link, exactly as it
    was checked; the text is split around those links and only the pieces
    between them are read. A value the run itself recorded is defanged before
    this, by the context's own pass, wherever it stands; ``run_values`` is that
    pass for the closing read of a whole section, applied to each piece
    between the kept links, so a kept link stays exactly as it was checked.
    """

    def piece(part: str) -> str:
        return _defanged_piece(run_values(part) if run_values is not None else part)

    out: list[str] = []
    at = 0
    for start, end in _reference_spans(text):
        out += [piece(text[at:start]), text[start:end]]
        at = end
    out.append(piece(text[at:]))
    return "".join(out)


# The HTML5 named character references a viewer decodes, each with its ";".
_NAMED_REFERENCES = frozenset(name for name in html5 if name.endswith(";"))
# Where a character reference may start: "&#" and a digit, "&#x" and a hex
# digit, or "&" and a name. A numeric one is escaped with or without its ";",
# a named one only when it is a reference a viewer decodes.
_REFERENCE_START = re.compile(
    r"&(?:#(?:[0-9]" + _PIPE + r"[xX][0-9A-Fa-f])" + _PIPE + r"([A-Za-z][A-Za-z0-9]*;))"
)


def _every_reference_escaped(text: str) -> str:
    """``text`` with the ``&`` of every character reference in it escaped, wherever it stands.

    An ``&`` already escaped (after an odd run of backslashes) is left as it
    is. Each backslash is counted for the one ``&`` it stands before, so the
    text is read in time linear in its length.
    """
    if "&" not in text:
        return text
    out: list[str] = []
    at = 0
    for found in _REFERENCE_START.finditer(text):
        name = found.group(1)
        if name is not None and name not in _NAMED_REFERENCES:
            continue
        start = found.start()
        before = start
        while before > at and text[before - 1] == "\\":
            before -= 1
        if (start - before) % 2:
            continue
        out += [text[at:start], "\\"]
        at = start
    out.append(text[at:])
    return "".join(out)


# A code fence's opening line, after at most three spaces, as CommonMark reads
# it; and its closing line, after at most three spaces too. A fence opened at
# the line's very start stands in no container, so it is a fence wherever it
# stands, and its lines are code; one opened after spaces may stand in a list
# item that ends before it closes, so its lines, and every fence after it, are
# followed but read as text.
_FENCE_OPENER = re.compile(r" {0,3}(`{3,}" + _PIPE + r"~{3,})")
_FENCE_CLOSER_INDENT = 3
# How a line stands: plain text, a line of a fence every viewer reads as code,
# or a line of a fence a viewer may not read as one.
_TEXT, _CODE, _UNSURE = "text", "code", "unsure"
# A line that may open an HTML block: a "<" after whitespace, block quote
# marks and list markers. A viewer that reads raw HTML reads what follows as
# HTML, where it decodes a reference, fence or no fence.
_HTML_BLOCK_START = re.compile(r"[ \t>]*(?:(?:[-+*]" + _PIPE + r"\d{1,9}[.)])[ \t][ \t>]*)*<")
_BACKTICK_RUN = re.compile(r"`+")


@dataclass
class _ReferenceScan:
    """Where the closing pass stands across one render's sections, read in order.

    ``fence`` is the open fence's character and length; ``reads_code`` is whether
    code spans and fences are read at all (no line can open an HTML block).
    """

    reads_code: bool = True
    fence: tuple[str, int, str] | None = None
    # After a fence opened after spaces, which a viewer may have closed where
    # its list item ended, no later fence is known to be where it seems.
    fences_known: bool = True
    # Whether the line just yielded opened a fence, and where its info string starts.
    opened_at: int | None = None

    def lines(self, text: str) -> Iterator[tuple[str, str]]:
        """Each line of ``text`` with its line break, and how it stands (``_TEXT`` and so on)."""
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            self.opened_at = None
            if self.fence is not None:
                char, length, kind = self.fence
                stripped = body.lstrip(" ")
                if (
                    len(body) - len(stripped) <= _FENCE_CLOSER_INDENT
                    and stripped.rstrip() == char * len(stripped.rstrip())
                    and len(stripped.rstrip()) >= length
                ):
                    self.fence = None
                yield line, kind
                continue
            opener = _FENCE_OPENER.match(body)
            # A backtick fence's info string holds no backtick.
            if opener is not None and not (
                opener.group(1)[0] == "`" and "`" in body[opener.end() :]
            ):
                if opener.start(1):
                    self.fences_known = False
                kind = _CODE if self.fences_known else _UNSURE
                self.fence = (opener.group(1)[0], len(opener.group(1)), kind)
                self.opened_at = opener.end()
                yield line, kind
                continue
            yield line, _TEXT

    def read_for_html(self, text: str) -> None:
        """Read one section for a line that may open an HTML block; with one, no code is read."""
        for line, kind in self.lines(text):
            if kind != _CODE and _HTML_BLOCK_START.match(line):
                self.reads_code = False


def _code_spans_of_a_line(line: str) -> list[tuple[int, int]] | None:
    """The code spans of one line, or ``None`` where a viewer could read them otherwise.

    The spans are read as CommonMark reads them: an unescaped backtick run
    opens one, and the next run of the same length closes it. The line is
    read alone, so it must hold its own spans: a run that closes nothing, a
    ``<`` outside a span (a tag or an autolink a viewer reads first), a ``[``
    outside a span (a link's text, which a viewer reads to its end before it
    pairs the backticks after it, across the paragraph's lines) or an
    unescaped table separator inside one (a table splits its row there) make
    it ``None``. The runs of each length are read once, in order.
    """
    by_length: dict[int, list[int]] = {}
    for run in _BACKTICK_RUN.finditer(line):
        by_length.setdefault(run.end() - run.start(), []).append(run.start())
    seen: dict[int, int] = {}
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char in "<[":
            return None
        if char != "`":
            index += 1
            continue
        end = index
        while end < len(line) and line[end] == "`":
            end += 1
        length = end - index
        starts = by_length.get(length, [])
        at = seen.get(length, 0)
        while at < len(starts) and starts[at] < end:
            at += 1
        seen[length] = at
        # The closer is a whole run of the same length: a run of that length
        # starting after the opener and not part of a longer one.
        if at == len(starts):
            return None
        close = starts[at]
        content = line[end:close]
        for pipe in (found.start() for found in re.finditer(re.escape(_PIPE), content)):
            back = pipe
            while back > 0 and content[back - 1] == "\\":
                back -= 1
            if (pipe - back) % 2 == 0:
                return None
        spans.append((index, close + length))
        index = close + length
    return spans


def _escaped_references(text: str, scan: _ReferenceScan | None = None) -> str:
    """``text`` with the ``&`` of every character reference outside code escaped.

    A viewer decodes a reference after the defanger has read the text:
    ``https&#58;//evil&#46;example`` and ``[x](https&colon;//evil&period;example)``
    held nothing a defanger reads as a link, and became one once decoded. An
    escaped ``\\&`` prints as itself. Inside a code span or a fence a viewer
    decodes nothing, and the text is left byte for byte, where every viewer
    reads the same code: a fence opened at a line's very start (one opened
    after spaces is followed, and its lines escaped), and the spans of a
    block, the lines between two blank lines or fences, only where every line
    of it holds its own (:func:`_code_spans_of_a_line`). Anything else, a
    block with one line that does not and an indented code block included, is
    read as text and escaped whole; so is the whole render where a line may
    open an HTML block (``scan.reads_code``). Each line is held once, until its
    block ends, so the text is read in time linear in its length.
    """
    if "&" not in text:
        if scan is not None:
            for _line in scan.lines(text):
                pass
        return text
    scan = scan if scan is not None else _ReferenceScan()
    if not scan.reads_code:
        return _every_reference_escaped(text)
    out: list[str] = []
    block: list[str] = []
    for line, kind in scan.lines(text):
        if kind != _TEXT or not line.strip():
            _write_block(block, out)
            block = []
            if kind == _UNSURE:
                out.append(_every_reference_escaped(line))
            elif scan.opened_at is not None:
                # A viewer decodes a reference in the info string into the code
                # block's class attribute, whatever the fence holds below it.
                out.append(
                    line[: scan.opened_at] + _every_reference_escaped(line[scan.opened_at :])
                )
            else:
                out.append(line)
        else:
            block.append(line)
    _write_block(block, out)
    return "".join(out)


def _write_block(block: list[str], out: list[str]) -> None:
    """One block's lines, its spans kept only where every line holds its own."""
    if not block:
        return
    spans = [_code_spans_of_a_line(line) for line in block]
    kept = all(found is not None for found in spans)
    for line, held in zip(block, spans, strict=True):
        if not kept or held is None:
            out.append(_every_reference_escaped(line))
            continue
        at = 0
        for start, end in held:
            out += [_every_reference_escaped(line[at:start]), line[start:end]]
            at = end
        out.append(_every_reference_escaped(line[at:]))


# What follows the "]" that closes a link's text or a reference definition's label, up to
# where its target starts: "(" or ":", white space with at most one line ending (and the
# block quote marks the next line opens with), an optional "<".
_AFTER_LINK_TEXT = re.compile(r"\]([(:])[ \t]*+(?:\r?\n[ \t>]*+)?(<?)")
# A tag as a browser reads it (:class:`_TagReader`): where one opens, a "<" and a letter;
# what ends its name; the white space and slashes between its attributes; white space;
# what ends an attribute's name; what ends a value written without quotes.
_TAG_START = re.compile(r"<[A-Za-z]")
_TAG_NAME_END = re.compile(r"[\t\n\f\r />]")
_TAG_GAP = re.compile(r"[\t\n\f\r /]*+")
_TAG_SPACE = re.compile(r"[\t\n\f\r ]*+")
_ATTRIBUTE_NAME_END = re.compile(r"[\t\n\f\r />=]")
_UNQUOTED_VALUE_END = re.compile(r"[\t\n\f\r >]")
# The tags that change where the platform's own links lead, by name: a base that names a
# target for every relative link, and a meta element carrying an http-equiv, whatever its
# value (one of them refreshes the page to another address).
_RETARGETING_TAG = "base"
_EQUIV_TAG = "meta"
# A closing tag.
_TAG_CLOSING = re.compile(r"</([A-Za-z][A-Za-z0-9-]*)\s*>")
# How far a link's target is read: one longer is taken to reach the bundle, so its
# bracket is escaped outside code and it prints as its characters, a long link to
# anywhere else included (a model's links are defanged in any case).
_TARGET_REACH = 512
_TARGET_RUN = re.compile(rf"\S{{0,{_TARGET_REACH + 1}}}")
_BRACKETED_TARGET_RUN = re.compile(rf"[^<>\n]{{0,{_TARGET_REACH + 1}}}")
# A backslash escape as Markdown reads one inside a link's target.
_MARKDOWN_ESCAPE = re.compile(r"\\([!-/:-@\[-`{-~])")
# What starts a link target's fragment.
_FRAGMENT_MARK = chr(35)
# The anchors of the notes: ``cite-N`` in the evidence bundle, ``note-N`` in the
# self-contained report.
_NOTE_ANCHORS = ("cite-", "note-")
# The code a reader takes no link from, by markdown-it's token types.
_CODE_TOKENS = frozenset({"code_inline", "code_block", "fence"})
_LINK_READERS: list[Any] = []
# A line indented as code, the one kind of code a text holding no backtick or tilde fence
# can hold.
_INDENTED_LINE = re.compile(r"(?m)^(?: {4}" + _PIPE + r"[ ]{0,3}\t)")


def _into_the_bundle(target: str) -> bool:
    """Whether a link target reaches the evidence bundle or a note's anchor.

    Read as a viewer resolves it: Markdown escapes and character references
    decoded, percent-encoding decoded repeatedly, white space and control
    characters dropped, in any case, a backslash as a slash. A target whose last
    path segment names one of the bundle's files (``./evidence-bundle.html#…``),
    or one naming no file whose fragment is a note's anchor (``#cite-1``,
    ``#note-1``), does.
    """
    from html import unescape
    from urllib.parse import unquote

    read = unescape(_MARKDOWN_ESCAPE.sub(r"\1", target))
    for _ in range(4):
        decoded = unquote(read)
        if decoded == read:
            break
        read = decoded
    read = re.sub(r"[\x00-\x20\x7f]", "", read).lower().replace("\\", "/")
    path, _, fragment = read.partition(_FRAGMENT_MARK)
    path = path.partition("?")[0]
    if path.rsplit("/", 1)[-1] in BUNDLE_FILES:
        return True
    return all(part in ("", ".") for part in path.split("/")) and fragment.startswith(_NOTE_ANCHORS)


def _link_target_at(text: str, start: int, bracketed: bool) -> str | None:
    """The link target that starts at ``start``: to the ``>`` where it opened with ``<``,
    else to white space or a parenthesis that closes more than it opened; ``None`` where it
    runs past :data:`_TARGET_REACH`."""
    run = (_BRACKETED_TARGET_RUN if bracketed else _TARGET_RUN).match(text, start)
    held = run.group(0) if run is not None else ""
    if len(held) > _TARGET_REACH:
        return None
    if bracketed or ")" not in held:
        return held
    if "(" not in held:
        return held[: held.index(")")]
    depth = 0
    at = 0
    while at < len(held):
        char = held[at]
        if char == "\\":
            at += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if not depth:
                break
            depth -= 1
        at += 1
    return held[:at]


def _run_end(run: re.Pattern[str], text: str, at: int) -> int:
    """Where ``run``, a pattern that matches the empty text too, ends from ``at``."""
    found = run.match(text, at)
    return found.end() if found is not None else at


class _TagReader:
    """Every tag of one text read as a browser reads it, in time linear in the text's length.

    A tag opens at a ``<`` and a letter and its name runs to white space, ``/`` or ``>``;
    a quote opens a value only after ``=``, and a ``<`` or a ``>`` inside a quoted value is
    the value's; the tag ends at the first ``>`` outside one. Each opening is read on its
    own (a Markdown reader takes a tag inside another's attributes where it does not take
    the outer one). The reader has no bound on a tag's length: what ends each name, value
    and quote is looked up in positions found once for the whole text, and where a
    reading reaches a place between two attributes that an earlier one has read from, it
    takes that reading's result, so no part of the text is read twice in one state. A tag
    the text ends in inside a quoted value is not read safely: what ends it lies past the
    text, so its ``<`` is written as text (:func:`_hand_links`). The values it compares are
    read as a browser decodes them (:func:`_into_the_bundle`). ``steps`` counts its work:
    each tag and each place it reads from, and each character of a run of white space or
    of a value it reads.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.size = len(text)
        self._ends = {
            key: [found.start() for found in pattern.finditer(text)]
            for key, pattern in (
                ("name", _TAG_NAME_END),
                ("attribute", _ATTRIBUTE_NAME_END),
                ("unquoted", _UNQUOTED_VALUE_END),
                ('"', re.compile('"')),
                ("'", re.compile("'")),
            )
        }
        # From a place between two attributes: where the tag ends, whether it ends inside
        # a quoted value, whether a value after the place reaches the bundle or a note's
        # anchor, whether an attribute after it is an ``http-equiv``, and whether one is an
        # ``href``.
        self._from: dict[int, tuple[int, bool, bool, bool, bool]] = {}
        self.steps = 0

    def _run(self, run: re.Pattern[str], at: int) -> int:
        """Where ``run`` ends from ``at`` (:func:`_run_end`), its characters counted."""
        end = _run_end(run, self.text, at)
        self.steps += end - at
        return end

    def _reaches(self, value: str) -> bool:
        """Whether ``value`` reaches the bundle or a note's anchor, its characters counted."""
        self.steps += len(value)
        return _into_the_bundle(value)

    def _next(self, key: str, at: int) -> int:
        """The first place at or after ``at`` where ``key``'s character stands, else the end."""
        places = self._ends[key]
        index = bisect.bisect_left(places, at)
        return places[index] if index < len(places) else self.size

    def read(self, start: int) -> tuple[str, int, bool, bool]:
        """The tag that opens at ``start``: its name in lower case (``""`` for a long one),
        where it ends, whether it is read safely, and whether it can lead a link into the
        bundle or to a note's anchor: a value that reaches one, or a tag that changes
        where the platform's links lead."""
        text, size = self.text, self.size
        self.steps += 1
        at = self._next("name", start + 1)
        name = text[start + 1 : at].lower() if at - start <= 64 else ""
        passed: list[list[Any]] = []
        tail: tuple[int, bool, bool, bool, bool]
        while True:
            known = self._from.get(at)
            if known is not None:
                tail = known
                break
            self.steps += 1
            passed.append([at, False, False, False])
            at = self._run(_TAG_GAP, at)
            if at >= size:
                tail = (size, False, False, False, False)
                break
            if text[at] == ">":
                tail = (at + 1, False, False, False, False)
                break
            first = at
            at = self._next("attribute", at + 1)
            attribute = text[first:at].lower() if at - first in (4, 10) else ""
            passed[-1][2] = passed[-1][2] or attribute == "http-equiv"
            passed[-1][3] = passed[-1][3] or attribute == "href"
            equals = self._run(_TAG_SPACE, at)
            if equals >= size or text[equals] != "=":
                at = equals
                continue
            at = self._run(_TAG_SPACE, equals + 1)
            if at < size and text[at] in "\"'":
                close = self._next(text[at], at + 1)
                value = text[at + 1 : close]
                passed[-1][1] = self._reaches(value) or passed[-1][1]
                if close >= size:
                    tail = (size, True, False, False, False)
                    break
                at = close + 1
            else:
                end = self._next("unquoted", at)
                value = text[at:end]
                passed[-1][1] = self._reaches(value) or passed[-1][1]
                at = end
        end, open_quote, reaches, equiv, href = tail
        for place, reached, carried, named in reversed(passed):
            reaches, equiv, href = reaches or reached, equiv or carried, href or named
            self._from[place] = (end, open_quote, reaches, equiv, href)
        leads = reaches or (name == _RETARGETING_TAG and href) or (name == _EQUIV_TAG and equiv)
        return name, end, not open_quote, leads


def _escaped_at(text: str, index: int) -> bool:
    """Whether the character at ``index`` stands after an odd run of backslashes."""
    before = index
    while before > 0 and text[before - 1] == "\\":
        before -= 1
    return (index - before) % 2 == 1


def _hand_links(text: str) -> list[int]:
    """Where ``text`` opens a link into the bundle or to a note's anchor: the ``]`` before
    such a target, and the ``<`` of a tag (:class:`_TagReader`) one of whose values holds
    one or that changes where the platform's links lead (a base with an ``href``, a meta
    with an ``http-equiv``), escaped by a backslash or not: a block another text left open
    makes a backslash escape nothing there, which no text can know. A tag not read safely
    and holding none counts too, if it is escaped only inside an HTML block of its own
    text. With it, the first closing tag of its name after it, which a reader of raw HTML
    would take too."""
    places: list[int] = []
    at = text.find("]")
    while at != -1:
        found = _AFTER_LINK_TEXT.match(text, at)
        if found is not None and not _escaped_at(text, at):
            target = _link_target_at(text, found.end(), bool(found.group(2)))
            if target is None or _into_the_bundle(target):
                places.append(at)
        at = text.find("]", at + 1)
    closings: dict[str, list[int]] | None = None
    in_block: Callable[[int], bool] | None = None
    reader: _TagReader | None = None
    for opening in _TAG_START.finditer(text):
        reader = reader or _TagReader(text)
        name, end, safe, leads = reader.read(opening.start())
        if not leads:
            if safe:
                continue
            if _escaped_at(text, opening.start()):
                # An escaped tag merely not read safely is text wherever a backslash
                # escapes: outside an HTML block of this text.
                in_block = in_block or _html_block_reader(text)
                if not in_block(opening.start()):
                    continue
        places.append(opening.start())
        if closings is None:
            closings = {}
            for closing in _TAG_CLOSING.finditer(text):
                if not _escaped_at(text, closing.start()):
                    closings.setdefault(closing.group(1).lower(), []).append(closing.start())
        ends = closings.get(name, [])
        after = bisect.bisect_left(ends, end)
        if after < len(ends):
            places.append(ends[after])
    return sorted(set(places))


def _link_readers() -> list[Any]:
    """markdown-it's readers: the HTML report's, then one that reads raw HTML."""
    from markdown_it import MarkdownIt

    if not _LINK_READERS:
        _LINK_READERS.extend(
            MarkdownIt("commonmark", {"html": raw}).enable("table").enable("strikethrough")
            for raw in (False, True)
        )
    return _LINK_READERS


def _html_block_reader(text: str) -> Callable[[int], bool]:
    """Whether a place of ``text`` lies inside an HTML block, as a reader of raw HTML
    reads the whole text: one it passes through as written."""
    lines: list[tuple[int, int]] = []
    tokens = list(_link_readers()[1].parse(text))
    while tokens:
        token = tokens.pop()
        tokens.extend(token.children or ())
        if token.type == "html_block" and token.map:
            lines.append((token.map[0], token.map[1]))
    starts = [0, *(found.end() for found in re.finditer(r"\n", text))]

    def inside(place: int) -> bool:
        line = bisect.bisect_right(starts, place) - 1
        return any(first <= line < last for first, last in lines)

    return inside


def _in_code(text: str, places: list[int]) -> set[int]:
    """Those of ``places`` every reader takes as code: the HTML report's reader and one
    that reads raw HTML, both markdown-it's, each over the whole text with a word of its
    own at each place."""
    if "`" not in text and "~~~" not in text and _INDENTED_LINE.search(text) is None:
        return set()
    mark = secrets.token_hex(8)
    probe = list(text)
    for index, place in enumerate(places):
        probe[place] = f"z{mark}{index}z"
    joined = "".join(probe)
    word = re.compile(rf"z{mark}(\d+)z")
    coded: set[int] | None = None
    for reader in _link_readers():
        found: set[int] = set()
        tokens = list(reader.parse(joined))
        while tokens:
            token = tokens.pop()
            tokens.extend(token.children or ())
            if token.type in _CODE_TOKENS:
                found.update(int(m.group(1)) for m in word.finditer(token.content + token.info))
        coded = found if coded is None else coded & found
    return {places[index] for index in coded or ()}


def _hand_links_unlinked(text: str, keep: Callable[[str], str] = str) -> str:
    """``text`` with every link into the evidence bundle or to a note's anchor printed as
    its characters (T-814).

    The platform's own note markers and links into the bundle are set aside from the
    closing pass (``_Context.keep``), so a link of that kind still in the text was
    written by a model, a sample, a tool or the operator: the ``]`` that closes its text
    or a reference definition's label is escaped. The ``<`` of a tag that holds one is
    written as ``&lt;``, set aside by ``keep`` from the reference escape: text in a
    paragraph, a table cell and an HTML block alike, where a viewer that passes raw HTML
    through would read a backslash before it as a character and the tag as a tag; inside
    an HTML block a backslash before the ``<``, which escapes nothing there, gives way to
    it. A target longer than :data:`_TARGET_REACH` is taken to reach the bundle and prints
    as its characters too.
    What a reader takes as code is left byte for byte, and nothing else of the text
    changes.
    """
    if "]" not in text and "<" not in text:
        return text
    places = _hand_links(text)
    if not places:
        return text
    coded = _in_code(text, places)
    out: list[str] = []
    at = 0
    for place in places:
        if place in coded:
            continue
        if text[place] == "]":
            out += [text[at:place], "\\"]
            at = place
            continue
        cut = place - 1 if _escaped_at(text, place) else place
        out += [text[at:cut], keep("&lt;")]
        at = place + 1
    out.append(text[at:])
    return "".join(out)


def _reference_spans(text: str) -> list[tuple[int, int]]:
    """Where ``text`` holds a reference service's own lookup, kept as checked.

    A sentence's punctuation after the link is trimmed before the check, and
    only what was checked is kept: the trimmed characters are read with the
    rest of the text. A link the run's own indicator was defanged inside is no
    lookup. Inside a value the value writer reads (:func:`_inline_safe`), no
    link is a lookup kept.
    """
    spans: list[tuple[int, int]] = []
    if _IN_A_VALUE.get():
        return spans
    for found in _REFERENCE_CANDIDATE.finditer(text):
        if text[found.end() : found.end() + 3] in _DEFANGED_MARKS:
            continue
        checked = found.group(0).rstrip(",.;:!?")
        if _reference_lookup(checked):
            spans.append((found.start(), found.start() + len(checked)))
    return spans


def _defanged_piece(text: str) -> str:
    """``text``, holding no kept link, with every network value in it defanged, in one reading.

    Each place a viewer starts a link is read where it stands, whatever is
    around it and however deeply it is nested, and the characters that make it
    live are rewritten in place: a scheme's letters (``hxxp``), the dots of a
    host (``[.]``), a mailbox's ``@`` and an IPv6 address's first colon. Nothing
    is read twice and no pass is repeated, so a text of any length and any
    nesting is read in time linear in its length.
    """
    if not text:
        return text
    marks: dict[int, str] = {}
    _mark_links(text, marks)
    _mark_scheme_openers(text, marks)
    _mark_protocol_relative_targets(text, marks)
    _mark_mailboxes(text, marks)
    _mark_hosts(text, marks)
    if not marks:
        return text
    out: list[str] = []
    at = 0
    for index in sorted(marks):
        out += [text[at:index], marks[index]]
        at = index + 1
    out.append(text[at:])
    return "".join(out)


def _bracket(text: str, index: int, marks: dict[int, str]) -> None:
    """Write the ``.``, ``:`` or ``@`` at ``index`` bracketed, unless it already is."""
    if 0 < index < len(text) - 1 and text[index - 1] == "[" and text[index + 1] == "]":
        return
    marks[index] = f"[{text[index]}]"


def _bracket_dots(text: str, start: int, end: int, marks: dict[int, str]) -> None:
    for index in range(start, end):
        if text[index] == ".":
            _bracket(text, index, marks)


def _mark_links(text: str, marks: dict[int, str]) -> None:
    """Every ``//`` target and every scheme before one: the authority's dots, and the scheme.

    Each ``//`` starts its own authority, so a URL nested in another's path is
    read where it stands, at any depth. The authority runs to the first
    separator; a defanged mark inside it is read past. A scheme before the
    ``//`` is defanged by form, whatever its host (:func:`_defang_scheme`).
    """
    at = text.find("//")
    while at != -1:
        if at > 0 and text[at - 1] == ":":
            _defang_scheme(text, at - 1, marks)
        # A browser reads past more slashes and backslashes to the host.
        index = at + 2
        while index < len(text) and text[index] in "/\\":
            index += 1
        while index < len(text):
            if text[index : index + 3] in _DEFANGED_MARKS:
                index += 3
                continue
            char = text[index]
            if char in _AUTHORITY_END or char.isspace():
                break
            if char == ".":
                _bracket(text, index, marks)
            index += 1
        at = text.find("//", max(index, at + 2))


def _defang_scheme(text: str, colon: int, marks: dict[int, str]) -> None:
    """Defang the scheme that ends at ``colon``, whatever follows it.

    The scheme is the run of scheme characters before the colon, from its
    first letter, read whole: http, https or ftp is renamed (``hxxp``,
    ``hxxps``, ``fxp``); a defanged spelling is left as it is; any other scheme
    (``ws``, ``irc``, ``a.http``, ``com-http``) has its colon bracketed
    (``ws[:]//``), so no viewer reads a scheme there at all, whichever of its
    characters a viewer would take for the scheme.
    """
    from malspark.reporting.defang import _SCHEMES

    start = colon
    while (
        start > 0
        and text[start - 1].isascii()
        and (text[start - 1].isalnum() or text[start - 1] in "+.-")
    ):
        start -= 1
    while start < colon and not text[start].isalpha():
        start += 1
    if start == colon:
        return
    scheme = text[start:colon]
    renamed = _SCHEMES.get(scheme.lower(), "")
    if renamed:
        for offset, (was, now) in enumerate(zip(scheme.lower(), renamed, strict=False)):
            if was != now:
                marks[start + offset] = now.upper() if scheme[offset].isupper() else now
    elif scheme.lower() not in _DEFANGED_SCHEMES:
        _bracket(text, colon, marks)


# The spellings a defanged scheme is written in.
_DEFANGED_SCHEMES = frozenset({"hxxp", "hxxps", "fxp"})
# A scheme a link or autolink syntax opens: ``<scheme:…>``, ``[x](scheme:…)``,
# ``[x](<scheme:…>)`` and a reference definition's ``[r]: scheme:…``.
_SCHEME_IN_LINK_SYNTAX = re.compile(
    r"(?:<" + _PIPE + r"\]\(<?" + _PIPE + r"(?<!\[[.:@])\]:[ \t]*)[A-Za-z][A-Za-z0-9+.-]{1,31}:"
)
# A scheme a viewer links with no "//" after it, before a target: not before
# a space or a second colon ("Data::Data::Modulo" names a capa namespace).
_SCHEME_WITHOUT_SLASHES = re.compile(
    r"(?i)(?<![a-z0-9+.-])(?:mailto"
    + _PIPE
    + r"xmpp"
    + _PIPE
    + r"javascript"
    + _PIPE
    + r"vbscript"
    + _PIPE
    + r"data):(?=[^\s:])"
)


# A link or image target, a reference definition's, or the value of a raw HTML
# attribute that fetches or follows, that starts with two slashes or
# backslashes: a protocol-relative target a viewer resolves against the page's
# own scheme, whatever its host (a single label, a decimal address). What
# stands before it is a link's own opener (``](``), a reference definition
# (a line start, after any block quote or list markers and up to three
# spaces, so ``case a[0]: //`` in code is no target), or an attribute name and
# ``=``. White space, a line ending and an optional ``<`` may stand between.
# A URL parser drops a tab, a carriage return and a line feed from anywhere in
# a target, so they may stand between the two slashes too.
# Every run of white space is possessive and each branch spends its own, so none
# can be split between two quantifiers and given back: nothing backtracks.
_GAP = r"[ \t\r\n]*+"
_OPTIONAL_BRACKET = r"(?:<" + _GAP + r")?"
_PROTOCOL_RELATIVE_TARGET = re.compile(
    r"(?:\]\("
    + _GAP
    + _OPTIONAL_BRACKET
    + _PIPE
    + r"(?m:^)(?:[ ]{0,3}(?:>"
    + _PIPE
    + r"[-+*]"
    + _PIPE
    + r"\d{1,9}[.)])[ \t]*+)*+[ ]{0,3}\[[^\]\n]*(?<!\[[.:@])\]:"
    + _GAP
    + _OPTIONAL_BRACKET
    + _PIPE
    + r"(?i:\b(?:"
    + _PIPE.join(
        (
            "href",
            "src",
            "action",
            "formaction",
            "poster",
            "data",
            "srcset",
            "background",
            "ping",
            "cite",
            "longdesc",
            "lowsrc",
            "dynsrc",
            "icon",
            "manifest",
            "codebase",
        )
    )
    + r"))"
    + _GAP
    + r"="
    + _GAP
    + r"[\"']?"
    # A URL parser strips every C0 control and space before an attribute's
    # value, so any of them may stand before its first slash.
    + r"[\x00-\x20]*+"
    + _OPTIONAL_BRACKET
    + r")(?=[/\\][\t\r\n]*+[/\\])"
)


def _mark_protocol_relative_targets(text: str, marks: dict[int, str]) -> None:
    """Every protocol-relative link target: its first slash bracketed, so it is no ``//``."""
    for found in _PROTOCOL_RELATIVE_TARGET.finditer(text):
        marks[found.end()] = f"[{text[found.end()]}]"


def _mark_scheme_openers(text: str, marks: dict[int, str]) -> None:
    """Every scheme a link syntax opens, and every ``mailto:``-style scheme: defanged by form."""
    for pattern in (_SCHEME_IN_LINK_SYNTAX, _SCHEME_WITHOUT_SLASHES):
        for found in pattern.finditer(text):
            _defang_scheme(text, found.end() - 1, marks)


def _mark_mailboxes(text: str, marks: dict[int, str]) -> None:
    """Every mailbox, and every host after a bare ``@``: the ``@`` and the domain's dots."""
    from malspark.pipeline.validation import network_values_in

    for found in _EMAIL_IN_TEXT.finditer(text):
        at = text.index("@", found.start())
        _bracket(text, at, marks)
        _bracket_dots(text, at + 1, found.end(), marks)
    for found in _BARE_AT_HOST.finditer(text):
        if network_values_in(found.group(1)):
            _bracket(text, found.start(), marks)
            _bracket_dots(text, found.start(1), found.end(1), marks)


def _mark_hosts(text: str, marks: dict[int, str]) -> None:
    """Every ``www.`` host, ``.onion`` name, host under a real TLD and address: dots, or a colon."""
    from malspark.pipeline.validation import network_values_in

    for pattern in (_WWW_HOST, _ONION_HOST):
        for found in pattern.finditer(text):
            _bracket_dots(text, found.start(), found.end(), marks)
    # A name with an underscore in a label ("_ldap._tcp.dc._msdcs.example.com",
    # "cdn_.example.net"): no registrar hands one out, but DNS serves one under
    # a registered name. Read whole where what follows its last underscore
    # label is a host this reader takes alone (:func:`_underscore_host`).
    for found in _UNDERSCORE_HOST.finditer(text):
        if "_" in found.group(0) and _underscore_host(found.group(0)):
            _bracket_dots(text, found.start(), found.end(), marks)
    # Any run an IPv6 address could be is defanged, a short one too ("fe80::1"):
    # only its first colon is bracketed, and the publish checks' stricter
    # reader (``validation.ipv6_addresses_in``) decides which is a value.
    for found in _IPV6_CANDIDATE.finditer(text):
        if _is_ipv6(found.group(0)):
            _bracket(text, text.index(":", found.start()), marks)
    # An address with an IPv4 tail written in full ("2001:db8:0:0:0:0:1.2.3.4"),
    # which the run above stops short of, read whole by the checks' candidate.
    for found in _IPV6_WITH_A_TAIL.finditer(text):
        if "." in found.group(0) and _is_ipv6(found.group(0)):
            _bracket(text, text.index(":", found.start()), marks)
    # Read with "@" and backslashes as spaces as well, so a host written after
    # either ("…/\@evil.com") is found; the mailbox itself is read above.
    values = {
        value: kind
        for kind, value in network_values_in(re.sub(r"[@\\]", " ", text))
        if not _file_name_host(kind, value)
    }
    # A host written in capitals ("EVIL.COM") is read as the host it spells;
    # the string sweep's reader takes an inner capital for a type name.
    for found in _SHOUTED_HOST.finditer(text):
        if not _DOTNET_NAME.fullmatch(found.group(0)):
            for kind, value in network_values_in(found.group(0).lower()):
                if not _file_name_host(kind, value):
                    values.setdefault(value, kind)
    if not values:
        return
    # Where each value stands: a dotted token, or the part of one after a dot,
    # that ends where the token ends. One reading of the text's tokens, each
    # looked up by its suffixes, longest first.
    lengths = {len(value) for value in values}
    places: dict[str, list[tuple[int, int]]] = {}
    for token in _DOTTED_TOKEN.finditer(text):
        written = token.group(0).lower()
        starts = [0] + [index + 1 for index, char in enumerate(written) if char == "."]
        for start in starts:
            if len(written) - start in lengths and written[start:] in values:
                places.setdefault(written[start:], []).append((token.start() + start, token.end()))
                break
    for value, found_at in places.items():
        # An address is a version number only where every place it stands
        # follows a version word; one place that does not makes it an address.
        if values[value] == "ip" and all(
            _VERSION_BEFORE.search(text[max(0, start - _VERSION_WORD_REACH) : start])
            for start, _end in found_at
        ):
            continue
        for start, end in found_at:
            _bracket_dots(text, start, end, marks)


# The links a report keeps as links, besides the ATT&CK knowledge base's
# below: the report's own references and the links its reputation records
# hold (``_Kept``), read from the report itself and set for one render.
_KEPT_LINKS: ContextVar[_Kept | None] = ContextVar("markdown_kept_links", default=None)


@dataclass(frozen=True)
class _Kept:
    """The links one report keeps: its own, and whether it reads the legacy services' shapes."""

    links: frozenset[str]
    legacy: bool

    @classmethod
    def of(cls, report: MalwareReport) -> _Kept:
        links = {str(ref.url) for ref in report.references or () if ref.url}
        # A target as the link writes it (:func:`_link_target`) is the same link.
        links.update(_link_target(link) for link in list(links))
        links.update(
            str(answer.link) for answer in report.reputation or () if getattr(answer, "link", None)
        )
        # A report stored before reputation records (``reputation`` absent)
        # was written when the two lookup services below were linked on every
        # report; it keeps their shapes as links, as it always rendered them.
        return cls(frozenset(links), report.reputation is None)


# The shapes of the lookups a report stored before declared references linked
# on every report: read only for such a report (``_Kept.legacy``), so it
# renders as it always did. A newer report keeps its own links instead.
_LEGACY_REFERENCE_LOOKUPS: dict[str, re.Pattern[str]] = {
    "www.virustotal.com": re.compile(
        r"/gui/(?:(?:file"
        + _PIPE
        + r"url)/[0-9a-f]+"
        + _PIPE
        + r"(?:domain"
        + _PIPE
        + r"ip-address)/[A-Za-z0-9.:-]+)/?"
    ),
    "bazaar.abuse.ch": re.compile(r"/sample/[0-9a-f]{64}/?"),
}

# The ATT&CK knowledge base's lookups, which every report links: a link of
# that shape, with no query, fragment, userinfo, backslash or dot segment,
# stays a link; anything else on that host is defanged.
_REFERENCE_LOOKUPS: dict[str, re.Pattern[str]] = {
    "attack.mitre.org": re.compile(
        r"/(?:"
        + _PIPE.join(
            (
                r"techniques/T\d{4}(?:/\d{3})?",
                r"tactics/TA\d{4}",
                r"software/S\d{4}",
                r"matrices/[a-z]+(?:/[a-z]+)?",
            )
        )
        + r")/?"
    ),
}


def _reference_lookup(url: str) -> bool:
    """Whether ``url`` is one of a reference service's own lookups, and so stays a link.

    The path is decoded (``%2e``, ``%2f``, ``%5c`` and the rest, repeatedly)
    and the service's pattern must match the whole decoded path. A backslash,
    an ``@``, a dot segment or a second ``//`` anywhere, raw or decoded, and a
    query, fragment, port or userinfo make it no lookup.
    """
    from urllib.parse import unquote

    try:
        parts = urlparse(url)
    except ValueError:
        return False
    kept = _KEPT_LINKS.get()
    host = (parts.hostname or "").lower()
    shape = _REFERENCE_LOOKUPS.get(host)
    if shape is None and (kept is None or kept.legacy):
        shape = _LEGACY_REFERENCE_LOOKUPS.get(host)
    own = kept is not None and url in kept.links
    if (
        (shape is None and not own)
        or parts.scheme.lower() != "https"
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.port is not None
        or parts.netloc.lower() != (parts.hostname or "").lower()
    ):
        return False
    path = parts.path
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    else:
        return False
    if any(mark in path for mark in ("\\", "@", "//", "%")) or "/." in path:
        return False
    return own or (shape is not None and shape.fullmatch(path) is not None)


# A dotted name written wholly in capitals, and a name under ``.onion``.
# A dotted token: labels of letters, digits and hyphens joined by dots.
_DOTTED_TOKEN = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_SHOUTED_HOST = re.compile(r"(?<![\w.-])[A-Z0-9-]+(?:\.[A-Z0-9-]+)+(?![\w-])")
_ONION_HOST = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9-]+\.)+onion(?![\w-])")
# A dotted name whose labels may hold an underscore, ending in letters; read
# as a host only by :func:`_underscore_host`. A sentence's full stop after it
# is no label. It may follow a path's slash or a run of dots ("dir/_dmarc.",
# "./_a.", ".._a."), never a label's dot, so it starts where a name starts.
_UNDERSCORE_HOST = re.compile(
    r"(?<![\w@-])(?<![\w-]\.)(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-]"
    + _PIPE
    + r"\.[A-Za-z0-9])"
)
# A .NET technology's name, which ends in a real top-level domain.
_DOTNET_NAME = re.compile(r"(?i)(?:" + _PIPE.join(("ASP", "ADO", "VB")) + r")\.NET")
# The top-level domains that are also common files' extensions: a two-label
# name under one ("lib.rs", "README.md", "install.sh", "archive.zip") is read
# as a file in free prose. ".pl" and ".ml" are country codes a sample's hosts
# use often enough that a name under them stays a host. Under a scheme, a
# "//", "www." or "@" such a name is a host and defanged, and so is any value
# the run itself recorded. A display rule of this report alone: no
# extraction, tool or publish check reads it.
_FILE_EXTENSION_TLDS = frozenset(
    {"zip", "mov", "py", "so", "sh", "ps", "ai", "md", "rs", "pm", "cat", "one", "cab"}
)
# What a dotted quad of a version number follows: "FileVersion", "version",
# "ProductVersion:" or a "v" written against it, and how far before the quad
# that is looked for.
_VERSION_BEFORE = re.compile(r"(?i)(?:version\s*[:=]?\s*" + _PIPE + r"\bv)$")
_VERSION_WORD_REACH = 64


def _is_ipv6(text: str) -> bool:
    """Whether ``text`` is an IPv6 address."""
    try:
        return ipaddress.ip_address(text).version == 6
    except ValueError:
        return False


def _file_name_host(kind: str, value: str) -> bool:
    """Whether a host the reader found is a two-label name under a file-extension TLD."""
    labels = value.lower().split(".")
    return kind == "domain" and len(labels) == 2 and labels[-1] in _FILE_EXTENSION_TLDS


def _underscore_host(name: str) -> bool:
    """Whether a dotted name with an underscore label is a host under a name this reader reads.

    The labels after the last one holding an underscore must be two or more
    and be, alone, a host the reader of every host takes (the string sweep's
    TLD list and shape rules, the file-extension rule above): ``victimcorp.com``
    in ``_ldap._tcp.dc._msdcs.victimcorp.com``. A registered name never holds
    an underscore, so a name whose underscore is in its last two labels
    (``my_site.com``, ``foo._bar.com``) is no host, and neither is a dunder, a
    decompiler's function or a module path (``__init__.py``, ``FUN_00401310``,
    ``self._data.items``): nothing after the underscore is a host.
    """
    from malspark.pipeline.validation import network_values_in

    labels = name.split(".")
    last = max(index for index, label in enumerate(labels) if "_" in label)
    tail = ".".join(labels[last + 1 :])
    if tail.count(".") < 1:
        return False
    # The tail is read in lower case, as a resolver reads it: a host written
    # in capitals or mixed case ("VictimCorp.Com") is the host it spells.
    read = tail.lower()
    return any(
        kind == "domain" and value == read and not _file_name_host(kind, value)
        for kind, value in network_values_in(read)
    )


def run_network_values(
    report: MalwareReport, rows: list[ConsolidatedIOC] | None = None
) -> list[tuple[str, str]]:
    """Every network value the run recorded, ``(value, kind)``: what the run's defanger reads.

    The IOC table's network rows (``rows``, or the table rebuilt when none
    are given), the network block's domains, addresses and URLs, and every
    value a recovering tool decoded, row or not, so a decoded C2 printed in a
    FLOSS or decoder table is never printed live. The render's context, a
    listing figure and the HTML renderer's read of stored figures all read it.
    """
    if rows is None:
        rows = _indicator_rows(report) or []
    values = [(row.value, row.kind or "") for row in rows if row.kind in _NETWORK_KINDS]
    net = report.network
    if net is not None:
        values += [(d.fqdn, "domain") for d in net.domains]
        values += [(ip.address, "ip") for ip in net.ips]
        values += [(u.url, "url") for u in net.urls]
    recovered = report.emulated_strings
    for key in recovered.recovered_by if recovered is not None else {}:
        values += [(value, kind) for kind, value in cell_network_values(key, None)]
    return values


def _escaped_spelling(value: Any) -> str:
    """A recorded value as a tool's escaped text writes it: Markdown escaped, then underscores."""
    return _emphasis_escaped(_escaped_keeping_spans(str(value or "")))


def _inline_safe(
    text: Any,
    *,
    pipes: bool = True,
    plain: Callable[[str], str] = _defanged_text,
    links: bool = False,
) -> str:
    """A value this report's checks wrote about the sample: escaped, then defanged.

    Markdown's own characters are escaped first, so a sample's value cannot
    open a link, a tag or a code span; ``pipes=False`` leaves the table
    separator to the row, which escapes it itself (:func:`_cell`). ``plain``
    is the render's own defanger (``ctx.plain``) wherever a section has it,
    so the run's recorded values are read before the escape of an underscore
    could hide one from the closing pass.

    A link is live only where the platform writes the link: inside a value a
    reference service's lookup URL is defanged as any URL is, unless ``links``
    keeps it (a viewer's autolink would otherwise vouch for a destination the
    sample or a tool chose). A line ending is the space a reader shows for it
    inside a line, so no line of the value opens a block.
    """
    meta = _INLINE_META if pipes else _INLINE_META_NO_PIPE
    token = _IN_A_VALUE.set(not links)
    try:
        text = _LINE_ENDING.sub(" ", str(text or ""))
        return _emphasis_escaped(plain(meta.sub(r"\\\1", text)))
    finally:
        _IN_A_VALUE.reset(token)


def _value_parts(text: str, plain: Callable[[str], str] = _defanged_text) -> list[tuple[str, bool]]:
    """``text`` as the value writer reads it (:func:`_inline_safe`: escaped, then defanged, no
    link in it kept), in pieces before any cut, each character as the reader is shown it: the
    marks the defanger sets (the brackets of ``[.]``) the platform's, every other piece the
    value's own characters."""
    token = _IN_A_VALUE.set(True)
    try:
        read = plain(_INLINE_META.sub(r"\\\1", _LINE_ENDING.sub(" ", str(text or ""))))
    finally:
        _IN_A_VALUE.reset(token)
    # Every character of the value Markdown reads is escaped above: one the defanged text
    # holds unescaped is a mark the defanger set.
    parts: list[tuple[str, bool]] = []
    run: list[str] = []
    at = 0
    while at < len(read):
        if read[at] == "\\" and at + 1 < len(read):
            run.append(read[at + 1])
            at += 2
            continue
        if _INLINE_META.match(read[at]):
            if run:
                parts.append(("".join(run), False))
                run = []
            parts.append((read[at], True))
        else:
            run.append(read[at])
        at += 1
    return [*parts, ("".join(run), False)] if run else parts


def _quote_written(parts: list[tuple[str, bool]], *, pipes: bool = True) -> str:
    """A platform sentence quoting a model's words, from its pieces after any cut: each piece
    the platform set (a mark, a defanger's mark, the cut mark, the brackets a cut closes) as it
    is, every other piece, the value's characters as :func:`_value_parts` reads them, escaped
    as the value writer escapes them (:func:`_inline_safe`), so no escape is cut and every
    character shows as the record holds it. ``pipes=False`` leaves the table separator to the
    row."""
    meta = _INLINE_META if pipes else _INLINE_META_NO_PIPE
    return "".join(
        piece if platform else _emphasis_escaped(meta.sub(r"\\\1", piece))
        for piece, platform in parts
    )


# What Markdown reads as the end of a line.
_LINE_ENDING = re.compile(r"\r\n?" + _PIPE + r"\n")

# Set while the value writer reads a value: no reference lookup in it is kept.
_IN_A_VALUE: ContextVar[bool] = ContextVar("markdown_in_a_value", default=False)


def _escaped_keeping_spans(text: Any, meta: re.Pattern[str] = _INLINE_META_NO_PIPE) -> str:
    """Text a tool or a model wrote, each balanced backtick pair a code span, the rest escaped.

    A finding or a tool's message quotes what it is about between backticks
    (`` `cmd.exe` ``): each run of backticks closed by the next run of the same
    length is written by :func:`_code_span`, which no backtick inside it can
    close, and every other character of Markdown is escaped, an unpaired
    backtick included. Not defanged: the caller's defanger reads it after.
    Each run's partner is found by one reading from the end.
    """
    raw = str(text or "")
    runs = [(found.start(), found.end()) for found in _BACKTICK_RUN.finditer(raw)]
    if not runs:
        return meta.sub(r"\\\1", raw)
    partner: list[int | None] = [None] * len(runs)
    latest: dict[int, int] = {}
    for index in range(len(runs) - 1, -1, -1):
        length = runs[index][1] - runs[index][0]
        partner[index] = latest.get(length)
        latest[length] = index
    out: list[str] = []
    at = 0
    index = 0
    while index < len(runs):
        closer = partner[index]
        if closer is None:
            index += 1
            continue
        out += [
            meta.sub(r"\\\1", raw[at : runs[index][0]]),
            _code_span(_span_content(raw[runs[index][1] : runs[closer][0]])),
        ]
        at = runs[closer][1]
        index = closer + 1
    out.append(meta.sub(r"\\\1", raw[at:]))
    return "".join(out)


def _span_content(inner: str) -> str:
    """The text a kept span shows when it holds a backtick: less :func:`_code_span`'s padding.

    A span whose text holds a backtick is written with a space inside each
    fence, which the reader takes off; written again by :func:`_code_span`, it
    is the span it was. Any other span's text is kept as it stands.
    """
    if len(inner) > 2 and inner[0] == inner[-1] == " " and "`" in inner[1:-1]:
        return inner[1:-1]
    return inner


# What stands around the run of backticks that closes a code span: no backtick.
_NOT_A_TICK_BEFORE = "(?<!" + chr(96) + ")"
_NOT_A_TICK_AFTER = "(?!" + chr(96) + ")"


def _emphasis_escaped(text: str) -> str:
    """Escaped, defanged text with each underscore that could open emphasis escaped too.

    Run after the defanger, which has to read a value's underscores as the
    value's (``_ldap._tcp.example.com`` is a host), and whose marks hold none.
    A pair a backslash already escapes is left as it is, and so is a code span:
    a run of backticks and the next run of the same length, which no escape
    inside it reaches.
    """
    out: list[str] = []
    plain: list[str] = []

    def flush() -> None:
        out.append(_EMPHASIS_UNDERSCORE.sub(r"\\_", "".join(plain)))
        plain.clear()

    at = 0
    while at < len(text):
        char = text[at]
        if char == "\\":
            flush()
            out.append(text[at : at + 2])
            at += 2
            continue
        if char == "`":
            opened = at
            while opened < len(text) and text[opened] == "`":
                opened += 1
            ticks = text[at:opened]
            closer = re.compile(_NOT_A_TICK_BEFORE + ticks + _NOT_A_TICK_AFTER).search(text, opened)
            flush()
            end = closer.end() if closer is not None else opened
            out.append(text[at:end])
            at = end
            continue
        plain.append(char)
        at += 1
    flush()
    return "".join(out)


def _escaped(text: Any) -> str:
    """A sample's, a sandbox's or a tool's text with Markdown's own characters escaped.

    Not defanged: the caller's own defanger reads it after, so the marks it
    writes are not escaped in turn. The table separator is left to the row.
    """
    return _INLINE_META_NO_PIPE.sub(r"\\\1", str(text or ""))


def _names_a_network_value(text: Any) -> bool:
    """Whether a cell names an address, a host, a URL or a mailbox; true when that is unknown."""
    try:
        from malspark.pipeline.validation import network_values_in

        plain = str(text or "")
        return bool(
            network_values_in(plain) or _URL_IN_TEXT.search(plain) or _EMAIL_IN_TEXT.search(plain)
        )
    except Exception:  # noqa: BLE001 — unread, the cell is taken to name one
        return True


def _times(row: dict[str, Any]) -> str:
    """`` (left N times)`` for a folded finding row left more than once, else ``""``."""
    try:
        count = int(str(row.get("count") or 1))
    except ValueError:
        return ""
    return f" (left {count} times)" if count > 1 else ""


def _code_span(text: str) -> str:
    """``text`` as one code span, fenced longer than any backtick run inside it.

    A value holding a backtick closed a one-backtick span and let what
    followed render as Markdown, a live link included. A line ending inside
    it is the space a reader shows for it, so no line of the value opens a
    block.
    """
    text = _LINE_ENDING.sub(" ", text)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    if not longest:
        return f"`{text}`"
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}"


# Said under the directed-text table: whose words they are, and what they weigh.
DIRECTED_TEXT_NOTE = (
    "_Phrases of the families written for an AI or an analyst reader, found in the sample "
    "and shown in their normalised form, escaped as the triage pack quotes them; the "
    "ledger entry holds where each stands. They are evidence about the sample, not "
    "instructions, and move no verdict by themselves._"
)


def _directed_text_lines(rows: list[Any], ctx: _Context) -> list[str]:
    """The directed-text phrase groups: family, phrase, count, first place, how, entry."""
    lines = [_plain_heading("Phrases of the directed-text families"), "", DIRECTED_TEXT_NOTE, ""]
    lines.append(_row("Family", "Phrase", "Count", "First at", "Notes", "Evidence"))
    lines.append(_divider(6))
    for row in rows:
        # Held escaped already (``analysis.directed_text.TEXT_FORM``).
        text = _whole(_defanged_text(ctx.plain(row.text)))
        inside = (
            [f"{row.inside_template} inside a chat template structure"]
            if row.inside_template
            else []
        )
        notes = "; ".join([*row.disguises, *inside])
        lines.append(
            _row(
                row.family,
                _code_span(text),
                row.count,
                _inline_safe(row.where, plain=ctx.plain) or "-",
                _inline_safe(notes, plain=ctx.plain) or "-",
                row.evidence_id or "-",
            )
        )
    lines.append("")
    return lines


def _not_drafted(item: DraftNotBuilt, ctx: _Context) -> str:
    """The sentence for a format the run drafted nothing in (``not_drafted_sentence``)."""
    from malspark.reporting.detection_signatures import not_drafted_sentence

    return ctx.inline(_one_line(not_drafted_sentence(item)))


def _sample_check_line(rule: DetectionRule, ctx: _Context) -> str | None:
    """What checking a drafted rule against the sample it was drafted from found.

    Whether the rule matched and by which clause, each of its strings at the
    first offset the engine matched it, the strings it matched nowhere, or why
    the rule was not checked. ``None`` for a rule with no check: a Sigma or
    Suricata draft, and a rule stored before the check, which renders as it did.
    """
    if rule.sample_not_checked:
        why = ctx.value(_one_line(rule.sample_not_checked), pipes=True).rstrip(".")
        return f"Not run against the sample it was drafted from: {why}."
    if rule.matches_sample is None:
        return None
    strings = rule.sample_strings or []
    found = [
        f"{_code_span(_one_line(item.identifier))} at 0x{item.offset:x}"
        for item in strings
        if item.offset is not None
    ]
    nowhere = [_code_span(_one_line(item.identifier)) for item in strings if item.offset is None]
    said = [
        "Run against the sample it was drafted from: "
        + _held_by_clauses(rule.matches_sample, rule.matched_by, len(found), len(strings))
    ]
    if found:
        said.append(f"Found in the sample (first match of each): {', '.join(found)}.")
    if nowhere:
        said.append(f"Found nowhere in the sample: {', '.join(nowhere)}.")
    return " ".join(said)


def _held_by_clauses(
    matches: bool, matched_by: Sequence[str] | None, found: int, declared: int
) -> str:
    """Which clauses of a drafted rule's condition held on its sample, as one sentence.

    Read from ``matched_by``, the engine's answer: the strings clause, the
    sha256 or imphash clause without it, or none. A rule whose strings clause
    did not hold matches by its hash only, which is all a rule carrying the
    sample's own sha256 then says. A record without ``matched_by`` says only
    whether the rule matched.
    """
    counted = f"{found} of {declared} strings found"
    if matched_by is None:
        return "the rule matches it." if matches else "the rule does not match it."
    hashes = [part for part in matched_by if part != "strings"]
    named = " and ".join(hashes)
    if "strings" in matched_by:
        also = f", and so {'do' if len(hashes) > 1 else 'does'} its {named}" if hashes else ""
        return f"its strings match it ({counted}){also}."
    if hashes:
        rest = f"its strings do not ({counted})." if declared else "the draft declares no strings."
        return f"the rule matches it by its {named} only; {rest}"
    return "the rule does not match it" + (f" ({counted})." if declared else ".")


def _finding_text(row: dict[str, Any], plain: Callable[[str], str] = _defanged_text) -> str:
    """A finding's message as the report prints it: written whole by the value writer.

    A message is the platform's sentence quoting the claim, the value or the
    object it is about, which a sample, a tool or a model wrote, all in one
    string: it is written as text (:func:`_inline_safe`), so every character
    the record holds is shown, a backtick pair included, and nothing in it
    opens a link, a tag, a code span or emphasis. ``plain`` is the render's
    own defanger (``ctx.plain``): the run's recorded values first, then every
    other value.
    """
    message = str(row.get("message") or "")
    try:
        return _inline_safe(message, plain=plain)
    except Exception as exc:  # noqa: BLE001 — never the raw values
        logger.debug("markdown: a finding was not written (%s).", exc)
        return STATE_UNKNOWN


# The marks whose labels name values: several on one sentence or row read as
# one list in one mark.
_JOINED_MARK_CODES = frozenset(
    {"report.citation_wrong_entry", "report.value_only_in_call_arguments"}
)


def _joined_marks(rows: Sequence[Any]) -> list[Any]:
    """``rows`` with the labels of one sentence's marks of a joined code in one row."""
    out: list[Any] = []
    joined: dict[tuple[str, str, bool], int] = {}
    for row in rows:
        if row.code not in _JOINED_MARK_CODES:
            out.append(row)
            continue
        key = (row.sentence, row.code, row.asked)
        if key not in joined:
            joined[key] = len(out)
            out.append(row)
        elif row.label and row.label not in out[joined[key]].label:
            first = out[joined[key]]
            out[joined[key]] = first.model_copy(update={"label": f"{first.label}; {row.label}"})
    return out


def as_rendered(statement: Any, read_again: Callable[[str], Any]) -> Any:
    """A stored mark as a render prints it, or ``None`` for one the render drops.

    A mark of the unpublished-value code is read again against the render's IOC
    table (``read_again``: the values of the sentence the table does not
    publish and the sentence leaves unstated, ``None`` where the sentence
    cannot be read). None left: every value stands with a state the table
    agrees with, and a mark beside it would state it twice, so it is dropped.
    Some left: the label says what the table says of each
    (``validation.unpublished_value_label``), as the indicator rows beside it
    do. Not read, or any other code: the mark as stored. Whether the model was
    asked stays the recorded fact.
    """
    if statement.code != "report.unpublished_value":
        return statement
    unstated = read_again(statement.sentence)
    if unstated == []:
        return None
    if not unstated:
        return statement
    from malspark.pipeline.validation import unpublished_value_label

    label = unpublished_value_label(unstated)
    return statement if label == statement.label else statement.model_copy(update={"label": label})


def served_statements(report: MalwareReport, statements: Sequence[Any], rows: Any) -> list[Any]:
    """The flagged statements a report is served with: the marks its render prints.

    Each is read as the render reads it (:func:`as_rendered`) against ``rows``,
    the IOC table served beside it; a statement the agreement round left out of
    the analyst report (``left_out``) is served as stored, as the bundle prints
    it whole. A table that cannot be read refuses every value for that reason,
    as the render's does. Nothing stored changes.
    """
    from malspark.pipeline.validation import _unstated_values

    try:
        from malspark.reporting.narrative_agent import published_answers

        answers: Callable[[str, str], str] = published_answers(report, rows=rows)
    except Exception as exc:  # noqa: BLE001 — every value is then refused
        logger.debug("markdown: the served IOC table was not read (%s).", exc)
        answers = lambda kind, value: TABLE_NOT_READ  # noqa: E731

    def read_again(sentence: str) -> list[tuple[str, str, str]] | None:
        try:
            return _unstated_values(str(sentence or ""), answers)
        except Exception as exc:  # noqa: BLE001 — the stored row is served
            logger.debug("markdown: a served mark was not read again (%s).", exc)
            return None

    out: list[Any] = []
    for statement in statements:
        shown = statement if statement.left_out else as_rendered(statement, read_again)
        if shown is not None:
            out.append(shown)
    return out


# The words of the mark a sentence printed in its writer's own words carries where the
# agreement round dropped it naming no source it is read against
# (``section_agreement.LISTED_CODE``): asked about and left standing (T-613).
_LEFT_STANDING_WORDS = "asked about and left standing"


def _flag_mark(code: str, label: str, *, asked: bool = True) -> str:
    """The mark printed after a sentence a check left standing, in the platform's voice.

    ``asked=False`` for an answer that came by a path with no turn to ask on:
    the mark says the model was not asked.
    """
    from malspark.reporting.section_agreement import LISTED_CODE

    words = _FLAG_WORDS.get(code) or (
        _LEFT_STANDING_WORDS if code == LISTED_CODE else "asked about and kept"
    )
    said = f"{words}: {label}" if label else words
    return f"**[{said}; not asked]**" if not asked else f"**[{said}]**"


def _findings_beside(rows: list[dict[str, str]], plain: Callable[[str], str]) -> list[str]:
    """The platform's unresolved findings on a section, printed under it."""
    if not rows:
        return []
    lines = ["", f"_The platform's unresolved findings on this section ({MEASURED}):_", ""]
    lines.extend(_item(f"{_code_span(row['code'])}: {_finding_text(row, plain)}") for row in rows)
    return lines


def _family_voice(report: MalwareReport) -> str:
    """Who named the family: the judge, the sandbox's own classification, or a model unnamed."""
    attr = report.attribution
    if not stated_family(attr.family):
        return _verdict_voice(report)
    if attr.family_source == "sandbox":
        return MEASURED
    if attr.family_source == "judge":
        return JUDGE
    return ASSESSED


def _indicator_rows(
    report: MalwareReport, word: Callable[[str], str] = str
) -> list[ConsolidatedIOC] | None:
    """The IOC table's rows, answered by the publish rule on this render; ``None`` when unread.

    Built on request from the stored report by the reader
    ``/reports/{id}/iocs`` uses for its analyst rows (``builder.ioc_table``),
    so an enrichment that ran after the report was stored is reflected and a
    report stored before the table carried a kind prints in the new shape. A
    cell's publish state reads these same rows
    (``narrative_agent.published_answers``), so a render reads the table, and
    logs a failed rebuild, once. ``None`` is a rebuild that failed with no
    stored row to read: §9 prints no row and every cell's value is refused
    for that reason.
    """
    from malspark.reporting.builder import ioc_table

    try:
        return ioc_table(report, raise_unread=True, word=word)
    except Exception:  # noqa: BLE001 — the table is then unread
        logger.exception(
            "markdown: the IOC table could not be rebuilt and no stored row holds one."
        )
        return None


# The counts an enrichment record holds under these names are a reputation
# cell's counts (a source's declared ``record``, ``enrichment.builtin_sources``).
_NETWORK_COUNTS = ("malicious", "suspicious", "harmless", "undetected")


def _held_count(value: Any) -> int | None:
    """``value`` as the whole number the record holds, or ``None`` where it holds none.

    A count is a whole number however the record holds it: an ``int`` (not a
    bool), a finite ``float`` with no fraction (``19.0`` is 19), or a string
    of digits that converts; any other value, a digit string too long to
    convert among them, is no count. Reading a value never raises.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d+\s*", value):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _service_name(rep: dict[str, Any]) -> str:
    """The record's ``source`` where it is text; a value of another type names no service."""
    source = rep.get("source")
    return source if isinstance(source, str) else ""


def _network_counts(rep: dict[str, Any]) -> str:
    """The counts an enrichment record holds under ``malicious``, ``suspicious``,
    ``harmless``, ``undetected`` (:data:`_NETWORK_COUNTS`) and ``engines``, as
    the header cell prints a record's counts.

    Written by :func:`counts_line`, the one wording of a reputation record's
    counts: the flagged count, each count the record holds under
    :data:`_NETWORK_COUNTS` that is not zero, under the record's own name for
    it and in the record's order, and the engine count the service gave
    (``engines``). A count the record holds under any other name is not
    printed. No denominator is summed and no "of" is written. The
    record's ``total`` is never printed: in a server source's record
    (``enrichment.declared.read_reputation_record``) it is, where the answer's
    declaration names no total and its text states none, the sum of the
    members its reader kept (``core.reputation.read_answer``), and the record
    does not say which it is, so it cannot be printed as the answer's figure.
    The cell does not owe the count of members its reader did not keep: an
    enrichment record holds the fields its source declares and stores no count
    of the members it left, so the cell says "counts in the lookup's record",
    claims no tally is whole, and says nothing of a category the record holds
    no count of; it never prints a number the record does not hold. A flagged
    count the record holds as a value that is no whole number is said to be
    one, never "not counted". ``""`` where the record holds no count.
    """
    stats = {
        name: held
        for name, value in rep.items()
        if name in _NETWORK_COUNTS and (held := _held_count(value)) is not None
    }
    # A flagged count the record holds as no whole number (2.5, a boolean, a
    # digit string that does not convert) is said to be one, not "not counted".
    held = rep.get("malicious")
    record = ReputationRecord(
        service=_service_name(rep).strip(),
        malicious=stats.get("malicious"),
        suspicious=stats.get("suspicious"),
        engines=_held_count(rep.get("engines")),
        stats=stats,
        not_whole=["malicious"] if held is not None and _held_count(held) is None else [],
    )
    # The service's name is its answer's text, by the inline rule; the row
    # escapes the table separator itself (:func:`_cell`).
    return counts_line(
        record, unnamed="reputation", written=lambda text: _inline_safe(text, pipes=False)
    )


def _analysed(stamp: Any) -> str:
    """The date clause of a record's analysis time, or ``""`` where it converts to no date.

    A date is a positive whole number of seconds (not a bool) that converts;
    one too large for the platform is no date, and reading it never raises.
    """
    if isinstance(stamp, bool) or not isinstance(stamp, int) or stamp <= 0:
        return ""
    from datetime import UTC, datetime

    try:
        day = datetime.fromtimestamp(stamp, tz=UTC).date()
    except (OverflowError, OSError, ValueError, TypeError):
        return ""
    return f" (analysed {day.isoformat()})"


def _reputations(report: MalwareReport) -> dict[str, str]:
    """A short reputation cell per network value the enrichment answered for.

    The counts each record holds (:func:`_network_counts`). A report stored
    before the lookups' records (``reputation`` is ``None``) prints a cell as
    it was printed then (``core.legacy_reputation``) only where the value's
    record holds all of :data:`_NETWORK_COUNTS` as whole numbers, the record
    every such cell was printed from; any other record of such a report, one
    a later enrichment wrote among them, is printed by its counts.
    """
    out: dict[str, str] = {}
    net = report.network
    if net is None:
        return out
    rows = [(d.fqdn, d.reputation) for d in net.domains] + [
        (ip.address, ip.reputation) for ip in net.ips
    ]
    for value, rep in rows:
        if not isinstance(rep, dict) or "malicious" not in rep:
            continue
        held = [_held_count(rep.get(k)) for k in _NETWORK_COUNTS]
        if report.reputation is None and all(count is not None for count in held):
            # The service's name is its answer's text, by the inline rule.
            name = _inline_safe(_service_name(rep), pipes=False) or "reputation"
            total = sum(count for count in held if count is not None)
            said = f"{name}: {held[0]} of {total} engines flag it as malicious"
        else:
            said = _network_counts(rep)
            if not said:
                continue
        said += _analysed(rep.get("last_analysis_date_unix"))
        out[value.strip().lower().rstrip(".")] = said
    return out


def _enrichment_not_asked_lines(report: MalwareReport) -> list[str]:
    """The network values the enrichment left unasked, each with the questions not asked.

    Empty for a report that states none, so a stored report renders as it did.
    """
    rows = report.enrichment_not_asked or []
    if not rows:
        return []
    listed = "; ".join(
        f"{row.kind} {_code_span(defang(row.value, row.kind))} ({', '.join(row.questions) or '-'})"
        for row in rows
    )
    caps = sorted({row.cap for row in rows})
    return [
        f"_Post-hoc enrichment did not ask about {len(rows)} network "
        f"value{'s' if len(rows) != 1 else ''}: the per-kind lookup cap "
        f"({', '.join(str(c) for c in caps)}, setting enrichment_max_lookups) was reached. "
        f"A missing reputation, ASN or geography on them is not asked, not clean. "
        f"Not asked: {listed}._",
        "",
    ]


def _title_heading(title: str) -> str:
    """The report's H1: its title, on one line."""
    return f"# {_one_line(title)}"


def _claims_not_discussed_lines(report: MalwareReport, ctx: _Context) -> list[str]:
    """The claims in force whose code the body does not name, each whole, with what it lacks."""
    from malspark.reporting.claim_coverage import COVERAGE_RULE, carried_sentence, claim_label
    from malspark.schemas.isr_models import retry_added_marker

    rows = list(getattr(report, "claims_not_discussed", None) or [])
    if not rows:
        return []
    lines = ["", _subheading("13.1", CLAIMS_NOT_DISCUSSED_TITLE, MEASURED), "", COVERAGE_RULE, ""]
    # A claim a revision carried forward unwritten is counted per analyst,
    # not listed: each is in the run summary and the evidence bundle.
    carried: dict[str, list[int]] = {}
    listed = []
    for row in rows:
        since = getattr(row, "carried_since_round", None)
        if isinstance(since, int) and not isinstance(since, bool):
            carried.setdefault(row.agent, []).append(since)
        else:
            listed.append(row)
    for agent, rounds in carried.items():
        lines.append(
            _item(
                f"**{ctx.plain(agent)}**: {len(rounds)} claim{'s' if len(rounds) != 1 else ''} "
                f"carried forward unwritten by a revision (from round {min(rounds)}) "
                f"{'is' if len(rounds) == 1 else 'are'} not discussed in the body; each is "
                "listed in the evidence bundle."
            )
        )
    for row in listed:
        stated = (
            f"confidence {row.confidence:.2f}; " if isinstance(row.confidence, int | float) else ""
        )
        evidence = f" Evidence: {row.evidence_ref}" if row.evidence_ref.strip() else ""
        retried = getattr(row, "added_by_retry_in_round", None)
        added = f"{retry_added_marker(retried)}; " if isinstance(retried, int) else ""
        # A claim mapped to several techniques is one claim: its ids together.
        # Each id carries the note the ATT&CK table prints beside it.
        ids = list(getattr(row, "technique_ids", None) or [])
        unverified = set(getattr(row, "unverified_technique_ids", None) or [])
        kept = set(getattr(row, "absence_kept_technique_ids", None) or [])
        written = []
        for tid in ids:
            notes = [UNVERIFIED_TECHNIQUE_MARKER] if tid in unverified else []
            notes += [ABSENCE_TECHNIQUE_MARKER] if tid in kept else []
            shown = _inline_safe(tid, plain=ctx.plain)
            written.append(f"{shown} ({'; '.join(notes)})" if notes else shown)
        mapped = f"technique{'s' if len(ids) > 1 else ''} {', '.join(written)}; " if ids else ""
        # The names the body never names are read off the claim: each is a value
        # in the platform's sentence, written as the ids beside it are.
        found = carried_sentence(row, name=lambda held: _inline_safe(held, plain=ctx.plain))
        lines.append(
            _item(
                f"**{claim_label(row.agent, row.claim_number)}** ({added}{mapped}{stated}"
                f"{found}): {ctx.plain(row.claim)}{ctx.plain(evidence)}"
            )
        )
    return lines


# The heading of the list of claims in force the body does not discuss.
CLAIMS_NOT_DISCUSSED_TITLE = "Claims whose code locations or API names the body does not name"


def _attck_detection_block(report: MalwareReport) -> str:
    """ATT&CK's own detection strategies and data components for the published techniques."""
    rows = [r for r in report.attck_defense if r.detection_strategies or r.data_components]
    if not rows:
        return ""
    lines = [
        _subheading("10.4", "ATT&CK detection data", REFERENCE),
        "",
        f"_ATT&CK's own detection strategies and the data components they read{_release(report)}, "
        "for each technique this report publishes; the evidence is what the technique rests "
        "on in this run._",
        "",
        _row("Technique", "Detection strategies", "Data components", "Evidence"),
        _divider(4),
    ]
    for row in rows:
        lines.append(
            _row(
                _technique_cell(row),
                _links_cell(row.detection_strategies),
                _links_cell(row.data_components),
                evidence_words(row.evidence_ids, row.sandbox_items, row.absence_sources),
            )
        )
    return "\n".join(lines)


def _attck_mitigation_block(report: MalwareReport) -> str:
    """ATT&CK's own mitigations for the published techniques."""
    rows = [r for r in report.attck_defense if r.mitigations]
    if not rows:
        return ""
    lines = [
        "**ATT&CK mitigations** · _" + REFERENCE + "_",
        "",
        f"_ATT&CK's own mitigations{_release(report)} for each technique this report publishes; "
        "the evidence is what the technique rests on in this run._",
        "",
        _row("Technique", "Mitigation", "How it applies", "Evidence"),
        _divider(4),
    ]
    for row in rows:
        for link in row.mitigations:
            lines.append(
                _row(
                    _technique_cell(row),
                    _link_label(link),
                    link.text or "-",
                    evidence_words(row.evidence_ids, row.sandbox_items, row.absence_sources),
                )
            )
    return "\n".join(lines)


def _release(report: MalwareReport) -> str:
    version = _one_line(report.attck_defense_version)
    return f" (ATT&CK {version})" if version else ""


def _technique_cell(row: Any) -> str:
    return f"{row.technique_id} {row.technique_name}".strip()


def _link_label(link: Any) -> str:
    return f"{link.attck_id} {link.name}".strip()


def _links_cell(links: Iterable[Any]) -> str:
    return "; ".join(_link_label(link) for link in links) or "-"


def _heading(number: int, title: str, voice: str) -> str:
    """An H2 with its section number and its voice tag."""
    return f"## {number}. {_one_line(title)} · _{voice}_"


# A line that would open a list or draw a rule, read after its other openers
# are escaped (:func:`_paragraph_line`).
_LIST_OPENER = re.compile(r"^([-+*])(?![^ \t])")
_ORDERED_OPENER = re.compile(r"^(\d{1,9})([.)])(?![^ \t])")
# Each "#" of a heading's text, to be escaped so a trailing run of them cannot
# close the heading.
_HEADING_HASH = re.compile(r"(?=#)")
_THEMATIC_BREAK = re.compile(r"^([-_*])(?:[ \t]*\1){2,}[ \t]*$")


def _paragraph_line(text: str) -> str:
    """One paragraph of text already escaped as inline text, on one line, opening no block.

    The answer a model writes to a question: its line breaks become spaces and
    its indent goes, so no line of it can start a code block; a heading, a
    fence, a quote, a setext underline or a table row is escaped
    (:func:`_escape_block`), and so is a leading list marker, a numbered-list
    opener and a thematic break.
    """
    line = _escape_block(_one_line(text).strip())
    if _THEMATIC_BREAK.match(line):
        return "\\" + line
    line = _LIST_OPENER.sub(r"\\\1", line)
    return _ORDERED_OPENER.sub(r"\1\\\2", line)


def _lead_heading(title: str, voice: str) -> str:
    """An unnumbered H2 before §1, with its voice tag."""
    return f"## {_one_line(title)} · _{voice}_"


# The line the "Questions asked of this run" section opens with.
QUESTIONS_NOTE = (
    "_The analyst's questions, each answered from this run's evidence with one outcome: "
    "established, partial, limited negative, not determinable from this run, out of scope. "
    "The platform checks each answer: it refuses established with no answered entry cited "
    "and limited negative with no record of what was looked at, and an open question is "
    "never read as an absence._"
)


def _appendix_heading(letter: str, title: str, voice: str) -> str:
    """An appendix's H2, lettered, with its voice tag."""
    return f"## Appendix {letter}. {_one_line(title)} · _{voice}_"


def stored_report_id(report: Any) -> Any:
    """The stored report's id, as the seal the stored report carries names it.

    The worker stores the seal at the top of the report (``report.ledger_seal``);
    a seal in the run summary is read next, and a report with no seal reads the
    run summary's own ``report_id``, as it always did (``None`` where it holds
    none).
    """
    summary = getattr(report, "run_summary", None) or {}
    for seal in (getattr(report, "ledger_seal", None), summary.get("ledger_seal")):
        if isinstance(seal, dict) and seal.get("report_id"):
            return seal["report_id"]
    return summary.get("report_id")


def _ledger_seal_lines(report: Any) -> list[str]:
    """The stored ledger's seal as one line, with the amendments after it; none without a seal.

    A report stored before sealing existed has no seal and prints nothing here,
    so it renders as it always did.
    """
    seal = getattr(report, "ledger_seal", None)
    if not isinstance(seal, dict) or not seal.get("head"):
        return []
    span = (
        f" (seq {seal.get('first_seq')} to {seal.get('last_seq')})"
        if seal.get("first_seq") is not None
        else ""
    )
    key = f"key {_code_span(str(seal['key_id']))}" if seal.get("key_id") else "no key"
    line = (
        f"_Ledger seal: chain head {_code_span(str(seal['head']))} over {seal.get('entries', 0)} "
        f"entr{'y' if seal.get('entries') == 1 else 'ies'}{span}, {key}; "
        f"seal digest {_code_span(str(seal.get('digest', '')))}."
    )
    amendments = getattr(report, "ledger_amendments", None) or []
    if amendments:
        last = amendments[-1] if isinstance(amendments[-1], dict) else {}
        line += (
            f" Amended {len(amendments)} time{'' if len(amendments) == 1 else 's'} "
            f"since; last amendment digest {_code_span(str(last.get('digest', '')))}."
        )
    return [line + "_", ""]


def _subheading(number: str, title: str, voice: str) -> str:
    """An H3 with its subsection number and its voice tag."""
    label = f"{number} {title}" if number else title
    return f"### {_one_line(label)} · _{voice}_"


# The line the "Open questions" section is printed under in Appendix A.
OPEN_QUESTIONS_NOTE = (
    "_What the analysts said they could not establish, why, and what would answer it: "
    "unknowns, not absences. No measured table, count or published value reads them._"
)


def _evidence_heading(section: Any, plain: Callable[[str], str] = _defanged_text) -> str:
    """An Appendix A section's H3 with its voice: a tool's is Measured, an analyst's Assessed.

    The title is a tool's or an analyst's words, written by the inline rule.
    """
    source = str(getattr(section, "source", "") or "").strip().lower()
    assessed = source.startswith(ANALYST_SECTION_SOURCES) or is_open_question_section(section)
    voice = ASSESSED if assessed else MEASURED
    return f"{_plain_heading(_inline_safe(section.title, plain=plain))} · _{voice}_"


# Where the indicator section holds a value an analyst's table gives (:func:`_typed_values_shown`).
_AS_THE_ANALYSTS = "analyst"
_UNDER_ANOTHER_SOURCE = "other"
_NOT_IN_THE_SECTION = "absent"


def _typed_values_shown(section: Any, kind: str, ctx: _Context) -> list[set[str]] | None:
    """For an analyst's table of values, one entry per row of the table: where the indicator
    section's tables hold the values the row gives, read as the report builder reads the
    table (``listed_non_network_values``, ``kept_network_values``) — as the analyst's row,
    under another source, or not at all — and an empty set for a row that gives none (a row
    the reading of a merged table does not read among them). ``None`` for any other table
    (C15: the line counts the table's rows)."""
    from malspark.reporting.ledger_projection import kept_network_values, listed_non_network_values
    from malspark.reporting.ledger_report import listed_headings, listed_rows

    if listing_kind(kind) != "values":
        return None
    headings = listed_headings(section)
    cells = [row for _analyst, _cited, row in listed_rows(section)]

    def key(value: Any) -> str:
        return str(value or "").strip().lower().rstrip(".")

    sources: dict[str, set[str]] = {}
    for row in ctx.iocs:
        sources.setdefault(key(row.value), set()).add(str(row.source or ""))
    ta = ctx.report.technical_analysis
    for item in ta.host_identifiers if ta is not None else []:
        sources.setdefault(key(item.value), set()).add("")
    places: list[set[str]] = []
    for listed in cells:
        values = [value for _kind, value, _p in listed_non_network_values(kind, [listed], headings)]
        table = SimpleNamespace(kind=kind, rows=[listed], columns=headings, value=None)
        values += [value for _kind, value in kept_network_values(table)]
        places.append(
            {
                _AS_THE_ANALYSTS
                if "analyst" in sources.get(k, ())
                else _UNDER_ANOTHER_SOURCE
                if k in sources
                else _NOT_IN_THE_SECTION
                for k in (key(value) for value in values)
                if k
            }
        )
    unread = len(getattr(section, "rows", None) or []) - len(cells)
    return places + [set() for _ in range(max(unread, 0))]


def analyst_list_note(
    analysts: list[str], kind: str = "", typed: list[set[str]] | None = None
) -> str:
    """The line an analyst's table is printed under in Appendix A, saying where else it is shown.

    ``typed`` gives, for each row of a table of values, where the indicator section holds the
    values the row gives (:func:`_typed_values_shown`). Where every value is the analyst's row
    there, the line says so; where the report reads none, it says so; otherwise it counts the
    table's rows, each by where its values are (C15): two numbers in one sentence are counts
    over the same rows."""
    who = ", ".join(f"the {_one_line(name)} analyst" for name in analysts)
    indicators = section_reference(INDICATORS_TITLE)
    values = (
        f" Each value it types as an indicator is in {indicators} as the analyst's, with the "
        "publish rule's answer."
    )
    if typed is not None and not any(typed):
        # Read as the builder reads it, the table gives no value: nothing is
        # said of where its values are.
        values = " The report reads no value of it as an indicator."
    elif typed is not None and any(row - {_AS_THE_ANALYSTS} for row in typed):
        cases = [
            (
                {_AS_THE_ANALYSTS},
                f"only values in {indicators} as the analyst's, with the publish rule's answer",
            ),
            ({_UNDER_ANOTHER_SOURCE}, f"only values in {indicators} under another source"),
            ({_NOT_IN_THE_SECTION}, f"only values not in {indicators}"),
        ]
        mixed = (
            f"values of more than one kind: in {indicators} as the analyst's, in {indicators} "
            f"under another source, or not in {indicators}"
        )
        counted = [(sum(1 for row in typed if row == held), said) for held, said in cases]
        counted.append((sum(1 for row in typed if len(row) > 1), mixed))
        counted.append(
            (sum(1 for row in typed if not row), "no value the report reads as an indicator")
        )
        values = (
            f" Its one row gives {next(said for n, said in counted if n)}."
            if len(typed) == 1
            else f" Of its {len(typed)} rows, "
            + "; ".join(f"{n} {'gives' if n == 1 else 'give'} {said}" for n, said in counted if n)
            + "."
        )
    shown = {
        "persistence": f" Its rows are in {section_reference('Persistence')} under Assessed, "
        f"and its Run keys, tasks and services in {section_reference(INDICATORS_TITLE)} as "
        "the analyst's, each with the publish rule's answer.",
        "values": values,
    }
    where = shown.get(listing_kind(kind), "")
    return (
        f"_Listed by {who}: a model's table, not a tool's output.{where} No measured table, "
        "count, rule match or capability profile reads it._"
    )


def _plain_heading(title: Any) -> str:
    """An unnumbered H3 on one line, each ``#`` of its title escaped.

    The title is written by its caller (a value by the inline rule); a
    trailing run of ``#`` would otherwise close the heading and not be shown.
    """
    return "### " + _HEADING_HASH.sub("\\\\", _one_line(title))


def _item(text: Any) -> str:
    """One list item, on one line, opening no block whatever its text begins with.

    The list counterpart of :func:`_row`: a newline in a value from the
    sample, a tool or a model would end the item and could start a heading
    or a fence on the next line, and a value at the item's start would open a
    rule, a nested list, a heading, a quote or a code block. The text is
    written by its caller (a value by the inline rule) and here by the
    block-start rule (:func:`_paragraph_line`). A model's line keeps its own
    writing (:func:`_prose_item`). Every bullet in this renderer is built
    here, and ``test_a_list_item_is_never_assembled_by_hand`` fails the build
    if a new one is not.
    """
    return f"- {_paragraph_line(text)}"


def _step(number: int, text: Any) -> str:
    """One numbered step, on one line, opening no block (:func:`_item`)."""
    return f"{number}. {_paragraph_line(text)}"


def _prose_item(text: Any) -> str:
    """One list item that begins with a model's line: on one line, its quote opener escaped.

    A model's line keeps the writing the recorded reading gives model prose;
    only the line break and the quote opener are the item's.
    """
    return f"- {_unquoted(_one_line(text))}"


def _prose_step(number: int, text: Any) -> str:
    """One numbered step that begins with a model's line (:func:`_prose_item`)."""
    return f"{number}. {_unquoted(_one_line(text))}"


# A ``>`` that opens a block quote: at the start of a line, after any run of
# whitespace and list markers ("- ", "* ", "+ ", "1. ", "2) ", a tab after one).
_QUOTE_OPENER = re.compile(r"^[ \t]*(?:(?:[-+*]" + _PIPE + r"\d{1,9}[.)])[ \t]+)*(?=>)")


def _unquoted(line: str) -> str:
    """A line with the ``>`` that would open a block quote escaped, after any list markers.

    The HTML report draws a block quote as its degraded-run callout, so a value
    written into an item or a paragraph could otherwise draw one, nested in a
    list item ("- > …", "1. > …", "- - > …") as well as at the line's start.
    """
    found = _QUOTE_OPENER.match(line)
    return line if found is None else line[: found.end()] + "\\" + line[found.end() :]


def _absent_subsection(number: str, title: str, line: str) -> str:
    """A numbered subsection with nothing in this run: its heading and one line."""
    return "\n".join([_subheading(number, title, MEASURED), "", line])


def _escape_block(text: str) -> str:
    """A paragraph whose lines cannot open a heading, a code fence or a table.

    Five shapes restructure a document from inside a paragraph: an ATX heading
    (``#``), a code fence, a block quote (``>``, which the HTML report draws as
    its degraded-run callout), a setext underline — a line of only ``=`` or ``-``
    turns the line above it into an H1 or H2, which the HTML renderer would
    then list in its contents with no voice tag — and a table's delimiter row,
    which turns the lines around it into a table. A backslash in front of the
    line's first character makes each of them text.
    """
    # What opens a heading or a code fence at the start of a Markdown line; a
    # block quote's ``>`` is escaped after any list markers (:func:`_unquoted`).
    # A run of backticks opens a fence only where no backtick follows it on the
    # line: otherwise it opens a code span, which an escape would break.
    openers = ("#", "~~~")
    out: list[str] = []
    for line in str(text or "").splitlines():
        body = line.lstrip()
        fence = _BACKTICK_FENCE.match(body)
        if (
            body.startswith(openers)
            or (fence is not None and "`" not in body[fence.end() :])
            or _is_setext_underline(body)
            or _is_delimiter_row(body)
        ):
            line = line[: len(line) - len(body)] + "\\" + body
        out.append(_unquoted(line))
    return "\n".join(out)


# The run of three or more backticks a fence opens with.
_BACKTICK_FENCE = re.compile(r"`{3,}")


def _is_setext_underline(line: str) -> bool:
    """Whether a line is only ``=`` or only ``-``: it would underline the line above."""
    return set(line.strip()) in ({"="}, {"-"})


def _is_delimiter_row(line: str) -> bool:
    """Whether a line is a table's delimiter row: dashes, optional colons, pipes."""
    cells = r"\s*:?-+:?\s*"
    return bool(
        re.match(rf"^\|?{cells}(?:\|{cells})+\|?\s*$", line) or re.match(rf"^\|{cells}\|\s*$", line)
    )


# A token :meth:`_Context.keep` hands out.
_KEPT_TOKEN_RE = re.compile(r"\x00[0-9a-f]{16}k\d+\x00")


def _fenced(text: str, info: str = "") -> list[str]:
    """``text`` in a code fence longer than any backtick run inside it."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}{info}", text, fence]


def _ids(ids: Iterable[Any]) -> str:
    """Evidence ids, comma-separated, each on the line it is printed on."""
    return ", ".join(_one_line(i) for i in ids if str(i).strip())


def _cite(ids: Iterable[str]) -> str:
    listed = _ids(ids)
    return f"[{listed}]" if listed else _NO_CITATION


def _cited(text: str, ids: Iterable[str], written: str) -> str:
    """``text`` with the entries of ``ids`` its words (``written``) do not cite printed after it.

    A report model writes its citations into a bullet and lists them again
    beside it; printed twice, every bullet cited each entry twice. An entry
    the words already cite is not printed again, a text citing every one gets
    nothing after it, and a text citing none gets them all, or the note that
    nothing is cited. The words are read as the model wrote them, so an entry
    a mark beside them names is no citation of theirs. They are not changed.
    """
    cited = set(_EV_RE.findall(written))
    rest = [i for i in ids if str(i).strip() and _one_line(i).strip() not in cited]
    if cited and not rest:
        return text
    return f"{text} {_cite(rest)}"


def _ids_in(texts: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(match for text in texts for match in _EV_RE.findall(str(text))))


def _subsection(
    number: str,
    title: str,
    prose: list[TechnicalSubsection | None],
    measured: list[str],
    ctx: _Context,
    *,
    absent: str,
) -> str:
    """One capability subsection: the model's prose, then the tables that prove it.

    A subsection with neither prints ``absent``, the one line that says why.
    The prose is the report model's and is printed as written, defanged, with
    its citations after it; a subsection whose prose cites nothing says so
    once. A subsection holding both prose and tables is tagged "Source per
    row" and labels its prose the way each table is labelled.
    """
    parts = [sub for sub in prose if sub is not None and sub.body.strip()]
    if not parts and not measured:
        return _absent_subsection(number, title, absent)
    voice = PER_ROW if parts and measured else REPORT_MODEL if parts else _voice_of(measured)
    lines = [_subheading(number, title, voice), ""]
    if parts and measured:
        lines.extend([f"_{REPORT_MODEL}:_", ""])
    for sub in parts:
        body = sub.body.strip()
        lines.append(ctx.prose(body))
        lines.append("")
        lines.append(_cite(sub.evidence_refs))
        if not sub.evidence_refs and not _EV_RE.search(body):
            lines.extend(["", _UNCITED_NOTE])
        lines.append("")
    lines.extend(measured)
    return "\n".join(lines).rstrip()


def _voice_of(measured: list[str]) -> str:
    """The voice of a subsection that holds tables only: the first one's label."""
    for line in measured:
        for voice in (OBSERVED, MEASURED, REPORT_MODEL, PER_ROW):
            if line.startswith(f"_{voice}:_"):
                return voice
    return MEASURED


# How much of a ransom note's verbatim text the report prints before saying so.
_NOTE_LIMIT = 4000


# What a model writes in a field it has nothing for. A field holding one of
# these carries no content, and a block made only of them is not printed.
_PLACEHOLDERS = frozenset(
    {"", "none", "unknown", "n/a", "na", "null", "-", "not applicable", "not found", "no data"}
)


def _said(value: Any) -> Any:
    """A model-written value, or ``None`` when it is a placeholder for nothing."""
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in _PLACEHOLDERS:
        return None
    return value


def _encrypts_files(enc: Any) -> bool:
    """Whether the scheme the model wrote is a file-encryption one.

    The ransomware block is family-specific: a file marker, an extension, a
    partial-encryption threshold or a per-file key make it one. A loader's
    string or traffic cipher is not, and prints beside the anti-analysis prose.
    ``per_file_key: false`` says the model saw no per-file key, which names no
    file encryption; only ``true`` does.
    """
    return bool(
        _said(enc.file_marker)
        or _said(enc.extension)
        or _said(enc.partial_threshold)
        or enc.per_file_key is True
    )


def _encryption_table(enc: Any, ctx: _Context) -> list[str]:
    """The scheme the model wrote, the fields it filled only, or nothing. A field the
    agreement question left no sentence of prints "-", not nothing (T-600)."""
    rows = [
        ("Cipher", "cipher", enc.cipher),
        ("Mode", "mode", enc.mode),
        ("Library", "library", enc.library),
        ("Key source", "key_source", enc.key_source),
        ("Key management", "key_management", enc.key_management),
        ("IV", "iv", enc.iv),
        ("File marker", "file_marker", enc.file_marker),
        ("Extension", "extension", enc.extension),
        ("Partial-encryption threshold", "partial_threshold", enc.partial_threshold),
        (
            "Per-file key",
            "per_file_key",
            None if enc.per_file_key is None else ("yes" if enc.per_file_key else "no"),
        ),
    ]
    present = [
        (label, value if _said(value) else "-")
        for label, field, value in rows
        if _said(value) or ctx.left_out(f"encryption_scheme.{field}")
    ]
    if not present:
        return []
    out = [f"_{REPORT_MODEL}:_ encryption scheme", "", _row("Property", "Value"), _divider(2)]
    out.extend(_row(label, ctx.cell(value)) for label, value in present)
    out.append(
        _row(
            "Evidence",
            (_said(enc.evidence_ref) or "no evidence cited") + ctx.cited_row_mark(enc),
        )
    )
    return out


# The technique a ransomware verdict publishes: Data Encrypted for Impact.
_RANSOMWARE_TECHNIQUE = "T1486"


def _states_ransomware(report: MalwareReport) -> bool:
    """Whether the run's own verdict says ransomware: the report publishes Data
    Encrypted for Impact.

    The judge's category is free text ("loader (delivers ransomware)", "loader,
    not ransomware") and says nothing a word in it can be read for. What the
    report model wrote in its encryption table does not say it either: a
    loader's string cipher fills the same fields, and a model filling "none"
    into them is still writing.
    """
    return any(
        str(row.technique_id).strip().upper().split(".")[0] == _RANSOMWARE_TECHNIQUE
        for row in report.ttp_mappings
    )


def _ransomware_block(ta: Any, ctx: _Context, *, ransomware: bool) -> str:
    lines: list[str] = []
    spk = ta.service_process_kill
    if spk is not None and (spk.kill_list or spk.white_list or spk.mechanism):
        lines.extend(["Services and processes terminated:", ""])
        if spk.mechanism:
            lines.append(_item(f"Mechanism: {ctx.line(spk.mechanism)}"))
        if spk.kill_list:
            lines.append(
                _item("Kill list: " + ", ".join(_code_span(ctx.plain(x)) for x in spk.kill_list))
            )
        if spk.white_list:
            # The exclusions are often the more identifying half: a list that
            # spares the attacker's own tooling names it.
            lines.append(
                _item("Spared: " + ", ".join(_code_span(ctx.plain(x)) for x in spk.white_list))
            )
        lines.append("")
    if ta.shadow_copy_destruction:
        lines.extend(["Shadow copy destruction:", ""])
        lines.extend(_item(_code_span(ctx.plain(cmd))) for cmd in ta.shadow_copy_destruction)
        lines.append("")
    enc = ta.encryption_scheme
    if enc is not None and _encrypts_files(enc):
        lines.extend(_encryption_table(enc, ctx))
        lines.append("")
    note = ta.ransom_note
    if note is not None and (note.filename or note.verbatim_content or note.sections):
        lines.extend(["Ransom note:", ""])
        if note.filename:
            lines.extend([f"Filename: {_code_span(_one_line(note.filename))}", ""])
        if note.company_id_hash:
            lines.extend([f"Victim/company ID: {_code_span(_one_line(note.company_id_hash))}", ""])
        if note.verbatim_content:
            # Fenced, not inlined: note text routinely contains markdown
            # characters and onion URLs, and the verbatim wording is what
            # links one incident to another.
            verbatim = note.verbatim_content.strip()
            lines.extend([*_fenced(verbatim[:_NOTE_LIMIT], "text"), ""])
            if len(verbatim) > _NOTE_LIMIT:
                lines.extend(
                    [
                        f"_The note is cut here at {_NOTE_LIMIT:,} of its {len(verbatim):,} "
                        "characters; the JSON report carries it whole._",
                        "",
                    ]
                )
        elif note.sections:
            lines.extend(_prose_item(ctx.line(part)) for part in note.sections)
            lines.append("")
    if not lines:
        return ""
    # The heading names ransomware only when the verdict does; a loader's
    # cipher table under it read as a ransomware finding.
    title = "Ransomware behaviour" if ransomware else "Family-specific behaviour"
    return "\n".join([_subheading("5.9", title, REPORT_MODEL), "", *lines]).rstrip()


def report_title(report: MalwareReport, write: Callable[[str], str] = str) -> str:
    """``<Family> <category> analysis`` when the judge named a family with evidence.

    A family the judge named without citing anything is often a placeholder
    label ("generic packed malware") and does not title the report; neither
    does one only a sandbox's classification named. ``write`` writes the
    sample's format where the title names it (:func:`_titled_format`).
    """
    attr = report.attribution
    family = stated_family(_one_line(attr.family))
    named = attr.family_source != "sandbox" and bool(attr.family_evidence_ids)
    if family and named:
        category = _one_line(report.malware_category).strip()
        if category and category.lower() != "unknown":
            return f"{family} {category} analysis"
        return f"{family} analysis"
    sha = (report.identity.hashes.sha256 or "unknown")[:12]
    fmt = _one_line(report.identity.file_type).strip()
    # A format tag is an acronym ("pe", "elf") however the identity spelled it.
    fmt = fmt.upper() if len(fmt) <= 6 else fmt
    if fmt and fmt != "unknown":
        return f"{write(fmt)} sample {sha} analysis"
    return f"Sample {sha} analysis"


def _titled_format(plain: Callable[[str], str]) -> Callable[[str], str]:
    """How a heading writes the sample's format: by the inline rule, each ``#`` escaped."""
    return lambda text: _HEADING_HASH.sub("\\\\", _inline_safe(text, plain=plain))


def _verdict_voice(report: MalwareReport) -> str:
    """Who gave the verdict: the judge, or nobody when no verdict stage ran."""
    return NOT_ASSESSED if report.verdict_not_assessed else JUDGE


def _verdict_words(report: MalwareReport) -> str:
    if report.verdict_not_assessed:
        # The schema's placeholder is not printed: no stage reached a verdict.
        return f"not assessed ({_one_line(report.verdict_not_assessed)})"
    return f"{report.verdict} ({confidence_phrase(report.overall_confidence, 'the judge')})"


def _family_words(report: MalwareReport) -> str:
    attr = report.attribution
    family = _one_line(attr.family)
    if not family or family.lower() == "unknown":
        return "none attributed"
    if attr.family_source == "sandbox":
        return f"{family} ({family_qualifier(attr)})"
    said = f"{family} ({confidence_phrase(attr.family_confidence, 'the judge')})"
    if attr.family_evidence_ids:
        said += f" [{_ids(attr.family_evidence_ids)}]"
    elif not attr.family_grounded:
        said += f" ({family_qualifier(attr)})"
    return said


def family_qualifier(attr: Any) -> str:
    """Who named a family where the report head qualifies it, or ``""``.

    A family the sandbox's own classification named, the judge naming none,
    with the sandbox's note; a judge family with no evidence cited. A judge
    family with cited evidence is not qualified. The report head and the HTML
    header card both say it in these words.
    """
    if attr.family_source == "sandbox":
        note = f"; {_one_line(attr.family_note)}" if attr.family_note else ""
        return f"named by the sandbox's own classification; the judge named none{note}"
    if not attr.family_evidence_ids and not attr.family_grounded:
        return "no evidence cited"
    return ""


def _verdict_line(report: MalwareReport) -> str:
    severity = report.severity.rating if report.severity else "not assessed"
    return (
        f"**Verdict:** {_verdict_words(report)} · **Severity:** {severity} · "
        f"**Family:** {_family_words(report)}"
    )


def _reputation_line(report: MalwareReport) -> str:
    """The sample's own reputation lookup, as the tool answered it, or that there was none."""
    entries = [row for row in report.evidence_index if tool_kinds.is_of(row, _REPUTATION_TOOLS)]
    if not entries:
        return "no reputation lookup in this run"
    ids = {row.id for row in entries}
    # Each tool named once before its entries: four lookups of one sample are
    # four ids, not four repetitions of the tool's name.
    by_tool: dict[str, list[str]] = {}
    for lookup in entries:
        by_tool.setdefault(lookup.tool, []).append(lookup.id)
    # A tool's name is the tool's text, by the inline rule; the row keeps its separator.
    where = ", ".join(
        f"{_inline_safe(tool, pipes=False)}, {', '.join(named)}" for tool, named in by_tool.items()
    )
    rows: dict[str, str] = {}
    for section in report.sections:
        if not ids.intersection(section.evidence_ids) or section.kind != "kv":
            continue
        for row in section.rows:
            if len(row) >= 2:
                rows.setdefault(str(row[0]).strip().lower(), str(row[1]))
    if report.reputation is not None:
        # The records each lookup's declaration read from its answer
        # (``core.reputation``), from any server, named by the service the
        # declaration names.
        answers = [answer for answer in report.reputation if answer.entry_id in ids]
        counted = next(
            (a for a in answers if a.malicious is not None and a.engine_count() is not None),
            None,
        )
        if counted is not None:
            # Each count under the record's name for it, never a fraction
            # (:func:`counts_line`). The service's name, a member's name and the
            # date are its answer's words: escaped and defanged; the row escapes
            # the table separator itself (:func:`_cell`).
            said = counts_line(counted, written=lambda text: _inline_safe(text, pipes=False))
            when = _inline_safe(counted.last_seen, pipes=False) if counted.last_seen else ""
            return said + (f" (analysis {when}; {where})" if when else f" ({where})")
        flagged = next((a for a in answers if a.malicious is not None), None)
        if flagged is not None:
            service = _inline_safe(flagged.service or "Reputation lookup", pipes=False)
            said = f"{service}: {flagged.malicious} engines flag it as malicious"
            return f"{said} ({where})"
    else:
        # A report stored before the records: its section rows, as it was read.
        flagged_count, engines, source = tool_kinds.stored_reputation_counts(rows)
        if flagged_count and engines:
            dated = rows.get("analysis date")
            when = _inline_safe(dated, pipes=False) if dated else ""
            named = _inline_safe(source, pipes=False)
            said = f"{named}: {flagged_count} of {engines} engines flag it as malicious"
            return said + (f" (analysis {when}; {where})" if when else f" ({where})")
    facts = [f"{k} {v}" for k, v in rows.items() if k in _REPUTATION_KEYS]
    return f"{where}: {'; '.join(facts)}" if facts else f"{where}; see Appendix A"


def _environment_line(report: MalwareReport) -> str:
    """What the sandbox ran the sample in, as the sandbox's own report recorded it."""
    keys = ("machine", "platform", "os", "duration", "package", "options", "route", "timeout")
    facts: list[str] = []
    for section in report.sections:
        if not section.key.startswith("sandbox_") or section.kind != "kv":
            continue
        for row in section.rows:
            if len(row) >= 2 and str(row[0]).strip().lower() in keys:
                facts.append(f"{row[0]} {row[1]}")
    if facts:
        return "Environment: " + "; ".join(facts) + "."
    return "Environment: the sandbox's own report recorded no environment details in this run."


def _model_line(snapshot: Any) -> str:
    """The provider and model the run used, from its settings snapshot."""
    if not isinstance(snapshot, dict):
        return ""
    llm = snapshot.get("llm")
    if not isinstance(llm, dict):
        return ""
    provider = str(llm.get("provider") or "").strip()
    block = llm.get(provider) if provider else None
    model = str(block.get("model") or "").strip() if isinstance(block, dict) else ""
    return f"{provider} {model}".strip()


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def _names_any(text: str, words: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


def _endpoint_with_state(value: str, ctx: _Context) -> str:
    """An endpoint as :func:`_endpoint` writes it, with the IOC table's state where it adds one.

    An endpoint already marked as no host outside could answer keeps that
    mark alone.
    """
    written = _endpoint(value)
    return written + ctx.publish_state(value) if written.endswith("`") else written


def _endpoint(value: str) -> str:
    """One model-written endpoint, defanged, and marked with the rule's reason where it refuses it.

    Read by its form first (:func:`path_or_host_form`): a name on the analysed
    machine (a device or pipe name, a local file, a registry path) names no
    host and prints as written, with no mark; a network path keeps its host
    defanged in place and asks the mark of that host; a URL written with
    backslashes prints as written, defanged as a URL, its host read from the
    URL its forward slashes spell. Any other value is read as a host.
    """
    from malspark.extractors.network_extractor import (
        address_is_publishable,
        host_failure,
        url_failure,
        url_host,
    )

    text = str(value or "").strip()
    if not text:
        return ""
    form = path_or_host_form(text)
    if form.form in NO_HOST_FORMS:
        return _code_span(text)
    url = ""
    if form.host or form.form == FORM_URL:
        host = form.host
        url = text.replace("\\", "/") if form.form == FORM_URL else ""
        start, end = form.at
        if form.form == FORM_URL:
            # The scheme renamed and the authority's dots bracketed, as the URL
            # its forward slashes spell is written; its separators as written.
            twin = defang(f"{text[: text.index(':')]}://{text[start:end]}", "url")
            head = twin.replace("://", text[text.index(":") : start], 1)
        else:
            head = text[:start] + defang(text[start:end], "ip" if _is_address(host) else "domain")
        written = _code_span(head + text[end:])
    else:
        if "://" in text:
            kind, host, url = "url", url_host(text), text
        elif _is_address(text):
            kind, host = "ip", text
        else:
            kind, host = "domain", text.split("/", 1)[0].split(":", 1)[0]
        written = _code_span(defang(_whole(text), kind))
    if _is_address(host):
        # The publish rule's own question, asked of an address a model wrote:
        # a private or reserved one is nothing a consumer could act on.
        if not address_is_publishable(host, ""):
            return f"{written} (not an address this run may publish)"
        return written
    # The rule's own reason, the URL's where a URL was read: the parser's, a
    # missing host's or its host's, and the host test's for a host.
    # Written into a table cell, whose row escapes the separator (:func:`_row`).
    failure = url_failure(url) if url else host_failure(host)
    if not failure:
        return written
    mark = failure if url else f"fails the host test: {failure}"
    return f"{written} ({_inline_safe(mark, pipes=False)})"


# What the purpose cell says when the report model gave none. A dash read as a
# cell nobody filled in; the model was asked for a purpose where the evidence or
# an analyst's claim states one, so an empty one is a purpose not stated.
PURPOSE_NOT_STATED = "not stated"
# What it says where the agreement question left the purpose the model wrote out (T-600).
PURPOSE_LEFT_OUT = "left out by the agreement question"


def _host_identifier_table(identifiers: list[Any], ctx: _Context) -> list[str]:
    """The identifiers the report model read, as it wrote them, each with its entries.

    The model's own table, under its own voice: the platform copies no string
    into it and publishes none of it. Host values are never defanged. A row
    the validator asked about and the model kept says so beside its evidence.
    A row whose whole value the IOC table publishes names the table of this
    section that does (:func:`_published_in`). Every row carries the one
    rule's answer for the value it states, asked under source ``analysis``
    (``stated_host_values.identifier_answers``): the IOC table holds a row for
    each one it publishes.
    """
    published = _published_in(ctx)
    answers = _identifier_answers(ctx)
    lines = [_subheading("", "Host identifiers read by the report model", REPORT_MODEL), ""]
    lines.append(_row("Kind", "Value", "Purpose", "Evidence", "Published"))
    lines.append(_divider(5))
    for index, item in enumerate(identifiers):
        cited = ", ".join(item.evidence_refs) or "no evidence cited"
        cited += _row_mark("report.identifier_uncited", ctx.identifier_findings.get(index + 1))
        cited += _row_mark("report.value_not_in_cited_entry", ctx.identifier_unheld.get(index + 1))
        cited += _row_mark(
            _INSIDE_A_TOKEN_CODE,
            ctx.identifier_inside.get(index + 1),
            shown=index + 1 not in ctx.identifier_run_unshown,
        )
        cited += ctx.cited_row_mark(item)
        where = published(item.value)
        lines.append(
            _row(
                ctx.cell(item.kind),
                _code_span(ctx.plain(_one_line(item.value)))
                + (f" (published in the {where} table)" if where else "")
                + ctx.publish_state(item.value),
                ctx.cell(item.purpose)
                if item.purpose.strip()
                else PURPOSE_LEFT_OUT
                if ctx.left_out(f"host_identifiers.{index + 1}")
                else PURPOSE_NOT_STATED,
                cited,
                ctx.plain(_identifier_published(answers, index, where)),
            )
        )
    lines.extend(
        [
            "",
            "_Read out of this run's evidence by the report model and cited to the entries it "
            "names. A value is exported only where the IOC table of this section publishes it: "
            "a row the platform found whole in an entry it cites, of a kind the export carries, "
            "created or written by the sample, and not a value every host holds, is published "
            "there as stated by the analysis; Published gives the answer for each row. The "
            "export and `/iocs` carry the IOC table's published rows._",
            "",
        ]
    )
    return lines


def _identifier_published(answers: list[str], index: int, where: str) -> str:
    """The Published cell of one identifier row: the rule's answer, or the table publishing it.

    A value a tool's row of the IOC table already publishes is published by
    that row, whatever the identifier row's own answer is.
    """
    from malspark.reporting.renderers.stix_renderer import publishes

    answer = answers[index] if index < len(answers) else ""
    if where and not publishes(answer):
        return f"yes: published by its row in the {where} table"
    return answer or "-"


def _identifier_answers(ctx: _Context) -> list[str]:
    """The rule's answer for each row of the report model's identifier table, in its order.

    ``yes:`` for a row the IOC table publishes in its own row, and the
    refusal with its reason for every other. Fails closed: a table that
    cannot be read answers no row.
    """
    from malspark.reporting.stated_host_values import identifier_answers

    try:
        return [answer for _stated, answer in identifier_answers(ctx.report)]
    except Exception as exc:  # noqa: BLE001 — the column says the answer is not known
        logger.debug("markdown: the identifier rows' answers were not read (%s).", exc)
        return []


def _published_in(ctx: _Context) -> Callable[[Any], str]:
    """``value -> the §9 table that publishes it whole``, or ``""`` when none does.

    Read off the IOC table's own answers, row by row, in the one spelling
    every lookup uses (``ledger_projection.value_key``): a value is marked
    only where a row holds it whole and that row's answer publishes. A table
    that could not be read marks nothing, and its cell states say why.
    """
    from malspark.reporting.ledger_projection import value_key
    from malspark.reporting.renderers.stix_renderer import publishes

    held: dict[tuple[str, str], str] = {}
    for row in ctx.iocs if ctx._table_read else []:
        kind = str(row.kind or "")
        if publishes(row.published):
            table = "Network indicators" if kind in _NETWORK_KINDS else "File and host indicators"
            held.setdefault((kind, value_key(kind, row.value)), table)
    kinds = sorted({kind for kind, _ in held})

    def _where(value: Any) -> str:
        text = _one_line(str(value or "")).strip()
        if not text:
            return ""
        for kind in kinds:
            table = held.get((kind, value_key(kind, text)))
            if table:
                return table
        return ""

    return _where


def _string_row_forms(report: MalwareReport, rows: list[ConsolidatedIOC]) -> dict[Any, str]:
    """The form rows of the IOC table and their printed types (``string_row_form``); ``{}`` unread.

    A table whose forms cannot be read prints each row's type as the table
    gives it.
    """
    from malspark.reporting.string_row_form import string_row_forms

    try:
        return string_row_forms(report, rows)
    except Exception as exc:  # noqa: BLE001 — the types are then printed as the table gives them
        logger.debug("markdown: the strings rows' forms were not read (%s).", exc)
        return {}


def _form_of(row: Any, forms: Mapping[Any, str]) -> str:
    """The printed type of a form row of the IOC table, ``""`` for any other row.

    ``row`` is a row of the table or a string of the file, read by its kind and
    value; a table row of another source than the file's strings has none.
    """
    from malspark.reporting.ledger_projection import value_key

    if not forms or str(getattr(row, "source", None) or "strings") != "strings":
        return ""
    kind = str(row.kind or "")
    return forms.get((kind, value_key(kind, row.value)), "")


def _port_or_path(row: ConsolidatedIOC, report: MalwareReport) -> str:
    if row.kind == "url":
        try:
            parsed = urlparse(row.value)
            port = f":{parsed.port}" if parsed.port else ""
            return _inline_safe(port + (parsed.path or ""), pipes=False) or "-"
        except ValueError:
            return "-"
    if row.kind == "ip" and report.network is not None:
        ports = [str(ip.port) for ip in report.network.ips if ip.address == row.value and ip.port]
        return ", ".join(ports) or "-"
    return "-"


def _tactic_key(cell: CapabilityCell) -> tuple[int, str]:
    order = _TACTIC_ORDER.index(cell.tactic) if cell.tactic in _TACTIC_ORDER else len(_TACTIC_ORDER)
    return order, cell.technique_id


# The unresolved codes that are about one technique and print beside its row.
_TECHNIQUE_FINDING_CODES = ("attck.", "stix.credit_without_claim")

# The technique a finding row stored without a ``subject`` opens with.
_LEADING_TECHNIQUE_RE = re.compile(rf"^\s*TECHNIQUE\s+({ID_BODY})\b", re.IGNORECASE)


def _finding_technique(row: dict[str, Any]) -> str:
    """The technique id an unresolved finding row is about, or ``""``.

    Its ``subject`` where the check set one; otherwise only the id the message
    opens with (``TECHNIQUE <id> …``), never an id named later in it.
    """
    subject = str(row.get("subject") or "").strip()
    if subject:
        return subject.upper()
    match = _LEADING_TECHNIQUE_RE.match(str(row.get("message") or ""))
    return match.group(1).upper() if match else ""


def _rule_labels(asserted: list[str], rules: list[dict[str, Any]]) -> dict[str, str]:
    """The label the ATT&CK table prints beside each deterministic source of a technique's
    row, by source, in the row's order: the sources that asserted it and the sources of the
    rule hits folded into it, ``rule match``, or the runtime-only label for a source all of
    whose hits matched only names resolved at runtime."""
    rule_sources = [str(hit.get("source") or "rule") for hit in rules]
    runtime_only = {
        str(hit.get("source") or "rule")
        for hit in rules
        if _resolved_only(hit)
        and all(_resolved_only(h) for h in rules if h.get("source") == hit.get("source"))
    }
    return {
        source: RESOLVED_ONLY_RULE_LABEL if source in runtime_only else "rule match"
        for source in dict.fromkeys(asserted + rule_sources)
    }


def _stated(value: float | None, producer: str) -> str:
    """A stated confidence with its producer, or that the producer is not recorded.

    ``None`` is a technique nobody put a number on: "not given".
    """
    if value is None:
        return "not given"
    if producer:
        return confidence_phrase(value, producer)
    return f"{confidence_word(value)}, {float(value):.2f}, producer not recorded"


def _attack_row(
    cell: CapabilityCell,
    mapping: Any,
    corroboration: dict[str, Any],
    ctx: _Context,
    rules: list[dict[str, Any]],
    capability_ids: list[str],
) -> tuple[str, int]:
    """A technique's row of the ATT&CK table, and how many cuts its status makes to fit
    (:func:`judge_reasons.status_cuts`, :func:`judge_reasons.reasons_cut`)."""
    cuts = 0
    row = corroboration.get(cell.technique_id)
    asserted = list(row.get("asserted_by") or []) if isinstance(row, dict) else []
    claimed = list(row.get("claimed_by") or []) if isinstance(row, dict) else []
    rule_sources = [str(hit.get("source") or "rule") for hit in rules]
    # Every producer that named the technique, each once: the rules that
    # asserted it, the analysts that claimed it, and the matrix's own layers —
    # the judge's verdict among them — which the corroboration does not count.
    # A rule that matched only names resolved at runtime says so in its label.
    # Each producer's name is a tool's or the operator's text, by the inline rule.
    named = [
        f"{ctx.value(source)} ({label})" for source, label in _rule_labels(asserted, rules).items()
    ]
    named += [
        ctx.value(str(x))
        for x in [*claimed, *cell.contributing_layers]
        if x not in asserted + rule_sources
    ]
    source = ", ".join(dict.fromkeys(named)) or "-"
    # No number, or the 0.0 a row stored before ``None`` existed carried for
    # one: no producer states a confidence of zero for a technique.
    unstated = cell.confidence is None or (cell.confidence == 0.0 and not cell.confidence_source)
    ruled = bool(asserted or rules)
    if unstated:
        # No producer put a number on it; the number the matrix carries is not
        # an assessment of anything.
        confidence = "rule match" if ruled else "not given"
    elif ruled and not claimed and set(cell.contributing_layers) <= set(asserted + rule_sources):
        confidence = "rule match"
    else:
        confidence = _stated(cell.confidence, cell.confidence_source)
    if not cell.technique_id_valid:
        status = f"unverified id ({UNVERIFIED_TECHNIQUE_MARKER})"
    elif cell.not_published:
        # A judge's reason is shortened by its own rule and never cut into;
        # what follows it, and any other reason, keeps the cell's cut.
        # The cut and the marks are made on the record's characters; each piece
        # between them is then written as text (:func:`_quote_written`).
        status = "claimed, not published: " + _quote_written(
            status_parts(cell.not_published, JUDGE_REASON_WIDTH, ctx.quoted), pipes=False
        )
        cuts = status_cuts(cell.not_published, JUDGE_REASON_WIDTH, ctx.quoted)
    else:
        status = "published" + _corroborated_words(mapping, rules)
        rule_only = ctx.rule_only.get(cell.technique_id)
        if rule_only:
            status += f"; {rule_only}"
        if cell.note:
            note = ctx.quoted(judge_reasons_shown(cell.note)[0])
            status += f"; {_quote_written(note, pipes=False)}"
            cuts = reasons_cut(cell.note)
    # The platform's unresolved findings about this technique, beside its
    # row: the ATT&CK checks, and the judge crediting a source that never
    # named it. Matched on what the finding is about (``subject``), because
    # its message can name other techniques — an unknown id's names the
    # closest real ones — and those rows are not what it is about.
    notes = [
        str(r.get("code"))
        for r in ctx.unresolved
        if str(r.get("code", "")).startswith(_TECHNIQUE_FINDING_CODES)
        and _finding_technique(r) == cell.technique_id.upper()
    ]
    if notes:
        status += "; unresolved: " + ", ".join(dict.fromkeys(notes))
    observed = _observed_cell(getattr(mapping, "observed_in", None), ctx)
    if observed:
        status += f"; {observed}"
    tactic = f"{cell.tactic_name} ({cell.tactic})" if cell.tactic else cell.tactic_name
    # The statement whole: a table cell wraps, it is never cut.
    procedure = ctx.cell(str(cell.evidence[0])) if cell.evidence else "-"
    return (
        _row(
            tactic,
            cell.technique_id,
            cell.technique_name,
            _with_rules(procedure, rules),
            source,
            confidence,
            status,
            _technique_evidence_cell(cell, rules, capability_ids),
        ),
        cuts,
    )


def _technique_evidence_cell(
    row: Any, rules: list[dict[str, Any]], capability_ids: list[str]
) -> str:
    """A technique's Evidence cell: its evidence, then the entries of the rules that matched it.

    The evidence is the set every surface prints (``technique_evidence``),
    the entries cited by the statements that name the technique, with the
    sandbox items among its sources beside it, or that they cite no ledger
    entry. A rule's entries it does not already list follow it, named as the
    rules'. A row stored before the set was recorded that names no entry and
    no item prints the rules' entries alone, or ``-``.
    """
    ids = technique_evidence_ids(row)
    items = technique_sandbox_items(row)
    ruled = [eid for eid in _rule_ids(rules, capability_ids) if eid not in (ids or ())]
    # A rule hit's entry ids are the tool's text, written by the inline rule.
    rule_words = f"rule matches: {', '.join(_inline_safe(eid, pipes=False) for eid in ruled)}"
    if ids is None and not items and ruled:
        return rule_words
    words = evidence_words(ids, items)
    return f"{words}; {rule_words}" if ruled else words


def _rule_words(hit: dict[str, Any]) -> str:
    """One rule hit as the Procedure cell names it: the rule, where it looked, its base rate."""
    matched = (
        ", ".join(_code_span(_defanged_text(str(a))) for a in (hit.get("matched_apis") or [])[:6])
        or "-"
    )
    rule = _inline_safe(str(hit.get("rule") or hit.get("name") or "").strip(), pipes=False)
    # A capability-rule tool names the namespace a rule lives in; the knowledge table names the
    # imports its rule matched, and the names it matched that the run resolved
    # at runtime from stored values apart from them: those are not imports.
    where = f"namespace {matched}" if _capability_rule_hit(hit) else _matched_names(hit)
    source = _inline_safe(hit.get("source") or "rule", pipes=False)
    said = (f"rule {rule} ({source}), " if rule else "") + where
    rate = _inline_safe(hit.get("benign_rate"), pipes=False) or "not measured"
    return said + f"; base rate {rate}"


# How a rule that matched only names resolved at runtime is named as a source:
# a platform fact about the match, and no corroboration of the technique.
RESOLVED_ONLY_RULE_LABEL = (
    "rule match on names resolved at runtime from hashes only, no import; not counted as "
    "corroboration"
)


def _resolved_only(hit: dict[str, Any]) -> bool:
    """Whether a knowledge-table rule matched only names resolved at runtime."""
    matched = [str(a) for a in (hit.get("matched_apis") or [])]
    resolved = {str(a) for a in (hit.get("resolved_apis") or [])}
    return bool(matched) and all(name in resolved for name in matched)


def _corroborated_words(mapping: Any, rules: list[dict[str, Any]]) -> str:
    """The row's layer words (:func:`_layer_words`) with its evidence roots beside them.

    The roots are the distinct places in the sample the statements cite
    (``analysis.evidence_roots``): "one evidence root (0x1a40 in .text)" for a
    row a single place stands behind, counted and listed for more. A row with
    layer words carries them inside its parentheses; a row with none states
    its layers and roots on their own. A row stored before roots were read
    says nothing of them.
    """
    words = _layer_words(mapping, rules)
    if mapping is None:
        return words
    from malspark.analysis.evidence_roots import layers_and_roots, roots_phrase

    roots = list(getattr(mapping, "evidence_roots", None) or [])
    unread = list(getattr(mapping, "roots_not_read", None) or [])
    phrase = roots_phrase(roots, unread)
    if not phrase:
        return words
    if words.endswith(")"):
        return f"{words[:-1]}; {phrase})"
    if words:
        return f"{words} ({phrase})"
    independent = len(getattr(mapping, "independent_layers", None) or [])
    return f", {layers_and_roots(independent or _named_layers(mapping), roots, unread)}"


def _named_layers(mapping: Any) -> int:
    """How many analyst layers name a row's technique, the judge aside.

    A layer that named it only in claims a tool-less retry added, which
    nothing of its own backs (``TTPMapping.retry_only_layers``), is not
    counted as naming it.
    """
    from malspark.extractors.capability_matrix import JUDGE_SOURCE

    retry_only = set(getattr(mapping, "retry_only_layers", None) or [])
    return len(
        [
            lyr
            for lyr in mapping.contributing_layers
            if lyr != JUDGE_SOURCE and lyr not in retry_only
        ]
    )


def support_words(support: str, kinds: Any, sources: int, named: int, listed: str = "") -> str:
    """The status words of a technique no source of which is behaviour.

    ``as a capability, not observed (…)`` or ``as not observed (…)``: its
    sources counted by kind (each one ledger entry or sandbox item however
    many analysts cite it), that no sandbox observation, code listing or rule
    match stands behind it, and how many analyst layers named it.
    """
    from malspark.analysis.corroboration import (
        NO_BEHAVIOUR_SOURCE,
        sources_phrase,
        support_label,
    )

    label = support_label(support)
    if not label:
        return ""
    parts = [f"{sources_phrase(kinds, sources)}; {NO_BEHAVIOUR_SOURCE}"]
    if named:
        parts.append(
            f"named by {named} analyst layer{'' if named == 1 else 's'}, counted as the "
            "sources they cite"
        )
    if listed:
        parts.append(listed)
    opening = "as a capability, not observed" if support == "capability" else "as not observed"
    return f"{opening} ({'; '.join(parts)})"


def _layer_words(mapping: Any, rules: list[dict[str, Any]]) -> str:
    """``, corroborated`` for a row two analyst layers named, or ``""``.

    A technique a rule matched only on runtime-resolved names has its analysts'
    statements listed under the table; its row points there, so a reader of the
    row alone does not take the word for more than a count of layers.

    The count is of layers with a statement of their own: statements with the
    same words, or with at least 90% of the shorter one's words in the other,
    count once (``capability_matrix.repeats``), and the row says how many were
    identical or near-identical. A row fewer than two layers stand behind that
    way says it is not corroborated and why. A row stored before statements
    were counted keeps the count of layers it was stored with.
    """
    if mapping is None:
        return ""

    named = _named_layers(mapping)
    independent = len(getattr(mapping, "independent_layers", None) or [])
    identical = int(getattr(mapping, "identical_statements", 0) or 0)
    repeated = (
        f"{identical} statement{'' if identical == 1 else 's'} identical or near-identical "
        "to another, counted once"
        if identical
        else ""
    )
    listed = rules and all(_resolved_only(hit) for hit in rules)
    said = support_words(
        str(getattr(mapping, "support", "") or ""),
        getattr(mapping, "source_kinds", None),
        len(getattr(mapping, "sources", None) or []),
        named,
        "their statements are listed below the table" if listed else "",
    )
    if said:
        return " " + said
    if not mapping.is_corroborated:
        if named < 2 or not (independent or identical):
            return ""
        # Where the sources were read, a row they leave short of two says so.
        cited = len(getattr(mapping, "sources", None) or [])
        sources = int(getattr(mapping, "independent_sources", 0) or 0) or cited
        traced = (
            f"; they cite {sources} independent source{'' if sources == 1 else 's'}, each "
            "counted once"
            if cited and sources < 2
            else ""
        )
        return (
            f", not corroborated ({named} analyst layers name it; {independent} of them in a "
            "statement of its own"
            + (f"; {repeated}" if repeated else "")
            + traced
            + ("; their statements are listed below the table" if listed else "")
            + ")"
        )
    if not independent:
        # Stored before statements were counted: the layers it was stored with.
        if listed:
            return (
                f", corroborated (named by {named} analyst layers; their statements are listed "
                "below the table)"
            )
        return ", corroborated"
    parts = [f"named by {independent} analyst layers, each in a statement of its own"]
    if repeated:
        parts.append(repeated)
    if listed:
        parts.append("their statements are listed below the table")
    return f", corroborated ({'; '.join(parts)})"


def _resolved_only_lines(
    cells: list[Any], rules_by_tid: dict[str, list[dict[str, Any]]], ctx: Any
) -> list[str]:
    """For each technique a rule matched only on runtime-resolved names, the analysts' words.

    The statements naming the technique, verbatim and by analyst, so a reader
    weighs whether any says the sample does it; nothing here reads them.
    """
    lines: list[str] = []
    for cell in cells:
        hits = rules_by_tid.get(cell.technique_id) or []
        if not hits or not all(_resolved_only(hit) for hit in hits):
            continue
        said = list(getattr(cell, "statements", None) or [])
        if not lines:
            lines.extend(
                [
                    "",
                    "**Techniques a rule matched only on names resolved at runtime from hashes** "
                    "(the match is not counted as corroboration; each analyst statement naming "
                    "the technique follows, verbatim):",
                    "",
                ]
            )
        lines.append(_item(f"{cell.technique_id} {cell.technique_name}:"))
        lines.extend(f"  - {ctx.line(text)}" for text in said)
        if not said:
            lines.append("  - no analyst statement names it")
    return lines


def _matched_names(hit: dict[str, Any]) -> str:
    """What a knowledge-table rule matched: its imports, and its names resolved at runtime."""
    from malspark.tools.knowledge import RESOLVED_AT_RUNTIME

    matched = [str(a) for a in (hit.get("matched_apis") or [])]
    at_runtime = [a for a in matched if a in {str(r) for r in (hit.get("resolved_apis") or [])}]
    imported = [a for a in matched if a not in at_runtime]
    if not at_runtime:
        return f"imports {_quoted_names(imported)}"
    if not imported:
        return f"matched only names {RESOLVED_AT_RUNTIME}, no import: {_quoted_names(at_runtime)}"
    return (
        f"imports {_quoted_names(imported)}; names {RESOLVED_AT_RUNTIME} "
        f"{_quoted_names(at_runtime)}"
    )


def _quoted_names(names: list[str]) -> str:
    return ", ".join(_code_span(_defanged_text(str(a))) for a in names[:6]) or "-"


def _with_rules(procedure: str, rules: list[dict[str, Any]]) -> str:
    """A row's Procedure with the rules that named its technique folded in."""
    if not rules:
        return procedure
    said = "; ".join(_rule_words(hit) for hit in rules[:4])
    return said if procedure in ("", "-") else f"{procedure}; {said}"


def _rule_ids(rules: list[dict[str, Any]], capability_ids: list[str]) -> list[str]:
    """The evidence ids behind rule hits: each hit's own, or the capability-rule table's."""
    out: list[str] = []
    for hit in rules:
        if hit.get("evidence_id"):
            out.append(str(hit["evidence_id"]))
        elif _capability_rule_hit(hit):
            out.extend(capability_ids)
    return list(dict.fromkeys(out))


def _rule_only_row(
    tid: str, rules: list[dict[str, Any]], mappings: dict[str, Any], capability_ids: list[str]
) -> str:
    """A technique only rules named, one row, with the catalogue's tactic and name.

    Every cell is escaped by ``_row``, and the import names most of all: they
    are the sample's own bytes, and a crafted import table carrying a pipe or a
    newline would otherwise reshape a table a human reads to make a call.
    """
    tactic, name = _catalogue_names(tid)
    status = (
        "published"
        if tid in mappings
        else "not published: a rule matched it and no producer claimed it"
    )
    sources = ", ".join(
        dict.fromkeys(
            f"{_inline_safe(hit.get('source') or 'rule', pipes=False)} (rule match)"
            for hit in rules
        )
    )
    return _row(
        tactic,
        _inline_safe(tid, pipes=False) or "-",
        name,
        _with_rules("-", rules),
        sources,
        "rule match",
        status,
        ", ".join(_inline_safe(eid, pipes=False) for eid in _rule_ids(rules, capability_ids))
        or "-",
    )


def _catalogue_names(tid: str) -> tuple[str, str]:
    """``("<tactic> (<TA id>)", "<technique name>")`` for an id, from the vendored table."""
    try:
        from malspark.extractors.capability_matrix import _resolve_tactic, _resolve_technique_meta

        (name, slug), domain = _resolve_technique_meta(tid)
        tactic_id, tactic_name = _resolve_tactic(slug, domain)
    except Exception:  # noqa: BLE001 — a catalogue lookup degrades to "not recorded"
        return "not recorded", "not recorded"
    tactic = f"{tactic_name} ({tactic_id})" if tactic_id else "not recorded"
    return tactic, (name if name and name != tid else "not recorded")


# The capability rules each capability subsection prints beside its prose,
# chosen by the rule's namespace and, where the rule gave none, by its MBC
# behaviour.
_EVASION_NAMESPACES = (
    "anti-analysis",
    "data-manipulation/encryption",
    "data-manipulation/encoding",
    "data-manipulation/obfuscation",
    "executable/pe/packer",
)
_EVASION_BEHAVIOURS = ("anti-behavioral analysis", "anti-static analysis", "defense evasion")
_RESOLUTION_NAMESPACES = (
    "linking/runtime-linking",
    "load-code/pe",
    "data-manipulation/hashing",
    "data-manipulation/checksum",
    "anti-analysis/obfuscation/string",
)
_RESOLUTION_RULES = ("peb", "resolve function", "parse pe export", "runtime link")


def _capability_rules(report: MalwareReport) -> list[tuple[dict[str, str], list[str]]]:
    """Every capability rule the run recorded: ``({namespace, rule, attck, mbc}, evidence ids)``."""
    out: list[tuple[dict[str, str], list[str]]] = []
    seen: set[tuple[str, str]] = set()
    for section in report.sections:
        if section.key != _CAPABILITY_SECTION:
            continue
        columns = [c.strip().lower() for c in section.columns]
        for row in section.rows:
            cells = {name: str(row[i]) for i, name in enumerate(columns) if i < len(row)}
            rule = {
                "namespace": cells.get("namespace", ""),
                "rule": cells.get("rule", ""),
                "attck": cells.get("att&ck", ""),
                "mbc": cells.get("mbc", ""),
            }
            key = (rule["namespace"], rule["rule"])
            if rule["rule"] and key not in seen:
                seen.add(key)
                out.append((rule, list(section.evidence_ids)))
    return out


def _is_evasion_rule(rule: dict[str, str]) -> bool:
    namespace = rule["namespace"].lower()
    # A rule that speaks to API or string resolution is printed there, once.
    if _is_resolution_rule(rule):
        return False
    return namespace.startswith(_EVASION_NAMESPACES) or (
        not namespace and _names_any(rule["mbc"], _EVASION_BEHAVIOURS)
    )


def _is_resolution_rule(rule: dict[str, str]) -> bool:
    namespace = rule["namespace"].lower()
    return namespace.startswith(_RESOLUTION_NAMESPACES) or _names_any(
        rule["rule"], _RESOLUTION_RULES
    )


_BRACKETED_ID_RE = re.compile(r"\[([A-Z]{1,2}\d{3,4}(?:\.\d{3})?)\]")


def _capability_tool(report: MalwareReport) -> str:
    """The tools the capability-rule table's rows came from (``ledger_report.rule_table_tools``).

    The declared display name of each tool whose rows the table holds,
    whichever tools of the kind ran, joined by "and"; ``""`` for a report with
    no such table, or one whose title names none.
    """
    for section in report.sections:
        if section.key == _CAPABILITY_SECTION:
            named = rule_table_tools(section, CAPABILITIES_TITLE)
            if named:
                return " and ".join(named)
    return ""


def _rule_match_note(
    report: MalwareReport,
    cells: list[CapabilityCell],
    mappings: dict[str, Any],
    rules_by_tid: dict[str, list[dict[str, Any]]],
    ctx: _Context,
) -> str:
    """The note under the ATT&CK table on the sources it marks ``(rule match)`` (T-845).

    It names each source the table's rows print with that mark, read as the rows read it
    (:func:`_rule_labels`; a technique only rules named prints each hit's source so), and
    ``pipeline:`` only where a source cell prints one. "with no sandbox" is said only of the
    rules that fired over the binary, whose names and base rates the Procedure cell
    carries: a capability-rule tool's over its code, the knowledge table's over its imports,
    or over names it resolved at runtime where each of its hits matched only those."""
    corroboration = (report.run_summary or {}).get("corroboration") or {}
    marked: dict[str, None] = {}
    layers: list[str] = []
    seen: set[str] = set()
    for cell in cells:
        seen.add(cell.technique_id)
        row = corroboration.get(cell.technique_id)
        asserted = list(row.get("asserted_by") or []) if isinstance(row, dict) else []
        claimed = list(row.get("claimed_by") or []) if isinstance(row, dict) else []
        labels = _rule_labels(asserted, rules_by_tid.get(cell.technique_id, []))
        marked.update(dict.fromkeys(s for s, label in labels.items() if label == "rule match"))
        layers += [str(x) for x in [*claimed, *cell.contributing_layers] if x not in labels]
    for tid, mapping in mappings.items():
        if tid not in seen:
            seen.add(tid)
            layers += [str(x) for x in mapping.contributing_layers]
    for tid, folded in rules_by_tid.items():
        if tid not in seen:
            marked.update(dict.fromkeys(str(hit.get("source") or "rule") for hit in folded))
    piped = [x for x in dict.fromkeys(layers) if x.startswith("pipeline:")]
    names = sorted(ctx.value(source) for source in [*marked, *piped])
    lead = (
        f"_A source marked `(rule match)`{' or `pipeline:`' if piped else ''} is a rule that "
        f"fired, with no model; this table marks {_joined(names)}."
        if names
        else "_No source in this table is marked `(rule match)`."
    )
    hits = [hit for folded in rules_by_tid.values() for hit in folded]
    others = [hit for hit in hits if not _capability_rule_hit(hit)]
    over: list[str] = []
    if any(_capability_rule_hit(hit) for hit in hits):
        over.append(f"{_capability_owner(report)} over its code")
    imports = [hit for hit in others if not _resolved_only(hit)]
    if imports and len(imports) < len(others):
        over.append("the knowledge table's over its imports and over names resolved at runtime")
    elif others:
        over.append(
            "the knowledge table's over its imports"
            if imports
            else "the knowledge table's over names resolved at runtime"
        )
    capped = ", at most four a row," if any(len(f) > 4 for f in rules_by_tid.values()) else ""
    return (
        f"{lead} The Procedure cell names the rules that fired over the binary{capped} with no "
        f"sandbox — {', '.join(over)} — each with its base rate: how much ordinary software it "
        "fires on, over the corpus it names. It says nothing about how likely this sample is to "
        "be benign, and `not measured` means the rule has no measurement, not that it never "
        "fires._"
    )


def _capability_owner(report: MalwareReport) -> str:
    """Whose rules fired over the binary's code, in the ATT&CK table's note."""
    tool = _capability_tool(report)
    return f"{tool}'s" if tool else "a capability rule tool's"


def _capability_table(
    rules: list[tuple[dict[str, str], list[str]]],
    wanted: Callable[[dict[str, str]], bool],
    tool: str = "",
) -> list[str]:
    """The capability rules one subsection prints, as a Measured table, or nothing.

    Headed by the tool the table's title names (:func:`_capability_tool`),
    else as capability rules.
    """
    chosen = [(rule, ids) for rule, ids in rules if wanted(rule)]
    if not chosen:
        return []
    lines = ["", f"_{MEASURED}:_ {tool or 'capability'} rules", ""]
    lines.append(_row("Rule", "Namespace", "ATT&CK / MBC", "Evidence"))
    lines.append(_divider(4))
    for rule, ids in chosen:
        tags = _BRACKETED_ID_RE.findall(rule["attck"] + " " + rule["mbc"])
        lines.append(
            _row(
                rule["rule"],
                _code_span(rule["namespace"]) if rule["namespace"] else "-",
                ", ".join(dict.fromkeys(tags)) or "-",
                _ids(ids) or "-",
            )
        )
    return lines


def _capability_evidence_ids(report: MalwareReport) -> list[str]:
    """The ids the capability-rule table cites, whichever tool of the kind filled it."""
    return list(
        dict.fromkeys(
            i
            for section in report.sections
            if section.key == _CAPABILITY_SECTION
            for i in section.evidence_ids
        )
    )


def _rule_hit_key(hit: dict[str, Any]) -> tuple[Any, ...]:
    """What makes two rule hits the same hit: one rule, one technique, one source."""
    return (
        hit.get("technique_id"),
        hit.get("name"),
        hit.get("rule"),
        hit.get("source"),
        tuple(hit.get("matched_apis") or ()),
    )


def _distinct[T](rows: list[T], key: Callable[[T], Any]) -> list[T]:
    """``rows`` with each key printed once, at its first occurrence.

    A report stored before the projection folded repeated tool calls carries
    one binary's section table twice; one table is printed.
    """
    seen: set[Any] = set()
    out: list[T] = []
    for row in rows:
        marker = key(row)
        if marker not in seen:
            seen.add(marker)
            out.append(row)
    return out


def _header_facts(report: MalwareReport) -> dict[str, Any]:
    """The header facts the identity carries, or the stored ``pe_header`` section's.

    A report stored before the identity carried them has the same measurement
    in its format tool's section — the machine, the timestamp and the library
    flag — and that section is read rather than the fact left out.
    """
    from datetime import UTC, datetime

    from malspark.reporting.ledger_projection import pe_architecture

    ident = report.identity
    facts: dict[str, Any] = {
        "architecture": ident.architecture,
        "is_dll": ident.is_dll,
        "compile_timestamp": ident.compile_timestamp.isoformat()
        if ident.compile_timestamp
        else None,
        "export_name": ident.export_name,
    }
    header = next((s for s in report.sections if s.key == "pe_header"), None)
    rows = {
        str(r[0]).strip().lower(): str(r[1]).strip()
        for r in (header.rows if header else [])
        if len(r) >= 2
    }
    if facts["architecture"] is None and rows.get("machine", "").isdigit():
        facts["architecture"] = pe_architecture(int(rows["machine"]))
    if facts["is_dll"] is None and rows.get("is dll") in ("yes", "no", "true", "false"):
        facts["is_dll"] = rows["is dll"] in ("yes", "true")
    stamp = rows.get("timestamp", "")
    if facts["compile_timestamp"] is None and stamp.isdigit() and int(stamp) > 0:
        facts["compile_timestamp"] = datetime.fromtimestamp(int(stamp), tz=UTC).isoformat()
    if facts["export_name"] is None and rows.get("export name"):
        facts["export_name"] = rows["export name"]
    return facts


def started_by_the_sample(report: MalwareReport) -> tuple[list[ProcessNode], list[ProcessNode]]:
    """The processes with a command line the sample started, and the others below a root.

    A process the sample started is one of the sample's process tree whose
    parent is one too, by the rule the export attributes a process by
    (``sandbox_report.sample_process_tree``): the processes that run the
    submitted file and the processes the sandbox marks, each with what
    descends from them; where both facts name processes, only a process both
    reach. So a desktop process the sandbox marks under a root that runs none
    of the sample (explorer.exe under sihost.exe) is no command the sample
    started, and a renamed copy the sandbox marks keeps its own. The second
    list is every other process below a root with a command line.

    Each process is placed as the export places it
    (``sandbox_report.process_placement``): by its own place in the listing,
    never by its pid, so two processes that carry one pid are each placed by
    their own lineage, and one with no recorded pid by its own facts and its
    parent.
    """
    from malspark.schemas.sandbox_report import PLACED_IN_TREE, process_placement

    dynamic = report.dynamic
    roots = distinct_processes(dynamic.process_tree if dynamic else [])
    in_tree = {
        id(node)
        for node, where in process_placement(
            roots, str(report.identity.file_name or ""), str(report.identity.hashes.sha256 or "")
        )
        if where == PLACED_IN_TREE
    }
    started: list[ProcessNode] = []
    others: list[ProcessNode] = []

    def _walk(node: ProcessNode) -> None:
        parent_is_the_sample_s = id(node) in in_tree
        for child in node.children:
            if child.command_line:
                ours = parent_is_the_sample_s and id(child) in in_tree
                (started if ours else others).append(child)
            _walk(child)

    for root in roots:
        _walk(root)
    return started, others


def not_started_by_the_sample_line(
    others: list[ProcessNode], tree: str = "the process tree"
) -> list[str]:
    """The line under a table of the sample's commands for the processes it leaves out,
    naming where ``tree`` lists every process."""
    if not others:
        return []
    pids = ", ".join(str(node.pid) for node in others[:10])
    more = f" and {len(others) - 10:,} more" if len(others) > 10 else ""
    one = len(others) == 1
    return [
        "",
        f"_Not listed: {len(others):,} command line{'' if one else 's'} not attributed to "
        f"the sample (pid{'' if one else 's'} {pids}{more}); {tree} lists every process._",
    ]


def _as_is(text: str) -> str:
    return text


def _evidence_body(
    section: Any,
    write: Callable[[str], str] = _as_is,
    *,
    declared_code: bool = False,
    cites_cut: bool = False,
) -> list[str]:
    """One evidence section's rows, items and text, whichever of them it carries.

    A section may carry more than one. Rows are what a tool found; the text
    beside them is what this system has to say about how it got them — that
    the answer was too big for the prompt and the table below is a page of
    it. It goes above the rows, as prose rather than as a fenced block,
    because a reader has to know a table is partial before they read it as
    complete. A section with nothing but text is a tool's own output and
    keeps its fence, and so does the text of a section opened by such an
    output that a later call of the same tool answered with records: the
    section keeps the kind of its first answer, and its rows follow the fence.

    Code the section holds is drawn whole, each function as a listing under
    the table (:func:`_evidence_rows`); ``declared_code`` is whether an entry
    the section cites declares its answer code (:func:`declares_code`), and
    ``cites_cut`` whether one its index row says was cut (:func:`cites_a_cut_entry`).
    """
    rows = _evidence_rows(
        section, write, listings=True, declared_code=declared_code, cites_cut=cites_cut
    )
    if not rows:
        return _fenced(write(section.text)) if section.text else []
    if not section.text:
        return rows
    if section.kind == "text":
        return [*_fenced(write(section.text)), "", *rows]
    # The text is the platform's sentence about a tool's answer, carrying a
    # tool's keys and names: each of its lines by the inline rule, every
    # backtick escaped so no value in it pairs into a span, then the
    # block-start rule.
    text = "\n".join(
        _paragraph_line(_inline_safe(line, pipes=False, plain=write))
        for line in str(section.text).split("\n")
    )
    return [text, ""] + rows


# How much of one table cell, and of one list item, Appendix A prints; the
# body cuts none. Only a one-line value is ever cut so: code a section holds is drawn whole as a
# listing (``_evidence_rows``), and a section with a cut value says where it
# is whole (``_cut_note``).
CELL_WIDTH = 160
ITEM_WIDTH = 200


def _evidence_rows(
    section: Any,
    write: Callable[[str], str] = _as_is,
    *,
    listings: bool = False,
    declared_code: bool = False,
    cites_cut: bool = False,
) -> list[str]:
    """The tabular and bulleted parts of a section, or nothing.

    Drawn whatever kind the section was opened as: a tool keyed to one
    section can answer it in more than one shape, and a part the kind does
    not name is still a part of the answer. Every cell of a row is drawn, a
    cell past the declared columns under its position (``Column 4``), so a
    table merged from listings of other widths loses none of them.

    ``write`` is how a cell's text is written: the report's own network
    indicators defanged in it, where a section is printed for reading.

    With ``listings`` (Appendix A), a cell or an item that holds code
    (:func:`holds_code`) is no cell: the table points to a listing under
    it, and the listing draws the code whole in a fence, headed by the
    function it is. A one-line value is still cut to the page, and a
    section with a value cut says under it where the value is whole, or,
    where it ``cites_cut`` an entry, where that entry is held.
    Without ``listings`` (a section printed in the body) nothing is cut.
    """
    out: list[str] = []
    code: list[tuple[str, str]] = []
    cut = False
    if section.rows:
        columns = list(section.columns or [])
        widest = max(len(row) for row in section.rows)
        columns += [f"Column {i + 1}" for i in range(len(columns), widest)]
        # A column's name is the tool's, written as its cells are.
        out += [
            _row(*(_emphasis_escaped(write(_escaped(name))) for name in columns)),
            _divider(len(columns)),
        ]
        # The columns of a section that hold the sample's or a sandbox's own
        # text, each written as one code span after its cut, so the value
        # cannot open a link, a tag or a fence (``ledger_report``).
        spans, plain = _SAMPLE_TEXT_COLUMNS.get(str(getattr(section, "key", "") or ""), ((), ()))
        for row in section.rows:
            cells: list[str] = []
            for at, cell in enumerate(row):
                if listings and holds_code(cell, row, declared_code):
                    code.append((_listing_where(row, at), str(cell)))
                    cells.append(f"code: Listing {len(code)} below")
                    continue
                if at in spans and str(cell) and str(cell) not in plain:
                    whole = write(str(cell))
                    shown = _truncate(whole, CELL_WIDTH) if listings else whole
                    cells.append(_code_span(_one_line(shown)))
                else:
                    whole = _emphasis_escaped(write(_escaped(cell)))
                    shown = _truncate_escaped(whole, CELL_WIDTH) if listings else whole
                    cells.append(shown)
                cut = cut or shown != whole
            cells += [""] * (len(columns) - len(cells))
            out.append(_row(*cells))
    if section.items:
        out += [""] if out else []
        for item in section.items:
            if listings and holds_code(item, (), declared_code):
                code.append(("", str(item)))
                out.append(_item(f"code: Listing {len(code)} below"))
                continue
            whole = _emphasis_escaped(write(_escaped(item)))
            shown = _truncate_escaped(whole, ITEM_WIDTH) if listings else whole
            cut = cut or shown != whole
            out.append(_item(shown))
    if listings and cut:
        out += ["", _cut_note(section, cites_cut)]
    for number, (where, body) in enumerate(code, 1):
        out += ["", _listing_heading(number, where, body, section), ""]
        out += _fenced(write(body.strip("\n")))
        if body.rstrip().endswith(CUT_MARK):
            out += ["", _stored_cut_note(section, cites_cut)]
    return out


def declares_code(evidence_ids: Iterable[Any], evidence_index: Iterable[Any]) -> bool:
    """Whether an entry a section cites (``evidence_ids``) declares that its answer is code.

    Read from the kind the entry stored with its facts when it was written
    (``EvidenceIndexRow.facts``): decompiled code, of one function or of a
    batch, or code listed as instructions. An index row read from a stored
    report's JSON is read as the model's is.
    """
    cited = {str(i) for i in (evidence_ids or [])}
    if not cited:
        return False
    kinds = DECOMPILE_KINDS | CODE_LISTING_KINDS
    for row in evidence_index or []:
        said = row if isinstance(row, dict) else {"id": row.id, "facts": row.facts}
        if str(said.get("id")) in cited and str((said.get("facts") or {}).get("kind")) in kinds:
            return True
    return False


def cites_a_cut_entry(evidence_ids: Iterable[Any], evidence_index: Iterable[Any]) -> bool:
    """Whether an entry a section cites (``evidence_ids``) was cut, as its index row says.

    Read from ``EvidenceIndexRow.truncated``, the one record of a cut the
    report holds; an index row read from a stored report's JSON is read as
    the model's is.
    """
    cited = {str(i) for i in (evidence_ids or [])}
    if not cited:
        return False
    for row in evidence_index or []:
        said = row if isinstance(row, dict) else {"id": row.id, "truncated": row.truncated}
        if str(said.get("id")) in cited and said.get("truncated") is True:
            return True
    return False


def holds_code(value: Any, row: Iterable[Any] = (), declared: bool = False) -> bool:
    """Whether one value of a section is code, drawn whole as a listing rather than as a cell.

    Code spans lines: a one-line value is a table's fact whatever its
    section. Where an entry the section cites declares code
    (:func:`declares_code`), every value of more than one line is code;
    anywhere else a value is code when it names the function another value
    of its row names (``FUN_<address>`` under the address, or its first
    instruction at it). Read by the declared kind and the content, never by
    a tool's name.
    """
    text = str(value or "").strip()
    if "\n" not in text:
        return False
    if declared:
        return True
    return any(
        names_itself(CodePart(str(other).strip(), text, False))
        for other in row
        if "\n" not in str(other).strip()
    )


# The name a listing's first line declares its function under: the first
# word an opening parenthesis follows (``int FUN_00401000(int a)``).
_DECLARED_NAME_RE = re.compile(r"([A-Za-z_][\w.@$?]*)\s*\(")


def _listing_where(row: Sequence[Any], at: int) -> str:
    """The function a row's code stands under: an address another cell gives, else its first."""
    others = [str(c).strip() for i, c in enumerate(row) if i != at]
    others = [c for c in others if c and "\n" not in c]
    return next((c for c in others if function_address(c) is not None), others[0] if others else "")


def _listing_heading(number: int, where: str, body: str, section: Any) -> str:
    """One listing's heading: its number, the function's address and name, and its entry.

    The entry is named when the section cites one; a section merged from
    several calls names them all under it (``_Evidence:``).
    """
    first = next((line for line in body.splitlines() if line.strip()), "")
    declared = _DECLARED_NAME_RE.search(first)
    name = declared.group(1) if declared else ""
    parts = [f"**Listing {number}**"]
    parts += [_code_span(_one_line(where))] if where else []
    parts += [_code_span(name)] if name and name != where else []
    ids = [str(i) for i in (getattr(section, "evidence_ids", None) or []) if str(i).strip()]
    parts += [_ids(ids)] if len(ids) == 1 else []
    return " · ".join(parts)


def _whole_at(section: Any, cites_cut: bool = False) -> str:
    """Where a value the page shows cut is whole: the section's entry or entries, else the JSON.

    A section that cites several entries names them once, on its own
    ``_Evidence:`` line under it, and is pointed to there. Where an entry it
    cites was cut (``cites_cut``), the value is not said whole anywhere: the
    words say only where the entry is held.
    """
    ids = [str(i) for i in (getattr(section, "evidence_ids", None) or []) if str(i).strip()]
    if cites_cut and len(ids) == 1:
        return f"the evidence ledger holds the entry under {_ids(ids)}"
    if cites_cut and ids:
        return "the evidence ledger holds the entries cited below"
    if len(ids) == 1:
        return f"the evidence ledger carries it whole under {_ids(ids)}"
    if ids:
        return "the evidence ledger carries it whole under the entries cited below"
    key = _one_line(getattr(section, "key", "") or "")
    return f"the JSON report carries it whole under the section {_code_span(key)}"


def _cut_note(section: Any, cites_cut: bool = False) -> str:
    """The line under a section with a value cut to the page: where that value is whole."""
    return (
        f"_A value above that ends in … is cut to fit the page ({CELL_WIDTH} characters "
        f"a cell, {ITEM_WIDTH} an item; no code is cut to fit it); "
        f"{_whole_at(section, cites_cut)}._"
    )


def _stored_cut_note(section: Any, cites_cut: bool = False) -> str:
    """The line under a listing the report was built with cut: where the code is whole."""
    return (
        f"_The report was built with this listing cut at the …; {_whole_at(section, cites_cut)}._"
    )


# The sections whose table columns hold the sample's or a sandbox's own text,
# by section key: each such column by its position, and the platform's own
# words a cell of one may hold instead, written plain (``ledger_report``).
_SAMPLE_TEXT_COLUMNS: dict[str, tuple[tuple[int, ...], tuple[str, ...]]] = {
    BEHAVIOUR_CODE_SECTION: (BEHAVIOUR_CODE_SAMPLE_COLUMNS, BEHAVIOUR_CODE_PLAIN_WORDS),
}


_MBC_ID_RE = re.compile(r"^[BCF]\d{4}(?:\.\d{3})?$")


def _is_mbc_id(technique_id: str) -> bool:
    """Whether an id is a Malware Behavior Catalog behaviour (``B0001.019``), not ATT&CK."""
    return bool(_MBC_ID_RE.match(str(technique_id or "").strip().upper()))


def _mbc_lines(report: MalwareReport) -> list[str]:
    """The behaviours a producer named by their MBC id, under the ATT&CK table.

    They are claims, kept as the producer wrote them, and not ATT&CK
    techniques: no technique surface publishes them.
    """
    rows = [
        cell
        for cell in (getattr(report, "capability_matrix", None) or [])
        if _is_mbc_id(cell.technique_id)
    ]
    if not rows:
        return []
    lines = ["", _plain_heading("Behaviours named by a Malware Behavior Catalog id"), ""]
    for cell in rows:
        name = cell.technique_name if cell.technique_name != cell.technique_id else ""
        said = _ids_in(cell.evidence)
        source = ", ".join(cell.contributing_layers) or "not recorded"
        lines.append(
            _item(
                f"{cell.technique_id}"
                + (f" {name}" if name else "")
                + (f": {_one_line(cell.evidence[0])}" if cell.evidence else "")
                + f" (claimed by {source}"
                + (f"; {', '.join(said)}" if said else "")
                + "; not an ATT&CK technique, not published)"
            )
        )
    return lines


def _not_published_lines(
    report: MalwareReport, ctx: _Context | None = None
) -> tuple[list[str], int]:
    """The techniques a producer claimed and this report does not publish, and how many cuts
    their reasons make to fit (:func:`judge_reasons.status_cuts`).

    They are in the table above, with the reason in the Status column. This
    short list under it is for a reader who scans headings: the claims are in
    none of the technique surfaces — not the References, not the STIX
    attack-patterns, not ``/reports/{id}/mitre``.
    """
    rows = [
        cell
        for cell in (getattr(report, "capability_matrix", None) or [])
        if cell.not_published and not _is_mbc_id(cell.technique_id)
    ]
    if not rows:
        return [], 0
    lines = ["", _plain_heading("Claims that were not published as techniques"), ""]
    # The reason by the table's own rule, a judge's reason sentence by
    # sentence, each sentence a check left standing marked as every other place marks it,
    # and every network value in it defanged; each piece between the marks
    # written as text after the cut (:func:`_quote_written`).
    parts = ctx.quoted if ctx is not None else _value_parts
    lines.extend(
        _item(
            f"{cell.technique_id} {cell.technique_name}: "
            f"{_quote_written(status_parts(cell.not_published, _NOT_PUBLISHED_WIDTH, parts))}"
        )
        for cell in rows
    )
    return lines, sum(status_cuts(c.not_published, _NOT_PUBLISHED_WIDTH, parts) for c in rows)


def judge_cut_note(cuts: int, report: MalwareReport) -> str:
    """The line under the reasons a page shortens to fit (a technique's reason it is not
    published, the judge's reason in a row's note), counting the cuts it made, each where it is
    made and never from a mark in the text, and saying where each stands whole: the JSON
    report's ``capability_matrix``, which holds each as the report records it; ``""`` where the
    page cut none (T-780)."""
    if not cuts:
        return ""
    rid = _one_line(stored_report_id(report) or "{report_id}")
    full = _code_span(f"/reports/{rid}/full")
    held = _code_span("capability_matrix")
    if cuts == 1:
        return (
            f"_1 reason above is shortened to fit this page where it shows {CUT_MARK}; "
            f"the JSON report ({full}) carries it whole, under {held}._"
        )
    return (
        f"_The reasons above are shortened to fit this page in {cuts} places, each "
        f"where it shows {CUT_MARK}; the JSON report ({full}) carries each whole, under "
        f"{held}._"
    )


# How much of a reason the list of claims not published prints.
_NOT_PUBLISHED_WIDTH = 300


def _unmapped_behaviour_lines(report: MalwareReport) -> list[str]:
    """The behaviours the verdict named and could not map to a technique.

    Printed under the table and never inside it: a behaviour with no technique
    id is not an ATT&CK technique.
    """
    names = list(getattr(report, "unmapped_behaviours", None) or [])
    if not names:
        return []
    lines = ["", _plain_heading("Behaviours with no mapped technique"), ""]
    lines.extend(_item(_whole(name)) for name in names)
    lines.append("")
    lines.append(
        "_Named in the verdict without a MITRE ATT&CK technique id after the id was "
        "asked for. They are not ATT&CK techniques and are not counted as any._"
    )
    return lines


def _ran_column(row: Any) -> str:
    """Appendix A's OK cell: whether the call answered, or where its answer is.

    A repeat was not run: it names the entry that answered it. A guard's
    answer names itself, and nothing answered it.
    """
    if is_guard_answer(row):
        return "guard's answer, not run"
    if row.repeated_of:
        return f"repeat of {row.repeated_of}"
    return "yes" if row.ok else "no"


def _row(*cells: Any) -> str:
    """One table row, assembled from its cells so the cells cannot assemble it.

    Escaping per call site was the first attempt and it does not hold: it is a
    rule nothing enforces, and the evidence is that a careful sweep with a test
    behind it still left the PE Sections table — whose first cell is eight raw
    bytes out of the section header — building its own row. A row a caller
    cannot write by hand cannot be written wrong, so every table in this
    renderer goes through here, header rows included, and
    ``test_a_table_row_is_never_assembled_by_hand`` fails the build if a new one
    does not.

    A cell arrives composed: backticks, a parenthetical, a format spec are the
    caller's business. What is not the caller's business is the separator, so
    the escaping happens here, once, on whatever the cell turned out to be.
    """
    return "| " + " | ".join(_cell(cell) for cell in cells) + " |"


def _divider(columns: int) -> str:
    """The rule under a table's header, for as many columns as it has."""
    return "|" + "---|" * columns


def _cell(value: Any) -> str:
    """One table cell's text, with what would break the table taken out of it.

    Every string in this report that a sample, a sandbox, a tool payload or a
    model wrote is free text, and a Markdown table is one of the few places
    where free text is structural: a single ``|`` adds a column and shifts
    every cell after it, and a newline ends the row and orphans every row
    below. The worst case is not theoretical — an import name is the sample's
    own bytes and a URL, a registry key and a dropped file's path all come
    from the sample too — and the table it would wreck is one a human reads to
    make a call. Cheaper to escape at the cell than to trust each producer.

    Not a security control. ``markdown-it`` runs with ``html=False`` and React
    escapes text, so nothing here is about injection; this is table integrity.
    """
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _texts_of(record: Any) -> list[str]:
    """Every text ``record`` holds, its mappings' keys and its models' fields among them."""
    texts: list[str] = []
    stack = [record]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, BaseModel):
            stack.append(item.model_dump())
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            stack.extend(item)
        elif item is not None:
            texts.append(str(item))
    return texts


# A fence's number as a text can hold it: digits after a NUL with a NUL next.
# Longer digit runs than a counter reaches are no fence this module builds.
_FENCE_NUMBER = re.compile(r"\x00(\d{1,18})(?=\x00)")


def _fence_numbers(record: Any) -> frozenset[int]:
    """The numbers of every fence a text of ``record`` holds, read in one pass over each text."""
    held: set[int] = set()
    for text in _texts_of(record):
        if "\x00" in text:
            held.update(int(found.group(1)) for found in _FENCE_NUMBER.finditer(text))
    return frozenset(held)


def _absent_mark(record: Any, start: int = 0, held: frozenset[int] | None = None) -> str:
    """A short fence no text of ``record`` holds: a NUL, a number from ``start`` up, a NUL.

    The numbers the record's texts hold are read once (``held`` where the
    caller already read them), and the first number from ``start`` that is
    not among them is taken: there is always one, the fence stays a few
    characters long whatever the record holds, and the work is one pass over
    the record's text however many fences it holds.
    """
    numbers = _fence_numbers(record) if held is None else held
    number = start
    while number in numbers:
        number += 1
    return f"\x00{number}\x00"


def _placed(
    build: Callable[[Callable[[Any], str]], list[str]],
    line: Callable[[str], str],
    value: Callable[[str], str],
    record: Any,
) -> list[str]:
    """The lines ``build`` writes, each value it names written by itself and set in after.

    ``build`` is handed the writer of a value's place: it returns a mark for
    the value, and each line is written by ``line`` (the platform's sentence
    rule) with the marks in it; each value is written by ``value`` (the inline
    rule) and set into its marks in one pass, so no character of it is escaped
    twice and no two values pair. The mark is a fence no text of ``record``
    holds (:func:`_absent_mark`); where a line's writing does not keep every
    mark as built, the next fence is taken, at most :data:`_PLACING_TRIES`
    times in all. After that each line is composed from its parts
    (:func:`_composed`): every run of the platform's words between two values
    written by ``line``, every value by ``value``, and no mark in the line.
    """
    start = 0
    held = _fence_numbers(record)
    for _ in range(_PLACING_TRIES):
        mark = _absent_mark(record, start, held)
        done = _placed_with(mark, build, line, value)
        if done is not None:
            return done
        start = int(mark.strip("\x00")) + 1
    return _composed(_absent_mark(record, start, held), build, line, value)


# How many fences :func:`_placed` tries before it composes each line from its parts.
_PLACING_TRIES = 4


def _composed(
    mark: str,
    build: Callable[[Callable[[Any], str]], list[str]],
    line: Callable[[str], str],
    value: Callable[[str], str],
) -> list[str]:
    """The lines ``build`` writes, each composed from its parts with no writing over a mark.

    The lines are built with each value marked by ``mark``, as
    :func:`_placed_with` builds them, and each is cut at its marks: every run
    of the platform's words between two values is written by ``line`` and
    every value by ``value``, joined in the order built. No mark reaches the
    line's writer, so none is left in the line, and each value is written by
    the writer its caller gives it, whatever its kind.
    """
    placed, values, place = _marking(mark, value)
    composed: list[str] = []
    for text in build(place):
        parts = placed.split(text)
        composed.append(
            "".join(
                values[int(part)] if at % 2 else line(part) if part else ""
                for at, part in enumerate(parts)
            )
        )
    return composed


def _marking(
    mark: str, value: Callable[[str], str]
) -> tuple[re.Pattern[str], list[str], Callable[[Any], str]]:
    """The pattern of ``mark``'s places, the values written so far, and the writer of a place.

    The writer hands out ``mark`` around the value's number, one number per
    distinct value, and keeps the value as ``value`` writes it.
    """
    placed = re.compile(re.escape(mark) + r"v(\d+)" + re.escape(mark))
    values: list[str] = []
    index: dict[str, int] = {}

    def place(held: Any) -> str:
        text = str(held if held is not None else "")
        if text not in index:
            index[text] = len(values)
            values.append(value(text))
        return f"{mark}v{index[text]}{mark}"

    return placed, values, place


class _RowWords:
    """The values the IOC table's contexts name, each marked where the table built it.

    :meth:`place` is the table's ``word``: it hands out a fence no text of the
    report holds (:func:`_absent_mark`) around the value's number. :meth:`rows`
    gives the rows as a build with each value as recorded gives them, and
    keeps the marked text of each row's context and recovery for
    :meth:`written`.
    """

    def __init__(self, report: MalwareReport) -> None:
        self.mark = _absent_mark(report)
        self.placed = re.compile(re.escape(self.mark) + r"v(\d+)" + re.escape(self.mark))
        self.values: list[str] = []
        self.index: dict[str, int] = {}
        self.marked: dict[tuple[str, str, str], str] = {}

    def place(self, held: Any) -> str:
        text = str(held if held is not None else "")
        if text not in self.index:
            self.index[text] = len(self.values)
            self.values.append(text)
        return f"{self.mark}v{self.index[text]}{self.mark}"

    def _plain(self, text: str | None) -> str | None:
        if not text or self.mark not in text:
            return text
        return self.placed.sub(lambda found: self.values[int(found.group(1))], text)

    def rows(self, rows: list[ConsolidatedIOC]) -> list[ConsolidatedIOC]:
        out: list[ConsolidatedIOC] = []
        for row in rows:
            key = (row.type, str(row.value).strip().lower())
            changed: dict[str, Any] = {}
            for part in ("context", "description", "recovered_by"):
                held = getattr(row, part, None)
                if isinstance(held, str) and self.mark in held:
                    self.marked[(part, *key)] = held
                    changed[part] = self._plain(held)
            out.append(row.model_copy(update=changed) if changed else row)
        return out

    def written(
        self,
        row: Any,
        part: str,
        line: Callable[[str], str],
        value: Callable[[str], str],
    ) -> str:
        """``row``'s context or recovery: its words by ``line``, each value by ``value``."""
        plain = getattr(row, part, None)
        if not plain:
            return ""
        held = self.marked.get((part, row.type, str(row.value).strip().lower()))
        if held is not None:
            done = _placed_with(
                self.mark,
                lambda word: [self.placed.sub(lambda f: word(self.values[int(f.group(1))]), held)],
                line,
                value,
            )
            if done is not None:
                return done[0]
        return value(plain)


def _rested(row: dict[str, Any], word: Callable[[Any], str]) -> list[str]:
    """One rested tool server's sentence, its names and the reason it gave each by ``word``."""
    held = dict(row)
    for key in ("server", "label"):
        if str(row.get(key) or ""):
            held[key] = word(str(row[key]))
    if str(row.get("reason") or "").strip():
        held["reason"] = word(str(row["reason"]).strip())
    return [server_rest_sentence(held)]


def _placed_with(
    mark: str,
    build: Callable[[Callable[[Any], str]], list[str]],
    line: Callable[[str], str],
    value: Callable[[str], str],
) -> list[str] | None:
    """:func:`_placed` with one fence; ``None`` where a line's writing did not keep its marks."""
    placed, values, place = _marking(mark, value)
    built = build(place)
    written = [line(text) for text in built]
    if any(
        placed.findall(text) != placed.findall(done)
        for text, done in zip(built, written, strict=True)
    ):
        return None
    return [placed.sub(lambda found: values[int(found.group(1))], done) for done in written]


# What would end a link's target, escape its end, open a title or a tag inside it.
_LINK_TARGET_ENDS = re.compile(r'[()<>\s\\"]')


def _link_target(url: Any) -> str:
    """A target the platform writes into a link, no character of which can end the link.

    Encoded, as their UTF-8 bytes' percent-escapes: ``()<>\\"`` and white space (``\\`` is ``%5C``).

    A parenthesis, an angle bracket, white space, a backslash and a double
    quote are percent-encoded, so a target the operator configured is one link
    to that target and never closes it early, escapes its closing parenthesis,
    opens a title or carries a tag after it; the link's text is its own.
    """
    return _LINK_TARGET_ENDS.sub(
        lambda found: "".join(f"%{byte:02X}" for byte in found.group(0).encode()),
        str(url or ""),
    )


def _one_line(value: Any) -> str:
    """A value that has to stay on its line: its line breaks become spaces."""
    return " ".join(str(value or "").splitlines())


# Said wherever a list is shown in part: how many were left out and where
# every one is. The page is laid out for a reader; the JSON report (the same
# report's structured form) and the evidence ledger hold every value whole.
LEFT_OUT_LINE = "_{rest:,} more {what} not shown here; the JSON report carries every one._"
# Said once, in the methodology appendix, of the cuts the page makes for which
# the JSON report holds the text cut from: an Appendix A table value
# (``_evidence_rows``), a judge's reason in the ATT&CK table (``judge_reasons``,
# from ``capability_matrix``) and a code listing figure (``figures``, from
# ``technical_evidence``).
CUT_CELL_SENTENCE = (
    "Where the page cuts a table value in Appendix A or a judge's reason in the ATT&CK "
    "table to fit, the cut ends in …; a code listing cut to fit says so in its legend. "
    "The JSON report holds the text each of these was cut from."
)


def is_carve_note(row: Any) -> bool:
    """Whether an embedded-resource row is the carver's note of what its cap
    left out (``pe_extractor._carve_from``): not carved, and counting the rest."""
    return isinstance(row, dict) and not row.get("carved") and "left_out" in row


def _left_out(total: int, shown: int, what: str) -> list[str]:
    """The line a list shown in part ends with, or nothing when it is shown whole."""
    rest = int(total) - int(shown)
    if rest <= 0:
        return []
    return ["", LEFT_OUT_LINE.format(rest=rest, what=what)]


def _dropped_item(op: Mapping[str, Any]) -> str:
    """The item of a sandbox's dropped-files list a row names, as one key.

    A row with the sandbox's name for the file is that item whatever guest path
    it fills: two entries listing one item, one with the path and one without,
    name one file. A row with no name is keyed by every field, its path among them.
    """
    held = {k: v for k, v in op.items() if k != "path"} if op.get("name") else dict(op)
    return json.dumps(held, sort_keys=True, default=str)


def dropped_files_left_out(dropped: Sequence[Mapping[str, Any]], shown: int) -> int:
    """How many files the dropped-files table leaves out when it prints the first ``shown``
    rows of ``dropped``: each item of the rows after them that no row shown names, counted
    once (:func:`_dropped_item`)."""
    printed = {_dropped_item(op) for op in dropped[:shown]}
    return len({key for op in dropped[shown:] if (key := _dropped_item(op)) not in printed})


def _dropped_left_out(dropped: Sequence[Mapping[str, Any]], shown: int) -> list[str]:
    """The line the dropped-files table ends with, counting the files it leaves out
    (:func:`dropped_files_left_out`), or nothing when it shows every one."""
    rest = dropped_files_left_out(dropped, shown)
    return ["", LEFT_OUT_LINE.format(rest=rest, what="dropped files")] if rest else []


def _outside_marks(text: str, cut: int) -> int:
    """``cut``, or the start of the defang mark it would fall inside.

    A cell is defanged before it is cut, and ``skinnyjeanso[.…`` is neither
    the value nor a defanged spelling of it: the cut falls before the mark.
    """
    for mark in _DEFANGED_MARKS:
        for start in range(max(0, cut - len(mark) + 1), cut):
            if text.startswith(mark, start):
                return start
    return cut


def _whole(value: Any) -> str:
    """A body cell's value as text, whole; nothing for none."""
    return "" if value is None else str(value)


def _truncate(value: Any, length: int) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) <= length:
        return s
    return s[: _outside_marks(s, length - 1)] + "…"


def _truncate_escaped(text: str, length: int) -> str:
    """Text :func:`_escaped` wrote, cut as :func:`_truncate` cuts what a reader sees.

    Every backslash in such text escapes the character after it, and the pair
    is one character on the page: the cut counts it once, and never falls
    between the two, nor inside a defang mark.
    """
    cut = None
    index = visible = 0
    while index < len(text):
        if visible == length - 1:
            cut = index
        index += 2 if text[index] == "\\" else 1
        visible += 1
    if visible <= length or cut is None:
        return text
    return text[: _outside_marks(text, cut)] + "…"


# A size a row states as text: a number written out, read as it is written.
_SIZE_TEXT_RE = re.compile(r"[+-]?\d+(?:\.\d+)?")
# What a size cell says where its row states no size.
SIZE_NOT_RECORDED = "not recorded"


def dropped_size_cell(op: Mapping[str, Any]) -> str:
    """A file's size as a cell (a written file, a carved payload, a resource): what its row states.

    ``"<size> bytes"`` where the row states a size that is a number (``0`` is
    a file of no bytes), or text that is a number, written without the white
    space around it. Any other size the row states is a sandbox's free text:
    it is printed as it states it, trimmed, with no unit added, as one code
    span (:func:`_code_span`, as every other untrusted value of the table), so
    a viewer reads it as text and never as a link, an image or a tag
    (``"`12kB`"``). ``"not recorded"`` only where it states none: no value, an
    empty or blank text, a list, a mapping, a truth value. Nothing a row states
    is replaced by ``"not recorded"``.
    """
    size = op.get("size")
    if isinstance(size, int | float) and not isinstance(size, bool):
        finite = size == size and abs(size) != float("inf")
        return f"{size} bytes" if finite else str(size)
    if isinstance(size, str) and size.strip():
        text = size.strip()
        return f"{text} bytes" if _SIZE_TEXT_RE.fullmatch(text) else _code_span(text)
    return SIZE_NOT_RECORDED


def _process_tree_lines(
    node: ProcessNode, depth: int, plain: Callable[[str], str] = lambda text: text
) -> list[str]:
    """The process tree, one line per process, each name and command line defanged.

    A process whose image is the submitted file as the sandbox started it says
    so in words beside it (``sandbox_report.staged_words``).
    """
    from malspark.schemas.sandbox_report import staged_words

    indent = "  " * depth
    prefix = "└─ " if depth > 0 else ""
    label = _one_line(plain(node.name)) or f"pid={node.pid}"
    extra = f"  ({_one_line(plain(node.command_line))})" if node.command_line else ""
    staged = f"  [{staged_words(node)}]" if staged_words(node) else ""
    line = f"{indent}{prefix}pid={node.pid} ppid={node.ppid} {label}{extra}{staged}"
    out = [line]
    if node.injected_into:
        out.append(f"{indent}    [injected_into={', '.join(str(p) for p in node.injected_into)}]")
    for child in node.children:
        out.extend(_process_tree_lines(child, depth + 1, plain))
    return out


def _registry_row(reg: RegistryMod, plain: Callable[[str], str] = lambda text: text) -> str:
    """One registry modification, its key and value name defanged."""
    return _row(
        reg.hive,
        _code_span(_whole(plain(reg.key))),
        _code_span(_whole(plain(reg.value_name or "-"))),
        reg.operation,
    )


def _severity_cell(sig: SandboxSignature) -> Any:
    """A signature's severity as stated; ``unknown`` where the sandbox gave none, never 0."""
    return "unknown" if sig.severity is None else sig.severity


def _signature_row(
    sig: SandboxSignature, observed: str = "", plain: Callable[[str], str] = _defanged_text
) -> str:
    """A sandbox signature's row: its name, techniques and description are the sandbox's text."""

    def value(text: str) -> str:
        return _inline_safe(text, pipes=False, plain=plain)

    ttps = ", ".join(value(tid) for tid in sig.technique_ids) if sig.technique_ids else "-"
    described = value(_whole(sig.description or "-"))
    if observed:
        described = f"{value(sig.description)}; {observed}" if sig.description else observed
    return _row(value(sig.name), _severity_cell(sig), ttps, described)


def _observed_cell(marks: Any, ctx: Any) -> str:
    """Under which detonations a row was observed, as a cell says it; ``""`` for none.

    ``detonation_marks.observed_words``, a further detonation's arguments set
    as one code span with the run's network indicators defanged.
    """
    from malspark.reporting.detonation_marks import observed_words

    return observed_words(marks or (), lambda arguments: _code_span(ctx.plain(arguments)))
