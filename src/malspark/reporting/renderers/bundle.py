"""The evidence bundle: the record behind the analyst report, in one file and in JSON.

The analyst report (``renderers/analyst.py``) prints the findings and moves
the rest here, so nothing the single-file report prints is lost: the bundle
prints every section of the single-file report as that report prints it — the
observed behaviour, the static properties, the full ATT&CK, indicator and
detection sections with their published states, the limitations, every claim
whose code the body does not name, the evidence index of every tool call with
the sections built from their answers, and the run summary — and adds the notes
the analyst report cites, each listing its evidence ids, each id linked to its
row in the evidence index.

In HTML every evidence id the index lists has an anchor (``#ev_0064``), every
note has one (``#cite-3``) and every section and subsection has one
(``#sec-command-and-control``), so each link the analyst report makes lands.

The JSON form carries the same content for a program: the notes, the
evidence index and each section's Markdown under its anchor.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.analyst import CitationNote, bundle_anchor, unique_anchor
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, BUNDLE_HTML
from malspark.reporting.renderers.markdown import (
    _PIPE,
    MEASURED,
    _appendix_heading,
    _inline_safe,
    _item,
    report_title,
    stored_report_id,
)
from malspark.schemas.evidence import ENTRY_ID_RE

if TYPE_CHECKING:
    from malspark.reporting.renderers.markdown import MarkdownRenderer, _Context

FORMAT = "malspark-evidence-bundle/1"
NOTES_TITLE = "Notes cited by the analyst report"

# The analyst report's sections, by the key a note records, as its headings
# name them.
SECTION_TITLES: dict[str, str] = {
    "title": "Title block",
    "summary": "Executive summary",
    "scope": "Introduction and scope",
    "metadata": "Sample metadata",
    "flow": "Execution flow",
    "functionality": "Functionality",
    "c2": "Command and control",
    "conclusion": "Conclusion",
    "detection": "Detection",
    "recommendations": "Recommendations",
    "attack": "MITRE ATT&CK mapping",
    "limitations": "Limitations",
    "appendix": "Appendix",
}

_H2 = re.compile(r"^## ", re.MULTILINE)
_HEADING_TITLE = re.compile(r"^(?:\d+(?:\.\d+)*\.?\s+" + _PIPE + r"Appendix [A-Z]\.\s+)")


def bundle_sections(
    renderer: MarkdownRenderer,
    report: MalwareReport,
    ctx: _Context,
    sections: list[str],
    notes: list[CitationNote],
    cited: set[int] | None = None,
) -> list[str]:
    """The single-file report's sections under the bundle's title, then the notes.

    ``cited`` holds the numbers of the notes the analyst report prints a marker for; only
    those are listed, the others counted (every note, where it is ``None``)."""
    title, _, rest = sections[0].partition("\n") if sections else ("", "", "")
    heading = "# Evidence bundle: " + title.removeprefix("# ").strip()
    shown = [note for note in notes if cited is None or note.number in cited]
    unheld = _unindexed(report, shown)
    intro = (
        "_The record behind the analyst report of the same name: every section the "
        "single-file report prints, as it prints it, and a list of the notes the analyst "
        "report cites (Appendix E), "
        + (
            "each linked to the evidence entries it rests on._"
            if not unheld
            else "each with the evidence entries it rests on; Appendix E names each cited id "
            "the evidence index does not hold._"
        )
    )
    out = ["\n".join([heading, "", intro, rest]), *sections[1:]]
    out.append(
        renderer._safe_section(
            "bundle_notes", lambda: _notes_section(report, shown, len(notes) - len(shown))
        )
    )
    return out


# What may stand between the ids one item of a note joins ("ev_0142; ev_0212", "ev_0142 and
# ev_0212"), once the ids are taken out.
_ID_SEPARATORS = re.compile(r"(?:[\s,;]" + _PIPE + r"\band\b)*", re.IGNORECASE)


def note_ids(note: CitationNote) -> list[str]:
    """The evidence ids a note rests on, each once, as the citation reader reads them
    (``ENTRY_ID_RE``, in the spelling the counter issues): every id it finds in an item, and the
    item itself as written where it holds anything beyond ids and separators, so no id is lost
    and none is made up."""
    out: list[str] = []
    for item in note.evidence_ids:
        text = str(item).strip()
        parts = [found.lower() for found in ENTRY_ID_RE.findall(text)]
        if not parts or not _ID_SEPARATORS.fullmatch(ENTRY_ID_RE.sub("", text)):
            parts.append(text)
        out.extend(part for part in parts if part and part not in out)
    return out


def _unindexed(report: MalwareReport, notes: list[CitationNote]) -> list[str]:
    """The ids the notes rest on that no entry of the evidence index carries, each once."""
    indexed = {row.id for row in report.evidence_index}
    return list(dict.fromkeys(i for note in notes for i in note_ids(note) if i not in indexed))


def _notes_section(report: MalwareReport, notes: list[CitationNote], uncited: int = 0) -> str:
    """Each note with its ids linked to the index; an id the index does not hold, said so;
    the notes numbered for a passage the analyst report does not print, counted."""
    lines = [_appendix_heading("E", NOTES_TITLE, MEASURED), ""]
    left = (
        f"{uncited} further note{' was' if uncited == 1 else 's were'} numbered for a passage "
        "the analyst report does not print; no marker cites "
        f"{'it' if uncited == 1 else 'them'}, and {'it is' if uncited == 1 else 'they are'} "
        "not listed."
    )
    if not notes:
        lines.append("The analyst report cites no evidence entry.")
        if uncited:
            lines.extend(["", left])
        return "\n".join(lines)
    indexed = {row.id for row in report.evidence_index}
    missing = _unindexed(report, notes)
    lines.append(
        "_Each note the analyst report cites, the section it stands in, and the "
        + (
            "evidence entries it rests on, each linked to its row in Appendix A._"
            if not missing
            else "evidence entries it rests on, each the evidence index holds linked to its row "
            "in Appendix A._"
        )
    )
    lines.append("")
    for note in notes:
        # An id no entry carries is the cited text as written, by the inline rule.
        ids = ", ".join(f"[{i}](#{i})" if i in indexed else _inline_safe(i) for i in note_ids(note))
        section = SECTION_TITLES.get(note.section, note.section)
        lines.append(_item(f"**Note {note.number}** ({section}): {ids}"))
    if uncited:
        lines.extend(["", left])
    if missing:
        lines.extend(
            ["", "Cited by the analyst report and not in this report's evidence index:", ""]
        )
        lines.extend(
            _item(f"**{_inline_safe(i)}**: no entry of the evidence index carries this id.")
            for i in missing
        )
    return "\n".join(lines)


def section_index(markdown: str) -> list[dict[str, str]]:
    """The bundle's Markdown split at its H2 headings: each part with its title and anchor."""
    parts = _H2.split(markdown)
    out = [{"anchor": "title", "title": "Title", "markdown": parts[0].rstrip()}]
    seen: set[str] = set()
    for part in parts[1:]:
        heading = part.split("\n", 1)[0]
        title = _HEADING_TITLE.sub("", heading.split(" · ", 1)[0]).strip()
        anchor = unique_anchor(bundle_anchor(title), seen)
        out.append({"anchor": anchor, "title": title, "markdown": ("## " + part).rstrip()})
    return out


def bundle_json(report: MalwareReport) -> str:
    """The evidence bundle as JSON: the notes, the evidence index and every section."""
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    markdown, notes = MarkdownRenderer(layout=BUNDLE).render_with_notes(report)
    document: dict[str, Any] = {
        "format": FORMAT,
        "report": {
            "title": report_title(report),
            "sha256": report.identity.hashes.sha256,
            "report_id": stored_report_id(report),
            "generated_at": report.generated_at.isoformat(),
        },
        "notes": [
            {
                "number": note.number,
                "anchor": f"cite-{note.number}",
                "section": SECTION_TITLES.get(note.section, note.section),
                "evidence_ids": note_ids(note),
            }
            for note in notes
        ],
        "evidence_index": [row.model_dump(mode="json") for row in report.evidence_index],
        "sections": section_index(markdown),
    }
    return json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


@dataclass(frozen=True)
class Products:
    """The analyst report and its evidence bundle, rendered from one report."""

    report_markdown: str
    report_html: str
    bundle_markdown: str
    bundle_html: str
    bundle_json: str


def render_products(report: MalwareReport) -> Products:
    """Both products of one report, in every form they are served in."""
    from malspark.reporting.renderers.html import HtmlRenderer
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    return Products(
        report_markdown=MarkdownRenderer(layout=ANALYST).render(report),
        report_html=HtmlRenderer(layout=ANALYST).render(report),
        bundle_markdown=MarkdownRenderer(layout=BUNDLE).render(report),
        bundle_html=HtmlRenderer(layout=BUNDLE).render(report),
        bundle_json=bundle_json(report),
    )


# A note marker the analyst report writes (``CitationNotes.marker``, ``.linked``): its number
# or an id, linked to the note in the bundle, set aside whole under its own token.
_NOTE_MARKER = re.compile(
    r"\[(?:\[\d+\]"
    + _PIPE
    + r"(?:"
    + ENTRY_ID_RE.pattern
    + r"))\]\("
    + re.escape(BUNDLE_HTML)
    + r"#cite-(\d+)\)",
    re.IGNORECASE,
)


def marker_numbers(kept: Iterable[str]) -> list[int]:
    """The note numbers cited by the texts a render set aside (``_Context.kept_in``) that are
    each a whole note marker, in order: a marker is read only as the platform writes it, never
    from text a model wrote (a draft rule's body is set aside too, and is never one)."""
    return [int(found.group(1)) for text in kept if (found := _NOTE_MARKER.fullmatch(text))]
