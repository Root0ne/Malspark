"""A citation marker is the platform's only where the platform set it (T-814).

The analyst report's note marker (``[[N]](evidence-bundle.html#cite-N)``) is set
by the platform and kept from the closing pass. Text the platform did not
write that holds the marker's form, or any other link into the evidence bundle
or to a note anchor, is printed as the characters the record holds, on every
surface: no link, no superscript, no note link, no character lost. A code span
stays a code span. The platform's own markers and links are as they were.
"""

from __future__ import annotations

import html
import re
from collections import Counter
from collections.abc import Callable

import pytest
from markdown_it import MarkdownIt

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from malspark.reporting.renderers.markdown import (
    MarkdownRenderer,
    _escaped_references,
    _hand_links_unlinked,
)
from tests.unit.reporting._report_shapes import rich_report

_RAW_HTML = MarkdownIt("commonmark", {"html": True}).enable("table").enable("strikethrough")


def _set_section_prose(report: MalwareReport, text: str) -> None:
    assert report.technical_analysis is not None
    sub = report.technical_analysis.persistence_detail
    assert sub is not None
    sub.body = text


def _set_key_finding(report: MalwareReport, text: str) -> None:
    report.key_findings[0].text = text


def _set_technique_reason(report: MalwareReport, text: str) -> None:
    report.capability_matrix[0].evidence = [text]
    report.ttp_mappings[0].evidence_quotes = [text]


def _set_recommendation(report: MalwareReport, text: str) -> None:
    report.defensive_recommendations[0].action = text


def _set_note(report: MalwareReport, text: str) -> None:
    report.capability_matrix[1].note = text


def _set_table_cell(report: MalwareReport, text: str) -> None:
    assert report.technical_analysis is not None
    report.technical_analysis.commands[0].description = text


def _set_quoted_reason(report: MalwareReport, text: str) -> None:
    report.capability_matrix[2].not_published = text


# Each kind of text a model writes that reaches a surface, by where it is set.
PLACES: dict[str, Callable[[MalwareReport, str], None]] = {
    "section prose": _set_section_prose,
    "key finding": _set_key_finding,
    "technique reason": _set_technique_reason,
    "recommendation": _set_recommendation,
    "note": _set_note,
    "table cell": _set_table_cell,
    "quoted reason": _set_quoted_reason,
}

# The hand-written forms: the marker for a cited note, the last note and a number
# no note has; the id form; split, spaced, upper-case, percent-encoded and relative
# targets; a note anchor alone; a reference-style link; an HTML anchor; nested
# brackets; another link into the bundle.
FORMS = [
    "[[1]](evidence-bundle.html#cite-1)",
    "[[{last}]](evidence-bundle.html#cite-{last})",
    "[[999]](evidence-bundle.html#cite-999)",
    "[[1]]\n(evidence-bundle.html#cite-1)",
    "[[1]](\nevidence-bundle.html#cite-1)",
    "[[1]]( evidence-bundle.html#cite-1 )",
    "[[1]](EVIDENCE-BUNDLE.HTML#cite-1)",
    "[[1]](evidence%2Dbundle.html#cite-1)",
    "[[1]](evidence\\-bundle.html#cite-1)",
    "[[1]](./evidence-bundle.html#cite-1)",
    "[[1]](<evidence-bundle.html#cite-1>)",
    "[[1]](#note-1)",
    "[[1]](#cite-1)",
    "[1][x]\n\n[x]: evidence-bundle.html#cite-1",
    '<a href="evidence-bundle.html#cite-1">1</a>',
    "[a [b] c](evidence-bundle.html#cite-1)",
    "[Key findings](evidence-bundle.html#sec-key-findings)",
    "![1](evidence-bundle.json)",
]


def _notes(report: MalwareReport) -> list[int]:
    return [note.number for note in MarkdownRenderer(layout=ANALYST).render_with_notes(report)[1]]


def _surfaces(report: MalwareReport) -> dict[str, str]:
    """Every surface as HTML: the HTML products, and each Markdown read by both readers."""
    surfaces = {
        "report.html": HtmlRenderer(layout=ANALYST).render(report),
        "self-contained": HtmlRenderer(layout=ANALYST, self_contained=True).render(report),
        "bundle.html": HtmlRenderer(layout=BUNDLE).render(report),
        "full.html": HtmlRenderer(layout=FULL).render(report),
    }
    for layout in (ANALYST, BUNDLE, FULL):
        markdown = MarkdownRenderer(layout=layout).render(report)
        assert "rendering failed" not in markdown, layout
        closed = _escaped_references(markdown)
        surfaces[f"{layout}.md read"] = HtmlRenderer._markdown_to_html(closed)
        surfaces[f"{layout}.md raw"] = _RAW_HTML.render(closed)
    return surfaces


def _links(rendered: str) -> Counter[str]:
    """Every link target and superscript of a surface."""
    found = Counter(re.findall(r"""<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]*)""", rendered, re.I))
    found["<sup>"] = len(re.findall(r"<sup\b", rendered))
    return found


def _shown(rendered: str) -> str:
    body = rendered.split("<body>", 1)[-1]
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", body)).split())


_BASELINES: dict[str, dict[str, str]] = {}


def _baseline(place: str) -> dict[str, str]:
    """The surfaces of the report with a plain word where ``place`` is set; read once."""
    if place not in _BASELINES:
        plain = rich_report()
        PLACES[place](plain, "zA plain zB")
        _BASELINES[place] = _surfaces(plain)
    return _BASELINES[place]


def _hostile(report: MalwareReport, place: str, form: str) -> tuple[MalwareReport, str]:
    text = form.format(last=_notes(report)[-1])
    held = report.model_copy(deep=True)
    PLACES[place](held, f"zA {text} zB")
    return held, text


@pytest.mark.parametrize("form", FORMS, ids=range(len(FORMS)))
@pytest.mark.parametrize("place", PLACES)
def test_a_hand_written_marker_is_its_characters_on_every_surface(place: str, form: str) -> None:
    report = rich_report()
    held, text = _hostile(report, place, form)
    written, baseline = _surfaces(held), _baseline(place)
    owed = " ".join(text.split())
    # A model's prose keeps its writing: a backslash escape it wrote shows as the
    # character it escapes, as it does today; a value shows the backslash too.
    shown_as = {owed, owed.replace("\\-", "-")}
    printed = 0
    for surface, rendered in written.items():
        # No link and no superscript the plain text does not give.
        assert _links(rendered) == _links(baseline[surface]), (place, form, surface)
        shown = _shown(rendered)
        for found in re.finditer(r"zA (.*?) zB", shown):
            printed += 1
            assert found.group(1) in shown_as, (place, form, surface, found.group(1))
    assert printed, (place, form)


@pytest.mark.parametrize("place", PLACES)
def test_the_id_form_links_to_no_note_the_platform_did_not_set(place: str) -> None:
    # The analyst report moves a cited id to its own note marker, as it moves every
    # id a model cites; the target written by hand is never a link.
    report = rich_report()
    held, text = _hostile(report, place, "[ev_0004](evidence-bundle.html#cite-65)")
    printed = 0
    for surface, rendered in _surfaces(held).items():
        assert not re.search(r"""href\s*=\s*["']?[^"'\s>]*(cite|note)-65\b""", rendered), surface
        shown = _shown(rendered)
        for found in re.finditer(r"zA (.*?) zB", shown):
            printed += 1
            assert found.group(1).endswith("(evidence-bundle.html#cite-65)"), (surface, shown)
            if not surface.startswith(("report.html", "self-contained", "analyst.md")):
                assert found.group(1) == text, (surface, found.group(1))
    assert printed


@pytest.mark.parametrize("place", ["section prose", "key finding", "recommendation"])
def test_a_marker_in_a_code_span_stays_a_code_span(place: str) -> None:
    report = rich_report()
    marker = "[[1]](evidence-bundle.html#cite-1)"
    held, _text = _hostile(report, place, f"`{marker}`")
    spans = 0
    for surface, rendered in _surfaces(held).items():
        spans += rendered.count(f"<code>{marker}</code>")
        assert "\\]" not in _shown(rendered), surface
    assert spans


def test_the_platform_s_markers_and_notes_are_as_they_were() -> None:
    # A report whose model text holds hand-written markers cites the same notes, and
    # its own markers stay superscript links to them.
    report = rich_report()
    notes = _notes(report)
    held = report.model_copy(deep=True)
    for place, put in PLACES.items():
        put(held, f"{place} [[1]](evidence-bundle.html#cite-1) [[999]](#cite-999)")
    assert _notes(held) == notes
    shown = HtmlRenderer(layout=ANALYST).render(report)
    sups = re.findall(r'<sup class="cite"><a href="evidence-bundle.html#cite-(\d+)">', shown)
    assert sups and {int(n) for n in sups} == set(notes)
    contained = HtmlRenderer(layout=ANALYST, self_contained=True).render(held)
    assert {int(n) for n in re.findall(r'<a href="#note-(\d+)">', contained)} == set(notes)


# Texts as the closing pass reads them, and the characters a reader is owed.
CLOSING_TEXTS = [
    "[1][x]\n\n[x]: evidence-bundle.html#cite-1",
    "[1][x]\n\n> [x]:\n> evidence-bundle.html#cite-1",
    '<a href="evidence-bundle.html#cite-1">1</a>',
    "<A HREF='#note-1'>1</A>",
    "<area href=evidence-bundle.json>",
    "- [[1]](evidence-bundle.html#cite-1)",
    "| a | b |\n|---|---|\n| [[1]](evidence-bundle.html#cite-1) | c |",
    '[[1]](evidence-bundle.html#cite-1 "title")',
    "[[1]](evidence-bundle.html?x=1#cite-1)",
    "[[1]](evidence%252Dbundle.html#cite-1)",
    "[[1]](evidence-bundle&#46;html#cite-1)",
    "\\\\[[1]](evidence-bundle.html#cite-1)",
]


def _read(markdown: str) -> list[str]:
    closed = _escaped_references(markdown)
    return [HtmlRenderer._markdown_to_html(closed), _RAW_HTML.render(closed)]


@pytest.mark.parametrize("text", CLOSING_TEXTS, ids=range(len(CLOSING_TEXTS)))
def test_the_closing_pass_leaves_no_hand_written_link_into_the_bundle(text: str) -> None:
    written = _hand_links_unlinked(text)
    for reading in _read(written):
        assert not re.search(r"<a\b|<area\b|<sup\b", reading), (text, reading)
        assert "cite-1" in reading or "note-1" in reading or ".json" in reading, (text, reading)


@pytest.mark.parametrize(
    "text",
    [
        "```\n[[1]](evidence-bundle.html#cite-1)\n```",
        "para\n\n    [[1]](evidence-bundle.html#cite-1)",
        'see `[[1]](evidence-bundle.html#cite-1)` and ``<a href="#cite-1">``',
        "**bold** _em_ `code` [x](https://example.org) [y](#sec-summary) <b>b</b>\n- item",
        "[x](evidence-bundle.html.bak#cite-1) [y](#cite) [z](#citation-1)",
        "\\[[1]\\](evidence-bundle.html#cite-1)",
    ],
)
def test_code_ordinary_markdown_and_other_targets_are_left_byte_for_byte(text: str) -> None:
    assert _hand_links_unlinked(text) == text


def test_an_escaped_bracket_is_left_and_an_escaped_backslash_is_not_an_escape() -> None:
    assert _hand_links_unlinked("[1\\](#cite-1)") == "[1\\](#cite-1)"
    assert _hand_links_unlinked("[1\\\\](#cite-1)") == "[1\\\\\\](#cite-1)"
    # A tag the scan escapes: its closing tag too, so a reader of raw HTML loses nothing.
    assert _hand_links_unlinked('<a href="#cite-1">1</a>') == '\\<a href="#cite-1">1\\</a>'
