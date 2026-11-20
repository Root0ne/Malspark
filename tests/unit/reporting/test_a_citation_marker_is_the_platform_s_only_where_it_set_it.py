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
from html.parser import HTMLParser

import pytest
from markdown_it import MarkdownIt

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE, FULL
from malspark.reporting.renderers.markdown import MarkdownRenderer, _escaped_references
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
# targets; a note anchor alone; a reference-style link; an HTML anchor, also one with
# a "<" or a ">" inside a quoted attribute value; nested brackets; another link into
# the bundle.
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
    '<a title="<" href="evidence-bundle.html#cite-1">1</a>',
    "<a title='>' href='#note-1'>1</a>",
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
        # Read as the render leaves it, after its own closing pass.
        markdown = MarkdownRenderer(layout=layout).render(report)
        assert "rendering failed" not in markdown, layout
        surfaces[f"{layout}.md read"] = HtmlRenderer._markdown_to_html(markdown)
        surfaces[f"{layout}.md raw"] = _RAW_HTML.render(markdown)
    return surfaces


class _Tags(HTMLParser):
    """The tags of a surface as a browser reads them, quoted attribute values whole."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: Counter[str] = Counter()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("sup", "img"):
            self.found[f"<{tag}>"] += 1
        for name, value in attrs:
            if name in ("href", "src", "action") and value is not None:
                self.found[value] += 1


def _links(rendered: str) -> Counter[str]:
    """Every link target, image and superscript of a surface."""
    tags = _Tags()
    tags.feed(rendered)
    tags.close()
    return tags.found


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
    shown = HtmlRenderer(layout=ANALYST).render(held)
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
    # A tag read as a browser reads it: a quoted attribute value holds a "<" or a ">",
    # both kinds of quote, attributes in any order, upper-case names, a line ending
    # inside the tag, a tag inside a tag's attributes.
    '<a title="<" href="evidence-bundle.html#cite-1">1</a>',
    "<a title='<' href=#note-1>1</a>",
    '<a title=">" href="#cite-1">1</a>',
    "<a title=\"it's\" alt='say \"x\"' href='#cite-1'>1</a>",
    '<a href="#cite-1" title="<">1</a>',
    '<A TITLE="<" HREF="#CITE-1">1</A>',
    '<a title="<"\nhref="#cite-1">1</a>',
    '<a <a href="#cite-1">1</a>',
    # An HTML block, which a reader of raw HTML passes through: in a paragraph's place,
    # in a list item, with the tag escaped by a backslash; an anchor in a table cell.
    'x\n\n<div>\n<a href="evidence-bundle.html#cite-1">1</a>\n</div>\n\ny',
    '- <div>\n  <a href="#cite-1">1</a>\n  </div>',
    'x\n\n<div>\n\\<a href="#cite-1">1</a>\n</div>\n\ny',
    '| a | b |\n|---|---|\n| <a href="#cite-1">1</a> | c |',
]


def _closed(text: str) -> str:
    """``text`` through the closing pass as the renderer runs it: what the scan writes
    is set aside from the reference escape, then put back."""
    from malspark.reporting.renderers.markdown import _hand_links_unlinked

    kept: dict[str, str] = {}

    def keep(held: str) -> str:
        token = f"\x00k{len(kept)}\x00"
        kept[token] = held
        return token

    closed = _escaped_references(_hand_links_unlinked(text, keep))
    for token, held in kept.items():
        closed = closed.replace(token, held)
    return closed


def _read(markdown: str) -> list[str]:
    return [HtmlRenderer._markdown_to_html(markdown), _RAW_HTML.render(markdown)]


@pytest.mark.parametrize("text", CLOSING_TEXTS, ids=range(len(CLOSING_TEXTS)))
def test_the_closing_pass_leaves_no_hand_written_link_into_the_bundle(text: str) -> None:
    for reading in _read(_closed(text)):
        assert not _links(reading), (text, reading)
        shown = _shown(reading)
        assert "cite-1" in shown.lower() or "note-1" in shown or ".json" in shown, (text, shown)
        # A tag prints as its characters, with no character reference left as text.
        assert "&lt;" not in shown and "&amp;" not in shown, (text, shown)
        if "<a " in text.lower():
            assert "<a " in shown.lower(), (text, shown)


@pytest.mark.parametrize(
    "text",
    [
        '<a title="x href=#cite-1>1</a>',
        "<a href='evidence-bundle.html#cite-1>1</a>",
        "<p>\n<a title=\"it's\" href='#note-1>1</a>\n</p>",
    ],
)
def test_a_tag_left_with_an_unclosed_quote_has_its_opening_written_as_text(text: str) -> None:
    from malspark.reporting.renderers.markdown import _hand_links_unlinked

    written = _hand_links_unlinked(text)
    assert "&lt;a " in written and "<a " not in written, written


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
    from malspark.reporting.renderers.markdown import _hand_links_unlinked

    assert _hand_links_unlinked(text) == text


def test_an_escaped_bracket_is_left_and_an_escaped_backslash_is_not_an_escape() -> None:
    from malspark.reporting.renderers.markdown import _hand_links_unlinked

    assert _hand_links_unlinked("[1\\](#cite-1)") == "[1\\](#cite-1)"
    assert _hand_links_unlinked("[1\\\\](#cite-1)") == "[1\\\\\\](#cite-1)"
    # A tag the scan escapes: its closing tag too, so a reader of raw HTML loses nothing.
    # Its "<" is written as a character reference, which is text in a paragraph, in a
    # table cell and in an HTML block alike. A backslash escaping it is one only outside
    # an HTML block: there the tag is left, inside one it gives way to the reference.
    assert _hand_links_unlinked('<a href="#cite-1">1</a>') == '&lt;a href="#cite-1">1&lt;/a>'
    assert _hand_links_unlinked('\\<a href="#cite-1">1</a>') == '\\<a href="#cite-1">1</a>'
    assert (
        _hand_links_unlinked('<div>\n\\<a href="#cite-1">1</a>\n</div>')
        == '<div>\n&lt;a href="#cite-1">1&lt;/a>\n</div>'
    )
    assert _hand_links_unlinked('\\\\<a href="#cite-1">1') == '\\\\&lt;a href="#cite-1">1'


# A raw HTML block in text the platform did not write, by where it is set: one that
# opens a line of section prose, one that opens a list item, and one in a table cell.
BLOCKS = {
    "section prose": 'x\n\n<div>\nzA <a href="evidence-bundle.html#cite-1">1</a> zB\n</div>\n\ny',
    "key finding": '<div>\nzA <a href="evidence-bundle.html#cite-1">1</a> zB\n</div>',
    "table cell": '<div>\nzA <a href="evidence-bundle.html#cite-1">1</a> zB\n</div>',
}


@pytest.mark.parametrize("place", BLOCKS)
def test_an_anchor_inside_a_raw_html_block_is_its_characters_on_every_surface(place: str) -> None:
    held = rich_report()
    PLACES[place](held, BLOCKS[place])
    baseline = _baseline(place)
    printed = 0
    for surface, rendered in _surfaces(held).items():
        # No link the plain text does not give. (A block that opens a list item takes the
        # rest of its line, the platform's marker after it too, as raw HTML: a model's
        # block start keeps its writing, so a reader of raw HTML shows that marker as text.)
        assert not _links(rendered) - _links(baseline[surface]), (place, surface)
        for found in re.finditer(r"zA (.*?) zB", _shown(rendered)):
            printed += 1
            assert found.group(1) == '<a href="evidence-bundle.html#cite-1">1</a>', (
                place,
                surface,
                found.group(1),
            )
    assert printed, place


def _note_of(report: MalwareReport, evidence_id: str) -> int:
    notes = MarkdownRenderer(layout=ANALYST).render_with_notes(report)[1]
    return next(note.number for note in notes if note.evidence_ids == (evidence_id,))


# A character text the platform did not write puts directly before or after a place the
# platform sets its marker: an image's "!", a backslash, an opening bracket before; a
# closing bracket, an opening parenthesis after.
JOINS = [
    "See![ev_0004] here",
    "See\\[ev_0004] here",
    "See[[ev_0004] here",
    "See [ev_0004]] here",
    "See [ev_0004](here)",
]


@pytest.mark.parametrize("text", JOINS, ids=range(len(JOINS)))
@pytest.mark.parametrize("place", ["section prose", "key finding", "recommendation"])
def test_a_character_beside_a_marker_leaves_it_the_platform_s_link(place: str, text: str) -> None:
    held = rich_report()
    PLACES[place](held, f"zA {text} zB")
    number = _note_of(held, "ev_0004")
    baseline = _baseline(place)
    surfaces = _surfaces(held)
    rendered = surfaces["report.html"]
    sup = f'<sup class="cite"><a href="evidence-bundle.html#cite-{number}">{number}</a></sup>'
    assert sup in rendered, (place, text)
    contained = surfaces["self-contained"]
    assert re.search(rf'<a href="#note-{number}">', contained), (place, text)
    for surface in ("report.html", "self-contained", "analyst.md read", "analyst.md raw"):
        found = _links(surfaces[surface])
        assert found["<img>"] == _links(baseline[surface])["<img>"], (place, text, surface)
        # The HTML products print the marker as a superscript number, the Markdown as
        # the bracketed number its link holds.
        number_shown = str(number) if surface.endswith(("html", "contained")) else f"[{number}]"
        owed = " ".join(text.replace("[ev_0004]", f" {number_shown} ").split())
        assert f"zA {owed} zB" in _shown(surfaces[surface]), (place, text, surface)
