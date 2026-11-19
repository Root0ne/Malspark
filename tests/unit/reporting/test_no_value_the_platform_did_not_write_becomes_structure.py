"""Text of the sample, a tool, a sandbox or the operator never becomes Markdown or HTML structure.

Such a value is written by the inline rule (``_inline_safe``: every character
Markdown reads escaped, ``~`` among them, then the run's defang; a cell and any
other place differ only in the table separator), a platform sentence that
carries one by ``ctx.inline`` (its code spans kept), and a value printed as code
by ``_code_span``. Where the text can open a block, at the start of a list
item, a step or a paragraph, the block-start rule (``_paragraph_line``) writes
it after the inline rule; a heading escapes each ``#`` of its title. A run of
backticks opens a fence only where no backtick follows it on the line, so a
value printed as a code span with a longer fence stays one span at an item's
start. A model's line keeps the writing model prose has.

What is read: the HTML report's own reader and a reader that takes raw HTML.
Between its markers a payload forms no element its plain baseline does not,
and the reader is shown exactly its characters.
"""

from __future__ import annotations

import html
import re
from typing import Any

import pytest
from markdown_it import MarkdownIt

from malspark.reporting.models import (
    DynamicBehavior,
    EvidenceIndexRow,
    EvidenceSection,
    ExportRow,
    ExternalReference,
    FileHashes,
    MalwareReport,
    PESection,
    ReportFrontMatter,
    SampleIdentity,
    SandboxSignature,
    SignatureInfo,
    StaticAnalysis,
    VersionHistoryEntry,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.markdown import (
    MarkdownRenderer,
    _code_span,
    _Context,
    _escaped_references,
    _item,
    _paragraph_line,
    _plain_heading,
    _prose_item,
    _row,
    _step,
)

# The forms that open a block at the start of a line or of a list item's text
# (CommonMark 0.31, GFM 0.29), and the inline forms anywhere.
BLOCK_STARTS = [
    "---",
    "- - -",
    "   ---",
    "***",
    "___",
    "# heading",
    "###### heading",
    "=====",
    "- nested",
    "+ nested",
    "* nested",
    "1. ordered",
    "1) ordered",
    "    indented code",
    "\tindented code",
    "```py",
    "~~~py",
    "> quote",
    "[label]: #target",
    "[^1]: note",
    "|---|---|",
    "- [ ] task",
    "<script>run()</script>",
    "<!-- comment -->",
    "<?php run ?>",
    "<!DOCTYPE html>",
    "<![CDATA[data]]>",
    "<div>block</div>",
]
INLINE_FORMS = [
    "[link](#target)",
    "![image](#target)",
    "[1]",
    "**strong**",
    "__strong__",
    "*em*",
    "_em_",
    "~~struck~~",
    "~struck~",
    "`pair`",
    "``pair``",
    "a``b",
    "<https://relay.example/x>",
    "<user@relay.example>",
    "<u>under</u>",
    "&amp; &#60;",
    "title #",
    "\\\\host\\share",
    "C:\\",
    "CN=`x` a",
]
PAYLOADS = BLOCK_STARTS + INLINE_FORMS
# A value printed as a code span that holds a run of two backticks, at the
# start of an item and of a step.
TICK_RUNS = ["Global\\a``b", "``", "x``", "a`b", "vssadmin delete ``shadows"]

# Every element a value could form; counted against the place's plain baseline.
ELEMENTS = (
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "ol",
    "ul",
    "li",
    "pre",
    "blockquote",
    "table",
    "tr",
    "td",
    "th",
    "a",
    "img",
    "sup",
    "strong",
    "em",
    "s",
    "del",
    "code",
    "script",
    "div",
    "u",
)
_RAW_HTML = MarkdownIt("commonmark", {"html": True}).enable("table").enable("strikethrough")


def _readings(markdown: str) -> list[str]:
    """The HTML report's own reading of a Markdown text, and one that takes raw HTML.

    The text is read as a render leaves it: after the closing pass, which escapes
    the ``&`` of each character reference outside code.
    """
    closed = _escaped_references(markdown)
    return [HtmlRenderer._markdown_to_html(closed), _RAW_HTML.render(closed)]


def _elements(rendered: str) -> dict[str, int]:
    return {name: len(re.findall(rf"<{name}[\s>/]", rendered)) for name in ELEMENTS}


def _shown(rendered: str) -> str:
    """The text a reader sees: no element, references read, white space as one space."""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", rendered)).split())


def _same_words(text: str) -> str:
    return " ".join(text.split())


def _context() -> _Context:
    return _Context(MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64))))


# ---------------------------------------------------------------------------
# The writers, one place at a time
# ---------------------------------------------------------------------------


def _places(ctx: _Context) -> dict[str, Any]:
    """Each writer at its place, with the shown text it owes the reader."""

    def cell(v: str) -> str:
        return "\n".join([_row("Field", "Value"), "|---|---|", _row("x", ctx.value(v))])

    return {
        "cell": (cell, ctx.plain),
        "item": (lambda v: _item(ctx.value(v, pipes=True)), ctx.plain),
        "step": (lambda v: _step(1, ctx.value(v, pipes=True)), ctx.plain),
        "heading": (lambda v: _plain_heading(ctx.value(v, pipes=True)), ctx.plain),
        "paragraph": (lambda v: _paragraph_line(ctx.value(v, pipes=True)), ctx.plain),
        "sentence item": (lambda v: _item(ctx.inline(f"Said: {v}")), None),
        "value form item": (lambda v: _item(_code_span(v)), str),
        "value form step": (lambda v: _step(1, _code_span(v)), str),
        # A platform sentence's span: its network values defanged with the sentence.
        "kept span item": (lambda v: _item(ctx.inline(_code_span(v))), ctx.plain),
    }


@pytest.mark.parametrize("payload", PAYLOADS)
@pytest.mark.parametrize(
    "place",
    [
        "cell",
        "item",
        "step",
        "heading",
        "paragraph",
        "value form item",
        "value form step",
        "kept span item",
    ],
)
def test_a_value_forms_no_structure_and_is_shown_whole(place: str, payload: str) -> None:
    ctx = _context()
    write, owed = _places(ctx)[place]
    baseline = _readings(write("plain"))
    for reading, plain in zip(_readings(write(payload)), baseline, strict=True):
        assert _elements(reading) == _elements(plain), (place, payload, reading)
        shown, expected = _shown(reading), _same_words(owed(payload))
        assert shown.endswith(expected) or shown == expected, (place, payload, shown)


@pytest.mark.parametrize("payload", BLOCK_STARTS + ["~~struck~~", "<u>under</u>", "[link](#x)"])
def test_a_platform_sentence_carrying_a_value_forms_no_structure(payload: str) -> None:
    ctx = _context()
    write, _ = _places(ctx)["sentence item"]
    for reading, plain in zip(_readings(write(payload)), _readings(write("plain")), strict=True):
        assert _elements(reading) == _elements(plain), (payload, reading)


@pytest.mark.parametrize("value", TICK_RUNS)
@pytest.mark.parametrize("place", ["value form item", "value form step", "kept span item"])
def test_a_code_span_with_a_longer_fence_stays_one_span_at_the_start(
    place: str, value: str
) -> None:
    ctx = _context()
    write, _ = _places(ctx)[place]
    reading = HtmlRenderer._markdown_to_html(write(value))
    assert re.findall(r"<code>(.*?)</code>", reading, re.S) == [html.escape(value, quote=False)]


@pytest.mark.parametrize("value", TICK_RUNS)
def test_a_platform_sentence_s_span_keeps_every_character_of_its_value(value: str) -> None:
    ctx = _context()
    reading = HtmlRenderer._markdown_to_html(_item(ctx.inline(f"Mutex {_code_span(value)} held")))
    assert re.findall(r"<code>(.*?)</code>", reading, re.S) == [html.escape(value, quote=False)]


def test_struck_text_is_escaped_in_a_cell_and_anywhere_else() -> None:
    ctx = _context()
    assert ctx.value("~s~ ~~s~~") == "\\~s\\~ \\~\\~s\\~\\~"
    assert ctx.value("a|b", pipes=True) == "a\\|b"
    assert ctx.value("a|b") == "a|b"


def test_a_model_s_line_keeps_the_writing_of_model_prose() -> None:
    # A list a model writes at its line's start stays the model's.
    assert _prose_item("1. first, **bold**") == "- 1. first, **bold**"
    assert _prose_item("> quoted") == "- \\> quoted"


# ---------------------------------------------------------------------------
# The places of a report, every layout
# ---------------------------------------------------------------------------


def _report(text: str, n: int) -> MalwareReport:
    """A report whose sample, tool, sandbox and operator texts are ``text`` before a marker each.

    A platform sentence that carries such a text (``x()``) keeps a balanced
    backtick pair as a span by its rule, so it holds the text only when the
    text holds none.
    """
    marks = iter(range(n * 100, n * 100 + 99))
    sentence = "plain" if re.search(r"`[^`]+`", text) else text

    def v() -> str:
        return f"{text} zq{next(marks)}z"

    def x() -> str:
        return f"{sentence} zq{next(marks)}z"

    return MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256="a" * 64),
            file_type=v(),
            mime_type=v(),
            signing=SignatureInfo(is_signed=True, signer_subject=v(), signer_issuer=v()),
        ),
        verdict="Malware",
        front_matter=ReportFrontMatter(
            publisher=v(), product_type=v(), version=v(), report_date=v(), report_number=v()
        ),
        version_history=[VersionHistoryEntry(version=v(), date=v(), authors=v(), description=v())],
        references=[ExternalReference(source=x(), url="https://attack.mitre.org/", note=x())],
        degradation_reasons=[x()],
        operator_choices=[x()],
        evidence_index=[EvidenceIndexRow(id="ev_0001", agent=v(), server=v(), tool=v())],
        sections=[
            EvidenceSection(
                key="probe_table",
                title=v(),
                kind="table",
                columns=[v(), "Second"],
                rows=[["row", "cell"]],
                items=[v()],
                evidence_ids=["ev_0001"],
            )
        ],
        static=StaticAnalysis(
            sections=[PESection(name=".text", virtual_address=v(), characteristics=v())],
            export_rows=[ExportRow(name="Run", ordinal=1, rva=v())],
            api_technique_hits=[
                {
                    "technique_id": "T1027",
                    "rule": v(),
                    "source": v(),
                    "benign_rate": v(),
                    "evidence_id": v(),
                }
            ],
        ),
        dynamic=DynamicBehavior(
            sandbox_signatures=[SandboxSignature(name=v(), description=v(), technique_ids=[v()])]
        ),
        run_summary={
            "profile": {"name": v(), "analysts": [v()]},
            "stages": [{"key": "static", "ran": False, "reason": x()}],
            "evidence": {
                "entries": 1,
                "failures": [{"tool": "probe", "server": v(), "error": x(), "remediation": x()}],
            },
        },
    )


LAYOUTS = ("analyst", "bundle", "full")


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_no_place_of_a_report_lets_a_value_form_structure(payload: str) -> None:
    # The payload set in every place at once, against the same report with a
    # plain word there: each layout read by both readers forms the same
    # elements, and every marker is shown after the payload's own characters.
    for layout in LAYOUTS:
        written = MarkdownRenderer(layout=layout).render(_report(payload, 1))
        plain = MarkdownRenderer(layout=layout).render(_report("plain", 1))
        for reading, baseline in zip(_readings(written), _readings(plain), strict=True):
            assert _elements(reading) == _elements(baseline), (layout, payload)
            shown = _shown(reading)
            owed = _same_words(_context().plain(payload))
            for mark in re.findall(r"zq\d+z", _shown(baseline)):
                assert f"{owed} {mark}" in shown or f"plain {mark}" in shown, (
                    layout,
                    payload,
                    mark,
                )


# A reference service's lookup of another sample, as a value may hold it.
LOOKUP = "https://www.virustotal.com/gui/file/" + "b" * 64


def test_a_reference_lookup_inside_a_value_is_defanged_as_any_url() -> None:
    ctx = _context()
    assert "https://" not in ctx.value(LOOKUP)
    assert "https://" not in ctx.value(f"see [x]({LOOKUP})")


def test_a_value_s_lookup_is_no_link_and_the_platform_s_reference_stays_one() -> None:
    # The platform's own link position keeps its target; a value holding a
    # lookup prints it defanged, so no reader draws it as an anchor.
    own = "https://www.virustotal.com/gui/file/" + "a" * 64
    report = MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256="a" * 64),
            signing=SignatureInfo(is_signed=True, signer_subject=f"[x]({LOOKUP}) {LOOKUP}"),
        ),
        verdict="Malware",
        references=[ExternalReference(source="VirusTotal", url=own, note="detections")],
    )
    for layout in LAYOUTS:
        markdown = MarkdownRenderer(layout=layout).render(report)
        assert LOOKUP not in markdown, layout
        rendered = HtmlRenderer._markdown_to_html(markdown)
        assert f'href="{LOOKUP}"' not in rendered
        assert f'href="{own}"' in rendered, layout
