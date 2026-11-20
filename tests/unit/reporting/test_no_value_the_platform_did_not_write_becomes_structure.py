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
start. A platform sentence quoting a model's words, alone or with a value, as
one string, is written whole by the inline rule, the model's words shown as
the record holds them; where the platform cuts it to a width or marks a
sentence in it, the cut and the marks are made on its characters and each
piece between them is written by the inline rule after the cut. A model's
line keeps the writing model prose has.

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

from malspark.analysis.coverage import NEGATIVES_INTRO as COVERAGE_NEGATIVES_INTRO
from malspark.pipeline.mediation_models import mediator_no_answer_note
from malspark.reporting.ledger_report import shortened_sentence
from malspark.reporting.models import (
    CapabilityCell,
    DynamicBehavior,
    EvidenceIndexRow,
    EvidenceSection,
    ExportRow,
    ExternalReference,
    FileHashes,
    MalwareReport,
    PESection,
    QuestionAnswer,
    ReportFrontMatter,
    SampleIdentity,
    SandboxSignature,
    SignatureInfo,
    StaticAnalysis,
    VersionHistoryEntry,
)
from malspark.reporting.renderers import markdown as markdown_module
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.markdown import (
    MarkdownRenderer,
    _absent_mark,
    _code_span,
    _Context,
    _escaped_references,
    _evidence_body,
    _item,
    _one_line,
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
    # The forms of a citation only the platform sets (T-814).
    "[[1]](evidence-bundle.html#cite-1)",
    "[ev_0001](evidence-bundle.html#cite-1)",
    "[1](#note-1)",
    '<a href="evidence-bundle.html#cite-1">1</a>',
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


@pytest.mark.parametrize(
    "marker",
    [
        "[[1]](evidence-bundle.html#cite-1)",
        "[x](evidence-bundle.html#sec-key-findings)",
        "[1](#note-1)",
        '<a href="evidence-bundle.html#cite-1">1</a>',
    ],
)
def test_a_model_s_line_cites_no_note_and_keeps_its_other_writing(marker: str) -> None:
    # A model's line through the closing pass: a citation only the platform sets is
    # printed as its characters, and the line's bold and code span stay its own.
    ctx = _context()
    line = _prose_item(f"first, **bold** `code` {marker}")
    written = MarkdownRenderer()._closed([line], ctx)
    plain = MarkdownRenderer()._closed([_prose_item("first, **bold** `code` x")], ctx)
    for reading, baseline in zip(_readings(written), _readings(plain), strict=True):
        assert _elements(reading) == _elements(baseline), (marker, reading)
        assert _shown(reading).endswith(_same_words(html.unescape(marker))), (marker, reading)


# ---------------------------------------------------------------------------
# The places of a report, every layout
# ---------------------------------------------------------------------------


def _report(text: str, n: int) -> MalwareReport:
    """A report whose sample, tool, sandbox and operator texts are ``text`` before a marker each."""
    marks = iter(range(n * 100, n * 100 + 99))

    def v() -> str:
        return f"{text} zq{next(marks)}z"

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
        references=[ExternalReference(source=v(), url="https://attack.mitre.org/", note=v())],
        degradation_reasons=[v()],
        operator_choices=[v()],
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
        # The platform's sentences quoting a model's words, alone or with a
        # value, each one string.
        question_answers=[QuestionAnswer(question=v(), outcome="not_determinable", checks=[v()])],
        # A status with the judge's reason in one cell, and a note opening with the
        # platform's words: each one string the platform's words and a model's share.
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published=v(),
            ),
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1057",
                technique_name="Process Discovery",
                evidence=["Lists processes."],
                note=v(),
            ),
        ],
        run_summary={
            "profile": {"name": v(), "analysts": [v()]},
            "stages": [{"key": "static", "ran": False, "reason": v()}],
            "evidence": {
                "entries": 1,
                "failures": [{"tool": "probe", "server": v(), "error": v(), "remediation": v()}],
            },
            "negotiation": {
                "rounds_completed": 1,
                **{
                    key: [v()]
                    for key in (
                        "not_blocking",
                        "limit_rulings",
                        "revision_replacements",
                        "unread_marks",
                        "ledger_facts",
                        "ledger_stated",
                    )
                },
            },
            "validation": {
                "retries": 1,
                "unresolved": [
                    {"agent": "static", "code": "report.citation_wrong_entry", "message": v()},
                    {"agent": "sandbox", "code": "stix.unpublishable_endpoint", "message": v()},
                ],
                "retry_drops": [{"sentence": v()}],
                "retry_withdrawals": [{"sentence": v()}],
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


# ---------------------------------------------------------------------------
# A section's text, a reference's target, a mediation note, a quoted claim
# ---------------------------------------------------------------------------

# Section texts carrying a tool's JSON key, a section name or unbalanced
# backticks, and a platform sentence with a span of its own.
SECTION_TEXTS = [
    shortened_sentence(
        {
            "shortened": {
                "/rows`QK1 [l](#t)` and `<img src=x onerror=alert(1)>`": {"omitted": 3, "kept": 2}
            }
        }
    ),
    "The section carries no `x`y` mutexes.",
    "a ``` b ` c `` d",
    "The section carries no `mutexes`.",
    "two lines\n# heading\n    code\n- item\n```",
]


def _table_section(text: str) -> EvidenceSection:
    return EvidenceSection(
        key="probe_table", title="Probe", kind="table", columns=["A"], rows=[["r"]], text=text
    )


@pytest.mark.parametrize("text", SECTION_TEXTS, ids=range(len(SECTION_TEXTS)))
def test_a_section_s_text_prints_every_character_and_forms_no_span(text: str) -> None:
    ctx = _context()
    written = "\n".join(_evidence_body(_table_section(text), ctx.plain))
    plain = "\n".join(_evidence_body(_table_section("plain"), ctx.plain))
    for reading, baseline in zip(_readings(written), _readings(plain), strict=True):
        assert _elements(reading) == _elements(baseline), (text, reading)
        assert _same_words(text) in _shown(reading), (text, reading)


# Operator targets ending in a backslash, escaping the closing parenthesis, or
# holding a double quote; the last is already percent-encoded. A target with a
# backslash in its path is no link a reference keeps (:func:`_reference_lookup`)
# and prints defanged, every character of it shown.
TARGETS = [
    ("https://x.example/a\\", "https://x.example/a%5C", False),
    ("https://x.example/a\\)<img src=x>", "https://x.example/a%5C%29%3Cimg%20src=x%3E", False),
    ('https://x.example/a" title', "https://x.example/a%22%20title", True),
    ("https://x.example/a%20%29b", "https://x.example/a%20%29b", True),
]


@pytest.mark.parametrize(("url", "target", "kept"), TARGETS)
def test_a_reference_target_stays_one_link_and_its_text_loses_no_character(
    url: str, target: str, kept: bool
) -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        references=[ExternalReference(source="Source", url=url, note="note")],
    )
    for layout in LAYOUTS:
        markdown = MarkdownRenderer(layout=layout).render(report)
        product, raw = _readings(markdown)
        for reading in (product, raw):
            assert _elements(reading)["img"] == 0, (layout, url)
        if kept:
            for reading in (product, raw):
                anchors = re.findall(r'<a href="([^"]*)"[^>]*>(.*?)</a>', reading)
                assert (html.escape(target), "Source") in anchors, (layout, url, anchors)
        else:
            shown = target.replace("https://x.example", "hxxps://x[.]example")
            assert f"[Source]({shown}) — note" in _shown(product), (layout, url)


def test_a_mediation_note_carrying_a_provider_s_text_forms_no_structure() -> None:
    reason = "provider said <img src=x onerror=alert(1)> **b** [l](#t) `c` ~~s~~ <u>u</u>"

    def report(note: str) -> MalwareReport:
        return MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"negotiation": {"rounds_completed": 1, "mediation_notes": [note]}},
        )

    note = mediator_no_answer_note(reason)
    for layout in ("bundle", "full"):
        written = MarkdownRenderer(layout=layout).render(report(note))
        plain = MarkdownRenderer(layout=layout).render(report(mediator_no_answer_note("plain")))
        for reading, baseline in zip(_readings(written), _readings(plain), strict=True):
            assert _elements(reading) == _elements(baseline), (layout, reading)
            assert _same_words(note) in _shown(reading), layout


def _shown_whole(report: Any, baseline: Any, said: str, layouts: tuple[str, ...]) -> None:
    """Each layout of ``report`` forms the elements of ``baseline`` and shows ``said`` whole."""
    for layout in layouts:
        written = MarkdownRenderer(layout=layout).render(report)
        plain = MarkdownRenderer(layout=layout).render(baseline)
        for reading, held in zip(_readings(written), _readings(plain), strict=True):
            assert _elements(reading) == _elements(held), (layout, reading)
            assert _same_words(said) in _shown(reading), layout


def test_an_operator_s_model_name_in_a_check_of_an_answer_is_shown_whole() -> None:
    # A stop reason names the operator's model inside the platform's check of
    # an answer: the check is written whole as text, its backticks shown.
    from malspark.core.spend import SpendCeilingStop
    from malspark.reporting.question_round import unanswered

    def report(model: str) -> MalwareReport:
        stop = SpendCeilingStop(f"a report call of {model} was not made: over the ceiling")
        return MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            question_answers=unanswered(["Q?"], f"the question round was not written: {stop}"),
        )

    model = "acme`x [l](#t) | # h \\ &lt;`-v2"
    held = report(model)
    said = _defanged_lines(held.question_answers[0].checks[0])
    # The analyst report lists each question with its outcome, not its checks.
    _shown_whole(held, report("acme-v2"), said, ("bundle", "full"))


def test_an_observed_endpoint_quoted_by_a_finding_is_shown_whole() -> None:
    # An export's decline quotes a URL a sandbox observed: the finding's
    # message is written whole as text, its backticks shown.
    from malspark.pipeline.nodes import _note_export_findings
    from malspark.reporting.models import NetworkIOCs, NetworkURL
    from malspark.reporting.renderers.stix_renderer import _unpublishable_endpoints

    def report(url: str) -> MalwareReport:
        made = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            network=NetworkIOCs(urls=[NetworkURL(url=url, source="sandbox")]),
        )
        _note_export_findings(made, _unpublishable_endpoints(made, []))
        return made

    held = report("http://intranet.local/a`b [x](#t) | # h \\ &lt; <b>y</b>`c")
    (row,) = held.run_summary["validation"]["unresolved"]
    assert row["agent"] == "sandbox"
    said = _defanged_lines(row["message"])
    # The export's decisions are listed with the run's checks, which the
    # analyst report leaves to the bundle.
    _shown_whole(held, report("http://intranet.local/abc"), said, ("bundle", "full"))


def _defanged_lines(text: str) -> str:
    """``text`` as a reader is shown it: defanged, on one line."""
    return _context().plain(_one_line(text))


# Every character a placeholder of a quoted claim could be made of, and the
# shapes of the placeholders themselves.
MARK_CHARACTERS = "".join(
    chr(code) for code in (*range(0x09), *range(0x0E, 0x20), *range(0xFDD0, 0xFDF0))
)
MARK_SHAPES = "\x00claim0\x00 \x00\x00claim0\x00\x00 \x000\x00v0\x000\x00 \x001\x00v1\x001\x00"


def _coverage_report(record: dict) -> str:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"coverage": record},
    )
    return MarkdownRenderer().render(report)


def _negatives(claims: list[str]) -> list[dict]:
    return [{"agent": "static", "negative": claim, "coverage": "unknown"} for claim in claims]


def test_a_coverage_record_holding_every_mark_character_prints_each_value_whole() -> None:
    kind = f"{MARK_CHARACTERS} {MARK_SHAPES} kind"
    record = {
        "v": 1,
        "tools": [{"tool": "probe", "kind": kind, "calls": 1}],
        "negatives": _negatives([f"No mutex zc0z {MARK_SHAPES}", "No pipe zc1z"]),
    }
    markdown = _coverage_report(record)
    assert "rendering failed" not in markdown
    assert COVERAGE_NEGATIVES_INTRO in markdown
    # A coverage value stays on its line (:func:`_one_line`); every other character is its own.
    assert _one_line(kind) in markdown
    lines = markdown.splitlines()
    (first,) = [line for line in lines if "zc0z" in line]
    (second,) = [line for line in lines if "zc1z" in line]
    assert f"No mutex zc0z {MARK_SHAPES}" in first and "zc1z" not in first
    assert "No pipe zc1z" in second and "zc0z" not in second


def test_the_mark_of_a_quoted_claim_stays_short_whatever_the_record_holds() -> None:
    nuls = "\x00" * 100_000
    claims = [f"No value zc{n}z" for n in range(50)]
    record = {
        "v": 1,
        "tools": [{"tool": "probe", "kind": f"{nuls} {MARK_SHAPES}", "calls": 1}],
        "negatives": _negatives(claims),
    }
    assert len(_absent_mark(record)) < 32
    markdown = _coverage_report(record)
    assert "rendering failed" not in markdown
    lines = markdown.splitlines()
    for n, claim in enumerate(claims):
        (line,) = [held for held in lines if f"zc{n}z" in held]
        assert claim in line
        assert len(line) < 2 * len(claim) + 400


def test_the_mark_is_found_in_one_pass_however_many_fences_the_record_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fences that share their NULs, the densest a text can hold them.
    fences = "\x00" + "".join(f"{n}\x00" for n in range(20_000))
    record = {"tools": [{"tool": "probe", "kind": fences}], "long": "\x00" + "7" * 5_000 + "\x00"}
    assert _absent_mark(record) == "\x0020000\x00"
    assert _absent_mark(record, start=5) == "\x0020000\x00"
    assert _absent_mark({"kind": "\x000\x00 \x002\x00"}) == "\x001\x00"

    reads = []
    whole = markdown_module._texts_of
    monkeypatch.setattr(markdown_module, "_texts_of", lambda held: reads.append(1) or whole(held))
    assert _absent_mark(record) == "\x0020000\x00"
    assert len(reads) == 1


def test_a_writer_keeping_no_mark_ends_in_each_line_composed_from_its_parts() -> None:
    # A writer that drops every mark it is given, over a record holding the
    # fence of every try: the fences tried are bounded, and each line is then
    # composed from its parts, the platform's words by the line's writer and
    # each value by the value's, with no mark and every backtick shown.
    tried: list[str] = []

    def line(text: str) -> str:
        tried.append(text)
        return markdown_module._inline_safe(text.replace("\x00", ""))

    def build(word: Any) -> list[str]:
        return [f"Mutex {word('a`b')} held by {word('`c`')}.", f"Again {word('a`b')}"]

    def value(text: str) -> str:
        return _code_span(text)

    tries = markdown_module._PLACING_TRIES
    record = {"held": "".join(f"\x00{n}\x00v{n}\x00{n}\x00" for n in range(tries + 1))}
    written = markdown_module._placed(build, line, value, record)
    assert written == [
        f"Mutex {_code_span('a`b')} held by {_code_span('`c`')}.",
        f"Again {_code_span('a`b')}",
    ]
    assert len(tried) == tries * 2 + 4
    assert not any("\x00" in text for text in written)
    reading = HtmlRenderer._markdown_to_html(_item(written[0]))
    assert re.findall(r"<code>(.*?)</code>", reading) == ["a`b", "`c`"]


def test_a_context_naming_one_value_marks_it_where_the_table_builds_it() -> None:
    # A context naming one value only is written whole by the value writer
    # where it holds no mark, so no surface tells the two apart: the table
    # hands each such value to its writer of a value's place.
    from malspark.reporting.builder import ioc_table
    from malspark.reporting.models import StringIOC
    from tests.unit.reporting._report_shapes import rich_report

    report = rich_report()
    assert report.static is not None
    report.static.interesting_strings = [
        *report.static.interesting_strings,
        StringIOC(value="C:\\Users\\a.txt", kind="path", notes="no`te"),
    ]
    report.sections = [
        *report.sections,
        EvidenceSection(
            key="artifact_iocs",
            title="Indicators",
            kind="table",
            source="artifact:static",
            columns=["Listed by", "Evidence", "Type", "Value"],
            rows=[["an`alyst", "ev_0001", "mutex", "Global\\named"]],
        ),
    ]
    contexts = {row.value: row.context for row in ioc_table(report, word=lambda t: f"<{t}>")}
    assert contexts["C:\\Users\\a.txt"] == "<no`te>"
    assert contexts["Global\\named"] == "listed by the <an`alyst> analyst"
