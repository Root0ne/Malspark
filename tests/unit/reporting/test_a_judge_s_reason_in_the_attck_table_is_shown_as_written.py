"""A judge's reason in the ATT&CK table is a quote: its characters are shown as written.

The table's status cell, the list of claims not published and the analyst report's list of
them print the platform's words around the judge's reason ("the judge dropped it (…)"), and
a row's note opens with the platform's words. The reason is cut to its width and each
sentence a check left standing is marked, both on the record's characters; every piece
between the marks is then written as text. Nothing in the judge's words forms a link, a code
span or emphasis, no escape is cut, and the reader is shown exactly the characters the cut
keeps; a line ending inside the reason counts as one space before the cut. The run
summary's corroboration table prints the same reason after its own words, written the same
way. Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import html
import re

import pytest

from malspark.reporting.judge_reasons import JUDGE_REASON_WIDTH, status_parts, status_shown
from malspark.reporting.models import (
    CapabilityCell,
    FileHashes,
    FlaggedStatement,
    MalwareReport,
    SampleIdentity,
)
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.markdown import (
    MarkdownRenderer,
    _Context,
    _defanged_text,
    _escaped_references,
    _flag_mark,
    _quote_written,
    _value_parts,
)
from malspark.schemas.isr_models import judge_dropped_reason

# A judge's reason holding a code span, a link, a pipe, bold, a backslash and a reference.
REASON = "the claim says `a` [l](#t) | **b** \\ &lt; x"
# The elements a judge's words could form.
FORMED = ("code", "a", "strong", "em", "del", "h1", "h2", "pre")


def _reading(markdown: str) -> str:
    """The HTML report's reading of ``markdown``, after the render's closing pass."""
    return HtmlRenderer._markdown_to_html(_escaped_references(markdown))


def _elements(rendered: str) -> dict[str, int]:
    return {name: len(re.findall(rf"<{name}[\s>/]", rendered)) for name in FORMED}


def _shown(rendered: str) -> str:
    """The text a reader sees: no element, references read, white space as one space."""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", rendered)).split())


def _kept(text: str, width: int) -> str:
    """The characters the cut keeps of ``text``, as the record holds them, on one line."""
    return " ".join(status_shown(text, width, _defanged_text).split())


# A status whose judge's reason is cut by its own rule, one cut to the width, and one whose
# cut leaves a bracket open for the platform to close.
STATUSES = [
    judge_dropped_reason(REASON),
    judge_dropped_reason(" ".join([REASON] * 8)),
    "the judge described it: " + " ".join([REASON] * 8),
    "the judge described it: (" + " ".join([REASON] * 8),
]


@pytest.mark.parametrize("status", STATUSES, ids=range(len(STATUSES)))
def test_a_status_cut_at_any_width_shows_the_characters_the_cut_keeps(status: str) -> None:
    # On either side of every width, the written status forms no element and shows the
    # characters the cut keeps, the cut mark and the closing brackets among them: no
    # backslash left dangling, no reference halved by the writer, no code span opened.
    for width in range(20, len(status) + 2):
        written = _quote_written(status_parts(status, width, _value_parts))
        reading = _reading(f"- {written}")
        assert _elements(reading) == dict.fromkeys(FORMED, 0), (width, written)
        assert _shown(reading) == _kept(status, width), (width, written)


def test_a_status_cut_to_its_width_is_written_as_this_frozen_line() -> None:
    # The cut falls before the judge's stars: it keeps whole words up to the width, closes
    # the bracket it leaves open after the cut mark, and every kept character the reader
    # would take as Markdown is escaped.
    status = "the judge described it: (" + " ".join([REASON] * 3)
    written = _quote_written(status_parts(status, 60, _value_parts))
    assert written == "the judge described it: (the claim says \\`a\\` \\[l\\](#t) \\|\u2026)"


def test_a_line_ending_inside_a_quote_counts_as_one_space_before_the_cut() -> None:
    # Each line ending, ``\r\n`` or ``\n``, is one space before the cut is made, so the cut
    # counts it as one character and may fall at it as at any space.
    status = "the judge described it: " + "ab\r\ncd\n" * 40
    written = _quote_written(status_parts(status, 200, _value_parts))
    assert written == "the judge described it: " + "ab cd " * 28 + "ab cd\u2026"
    assert len(written) == 198


def test_a_status_written_in_a_cell_keeps_the_table_separator_to_the_row() -> None:
    written = _quote_written(status_parts(STATUSES[0], 200, _value_parts), pipes=False)
    assert " | " in written
    assert "\\`a\\`" in written


def test_a_flagged_sentence_of_a_judge_s_reason_keeps_its_mark() -> None:
    # The mark the platform sets after a flagged sentence is its own: it stays a mark,
    # while the judge's own stars around it show as characters.
    sentence = "The routine at 0x5e10 reads **one** buffer."
    ctx = _Context(MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64))))
    mark = _flag_mark("report.sample_code", "label")
    ctx.flagged = [(sentence, mark)]
    ctx._by_words = set()
    status = judge_dropped_reason(f"{sentence} It frees `it`.")
    written = _quote_written(status_parts(status, JUDGE_REASON_WIDTH, ctx.quoted))
    reading = _reading(f"- {written}")
    assert written.count(mark) == 1
    assert _elements(reading)["strong"] == 1
    assert _elements(reading)["code"] == 0
    assert f"{sentence} [" in _shown(reading)
    assert "It frees `it`." in _shown(reading)


def _report(reason: str) -> MalwareReport:
    """A report naming one technique the judge dropped and one it kept with a note."""
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published=judge_dropped_reason(reason),
            ),
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1057",
                technique_name="Process Discovery",
                evidence=["Routine 0x5a10 lists processes [ev_0101]."],
                note=f"carried forward: the revision did not write it again ({reason})",
            ),
        ],
        run_summary={"profile": {"analysts": ["static"]}},
    )


@pytest.mark.parametrize("reason", [REASON, " ".join([REASON] * 8)], ids=["whole", "cut"])
@pytest.mark.parametrize("layout", ["analyst", "bundle", "full"])
def test_every_layout_shows_the_judge_s_words_and_forms_none_of_their_elements(
    layout: str, reason: str
) -> None:
    # Against the same report with plain words, the judge's words form no element on any
    # layout, and the reason is shown with the characters its cut keeps.
    written = _reading(MarkdownRenderer(layout=layout).render(_report(reason)))
    plain = _reading(MarkdownRenderer(layout=layout).render(_report("the claim says a l b x")))
    assert _elements(written) == _elements(plain)
    shown = _shown(written)
    assert _kept(judge_dropped_reason(reason), JUDGE_REASON_WIDTH) in shown
    assert f"({REASON}" in shown


def test_the_analyst_report_s_held_line_cut_to_its_width_with_a_sentence_left_out() -> None:
    # A status cut to its width whose judge's reason has a sentence the agreement question
    # left out: the line prints without that sentence, the platform's cut mark stays its own,
    # and every other character is written as text.
    left = "Beta **b** goes."
    status = judge_dropped_reason(f"Alpha `a` stays. {left}") + ", " + "then a check said `x` " * 12
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="sample.dll"),
        verdict="Malware",
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published=status,
            )
        ],
        flagged_statements=[
            FlaggedStatement(
                sentence=left, code="agreement.dropped", left_out=["attack_note.T1055"]
            )
        ],
        run_summary={"profile": {"analysts": ["static"]}},
    )
    markdown = MarkdownRenderer(layout="analyst").render(report)
    line = (
        "- T1055 Process Injection: claimed, not published: the judge dropped it "
        "(Alpha \\`a\\` stays.), " + "then a check said \\`x\\` " * 6 + "then a\u2026"
    )
    assert line in markdown.splitlines()
    assert "Beta" not in markdown
    assert _elements(_reading(line)) == dict.fromkeys(FORMED, 0)


@pytest.mark.parametrize("layout", ["bundle", "full"])
def test_the_corroboration_table_writes_the_judge_s_reason_as_text_with_its_marks(
    layout: str,
) -> None:
    # The corroboration row of a technique not published prints the platform's words and
    # the judge's reason in one cell: the judge's backticks, stars and backslashes show as
    # written, and the mark after a sentence a check left standing stays the platform's.
    sentence = "The routine at 0x5e10 reads **one** buffer."
    reason = f"{sentence} It runs `net view \\\\host`."
    report = _report(REASON)
    report.flagged_statements = [
        FlaggedStatement(sentence=sentence, code="report.sample_code", label="label")
    ]
    report.run_summary = {
        **(report.run_summary or {}),
        "corroboration": {
            "T1135": {"claimed_by": ["static"], "not_published": judge_dropped_reason(reason)}
        },
    }
    markdown = MarkdownRenderer(layout=layout).render(report)
    (row,) = [line for line in markdown.splitlines() if line.startswith("| T1135 (")]
    mark = _flag_mark("report.sample_code", "label")
    assert row.count(mark) == 1
    cell = row.split(" | ")[0].removeprefix("| ")
    reading = _reading(cell)
    assert _elements(reading) == {**dict.fromkeys(FORMED, 0), "strong": 1}
    shown = _shown(reading)
    assert f"({sentence} [" in shown
    assert "It runs `net view \\\\host`.)" in shown
