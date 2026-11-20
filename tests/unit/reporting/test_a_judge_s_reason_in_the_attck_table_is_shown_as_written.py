"""A judge's reason in the ATT&CK table is a quote: its characters are shown as written.

The table's status cell, the list of claims not published and the analyst report's list of
them print the platform's words around the judge's reason ("the judge dropped it (…)"), and
a row's note opens with the platform's words. The reason is cut to its width and each
sentence a check left standing is marked, both on the record's characters; every piece
between the marks is then written as text. Nothing in the judge's words forms a link, a code
span or emphasis, no escape is cut, and the reader is shown exactly the characters the cut
keeps. Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import html
import re

import pytest

from malspark.reporting.judge_reasons import JUDGE_REASON_WIDTH, status_parts, status_shown
from malspark.reporting.models import CapabilityCell, FileHashes, MalwareReport, SampleIdentity
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
