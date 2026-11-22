"""A layout bound on the page says what it left out and where the whole is.

The report keeps its layout: a table value cut to fit, a long list shown in
part, a figure of a few rows, a drafted detection rule of a readable size. Each
of those now says so — how many were left out and that the JSON report, the
evidence ledger or the IOC table carries every one — so nothing on the page
reads as the whole when it is not.
"""

from __future__ import annotations

from malspark.reporting.detection_signatures import LEFT_OUT_COMMENT
from malspark.reporting.figures import _figure_left_out
from malspark.reporting.renderers.markdown import (
    CUT_CELL_SENTENCE,
    LEFT_OUT_LINE,
    _left_out,
)


class TestAListShownInPart:
    def test_says_how_many_more_and_where(self) -> None:
        assert _left_out(45, 40, "mutexes") == [
            "",
            LEFT_OUT_LINE.format(rest=5, what="mutexes"),
        ]
        assert "the JSON report carries every one" in LEFT_OUT_LINE

    def test_a_list_shown_whole_says_nothing(self) -> None:
        assert _left_out(40, 40, "mutexes") == []
        assert _left_out(3, 40, "mutexes") == []


class TestACutValue:
    def test_the_methodology_says_where_the_text_a_cut_was_made_from_is_held(self) -> None:
        assert "ends in …" in CUT_CELL_SENTENCE
        assert "The JSON report holds the text each of these was cut from." in CUT_CELL_SENTENCE

    def test_the_methodology_states_no_universal_over_the_cuts(self) -> None:
        words = CUT_CELL_SENTENCE.lower().split()
        assert not {"no", "never", "every", "whole"} & {w.strip(".,;:") for w in words}


class TestAFigure:
    def test_counts_what_it_did_not_draw(self) -> None:
        said = _figure_left_out(52, 40, "processes")
        assert said.startswith(" 12 more processes are not drawn")
        assert _figure_left_out(40, 40, "processes") == ""


class TestADraftedRule:
    def test_says_how_many_indicators_it_leaves_to_the_ioc_table(self) -> None:
        said = LEFT_OUT_COMMENT.format(rest=7, what="domains")
        assert said.startswith("7 more published domains are not in this draft")
        assert "IOC table" in said


def test_no_model_reads_the_methodology_s_cut_sentence() -> None:
    """The sentence is written by the report renderer only: no module of the pipeline, the
    agents, the prompts or the model-facing reporting code names it."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    readers = sorted(
        str(path.relative_to(root))
        for path in (root / "src").rglob("*.py")
        if "CUT_CELL_SENTENCE" in path.read_text(encoding="utf-8")
    )
    assert readers == ["src/malspark/reporting/renderers/markdown.py"]
