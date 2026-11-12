"""The debate's last mean claim confidence is never printed as a bare "Final confidence"."""

from __future__ import annotations

from pathlib import Path

from malspark.analysis import run_summary
from malspark.analysis.run_summary import NEGOTIATION_CONFIDENCE_LABEL

_SRC = Path(run_summary.__file__).resolve().parents[1]


def test_the_three_reader_facing_places_use_the_one_label() -> None:
    assert NEGOTIATION_CONFIDENCE_LABEL == "Mean analyst claim confidence (last round)"
    for rel in ("cli.py", "reporting/renderers/markdown.py"):
        text = (_SRC / rel).read_text(encoding="utf-8")
        assert "NEGOTIATION_CONFIDENCE_LABEL" in text, rel
        assert "Final confidence" not in text, rel
    assert "Final confidence" not in Path(run_summary.__file__).read_text(encoding="utf-8")


def test_the_run_summary_table_prints_the_label() -> None:
    src = Path(run_summary.__file__).read_text(encoding="utf-8")
    assert "| {NEGOTIATION_CONFIDENCE_LABEL} |" in src
