"""The ``strings`` tool's description says when ``match_offsets`` is given and what it holds.

A row's ``offset`` is where its run starts, so a run whose only match begins
at its start carries no ``match_offsets``: the run's ``offset`` already is
that match's. Where a match begins after the run's start, the row carries
``match_offsets`` with every match of that run, the one at its start
included. The description the model reads says exactly that.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from malspark.tools import strings as tool

ROOT = Path(__file__).resolve().parents[3]

SENTENCE = (
    "A row's ``offset`` is where its run starts; where ``pattern`` matched text "
    "that begins after a run's start, ``match_offsets`` gives where each match "
    "in that run starts in the file."
)

LEAD = b"\x00" * 40
MARKER = b"marker-text"
FILLER = b" alpha beta gamma "


@pytest.fixture(scope="module")
def analysis() -> Any:
    path = ROOT / "services" / "analysis-mcp" / "server.py"
    spec = importlib.util.spec_from_file_location("analysis_mcp_match_offsets_words", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _row(tmp_path: Path, run: bytes) -> dict[str, Any]:
    target = tmp_path / "runs.bin"
    target.write_bytes(LEAD + run + b"\x00")
    (row,) = tool.strings(str(target), pattern="marker-text")["strings"]
    found: dict[str, Any] = row
    return found


def test_the_description_says_when_the_key_is_given(analysis: Any) -> None:
    described = " ".join((analysis.strings.__doc__ or "").split())

    assert SENTENCE in described


def test_a_run_whose_only_match_is_at_its_start_carries_no_key(tmp_path: Path) -> None:
    row = _row(tmp_path, MARKER + FILLER)

    assert row["offset"] == len(LEAD)
    assert "match_offsets" not in row


def test_a_later_match_gives_every_match_of_the_run_the_start_match_included(
    tmp_path: Path,
) -> None:
    row = _row(tmp_path, MARKER + FILLER + MARKER)

    assert row["match_offsets"] == [len(LEAD), len(LEAD) + len(MARKER) + len(FILLER)]
