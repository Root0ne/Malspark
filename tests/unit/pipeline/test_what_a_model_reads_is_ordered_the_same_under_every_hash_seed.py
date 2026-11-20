"""What a model reads lists its entries and names in an order read from the data.

The debate facts, the judge's credit question, the analysts' language line
and the judge's history text each turn a set into an order, or pick one
member of it. A set of strings is iterated differently in each process, so
each order is a stated function of the members: analyst names longest first,
then by the name; technique ids sorted; of two python libraries the longest
name, then by the name; unread lines in the order the mediator wrote them.
``written_orders.py models`` prints them; it runs here under four seeds, one
process each.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import Any

HELPER = Path(__file__).with_name("written_orders.py")
SEEDS = ("0", "1", "2", "3")

# Written in the helper as DEBATE_LINE.
LINE = (
    "[analysts: triage, static, script, memory] triage claim 1 and static claim 1 read the "
    "decoder, script claim 1 and memory claim 1 read the writer: 3 matches against 4 matches"
)


@cache
def _read() -> dict[str, dict[str, Any]]:
    """The helper's output per seed, the four processes run at once."""
    running = {
        seed: subprocess.Popen(  # noqa: S603 - this interpreter and a script of this repository
            [sys.executable, str(HELPER), "models"],
            env={**os.environ, "PYTHONHASHSEED": seed},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for seed in SEEDS
    }
    read: dict[str, dict[str, Any]] = {}
    for seed, process in running.items():
        out, err = process.communicate(timeout=120)
        assert process.returncode == 0, f"seed {seed}: {err[-2000:]}"
        read[seed] = json.loads(out)
    return read


def _each_seed(key: str) -> list[Any]:
    return [orders[key] for orders in _read().values()]


def test_the_debate_count_fact_names_the_analysts_longest_first_then_by_name() -> None:
    # memory, script, static, triage: their entries ev_0009, ev_0008, ev_0007, ev_0006.
    said = "; ".join(f"entry ev_{n:04d} (yara_scan) states match_count = 3" for n in (9, 8, 7, 6))
    for facts in _each_seed("debate_facts"):
        assert facts["counts"] == [f'For the line "{LINE}": {said}.']


def test_the_debate_place_fact_prints_the_spelling_of_the_first_name_read() -> None:
    # memory writes the writer as an offset and static the decoder as a
    # virtual address; script's and triage's spellings of the same two
    # functions are skipped.
    said = "0x2000 is listed in ev_0003; 0x401000 is listed in ev_0002"
    for facts in _each_seed("debate_facts"):
        assert facts["places"] == [f'For the line "{LINE}": {said}.']


def test_the_credit_question_lists_the_sources_of_sorted_sub_techniques() -> None:
    # T1055.001's sources (capa, yara_scan) before T1055.012's (sigma).
    for question in _each_seed("credit_question"):
        (message,) = question
        assert "the sources that named T1055 are capa, yara_scan, sigma_match_sandbox —" in message


def test_the_language_line_names_the_longest_python_library_then_by_name() -> None:
    for line in _each_seed("language_line"):
        assert line == "Python (embedded python311.dll)"


def test_the_history_text_lists_unread_lines_in_the_order_written() -> None:
    for text in _each_seed("history_text"):
        rows = [r for r in text.splitlines() if "its mark was not read" in r]
        assert [r.rsplit(") ", 1)[1] for r in rows] == [
            "zeta reads the key",
            "alpha reads the key",
            "mu reads the key",
            "kappa reads the key",
        ]


def test_every_seed_reads_one_text() -> None:
    read = _read()
    for seed, orders in read.items():
        assert orders == read["0"], f"seed {seed} differs from seed 0"
