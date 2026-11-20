"""A prompt built from one state is one text under every hash seed.

The revision directive an analyst is sent, the mediation and verdict prompts
the judge is sent (the verdict's retry with its questions included) and the
static chunk with the analyst's first prompt over it are built from one
fixture state in two processes, each salting string hashes its own way. A
line whose order or member is taken from a set's iteration order makes the
two texts differ. ``prompt_texts.py`` builds them; no model is called.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest

HELPER = Path(__file__).with_name("prompt_texts.py")
SEEDS = ("1", "2")


@cache
def _built() -> tuple[dict[str, Any], ...]:
    """The helper's output per seed, the two processes run at once."""
    running = [
        subprocess.Popen(  # noqa: S603 - this interpreter and a script of this repository
            [sys.executable, str(HELPER)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for seed in SEEDS
    ]
    built: list[dict[str, Any]] = []
    for seed, process in zip(SEEDS, running, strict=True):
        out, err = process.communicate(timeout=180)
        assert process.returncode == 0, f"seed {seed}: {err[-2000:]}"
        built.append(json.loads(out))
    return tuple(built)


@pytest.mark.parametrize(
    ("part", "carries"),
    [
        # Each text carries the line a set used to order, so an equal pair
        # is not a pair of texts that lost it.
        ("debate_directive", "is listed in ev_0002"),
        ("judge.mediation", "states match_count = 3"),
        ("judge.verdict", "the sources that named T1055 are"),
        ("analyst", "Python (embedded"),
    ],
)
def test_the_prompt_is_one_text_under_both_seeds(part: str, carries: str) -> None:
    texts = []
    for built in _built():
        held: Any = built
        for key in part.split("."):
            held = held[key]
        texts.append(json.dumps(held, indent=1))
    assert carries in texts[0]
    assert texts[0] == texts[1]


def test_the_verdict_s_retry_and_history_are_built() -> None:
    first, retry = _built()[0]["judge"]["verdict"]
    assert first.count("its mark was not read") == 4
    assert "stix.credit_without_claim" in retry
