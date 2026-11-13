"""``redact_url`` costs time linear in its text, and its output is the one it always had (T-688).

A URL's scheme starts at the first letter of a run of scheme characters, so a
long run that is no scheme (a token, a dotted name, one long line) must be
read once, not from each of its characters. The corpus under
``tests/fixtures/redact_url_corpus.json`` holds inputs and the output the
function gave for each before the scheme pattern was anchored to a run's
start; the credential in every case is written ``PWPLACEHOLDER`` there and
built here (``tests/credential_shapes.py``).
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest
from tests.credential_shapes import password
from tests.linear_cost import assert_scales

from malspark.core import settings_masking as sm
from malspark.core import settings_overrides as ov

CORPUS = Path(__file__).resolve().parents[2] / "fixtures" / "redact_url_corpus.json"
PLACEHOLDER = "PWPLACEHOLDER"

# The scheme pattern as it was written before it was anchored to a run's start.
_OLD_URL_SPAN = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]*")


@pytest.fixture(autouse=True)
def _no_held_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sm, "held_values", lambda: frozenset())


def _cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = json.loads(CORPUS.read_text(encoding="utf-8"))
    return cases


def test_the_corpus_is_redacted_as_before() -> None:
    cred = password()
    cases = _cases()
    assert len(cases) > 50
    for case in cases:
        text = str(case["input"]).replace(PLACEHOLDER, cred)
        literals = [str(item).replace(PLACEHOLDER, cred) for item in case["literals"]]  # type: ignore[attr-defined]
        got = ov.redact_url(text, by_value=bool(case["by_value"]), literals=literals)
        assert got.replace(cred, PLACEHOLDER) == case["expected"], case["input"]


def test_redact_url_matches_the_unanchored_scheme_pattern() -> None:
    alphabet = list("aZ9+.-:/@?&#= \n\"'<>_") + ["://", "http", "x://", "1.", "token="]
    rnd = random.Random(688)
    for _ in range(4000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.choice((4, 12, 60, 200))))
        assert ov.redact_url(text) == _redact_with(_OLD_URL_SPAN, text), text


def _redact_with(pattern: re.Pattern[str], text: str) -> str:
    saved = ov._URL_SPAN
    ov._URL_SPAN = pattern
    try:
        return str(ov.redact_url(text))
    finally:
        ov._URL_SPAN = saved


@pytest.mark.parametrize(
    "unit",
    [
        "A",
        "a.",
        "ab-1+",
        "see https://h/p?token=x&a=1 and a.b.c ",
        "a@b:c/d@e:f/",
        "k=v&token=1 ",
        "://@a",
    ],
)
def test_the_cost_grows_with_the_text_not_its_square(unit: str) -> None:
    # Four calls to a call, so the small run is long enough to read a ratio from.
    assert_scales(
        lambda size: unit * (size // len(unit)),
        100_000,
        lambda text: [ov.redact_url(text) for _ in range(4)],
        factor=4,
    )
