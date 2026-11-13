"""``redact_url`` costs time linear in its text, and its output equals the reference's (T-688).

A URL's scheme starts at the first letter of a run of scheme characters, so a
long run that is no scheme (a token, a dotted name, one long line) is read
once, not from each of its characters. The reference is the per-character
scheme pattern (``_REFERENCE_URL_SPAN``): ``redact_url`` returns what it
returns on every input. The corpus under ``tests/fixtures/redact_url_corpus.json``
holds inputs and the reference's outputs; the credential in every case is
written ``PWPLACEHOLDER`` there and built here (``tests/credential_shapes.py``).
Every ``@`` and ``=`` is stored as the token ``{AT}`` or ``{EQ}`` and expanded here, so
no URL with user-info and no ``name=value`` pair is written in the file.

Two tests hold the cost. ``test_a_long_run_is_read_within_a_second`` is the one
that fails fast: a quadratic pattern takes seconds on its one run. The ratio
test compares growth and fails slowly on a quadratic pattern.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest
from tests.credential_shapes import password
from tests.linear_cost import assert_scales, assert_under

from malspark.core import settings_masking as sm
from malspark.core import settings_overrides as ov

CORPUS = Path(__file__).resolve().parents[2] / "fixtures" / "redact_url_corpus.json"
PLACEHOLDER = "PWPLACEHOLDER"

# The reference: the scheme pattern tried from every character of a run.
_REFERENCE_URL_SPAN = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]*")


@pytest.fixture(autouse=True)
def _no_held_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sm, "held_values", lambda: frozenset())


def _cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = json.loads(CORPUS.read_text(encoding="utf-8"))
    return [
        {
            **case,
            "input": _expanded(str(case["input"])),
            "expected": _expanded(str(case["expected"])),
        }
        for case in cases
    ]


def _expanded(text: str) -> str:
    return text.replace("{AT}", "@").replace("{EQ}", "=")


def test_the_corpus_is_redacted_as_the_reference_redacts_it() -> None:
    cred = password()
    cases = _cases()
    assert len(cases) > 50
    for case in cases:
        text = str(case["input"]).replace(PLACEHOLDER, cred)
        literals = [str(item).replace(PLACEHOLDER, cred) for item in case["literals"]]  # type: ignore[attr-defined]
        got = ov.redact_url(text, by_value=bool(case["by_value"]), literals=literals)
        assert got.replace(cred, PLACEHOLDER) == case["expected"], case["input"]


def test_redact_url_equals_the_reference_on_generated_text() -> None:
    alphabet = list("aZ9+.-:/@?&#= \n\"'<>_") + ["://", "http", "x://", "1.", "token" + "="]
    rnd = random.Random(688)
    for _ in range(4000):
        text = "".join(rnd.choice(alphabet) for _ in range(rnd.choice((4, 12, 60, 200))))
        assert ov.redact_url(text) == _redact_with(_REFERENCE_URL_SPAN, text), text


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
        "see https://h/p?" + "token" + "=x&a=1 and a.b.c ",
        "a@b:c/d@e:f/",
        "k=v&" + "token" + "=1 ",
        "://@a",
    ],
)
def test_the_cost_grows_with_the_text_not_its_square(unit: str) -> None:
    # Eight calls to a call, so the small run clears the helper's 2 ms floor.
    assert_scales(
        lambda size: unit * (size // len(unit)),
        50_000,
        lambda text: [ov.redact_url(text) for _ in range(8)],
        factor=4,
    )


@pytest.mark.parametrize("text", ["A" * 100_000, "a." * 50_000])
def test_a_long_run_is_read_within_a_second(text: str) -> None:
    # Linear: about 1 ms. A quadratic pattern: seconds, so one run is enough to fail.
    assert_under(lambda: ov.redact_url(text), 1.0, what="redact_url", repeats=1)
