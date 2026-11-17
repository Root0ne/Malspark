"""A TECHNIQUE line that opens with NONE and names no technique id claims none.

NONE is the word the format declares for a claim of no technique. A line that
opens with it and names no technique id anywhere, bracketed or not, is read as
no technique whatever note follows ("None; Process Injection is likely"); the
note, the line as written, stays on the claim's record (``technique_note``),
and no question is asked about it. A line that opens with NONE and names an id
may assert it ("none asserted beyond T1140") or set it aside ("none; T1027 not
observed"), which code cannot tell without reading the words: it is read as
before. A line that puts an id first and a doubt after it is asked about as
before, and so is a line whose every id is followed by words that do not
assert it.

Every id, address and sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from malspark.agents.base_agent import read_claim_blocks, read_technique_line
from malspark.pipeline.validation import TECHNIQUE_LINE_UNREAD_CODE, parse_violations
from malspark.schemas.isr_models import AgentISR

NONE_FIRST = (
    "None; Process Injection is likely",
    "none observed, though native api use is possible",
    "**NONE** — the capability label only (capa rule, not observed)",
    "NONE. The shared modules are the loader's, not the sample's.",
    "none (persistence covered by the scheduled-task claim)",
)
# A line that opens with NONE and names an id, bracketed or not: asked as before.
NONE_WITH_AN_ID = (
    "none asserted beyond T1140 for the decoded name.",
    "NONE (persistence covered by T1053.005)",
    "none (T1055 covers the observed injection)",
    "none (I do not tag T1573.001 on this evidence)",
    "none asserted; T1041 would apply if transmission is shown",
    "NONE, T1027",
)


@pytest.mark.parametrize("line", NONE_FIRST)
def test_a_line_that_opens_with_none_is_read_as_none(line: str) -> None:
    assert read_technique_line(line) == ((), None)


@pytest.mark.parametrize("line", NONE_WITH_AN_ID)
def test_a_none_line_that_names_an_id_is_asked_as_before(line: str) -> None:
    claims = _claims(line)
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    assert read_technique_line(line) == ((), line)
    assert [
        (c.technique_id, c.technique_line, c.technique_note)  # type: ignore[attr-defined]
        for c in claims
    ] == [(None, line, None)]
    assert TECHNIQUE_LINE_UNREAD_CODE in [v.code for v in parse_violations(isr)]


@pytest.mark.parametrize(
    "line",
    [
        # An id first and a doubt after it: asked, as before.
        "T1129 (capa rule-asserted, not observed)",
        "T1559 (lead only)",
        "T1129 (0.7)",
        "T1055; none other",
        "T1129 (Shared Modules). Asserted as code-level behaviour, not as sandbox-observed.",
        # Every id followed by words of not asserting: not read by code.
        "T1027.002 not asserted",
        "T1027 withheld, T1140 withdrawn",
        # A word that only begins with the letters of "none".
        "nonexistent T1027",
        "Nonetheless T1055",
        "Nonetheless Process Injection is likely",
        # "none" later on a line that names no id.
        "Process Injection; none other",
    ],
)
def test_a_line_that_does_not_open_with_none_is_asked_as_before(line: str) -> None:
    assert read_technique_line(line) == ((), line)


def _claims(technique: str) -> list[object]:
    return list(
        read_claim_blocks(
            "CLAIM: Routine 0x401000 writes no autostart value.\n"
            "EVIDENCE: [ev_0024] install routine\n"
            "CONFIDENCE: 0.8\n"
            f"TECHNIQUE: {technique}\n"
        ).claims
    )


@pytest.mark.parametrize("line", NONE_FIRST)
def test_its_note_stays_on_the_claim_and_no_question_is_asked(line: str) -> None:
    claims = _claims(line)
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    assert [
        (c.technique_id, c.technique_line, c.technique_note)  # type: ignore[attr-defined]
        for c in claims
    ] == [(None, None, line)]
    assert TECHNIQUE_LINE_UNREAD_CODE not in [v.code for v in parse_violations(isr)]


@pytest.mark.parametrize("line", ["NONE", "none", "**NONE**", "NONE.", "—"])
def test_a_line_that_is_none_alone_keeps_no_note(line: str) -> None:
    claim = _claims(line)[0]

    assert (claim.technique_id, claim.technique_line, claim.technique_note) == (  # type: ignore[attr-defined]
        None,
        None,
        None,
    )


def test_a_claim_with_no_note_is_serialised_as_before() -> None:
    claim = _claims("NONE")[0]

    assert "technique_note" not in claim.model_dump()  # type: ignore[attr-defined]


def test_an_id_first_line_keeps_its_question() -> None:
    line = "T1129 (capa rule-asserted, not observed)"
    claims = _claims(line)
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    assert [(c.technique_id, c.technique_line) for c in claims] == [(None, line)]  # type: ignore[attr-defined]
    assert TECHNIQUE_LINE_UNREAD_CODE in [v.code for v in parse_violations(isr)]
