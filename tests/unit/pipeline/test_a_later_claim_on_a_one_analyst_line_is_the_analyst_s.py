"""A later bare "claim N" on a line whose field names one analyst is that analyst's.

A mediator writes a line such as "[analysts: TRIAGE ANALYST] Claim 15 asserts
X, and claim 17 asserts Y". The earlier reading read only the claim right
after the field for the analyst and left "claim 17" for no analyst unless
"its" stood before it. Now:

- on a line whose field names exactly one analyst, every later bare
  "claim(s) N" is that analyst's, unless another participant is named
  between the field and it, it stands inside a mark's reason, it opens a
  parenthesis right after another participant's short name ("the reverser
  (claim 28)"), or another participant's name follows it ("claim 4 of the
  reverser");
- it is judged by the whole line's ledger ids and addresses, as the claim
  right after the field is, so a ruling at the round limit is written onto
  it too;
- a line whose field names two analysts places nothing new.

Every value is synthetic.
"""

from __future__ import annotations

from malspark.pipeline.debate_facts import NO_ANALYST_NAMED, read_claim_references
from malspark.pipeline.limit_rulings import Ruling, mark_claims
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["triage", "static", "all_tools_reverser_ghidra", "all_tools_qu1cksc0pe"]

LINE = (
    "[analysts: TRIAGE ANALYST] Claim 15 asserts T1547.014 at 0.40 from ev_0014, and claim 17 "
    "asserts T1120, T1082 and T1012 at 0.40 for the drive-root opens. [blocking: x]"
)


def test_both_claims_of_a_one_analyst_line_are_the_analyst_s() -> None:
    references = read_claim_references([LINE], NAMES)

    assert references.named == {"triage": {15: [(1, True)], 17: [(1, True)]}}
    assert references.unplaced == ()
    # Read as the claim right after the field is: the whole line speaks for it.
    assert 17 not in references.expanded.get("triage", {})


def test_a_line_whose_field_names_two_analysts_places_nothing_new() -> None:
    line = LINE.replace("[analysts: TRIAGE ANALYST]", "[analysts: TRIAGE ANALYST, STATIC ANALYST]")

    references = read_claim_references([line], NAMES)

    assert all(17 not in claims for claims in references.named.values())
    assert any(u.claims == "claim 17" and u.why == NO_ANALYST_NAMED for u in references.unplaced)


def test_a_claim_in_a_parenthesis_after_another_participant_s_short_name_is_not_the_field_s() -> (
    None
):
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed; "
        "the reverser (claim 28) finds no key at ev_0031. [not blocking: wording]"
    )

    references = read_claim_references([line], NAMES)

    assert references.named.get("triage") == {16: [(1, False)]}
    assert 28 not in references.named.get("triage", {})


def test_a_claim_another_participant_s_name_follows_is_not_the_field_s() -> None:
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed, "
        "against claim 28 of the reverser at ev_0031. [not blocking: wording]"
    )

    references = read_claim_references([line], NAMES)

    assert 28 not in references.named.get("triage", {})


def test_a_claim_after_another_participant_s_name_is_not_the_field_s() -> None:
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed, while "
        "ALL_TOOLS_REVERSER_GHIDRA reads it otherwise, and claim 28 finds no key. [blocking: x]"
    )

    references = read_claim_references([line], NAMES)

    assert 28 not in references.named.get("triage", {})


def _claim(text: str, ref: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.4)


def test_a_limit_ruling_on_the_line_is_written_onto_both_claims() -> None:
    isrs = {
        "triage": AgentISR(
            agent_id="triage",
            domain="triage",
            claims=[_claim(f"Filler claim {n}.", f"[ev_09{n:02d}]") for n in range(1, 15)]
            + [
                _claim("T1547.014 is used for persistence.", "[ev_0014]"),
                _claim("Filler claim 16.", "[ev_0916]"),
                _claim("T1120, T1082 and T1012 are used.", "[ev_0006] [ev_0012] [ev_0014]"),
            ],
        )
    }

    out = mark_claims([LINE], {1: Ruling(1, True, "r")}, isrs, NAMES, 5)

    claims = out.isrs["triage"].claims
    assert claims[14].limit_rulings and claims[16].limit_rulings
    assert not claims[15].limit_rulings
    assert not any("reads no analyst" in s for s in out.sentences)
