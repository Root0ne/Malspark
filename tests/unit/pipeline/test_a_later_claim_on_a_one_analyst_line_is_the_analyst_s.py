"""A later bare "claim N" on a line whose field names one analyst is that analyst's for a ruling.

A mediator writes a line such as "[analysts: TRIAGE ANALYST] Claim 15 asserts
X, and claim 17 asserts Y":

- on a line whose field names exactly one analyst, every later bare
  "claim(s) N" is that analyst's, unless another participant is named
  between the field and it (whole or in a short form: "the reverser's
  analysis in claim 28", "the reverser [claim 28]"), it stands inside a
  mark's reason, it names an earlier round's claim ("Round-2 claim 9"), it
  opens a parenthesis right after another participant's short name ("the
  reverser (claim 28)"), or another participant's name follows it ("claim 4
  of the reverser");
- a ruling at the round limit reads it as the claim right after the field
  is, judged by the whole line's ledger ids and addresses, so the ruling is
  written onto it too;
- the revision merge does not read it as named: a blocking line that only
  mentions it never withdraws it by rule, and the claim is carried;
- a line whose field names two analysts places nothing new.

Every value is synthetic.
"""

from __future__ import annotations

from malspark.pipeline.debate_facts import NO_ANALYST_NAMED, read_claim_references
from malspark.pipeline.limit_rulings import Ruling, mark_claims
from malspark.pipeline.revision_merge import claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["triage", "static", "all_tools_reverser_ghidra", "all_tools_qu1cksc0pe"]

LINE = (
    "[analysts: TRIAGE ANALYST] Claim 15 asserts T1547.014 at 0.40 from ev_0014, and claim 17 "
    "asserts T1120, T1082 and T1012 at 0.40 for the drive-root opens. [blocking: x]"
)


def test_both_claims_of_a_one_analyst_line_are_the_analyst_s_for_a_ruling() -> None:
    references = read_claim_references([LINE], NAMES, whole_line=True)

    assert references.named == {"triage": {15: [(1, True)], 17: [(1, True)]}}
    assert references.unplaced == ()
    # Read as the claim right after the field is: the whole line speaks for it.
    assert 17 not in references.expanded.get("triage", {})


def test_the_merge_s_reading_leaves_the_later_claim_unread() -> None:
    references = read_claim_references([LINE], NAMES)

    assert references.named == {"triage": {15: [(1, True)]}}
    assert [(u.claims, u.why) for u in references.unplaced] == [("claim 17", NO_ANALYST_NAMED)]


def test_a_line_whose_field_names_two_analysts_places_nothing_new() -> None:
    line = LINE.replace("[analysts: TRIAGE ANALYST]", "[analysts: TRIAGE ANALYST, STATIC ANALYST]")

    references = read_claim_references([line], NAMES, whole_line=True)

    assert all(17 not in claims for claims in references.named.values())
    assert any(u.claims == "claim 17" and u.why == NO_ANALYST_NAMED for u in references.unplaced)


def test_a_claim_in_a_parenthesis_after_another_participant_s_short_name_is_not_the_field_s() -> (
    None
):
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed; "
        "the reverser (claim 28) finds no key at ev_0031. [not blocking: wording]"
    )

    references = read_claim_references([line], NAMES, whole_line=True)

    assert references.named.get("triage") == {16: [(1, False)]}
    assert 28 not in references.named.get("triage", {})


def test_a_claim_another_participant_s_name_follows_is_not_the_field_s() -> None:
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed, "
        "against claim 28 of the reverser at ev_0031. [not blocking: wording]"
    )

    references = read_claim_references([line], NAMES, whole_line=True)

    assert 28 not in references.named.get("triage", {})


def test_a_claim_after_another_participant_s_name_is_not_the_field_s() -> None:
    line = (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed, while "
        "ALL_TOOLS_REVERSER_GHIDRA reads it otherwise, and claim 28 finds no key. [blocking: x]"
    )

    references = read_claim_references([line], NAMES, whole_line=True)

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


def test_a_claim_after_another_participant_s_short_name_is_not_the_field_s() -> None:
    for later in (
        "but the reverser's analysis in claim 28 finds no key",
        "but the reverser [claim 28] finds no key",
    ):
        line = (
            "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed at ev_0031, "
            f"{later}. [blocking: x]"
        )

        references = read_claim_references([line], NAMES, whole_line=True)

        assert references.named.get("triage") == {16: [(1, True)]}, later


def test_an_earlier_round_s_claim_without_a_name_is_not_the_field_s() -> None:
    for earlier in ("Round-2 claim 9", "round 2's claim 9"):
        line = (
            "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed at ev_0031, "
            f"against {earlier}. [blocking: x]"
        )

        references = read_claim_references([line], NAMES, whole_line=True)

        assert references.named.get("triage") == {16: [(1, True)]}, earlier


STATIC_IN_FORCE = AgentISR(
    agent_id="static",
    domain="static",
    claims=[
        ClaimEvidence(
            claim="The beacon waits 600 s between requests.",
            evidence_ref="[ev_0001]",
            confidence=0.6,
        ),
        *(
            ClaimEvidence(
                claim=f"Filler claim {n}.", evidence_ref=f"[ev_09{n:02d}]", confidence=0.6
            )
            for n in range(2, 20)
        ),
        ClaimEvidence(
            claim="The sleep call takes 900 s.", evidence_ref="[ev_0010]", confidence=0.6
        ),
    ],
)


def test_a_blocking_line_that_mentions_a_later_claim_carries_it() -> None:
    line = (
        "[analysts: STATIC ANALYST] Claim 1 still states the beacon waits 600 s, while the "
        "ledger (ev_0010) and the analyst's own claim 20 give 900 s. [blocking: restate claim 1]"
    )
    revision = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(
                claim="The beacon waits 900 s between requests.",
                evidence_ref="[ev_0010]",
                confidence=0.6,
            )
        ],
    )

    named = claims_named_in_force([line], NAMES, {"static": STATIC_IN_FORCE})
    merge = merge_revision(STATIC_IN_FORCE, revision, "the revision", 2, named.get("static"))

    assert [n for n, *_ in merge.withdrawn_by_rule] == []
    assert 20 in [n for n, _s in merge.carried]
