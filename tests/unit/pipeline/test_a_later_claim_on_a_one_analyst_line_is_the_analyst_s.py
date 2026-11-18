"""A later bare "claim N" on a line whose field names one analyst is that analyst's for a ruling.

A mediator writes a line such as "[analysts: TRIAGE ANALYST] Claim 15 asserts
X, and claim 17 asserts Y":

- on a line whose field names exactly one analyst, a later bare "claim(s) N"
  is that analyst's only where its own clause shares a ledger id or an
  address with that claim of the analyst's answer in force that no other
  claim of it writes; and never where another participant is named before
  it on the line or in its clause after it (whole or in a short form: "the
  reverser's analysis in claim 28", "claim 28 finds no key per the static
  analyst"), a possessive other than the analyst's stands right before it
  ("the code analyst's claim 28"), a word for an earlier answer stands before
  it ("the previous round's claim 9", "Round-2 claim 9", "R2's claim 9"), it
  stands inside a mark's reason, it opens a parenthesis right after another
  participant's short name ("the reverser (claim 28)"), or another
  participant's name follows it ("claim 4 of the reverser");
- a ruling at the round limit reads it as the claim right after the field
  is, so the ruling is written onto it too; a reference that fails any of
  these stays a number no analyst is read for;
- every other reader reads the line as it did: the revision merge does not
  read it as named, so a blocking line that only mentions it never
  withdraws it by rule and the claim is carried, and a revision is shown of
  it what a line citing a claim without naming its analyst shows;
- a line whose field names two analysts places nothing new.

Every value is synthetic.
"""

from __future__ import annotations

from malspark.pipeline.debate_facts import (
    NO_ANALYST_NAMED,
    claim_references_of,
    contested_refs,
    read_claim_references,
)
from malspark.pipeline.limit_rulings import Ruling, mark_claims
from malspark.pipeline.revision_merge import claims_named_in_force, merge_revision
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["triage", "static", "all_tools_reverser_ghidra", "all_tools_qu1cksc0pe"]

LINE = (
    "[analysts: TRIAGE ANALYST] Claim 15 asserts T1547.014 at 0.40 from ev_0014, and claim 17 "
    "asserts T1120, T1082 and T1012 at 0.40 from ev_0012 for the drive-root opens. [blocking: x]"
)

# The ledger ids each claim of the triage answer in force writes: claim 17
# alone writes ev_0012, claim 28 alone ev_0031, claim 9 alone ev_0039.
OWNERS = {
    "triage": {
        **{n: frozenset({f"ev_09{n:02d}"}) for n in range(1, 30)},
        9: frozenset({"ev_0039"}),
        15: frozenset({"ev_0014"}),
        17: frozenset({"ev_0006", "ev_0012", "ev_0014"}),
        28: frozenset({"ev_0031"}),
    }
}


def test_both_claims_of_a_one_analyst_line_are_the_analyst_s_for_a_ruling() -> None:
    references = read_claim_references([LINE], NAMES, OWNERS, whole_line=True)

    assert references.named == {"triage": {15: [(1, True)], 17: [(1, True)]}}
    assert references.unplaced == ()
    assert references.owned == ()
    # Read as the claim right after the field is: the whole line speaks for it.
    assert 17 not in references.expanded.get("triage", {})


def test_the_merge_s_reading_leaves_the_later_claim_unread() -> None:
    references = read_claim_references([LINE], NAMES)

    assert references.named == {"triage": {15: [(1, True)]}}
    assert [(u.claims, u.why) for u in references.unplaced] == [("claim 17", NO_ANALYST_NAMED)]


def test_only_a_ruling_asks_for_the_later_claim() -> None:
    text = LINE

    assert [r.numbers.numbers for r in claim_references_of(text, NAMES, ["triage"])] == [("15",)]
    assert [
        (r.numbers.numbers, r.whole_line)
        for r in claim_references_of(text, NAMES, ["triage"], whole_line=True)
    ] == [(("15",), False), (("17",), True)]


def test_a_revision_is_shown_of_the_later_claim_what_an_unnamed_claim_shows() -> None:
    (ref,) = contested_refs([LINE], NAMES)

    assert ref.claims == (("triage", 15),)
    assert ref.unattributed


def test_a_later_claim_whose_own_clause_shares_nothing_of_its_own_stays_unplaced() -> None:
    for clause in (
        # No ledger id or address in the reference's clause.
        "claim 17 asserts T1120 for the drive-root opens. [blocking: x]",
        # An id claim 15 writes too: no sign of which claim the line means.
        "claim 17 asserts T1120 from ev_0014. [blocking: x]",
        # The id is written, but in another clause of the line.
        "claim 17 asserts T1120; the opens are at ev_0012. [blocking: x]",
    ):
        line = "[analysts: TRIAGE ANALYST] Claim 15 asserts T1547.014 from ev_0014, and " + clause

        references = read_claim_references([line], NAMES, OWNERS, whole_line=True)

        assert 17 not in references.named.get("triage", {}), clause
        assert any(u.claims == "claim 17" for u in references.unplaced), clause
        assert references == read_claim_references([line], NAMES, OWNERS), clause


def test_without_the_answers_in_force_a_ruling_places_no_later_claim() -> None:
    references = read_claim_references([LINE], NAMES, whole_line=True)

    assert references.named == {"triage": {15: [(1, True)]}}
    assert [(u.claims, u.why) for u in references.unplaced] == [("claim 17", NO_ANALYST_NAMED)]


def test_a_line_whose_field_names_two_analysts_places_nothing_new() -> None:
    line = LINE.replace("[analysts: TRIAGE ANALYST]", "[analysts: TRIAGE ANALYST, STATIC ANALYST]")

    assert read_claim_references([line], NAMES, OWNERS, whole_line=True) == (
        read_claim_references([line], NAMES, OWNERS)
    )


def _later(later: str, mark: str = "[blocking: x]") -> str:
    return (
        "[analysts: TRIAGE ANALYST] Claim 16 states the XOR decoding is confirmed at ev_0916, "
        f"{later}. {mark}"
    )


def _placed(line: str) -> set[int]:
    """The triage claims a ruling reads the line to name, past those the merge reads it to own."""
    references = read_claim_references([line], NAMES, OWNERS, whole_line=True)
    owned = {o.claim for o in references.owned}
    return set(references.named.get("triage", {})) - owned


def test_a_claim_in_a_parenthesis_after_another_participant_s_short_name_is_not_the_field_s() -> (
    None
):
    line = _later("the reverser (claim 28) finds no key at ev_0031", "[not blocking: wording]")

    assert _placed(line) == {16}


def test_a_claim_another_participant_s_name_follows_is_not_the_field_s() -> None:
    line = _later("against claim 28 of the reverser at ev_0031", "[not blocking: wording]")

    assert _placed(line) == {16}


def test_a_claim_after_another_participant_s_name_is_not_the_field_s() -> None:
    line = _later(
        "while ALL_TOOLS_REVERSER_GHIDRA reads it otherwise, and claim 28 finds no key at ev_0031"
    )

    assert _placed(line) == {16}


def test_a_claim_after_another_participant_s_short_name_is_not_the_field_s() -> None:
    for later in (
        "but the reverser's analysis in claim 28 finds no key at ev_0031",
        "but the reverser [claim 28] finds no key at ev_0031",
    ):
        assert _placed(_later(later)) == {16}, later


def test_a_claim_whose_clause_names_another_participant_after_it_is_not_the_field_s() -> None:
    for later in (
        "and claim 28 finds no key at ev_0031 per the static analyst",
        "and claim 28 finds no key at ev_0031, as the reverser reads it",
    ):
        assert _placed(_later(later)) == {16}, later
    # Another participant named in a later clause leaves this one the analyst's.
    assert _placed(_later("and claim 28 finds no key at ev_0031; the static analyst agrees")) == {
        16,
        28,
    }


def test_a_claim_after_a_possessive_other_than_the_analyst_s_is_not_the_field_s() -> None:
    for later in (
        "but the code analyst's claim 28 finds no key at ev_0031",
        "but the analysts' claim 28 finds no key at ev_0031",
        "but the sample's claim 28 finds no key at ev_0031",
    ):
        assert _placed(_later(later)) == {16}, later


def test_a_claim_after_the_analyst_s_own_possessive_is_the_field_s() -> None:
    for later in (
        "but the analyst's own claim 28 finds no key at ev_0031",
        "but the same analyst's claim 28 finds no key at ev_0031",
        "but the triage analyst's claim 28 finds no key at ev_0031",
        "but its claim 28 finds no key at ev_0031",
        "but claim 28 finds no key at ev_0031",
    ):
        assert _placed(_later(later)) == {16, 28}, later


def test_a_claim_of_an_earlier_answer_is_not_the_field_s() -> None:
    for earlier in (
        "Round-2 claim 9",
        "round 2's claim 9",
        "round two's claim 9",
        "the previous round's claim 9",
        "R2's claim 9",
        "the earlier claim 9",
        "the previous claim 9",
        "the prior claim 9",
        "the former claim 9",
        "the old claim 9",
    ):
        assert _placed(_later(f"against {earlier} at ev_0039")) == {16}, earlier
    assert _placed(_later("against claim 9 at ev_0039")) == {16, 9}


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
