"""A finding's technique id meets the same validity checks as a claim's.

The evidence summary the judge reads counted a claim's id only when it was
valid, and an asserting tool's id only when no lookup of the run answered it
as not a technique. A finding's ``technique_ids`` skipped both checks, so an id
the run had established as no technique reached the judge as a source.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from malspark.pipeline.evidence_summary import collect
from malspark.schemas.isr_models import AgentISR, ClaimEvidence, Finding


def _isr(*, flagged_claim: bool = False) -> AgentISR:
    """A finding naming T9999 and T1055; a claim naming T9999 only when it is flagged."""
    claims = (
        [
            ClaimEvidence(
                claim="Hooks the keyboard",
                evidence_ref="[ev_0001]",
                confidence=0.6,
                technique_id="T9999",
                technique_id_valid=False,
            )
        ]
        if flagged_claim
        else []
    )
    findings = [
        Finding(
            title="Keylogging and injection",
            technique_ids=["T9999", "T1055"],
            evidence_ids=["ev_0001"],
            confidence=0.7,
        )
    ]
    return AgentISR(agent_id="static", domain="static", claims=claims, findings=findings)


def _ledger(*, lookup_says_invalid: bool = False) -> list[Any]:
    entries: list[Any] = [SimpleNamespace(id="ev_0001", tool="decompile", structured=None)]
    if lookup_says_invalid:
        entries.append(
            SimpleNamespace(
                id="ev_0002",
                tool="attck_lookup",
                structured={"technique_id": "T9999", "valid": False},
            )
        )
    return entries


class TestTheEvidenceSummary:
    def test_an_id_the_analyst_kept_unverified_is_not_counted_from_its_finding(self) -> None:
        rows = collect({"static": _isr(flagged_claim=True)}, _ledger())

        assert "T9999" not in rows
        assert rows["T1055"] == [("static", 0.7)]

    def test_an_id_a_lookup_answered_as_invalid_is_not_counted_from_a_finding(self) -> None:
        rows = collect({"static": _isr()}, _ledger(lookup_says_invalid=True))

        assert "T9999" not in rows
        assert "T1055" in rows

    def test_a_valid_finding_id_is_still_counted(self) -> None:
        rows = collect({"static": _isr()}, _ledger())

        assert {"T9999", "T1055"} <= set(rows)


class TestAnUnknownIdIsUnknownForEveryAnalyst:
    def _team(self) -> dict[str, AgentISR]:
        other = AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            findings=[
                Finding(title="Keylogging", technique_ids=["T9999"], evidence_ids=["ev_0001"])
            ],
        )
        return {"static": _isr(flagged_claim=True), "dynamic": other}

    def test_another_analyst_s_finding_is_not_counted_under_it(self) -> None:
        assert "T9999" not in collect(self._team(), _ledger())
