"""The stored-run remerge runs from its command line, under both rules, end to end.

``scripts/replay/remerge_revisions.py`` merges a stored run's debate
revisions again under this tree's rule and under the earlier one, which it
puts in place of the statement reader (``revision_merge._by_statement``).
Every implementation of that reader gives the merge the same four values
(``revision_merge.StatementPlacement``), so the earlier rule cannot drift from
what the merge unpacks.

Every analyst, address and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.replay import remerge_revisions

from malspark.pipeline import revision_merge
from malspark.schemas.isr_models import AgentISR, ClaimEvidence

MEDIATOR = "You are the Lead Cyber Security Mediator of a made-up test."
LOADER = "Routine 0x401000 loads the list at 0x402000"
GATE = "Routine 0x403000 checks the table at 0x404000"


def _request(text: str) -> str:
    options = {"json_data": {"system": MEDIATOR, "messages": [{"content": text}]}}
    return f"2026-01-01 DEBUG Request options: {options!r}\n"


def _answer(revision_round: int, claims: list[str], disputes: list[str]) -> str:
    lines = [
        f"[STATIC ANALYST — round {revision_round}]",
        "Domain: static | Mean confidence: 0.70",
        *(f"  {claim}" for claim in claims),
    ]
    if disputes:
        lines += ["  Disputes:", *(f"    - {item}" for item in disputes)]
    return "--- STATIC ANALYST ---\n" + "\n".join(lines) + "\n"


def _stored_run(root: Path) -> Path:
    first = _answer(
        0,
        [
            f"Claim 1: {LOADER}. | Evidence: [ev_0001] | Confidence: 0.70",
            f"Claim 2: {GATE}. | Evidence: [ev_0002] | Confidence: 0.70",
        ],
        ["the gate is read from ev_0002"],
    )
    second = _answer(
        1,
        [
            f"Claim 1: {LOADER} from ev_0001. | Evidence: [ev_0001] | Confidence: 0.80",
            f"Claim 2: {GATE}. | Evidence: [ev_0002] (carried forward: the round-1 revision "
            "neither wrote it again nor withdrew it) (unchanged since round 0) | Confidence: 0.70",
        ],
        ["the gate is read from ev_0002"],
    )
    second += (
        "\n- (standing: blocking) [analysts: STATIC ANALYST] STATIC claim 1 says 0x402000 is "
        "a list; nothing shows it. [blocking: show the read]\n"
    )
    run = root / "run"
    run.mkdir()
    (run / "worker.log").write_text(
        _request(first) + "noise\n" + _request(second), encoding="utf-8"
    )
    return run


class TestTheScriptRunsEndToEnd:
    def test_main_merges_every_revision_under_both_rules(self, tmp_path: Path, capsys) -> None:
        run = _stored_run(tmp_path)
        out = tmp_path / "record.json"

        assert remerge_revisions.main([str(run), "--json", str(out)]) == 0

        records = json.loads(out.read_text(encoding="utf-8"))
        assert [r["run"] for r in records] == ["run"]
        rows = records[0]["revisions"]
        assert [(r["round"], r["analyst"]) for r in rows] == [(1, "static")]
        assert rows[0]["earlier_rule"]["restated"] == [1]
        assert rows[0]["this_rule"]["restated"] == [1]
        assert "== run" in capsys.readouterr().out


class TestEveryStatementReaderGivesTheFourValues:
    def test_this_rule_and_the_earlier_rule(self) -> None:
        def isr(claims: list[str]) -> AgentISR:
            return AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(claim=c, evidence_ref="[ev_0001]", confidence=0.7) for c in claims
                ],
            )

        first = revision_merge._blocks(isr([LOADER, GATE]).claims)
        revised = revision_merge._blocks(isr([LOADER]).claims)
        readings = [revision_merge._read(b) for b in revised]
        stated = revision_merge._stated_addresses(revised)

        found = [revision_merge._by_statement(first, readings, stated)]
        with remerge_revisions._earlier_rule():
            found.append(revision_merge._by_statement(first, readings, stated))

        for placement in found:
            assert isinstance(placement, revision_merge.StatementPlacement)
            assert placement.restated == {1}
            assert placement.target == {0: 1}
            assert placement.by == {1: 0}
