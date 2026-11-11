"""Read a stored run's checked techniques the judge's question would list, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/checked_techniques.py <run dir> [<run dir> ...]

rebuilds, with the platform's own code and no model call, the list the judge's
post-verdict technique question puts to the judge as ``checked``: each
technique id an entry's call arguments write or an answer's declared technique
field names that no final claim, finding or bundle object carries
(``capability_matrix.checked_technique_questions``). It reads the analysts'
final claims (``report-byjob.json`` ``agent_findings``), their findings as the
stored report's Findings table keeps them (``report.json``), the judge's bundle
(``stix-judge.json``) and the ledger (``evidence.json``), and prints per id
where it was seen and how many entries each agent that passed it cites in its
final claims. An id an agent checked that a stored finding alone carries is
named apart: the question asks it already, as a finding. Stored text is
printed through ``scripts.replay.output.terminal_text``.

Read-only over the runs: nothing is written beside them, no network is reached,
no credential is read. ``--json PATH`` also writes the readings to ``PATH``.
This reads the question's inputs, not the judge's answer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _json(path: Path) -> Any:
    return json.loads(path.read_bytes()) if path.is_file() else None


def _ledger(run: Path) -> list[Any]:
    from scripts.replay.stored import evidence_rows

    from malspark.reporting.follow_up import stored_ledger

    document = _json(run / "evidence.json")
    if document is None:
        return []
    rows, _why = evidence_rows(document)
    ledger: list[Any] = stored_ledger(rows)[0]
    return ledger


def _isr_reports(run: Path) -> tuple[dict[str, Any], int]:
    """The analysts' final claims and stored findings, and how many claims did not read."""
    from scripts.replay.rules import _stored_findings

    from malspark.schemas.isr_models import AgentISR, ClaimEvidence

    byjob = _json(run / "report-byjob.json") or {}
    report = _json(run / "report.json") or {}
    findings = _stored_findings(SimpleNamespace(stored=SimpleNamespace(report=report)))  # type: ignore[arg-type]
    out: dict[str, Any] = {}
    unread = 0
    for row in byjob.get("agent_findings") or []:
        if not isinstance(row, dict):
            continue
        agent = str(row.get("agent_name") or "")
        claims: list[Any] = []
        for claim in row.get("claims") or []:
            try:
                claims.append(ClaimEvidence.model_validate(claim))
            except Exception:  # noqa: BLE001 — counted
                unread += 1
        out[agent] = AgentISR(
            agent_id=agent,
            domain=str(row.get("domain") or agent),
            claims=claims,
            findings=list(findings.get(agent) or []),
        )
    for agent, held in findings.items():
        if agent not in out:
            out[agent] = AgentISR(agent_id=agent, domain=agent, findings=list(held))
    return out, unread


def _bundle(run: Path) -> dict[str, Any] | None:
    stored = _json(run / "stix-judge.json")
    if isinstance(stored, dict) and isinstance(stored.get("bundle"), dict):
        bundle: dict[str, Any] = stored["bundle"]
        return bundle
    return stored if isinstance(stored, dict) else None


def read_run(run: Path) -> dict[str, Any]:
    """The checked techniques of one stored run, each with where it was seen."""
    from malspark.extractors.capability_matrix import checked_technique_questions

    isr_reports, unread = _isr_reports(run)
    bundle, ledger = _bundle(run), _ledger(run)
    questions = checked_technique_questions(bundle, isr_reports, ledger)
    # The ids a stored finding alone carries: the question asks them already, as
    # findings, so they are not listed again as checked.
    listed = {q.technique_id for q in questions}
    claims_only = {
        agent: isr.model_copy(update={"findings": []}) for agent, isr in isr_reports.items()
    }
    on_findings = [
        q.technique_id
        for q in checked_technique_questions(bundle, claims_only, ledger)
        if q.technique_id not in listed
    ]
    return {
        "run": run.name,
        "claims_unread": unread,
        "carried_by_a_finding": on_findings,
        "checked": [
            {
                "id": q.technique_id,
                "seen": [{"agent": a, "entry": e, "place": p} for a, e, p in q.checked],
                "claim_entries": q.claim_entries,
            }
            for q in questions
        ],
    }


def _print(read: dict[str, Any]) -> None:
    from scripts.replay.output import terminal_text

    ids = [row["id"] for row in read["checked"]]
    print(f"== {terminal_text(read['run'])}: {len(ids)} checked technique(s): {', '.join(ids)}")
    if read["carried_by_a_finding"]:
        print(
            "   checked, and carried by a stored finding only (asked as a finding): "
            + ", ".join(read["carried_by_a_finding"])
        )
    if read["claims_unread"]:
        print(f"   {read['claims_unread']} stored claim(s) did not read as this tree's claims")
    for row in read["checked"]:
        by_agent: dict[str, list[str]] = {}
        for seen in row["seen"]:
            by_agent.setdefault(seen["agent"], []).append(f"{seen['entry']} ({seen['place']})")
        print(f" - {row['id']}")
        for agent, places in by_agent.items():
            cited = row["claim_entries"].get(agent) or []
            print(
                f"     {terminal_text(agent)}: {terminal_text(', '.join(places))}; "
                f"its final claims cite {len(cited)} entr{'y' if len(cited) == 1 else 'ies'}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, default=None, help="write the readings here too")
    args = parser.parse_args(argv)
    found = []
    for run in args.runs:
        read = read_run(run)
        _print(read)
        found.append(read)
    if args.json is not None:
        args.json.write_text(json.dumps(found, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
