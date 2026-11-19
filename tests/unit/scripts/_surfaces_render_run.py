"""A tiny stored run with a report every surface renders from, for the surface render's tests.

``stored_run(at)`` copies the replay's tiny run (``_replay_tiny.FIXTURE``),
whose ledger, answers and judge's bundle the build mode rebuilds from, and
writes a report row beside it that the serve mode reads: a small report that
reads as today's model, with one figure of two SVG labels, one drafted rule
and one published technique, the row's STIX bundle and its ``/mitre`` rows.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from tests.unit.scripts._replay_tiny import FIXTURE

SHA256 = "6abc1626f78cdbe20895273317295fa86ef2f65069382495938fe76d34657448"
SUMMARY = "The sample decodes its configuration at run time."
LABELS = ("Defense Evasion", "T1027")
CAPTION = "MITRE ATT&CK tactic coverage"
LEGEND = "Each box is a technique the report publishes."


def report() -> dict[str, Any]:
    return {
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "generated_at": "2026-01-02T03:04:05+00:00",
        "identity": {
            "file_name": "fixture.bin",
            "file_type": "pe",
            "platform": "windows",
            "hashes": {"sha256": SHA256},
        },
        "degraded_mode": True,
        "degradation_reasons": [
            "no sandbox report (dynamic detonation unavailable) — static-only evidence"
        ],
        "executive_summary": SUMMARY,
        "key_findings": [
            {"text": "Its configuration strings are XOR-encoded.", "evidence_ids": ["ev_0002"]}
        ],
        "ttp_mappings": [
            {
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "TA0005",
                "tactic_name": "Defense Evasion",
                "confidence": 0.7,
            }
        ],
        "figures": [
            {
                "id": "fig-attack-matrix",
                "caption": CAPTION,
                "kind": "attack_matrix",
                "content": (
                    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 60">'
                    f'<text x="4" y="20">{LABELS[0]}</text>'
                    '<rect x="4" y="30" width="60" height="20"/>'
                    f'<text x="8" y="44">{LABELS[1]}</text>'
                    "</svg>"
                ),
                "legend": LEGEND,
            }
        ],
        "detection_signatures": [
            {
                "kind": "yara",
                "name": "fixture_rule",
                "body": "// the fixture's own rule\nrule fixture_rule { condition: true }\n",
            }
        ],
    }


def bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000002",
                "name": "Obfuscated Files or Information",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}],
            }
        ],
    }


def stored_run(at: Path, **row: Any) -> Path:
    """The tiny run under ``at``, its report row holding the report; ``row`` overrides columns."""
    run = at / "run"
    shutil.copytree(FIXTURE, run)
    byjob = json.loads((run / "report-byjob.json").read_text(encoding="utf-8"))
    byjob.update(
        {
            "malware_report": report(),
            "stix_bundle": bundle(),
            "mitre_techniques": [
                {"technique_id": "T1027", "name": "Obfuscated Files or Information"}
            ],
        }
    )
    for key, value in row.items():
        if value is None:
            byjob.pop(key, None)
        else:
            byjob[key] = value
    (run / "report-byjob.json").write_text(json.dumps(byjob), encoding="utf-8")
    return run
