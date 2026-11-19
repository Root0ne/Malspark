"""A tiny stored run with a report every surface renders from, for the surface render's tests.

``stored_run(at)`` copies the replay's tiny run (``_replay_tiny.FIXTURE``),
whose ledger, answers and judge's bundle the build mode rebuilds from, and
writes a report row beside it that the serve mode reads: a small report that
reads as today's model, with one figure of two SVG labels, one drafted rule
and one published technique, the row's STIX bundle and its ``/mitre`` rows.
``full_report()`` adds a process tree, execution-flow steps and an unresolved
finding to it.

``platform_repository(at)`` is a git repository of the test's own holding this
checkout's platform as its working tree has it, and ``commit_edits`` commits
strings replaced in it: the two refs a comparison test renders.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404 — git, argument lists only
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.unit.scripts._replay_tiny import FIXTURE

ROOT = Path(__file__).resolve().parents[3]
# A commit of the test's own needs a name, and no hook or signing of the
# machine's may run on it.
GIT = (
    "-c",
    "user.name=Render Test",
    "-c",
    "user.email=render-test@example.invalid",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgsign=false",
)
# What a platform repository holds: the platform, its tables, the API.
PLATFORM_PATHS: tuple[str, ...] = (
    "pyproject.toml",
    "src",
    "data",
    ":(exclude)data/samples",
    "apps/api/app",
)

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


def full_report() -> dict[str, Any]:
    """:func:`report` with what the fuller surfaces print from: a process tree the sandbox
    watched, two execution-flow steps (a figure whose boxes carry tooltips) and a finding
    the validation loop left unresolved."""
    return {
        **report(),
        "dynamic": {
            "process_tree": [
                {"pid": 1200, "ppid": 4, "name": "fixture.exe", "command_line": "fixture.exe /run"}
            ]
        },
        "technical_analysis": {
            "execution_flow": [
                {
                    "order": 1,
                    "action": "The sample decodes its configuration.",
                    "voice": "assessed",
                },
                {"order": 2, "action": "It starts a second process.", "voice": "observed"},
            ]
        },
        "run_summary": {
            "validation": {
                "unresolved": [
                    {
                        "code": "narrative.ungrounded_finding",
                        "message": "A key finding cites no evidence entry.",
                    }
                ]
            }
        },
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


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        ["git", *GIT, "-C", str(repo), *args], capture_output=True, check=True
    )
    return done.stdout.decode().strip()


def _working_tree_files(paths: Sequence[str]) -> list[str]:
    if shutil.which("git") is None:
        pytest.skip("git is not on this machine")
    listed = subprocess.run(  # nosec B603 B607 — a fixed git argument list
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *paths,
        ],
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip("this checkout is not a git repository")
    names = [name for name in listed.stdout.decode().split("\0") if name]
    return [name for name in names if (ROOT / name).is_file()]


def platform_repository(at: Path, *, extra: Sequence[str] = ()) -> tuple[Path, str]:
    """This checkout's platform (and the ``extra`` paths) committed once; the repository and sha.

    ``data/samples`` holds a placeholder, which the written-out tree leaves out.
    """
    repo = at / "platform"
    for name in _working_tree_files([*PLATFORM_PATHS, *extra]):
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, repo / name)
    placeholder = repo / "data" / "samples" / "placeholder.json"
    placeholder.parent.mkdir(parents=True, exist_ok=True)
    placeholder.write_text("{}", encoding="utf-8")
    git(repo, "init", "--quiet")
    git(repo, "add", "--", ".")
    git(repo, "commit", "--quiet", "-m", "the platform")
    return repo, git(repo, "rev-parse", "HEAD")


def commit_edits(repo: Path, edits: Sequence[tuple[str, str, str]]) -> str:
    """Each ``(file, old, new)`` replaced once in the repository, committed; the new sha."""
    for name, old, new in edits:
        target = repo / name
        text = target.read_text(encoding="utf-8")
        assert old in text, (name, old)
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
    git(repo, "commit", "--quiet", "--all", "-m", "strings changed")
    return git(repo, "rev-parse", "HEAD")
