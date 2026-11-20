"""A stored run the judge called Benign replays to the sample's identity and no technique.

The tiny stored run (``tests/fixtures/replay/tiny``) replayed through the
replay's entry point, once as stored (Malware) and once with the judge's
verdict Benign: the report's build, the matrix, the IOC table and the export
are the platform's own, so the verdict reaches the matrix and the table the way
a run's does.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from scripts.replay.rules import replay_run
from scripts.replay.stored import read_run

from tests.unit.scripts._replay_tiny import FIXTURE

# The digest the stored run's identity holds for the sample.
SHA256 = "6abc1626f78cdbe20895273317295fa86ef2f65069382495938fe76d34657448"


def _replayed(tmp_path: Path, verdict: str) -> dict[str, Any]:
    target = tmp_path / "tiny"
    shutil.copytree(FIXTURE, target)
    path = target / "stix-judge.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["bundle"]["x_malspark_assessment"]["verdict"] = verdict
    path.write_text(json.dumps(data), encoding="utf-8")
    return replay_run(read_run(target), show_text=True)["report"]


def _published(report: dict[str, Any]) -> set[str]:
    return {row["value"] for row in report["indicators"].values() if row["published"] == "yes"}


def test_a_benign_run_publishes_the_sample_s_identity_alone(tmp_path: Path) -> None:
    malware = _replayed(tmp_path / "m", "Malware")
    benign = _replayed(tmp_path / "b", "Benign")

    assert benign["verdict"] == "Benign"
    # As stored, the run publishes a URL and its host beside the sample's digest.
    assert _published(malware) > {SHA256}
    assert _published(benign) == {SHA256}
    # Every row stays listed.
    assert set(benign["indicators"]) == set(malware["indicators"])


def test_a_benign_run_publishes_no_technique_and_keeps_every_cell(tmp_path: Path) -> None:
    malware = _replayed(tmp_path / "m", "Malware")
    benign = _replayed(tmp_path / "b", "Benign")

    assert any(row["published"] for row in malware["techniques"].values())
    assert set(benign["techniques"]) == set(malware["techniques"])
    assert not any(row["published"] for row in benign["techniques"].values())
    # The record holds a reason as a digest; its words are held with the text.
    assert all(
        row["why_text"].startswith("the verdict is Benign") for row in benign["techniques"].values()
    )
    assert all(row["why"].startswith("sha256:") for row in benign["techniques"].values())
    assert benign["export"]["attack_patterns"] == []
