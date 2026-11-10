"""docker/docker-compose.named-data.yml moves every data mount of the base file, and nothing else.

A host that is not Linux keeps samples and uploads on named volumes: the
overlay re-points each bind mount of ../data/samples and ../data/uploads in
docker/docker-compose.yml at the volume, at the same container path, so
Compose's merge by target replaces it. Read from the two YAML files alone (no
docker), so it runs on every OS. The mounts are found in the base file, so a
service added there with a data mount the overlay does not move fails here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "docker" / "docker-compose.yml"
OVERLAY = ROOT / "docker" / "docker-compose.named-data.yml"

# The host directory each named volume stands for, as the base file names it.
VOLUMES = {"../data/samples": "samples", "../data/uploads": "uploads"}


def _load(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _mount(entry: object) -> tuple[str, str, bool]:
    """(source, target, read-only) of one short- or long-syntax volume entry."""
    if isinstance(entry, dict):
        return str(entry.get("source")), str(entry["target"]), bool(entry.get("read_only"))
    source, target, *mode = str(entry).split(":")
    return source, target, "ro" in ",".join(mode).split(",")


def _data_mounts(services: dict[str, Any]) -> dict[str, set[tuple[str, str, bool]]]:
    """Each service's mounts of a data directory, by service."""
    found: dict[str, set[tuple[str, str, bool]]] = {}
    for name, service in services.items():
        for entry in service.get("volumes") or []:
            source, target, read_only = _mount(entry)
            if source in VOLUMES:
                found.setdefault(name, set()).add((source, target, read_only))
    return found


BASE_MOUNTS = _data_mounts(_load(BASE)["services"])


def test_the_base_file_s_data_mounts_are_found() -> None:
    # The API, the worker and volume-init write both; the sidecars read samples.
    assert {"volume-init", "backend-api", "backend-worker"} <= set(BASE_MOUNTS)
    assert sum(len(mounts) for mounts in BASE_MOUNTS.values()) > len(BASE_MOUNTS)
    assert any(read_only for mounts in BASE_MOUNTS.values() for *_, read_only in mounts)


@pytest.mark.parametrize("service", sorted(BASE_MOUNTS))
def test_each_data_mount_is_the_volume_at_the_same_path_and_mode(service: str) -> None:
    overlay = _load(OVERLAY)["services"]
    assert service in overlay, f"{service} mounts a data directory the overlay does not move"
    wanted = {(VOLUMES[source], target, ro) for source, target, ro in BASE_MOUNTS[service]}
    entries = overlay[service].get("volumes") or []
    # Short syntax: no nocopy, so a fresh volume receives what the image holds there.
    assert all(isinstance(entry, str) for entry in entries), entries
    assert {_mount(entry) for entry in entries} == wanted
    assert len(entries) == len(wanted)


def test_the_overlay_changes_nothing_else() -> None:
    overlay = _load(OVERLAY)
    assert set(overlay) == {"services", "volumes"}
    assert set(overlay["services"]) == set(BASE_MOUNTS)
    assert all(set(service) == {"volumes"} for service in overlay["services"].values())
    assert overlay["volumes"] == {name: {"driver": "local"} for name in VOLUMES.values()}
    assert not set(VOLUMES.values()) & set(_load(BASE).get("volumes") or {})
