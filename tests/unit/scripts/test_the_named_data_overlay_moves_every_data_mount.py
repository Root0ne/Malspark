"""docker/docker-compose.named-data.yml moves every data mount of the base file, and nothing else.

A host that is not Linux keeps samples and uploads on named volumes: the
overlay re-points each bind mount of ../data/samples and ../data/uploads in
the compose files malspark_dev.py starts at the volume, at the same container
path, so Compose's merge by target replaces it. Two mounts are added: the
tracked fixture directories under data/samples, read-only from the checkout
for each container that sees the samples where the backend image keeps them,
and the samples volume at that same path for volume-init, which runs that
image, so a fresh volume is filled when volume-init is created. Read from the
YAML files and git's index alone (no docker), so it runs on every OS. The
mounts are found in the compose files and the fixture directories in what git
tracks, so a service with a data mount, or a fixture directory, the overlay
does not cover fails here.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
DOCKER = ROOT / "docker"
# Every compose file malspark_dev.py names before the overlay, or after it.
COMPOSE = [
    DOCKER / "docker-compose.yml",
    DOCKER / "docker-compose.dev.yml",
    DOCKER / "docker-compose.dev-polling.yml",
]
OVERLAY = DOCKER / "docker-compose.named-data.yml"

# The host directory each named volume stands for, as the compose files name it.
VOLUMES = {"../data/samples": "samples", "../data/uploads": "uploads"}
# Where the backend image keeps its sample fixtures, and the one-shot service
# that runs that image to hand the volumes over.
IMAGE_SAMPLES = "/app/data/samples"
OWNER = "volume-init"


def _load(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _mount(entry: object) -> tuple[str, str, bool]:
    """(source, target, read-only) of one short- or long-syntax volume entry."""
    if isinstance(entry, dict):
        return str(entry.get("source")), str(entry["target"]), bool(entry.get("read_only"))
    if ":" not in str(entry):
        # An anonymous volume: a target alone.
        return "", str(entry), False
    source, target, *mode = str(entry).split(":")
    return source, target, "ro" in ",".join(mode).split(",")


def _data_mounts() -> dict[str, set[tuple[str, str, bool]]]:
    """Each service's mounts of a data directory, by service, as Compose merges the files."""
    merged: dict[str, dict[str, tuple[str, str, bool]]] = {}
    for path in COMPOSE:
        for name, service in (_load(path).get("services") or {}).items():
            for entry in service.get("volumes") or []:
                source, target, read_only = _mount(entry)
                merged.setdefault(name, {})[target] = (source, target, read_only)
    return {
        name: found
        for name, mounts in merged.items()
        if (found := {mount for mount in mounts.values() if mount[0] in VOLUMES})
    }


def _fixture_dirs() -> set[str]:
    """The directories directly under data/samples that hold a file git tracks."""
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "data/samples"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return {parts[2] for path in listed.split("\0") if len(parts := path.split("/")) > 3}


BASE_MOUNTS = _data_mounts()
FIXTURES = _fixture_dirs()


def _wanted(service: str) -> set[tuple[str, str, bool]]:
    """The overlay's mounts for one service: its data mounts moved, and the two additions."""
    wanted = {(VOLUMES[source], target, ro) for source, target, ro in BASE_MOUNTS[service]}
    if ("samples", IMAGE_SAMPLES, False) in wanted:
        wanted |= {
            (f"../data/samples/{name}", f"{IMAGE_SAMPLES}/{name}", True) for name in FIXTURES
        }
    if service == OWNER:
        wanted.add(("samples", IMAGE_SAMPLES, False))
    return wanted


def test_the_compose_files_data_mounts_and_the_fixtures_are_found() -> None:
    # The API, the worker and volume-init write both; the sidecars read samples.
    assert {OWNER, "backend-api", "backend-worker"} <= set(BASE_MOUNTS)
    assert sum(len(mounts) for mounts in BASE_MOUNTS.values()) > len(BASE_MOUNTS)
    assert any(read_only for mounts in BASE_MOUNTS.values() for *_, read_only in mounts)
    assert {"dynamic", "static", "network"} <= FIXTURES


def test_volume_init_runs_the_image_whose_samples_path_it_fills() -> None:
    services = _load(COMPOSE[0])["services"]
    assert services[OWNER]["image"] == services["backend-api"]["image"]
    assert ("../data/samples", IMAGE_SAMPLES, False) in BASE_MOUNTS["backend-api"]


@pytest.mark.parametrize("service", sorted(BASE_MOUNTS))
def test_each_data_mount_is_the_volume_at_the_same_path_and_mode(service: str) -> None:
    overlay = _load(OVERLAY)["services"]
    assert service in overlay, f"{service} mounts a data directory the overlay does not move"
    wanted = _wanted(service)
    entries = overlay[service].get("volumes") or []
    # Short syntax: no nocopy, so a fresh volume receives what the image holds there.
    assert all(isinstance(entry, str) for entry in entries), entries
    assert {_mount(entry) for entry in entries} == wanted
    assert len(entries) == len(wanted)


def test_every_tracked_fixture_directory_is_read_from_the_checkout() -> None:
    overlay = _load(OVERLAY)["services"]
    for service in ("backend-api", "backend-worker"):
        read = {
            Path(target).name
            for source, target, read_only in map(_mount, overlay[service]["volumes"])
            if source.startswith("../data/samples/") and read_only
        }
        assert read == FIXTURES, service


def test_the_overlay_changes_nothing_else() -> None:
    overlay = _load(OVERLAY)
    assert set(overlay) == {"services", "volumes"}
    assert set(overlay["services"]) == set(BASE_MOUNTS)
    assert all(set(service) == {"volumes"} for service in overlay["services"].values())
    assert overlay["volumes"] == {name: {"driver": "local"} for name in VOLUMES.values()}
    assert not set(VOLUMES.values()) & set(_load(COMPOSE[0]).get("volumes") or {})
