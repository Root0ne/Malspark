"""The ATT&CK fixture script writes each tactic's column position from the bundle's matrix.

The position is the tactic's index in the active ``x-mitre-matrix`` object's
``tactic_refs`` (the first matrix that lists it wins), the rule the loader
applies to a live bundle. A tactic no active matrix lists gets no position.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "knowledge"
    / "prepare_attck_malware_fixtures.py"
)


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("prepare_attck_malware_fixtures", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tactic(stix_id: str, tactic_id: str, slug: str) -> dict[str, Any]:
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "external_references": [{"source_name": "mitre-attack", "external_id": tactic_id}],
        "x_mitre_shortname": slug,
        "name": slug.title(),
    }


def _matrix(*refs: str, **extra: Any) -> dict[str, Any]:
    return {"type": "x-mitre-matrix", "tactic_refs": list(refs), **extra}


def test_each_listed_tactic_gets_its_index_in_the_matrix() -> None:
    objects = [
        _tactic("x--b", "TA0003", "persistence"),
        _tactic("x--a", "TA0002", "execution"),
        _tactic("x--c", "TA0099", "unlisted"),
        _matrix("x--z", "x--b", "x--a"),
    ]
    tactics = _script()._extract_tactics(objects)
    assert tactics["persistence"] == {"id": "TA0003", "name": "Persistence", "position": 1}
    assert tactics["execution"] == {"id": "TA0002", "name": "Execution", "position": 2}
    assert tactics["unlisted"] == {"id": "TA0099", "name": "Unlisted"}


def test_a_retired_matrix_is_not_read_and_the_first_active_one_wins() -> None:
    objects = [
        _tactic("x--a", "TA0002", "execution"),
        _tactic("x--b", "TA0003", "persistence"),
        _matrix("x--b", "x--a", revoked=True),
        _matrix("x--a", "x--b"),
        _matrix("x--b", "x--a"),
    ]
    tactics = _script()._extract_tactics(objects)
    assert tactics["execution"]["position"] == 0
    assert tactics["persistence"]["position"] == 1


def test_a_bundle_without_a_matrix_writes_no_position() -> None:
    tactics = _script()._extract_tactics([_tactic("x--a", "TA0002", "execution")])
    assert tactics == {"execution": {"id": "TA0002", "name": "Execution"}}
