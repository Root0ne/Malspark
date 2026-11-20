"""One tree rendered twice, the clock moved between, gives the same units and the same files.

The build reads the stored report's clock, and so do the tree's STIX models
while it runs: an object they build at render time with a timestamp nobody
wrote, then validate again (which freezes the default into the fields set),
carries the stored report's time, never the time of the render. The run here
holds a judge's indicator written without ``valid_from`` that the export
carries as the judge wrote it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import stored_run

_STORED_CLOCK = "2026-01-02T03:04:05Z"
_INDICATOR = "Single-instance mutex fixture-mutex"


def _with_a_judge_indicator_without_valid_from(at: Path) -> Path:
    run = stored_run(at)
    judge = json.loads((run / "stix-judge.json").read_text(encoding="utf-8"))
    judge["bundle"]["objects"] += [
        {
            "id": "indicator--3",
            "type": "indicator",
            "name": _INDICATOR,
            "pattern": "[mutex:name = 'fixture-mutex']",
            "indicator_types": ["malicious-activity"],
        },
        {
            "id": "relationship--5",
            "type": "relationship",
            "source_ref": "indicator--3",
            "target_ref": "malware--1",
            "relationship_type": "indicates",
        },
    ]
    (run / "stix-judge.json").write_text(json.dumps(judge), encoding="utf-8")
    # The entry the indicator stands on.
    ledger = json.loads((run / "evidence.json").read_text(encoding="utf-8"))
    for row in ledger["items"]:
        if row["entry_id"] == "ev_0004":
            row["output"] += "; it creates the mutex fixture-mutex"
    (run / "evidence.json").write_text(json.dumps(ledger), encoding="utf-8")
    return run


def _moved(years: int) -> type[datetime]:
    class _Later(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Any:
            moved = datetime.now(UTC).replace(year=datetime.now(UTC).year + years)
            return moved.astimezone(tz) if tz is not None else moved.replace(tzinfo=None)

    return _Later


def test_two_renders_with_the_clock_moved_between_are_equal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from malspark.reporting.renderers import stix_renderer
    from malspark.schemas import stix_models

    # The run's IOC table publishes the indicator's value, so the export carries it.
    monkeypatch.setattr(stix_renderer, "_judge_indicator_unpublished", lambda *_a, **_k: None)
    run = _with_a_judge_indicator_without_valid_from(tmp_path)
    first, _files = rs.render_run(run)
    monkeypatch.setattr(stix_models, "datetime", _moved(5))
    second, _files = rs.render_run(run)

    diff = rs.compare_records(first, second)
    assert diff["changes"] == [] and "errors" not in diff
    assert first["file_digests"] == second["file_digests"]
    [carried] = [
        json.loads(u["text"])
        for u in first["units"]
        if u["mode"] == "build" and u["surface"] == "stix" and u["key"] == f"indicator {_INDICATOR}"
    ]
    assert carried["valid_from"] == _STORED_CLOCK


def test_the_stix_models_read_the_pinned_clock_and_their_own_after() -> None:
    from malspark.schemas.stix_models import Bundle, Indicator

    clock = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    with rs.pinned_stix_clock(clock):
        built = Indicator(pattern="[mutex:name = 'm']", pattern_type="stix")
        bundle = Bundle(objects=[built])
        again = Bundle.model_validate(bundle.model_dump())
    [indicator] = again.objects
    assert indicator.valid_from == clock and "valid_from" in indicator.model_fields_set
    later = Indicator(pattern="[mutex:name = 'm']", pattern_type="stix")
    assert later.valid_from.year == datetime.now(UTC).year
