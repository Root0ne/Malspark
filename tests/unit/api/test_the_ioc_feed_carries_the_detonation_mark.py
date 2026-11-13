"""The ``/iocs`` feed carries the detonation mark on a row a later detonation observed.

Each row of the report's IOC table a further detonation observed states
under which detonations and launches (``ConsolidatedIOC.observed_in``); the
feed serves it as ``observed_in``, and a row only the job's own detonation
observed serves no such field, so a run with one detonation is served as it
was (T-671 review r2 (a)). The value is served as JSON, each mark naming a
detonation in the citation checks' form. Offline.
"""

from __future__ import annotations

from tests.unit.reporting.test_a_later_detonation_s_observations_reach_the_report import (
    ARGS,
    _ledger,
    _report,
)

from app.schemas.job import IOCEntry
from app.services.report_service import ioc_feed_rows


def test_a_later_detonation_s_row_carries_the_mark() -> None:
    rows = {row["value"]: row for row in ioc_feed_rows(_report(_ledger()).model_dump(mode="json"))}
    assert rows["198.51.100.7"]["observed_in"] == [{"detonation": "d2", "launched_with": ARGS}]
    assert rows["c2.example.net"]["observed_in"] == [
        {"detonation": "d1"},
        {"detonation": "d2", "launched_with": ARGS},
    ]
    served = IOCEntry.model_validate(rows["198.51.100.7"]).model_dump(mode="json")
    assert served["observed_in"] == [{"detonation": "d2", "launched_with": ARGS}]


def test_a_row_of_the_job_s_own_detonation_serves_no_mark() -> None:
    rows = {row["value"]: row for row in ioc_feed_rows(_report(_ledger()).model_dump(mode="json"))}
    assert "observed_in" not in rows["192.0.2.10"]
    served = IOCEntry.model_validate(rows["192.0.2.10"]).model_dump(mode="json")
    assert "observed_in" not in served
    one = ioc_feed_rows(_report(_ledger(later=False)).model_dump(mode="json"))
    assert all("observed_in" not in row for row in one)


def test_the_response_serves_the_mark_only_where_it_is() -> None:
    from app.schemas.job import IOCListResponse

    rows = ioc_feed_rows(_report(_ledger()).model_dump(mode="json"))
    served = IOCListResponse(
        items=[IOCEntry.model_validate(row) for row in rows], total=len(rows)
    ).model_dump(mode="json")
    by_value = {item["value"]: item for item in served["items"]}
    assert "observed_in" in by_value["198.51.100.7"]
    assert "observed_in" not in by_value["192.0.2.10"]
