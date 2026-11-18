"""The full indicator list carries each identifier row the rule refuses, with its refusal.

The report's identifier table prints every host value the analysis states, each with
the publish rule's answer; the full indicator list (``/iocs?include=all``) held only
the ones the IOC table publishes, so it said nothing of a refused one. The full list
(``builder.full_ioc_list``) now lists each refused row after the table's rows,
unpublished, its answer the refusal, under source ``analysis`` and typed by the rule's
label or, where the rule has none, by the kind the analysis wrote; only where the list
holds no row of the same kind and value. The report's IOC table, and every surface that
reads it, is unchanged; the default list is unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.services import report_service
from app.services.report_service import ioc_feed_rows
from malspark.reporting.builder import build_consolidated_iocs, full_ioc_list, ioc_table
from malspark.reporting.models import MalwareReport, TechnicalAnalysis
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, publishes
from malspark.reporting.stated_host_values import identifier_answers, with_held_in
from malspark.schemas.stix_models import Bundle
from tests.unit.reporting.test_a_host_value_the_analysis_states_is_exported_when_code_finds_it_whole import (  # noqa: E501
    ENTRIES,
    _report,
    _row,
)

TEMPLATE = "Update_%x"
_TIMES = frozenset({"created", "modified", "published", "valid_from", "first_seen", "last_seen"})


def _refused(report: MalwareReport) -> dict[str, Any]:
    table = {(row.kind, row.value) for row in ioc_table(report)}
    return {row.value: row for row in full_ioc_list(report) if (row.kind, row.value) not in table}


def test_each_refused_row_is_listed_unpublished_with_the_identifier_table_s_refusal() -> None:
    report = _report([_row("folder", "AppData"), _row("folder", "Custom_update")])
    answers = {stated.value: answer for stated, answer in identifier_answers(report)}

    rows = _refused(report)

    assert sorted(rows) == ["AppData"]
    folder = rows["AppData"]
    assert folder.source == "analysis" and folder.kind == "folder" and folder.type == "Folder"
    assert not publishes(folder.published)
    assert folder.published == answers["AppData"]
    assert folder.evidence_ids == [] or set(folder.evidence_ids) <= {"ev_0021"}


def test_a_row_of_no_rule_kind_is_typed_by_the_kind_the_analysis_wrote() -> None:
    report = _report([_row("Install marker", "Custom_update")])

    (row,) = _refused(report).values()

    assert row.type == "Install marker" and row.kind == ""
    assert not publishes(row.published) and row.published


def test_a_value_the_list_already_holds_is_not_listed_again() -> None:
    report = _report([_row("folder", "AppData"), _row("folder", "AppData")])

    assert [row.value for row in full_ioc_list(report) if row.source == "analysis"] == ["AppData"]
    # A published analysis row is the table's own: nothing is added beside it.
    published = _report([_row("folder", "Custom_update")])
    assert full_ioc_list(published) == ioc_table(published)


def test_the_report_s_table_holds_no_refused_row() -> None:
    report = _report([_row("folder", "AppData"), _row("mutex", TEMPLATE)])

    assert _refused(report)
    assert report.consolidated_iocs == ioc_table(report)
    assert not any(row.source == "analysis" for row in report.consolidated_iocs)


def test_the_default_list_is_unchanged_and_the_full_list_gains_the_refused_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report([_row("folder", "AppData"), _row("Install marker", "Custom_update")])
    stored = report.model_dump(mode="json")
    rows = ioc_feed_rows(stored)
    monkeypatch.setattr(report_service, "full_ioc_list", ioc_table)
    table_rows = ioc_feed_rows(stored)

    assert [row for row in rows if row["published"] is True] == [
        row for row in table_rows if row["published"] is True
    ]
    assert rows[: len(table_rows)] == table_rows
    added = rows[len(table_rows) :]
    assert sorted(row["value"] for row in added) == ["AppData", "Custom_update"]
    assert all(row["published"] is False and row["source"] == "analysis" for row in added)
    assert all(row["publish_answer"].startswith("no") for row in added)
    assert sorted(row["type"] for row in added) == ["Folder", "Install marker"]
    assert not any("type" in row for row in table_rows)


def test_the_served_list_carries_each_refused_row_s_type_and_no_other_row_s() -> None:
    from app.schemas.job import IOCEntry

    report = _report([_row("Install marker", "Custom_update"), _row("folder", "Custom_update")])
    served = [
        IOCEntry.model_validate(row).model_dump(mode="json")
        for row in ioc_feed_rows(report.model_dump(mode="json"))
    ]

    assert [row["type"] for row in served if "type" in row] == ["Install marker"]


def _with_a_judge_indicator(identifiers: list[Any]) -> tuple[list[dict[str, Any]], list[Any]]:
    report = _report([])
    report.technical_analysis = TechnicalAnalysis(
        host_identifiers=with_held_in(identifiers, ENTRIES)
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    judge = Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                    "pattern": f"[mutex:name = '{TEMPLATE}']",
                    "pattern_type": "stix",
                }
            ]
        }
    )
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, base_bundle=judge)
    objects = bundle.model_dump(mode="json")["objects"]
    # Each object's id by its place, so a freshly minted id reads the same in both.
    text = json.dumps(objects, sort_keys=True)
    for at, obj in enumerate(objects):
        text = text.replace(obj["id"], f"{obj['type']}--{at}")
    timeless = [
        {key: value for key, value in obj.items() if key not in _TIMES} for obj in json.loads(text)
    ]
    return timeless, list(renderer.declined)


def test_a_judge_indicator_reads_the_same_with_a_refused_identifier_of_its_value() -> None:
    with_row, declined_with = _with_a_judge_indicator([_row("mutex", TEMPLATE)])
    without, declined_without = _with_a_judge_indicator([])

    assert declined_with == declined_without
    assert any(TEMPLATE in str(why) for _code, why in declined_with)
    assert with_row == without
