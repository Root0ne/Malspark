"""Each surface is what the tree's application serves over the run's row, through its HTTP stack.

The render sends each request to the tree's application through a test
client, the tree's service reading the stored row (``/markdown``, ``/html``,
``/evidence-bundle.*``, ``/full``, ``/iocs``, ``/signatures/{kind}`` with its
default and both ``include`` values, ``/mitre``, ``/misp-event``,
``/attack-layer``, ``/stix``) and the call map's route over the stored ledger
rows, so a change in a service or a route is a change of the surface. A JSON
answer is what the route's response model serves, written in its served key
order: a key the row model does not declare is never served, a key the
service moves where no model fixes the order is a change, and a row model
serves its keys in the order it declares them. The HTML is rendered with a
fixed nonce.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import report, stored_run

_SIGMA = {
    "kind": "sigma",
    "name": "fixture_sigma",
    "body": "title: fixture\nlogsource: {product: windows}\ndetection: {s: {Image: x}, "
    "condition: s}\n",
}


def _render(run: Path, *modes: str) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    return rs.render_run(run, modes=modes or ("serve",))


def _changes(a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    return rs.compare_records(a, b)["changes"]


@pytest.fixture
def run(tmp_path: Path) -> Path:
    rules = [*report()["detection_signatures"], _SIGMA]
    return stored_run(tmp_path, malware_report={**report(), "detection_signatures": rules})


class TestTheResponseModel:
    def test_a_key_the_row_model_does_not_declare_is_never_served(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import report_service

        before, _files = _render(run)
        feed = report_service.ioc_feed_rows

        def _with_more(mr: dict[str, Any], kind: str | None = None) -> list[dict[str, Any]]:
            return [{**row, "x_undeclared": "seeded"} for row in feed(mr, kind)]

        monkeypatch.setattr(report_service, "ioc_feed_rows", _with_more)
        after, files = _render(run)
        assert [c for c in _changes(before, after) if "seeded" in str(c["new"])] == []
        assert "x_undeclared" not in files["serve"]["iocs.json"]

    def test_a_row_model_serves_its_keys_in_the_order_it_declares(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.schemas.job import IOCEntry
        from app.services import report_service

        before, _files = _render(run)
        feed = report_service.ioc_feed_rows

        def _reordered(mr: dict[str, Any], kind: str | None = None) -> list[dict[str, Any]]:
            return [dict(reversed(list(row.items()))) for row in feed(mr, kind)]

        monkeypatch.setattr(report_service, "ioc_feed_rows", _reordered)
        after, files = _render(run)
        rows = json.loads(files["serve"]["iocs.json"])["items"]
        assert rows
        for row in rows:
            assert list(row) == [name for name in IOCEntry.model_fields if name in row]
        moved = [
            c
            for c in _changes(before, after)
            if str(c["group"]).startswith("iocs") or str(c["key"]).startswith("iocs")
        ]
        assert moved == []

    def test_a_key_moved_where_no_model_fixes_the_order_is_a_change(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import misp

        before, _files = _render(run)
        build = misp.build_misp_event

        def _reordered(*args: Any, **kwargs: Any) -> dict[str, Any]:
            event = build(*args, **kwargs)
            return {"Event": dict(reversed(list(event["Event"].items())))}

        monkeypatch.setattr(misp, "build_misp_event", _reordered)
        after, _files = _render(run)
        changes = _changes(before, after)
        assert {c["surface"] for c in changes} == {rs.FILE_LINES, rs.FILE_SURFACE, rs.HTTP_SURFACE}
        assert {c["group"] for c in changes if c["surface"] == rs.FILE_LINES} == {"misp-event.json"}
        # The bytes served are others; their length is the same.
        assert [c["key"] for c in changes if c["surface"] == rs.HTTP_SURFACE] == [
            "GET /reports/{id}/misp-event body"
        ]

    def test_the_call_map_is_served_through_its_response_model(self, run: Path) -> None:
        _record, files = _render(run)
        served = json.loads(files["serve"]["call-map.json"])
        assert list(served) == ["job_id", "image_base", "functions", "roots"]


class TestTheServiceIsCalled:
    def test_the_printed_download_is_its_own_surface(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import report_service

        before, files = _render(run)
        assert "fixture_sigma" in files["serve"]["signatures-sigma-printed.txt"]
        download = report_service.signature_download

        def _printed_none(signatures: Any, kind: str, include: str = "printed") -> str:
            return download(signatures, kind, include) if include == "all" else ""

        monkeypatch.setattr(report_service, "signature_download", _printed_none)
        after, _files = _render(run)
        groups = {c["group"] for c in _changes(before, after) if c["surface"] == "rules.download"}
        # The route's default is the printed rules: asked with no query, the same.
        assert groups == {"sigma default", "sigma printed"}

    def test_the_owner_the_service_derives_the_misp_event_from_is_compared(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import report_service
        from malspark.reporting.misp import build_misp_event

        before, _files = _render(run, "build")

        async def _owned_by_the_report(
            self: Any, report_id: Any, user: Any
        ) -> dict[str, Any] | None:
            row = await self.get_report(report_id, user)
            typed = report_service._typed_report(row.malware_report)
            served, _note = report_service.with_current_iocs(row.malware_report, str(row.id))
            attributes = served.get("misp_attributes") or []
            return dict(build_misp_event(typed, attributes, owner=str(row.id)))

        monkeypatch.setattr(
            report_service.ReportService, "get_malware_report_misp_event", _owned_by_the_report
        )
        after, _files = _render(run, "build")
        assert any(c["surface"] == "misp" and c["key"] == "event" for c in _changes(before, after))

    def test_full_is_a_surface_of_its_top_level_fields(
        self, run: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.api.v1 import reports

        before, _files = _render(run)
        keys = [u["key"] for u in before["units"] if u["surface"] == "full"]
        assert "verdict" in keys and "consolidated_iocs" in keys
        servers = reports.with_source_servers
        monkeypatch.setattr(
            reports, "with_source_servers", lambda mr: {**servers(mr), "seeded": True}
        )
        after, _files = _render(run)
        [added] = [c for c in _changes(before, after) if c["surface"] == "full"]
        assert (added["change"], added["key"], added["new"]) == ("added", "seeded", "true")


class TestTheHtmlIsServedWithAFixedNonce:
    def test_the_style_nonce_and_the_policy_header_are_the_same_on_each_render(
        self, run: Path
    ) -> None:
        first, files = _render(run)
        second, _files = _render(run)
        assert _changes(first, second) == []
        html = files["serve"]["report.html"]
        headers = files["serve"]["report.html.headers"]
        nonce = html.split('<style nonce="', 1)[1].split('"', 1)[0]
        assert f"'nonce-{nonce}'" in headers
        assert "content-disposition: inline;" in headers
