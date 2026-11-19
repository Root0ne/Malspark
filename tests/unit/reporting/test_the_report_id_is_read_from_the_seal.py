"""The report's id is read from the seal the stored report carries.

The worker writes the stored report's id into the ledger seal it stores at the
top of the report (``MalwareReport.ledger_seal["report_id"]``). The bundle's
``report.report_id`` and the links to the STIX bundle and the machine-readable
list in both reports read it there (``markdown.stored_report_id``); a report
with no seal reads exactly as it did: ``null`` and the ``{report_id}``
placeholder. Offline.
"""

from __future__ import annotations

import json

from malspark.reporting.models import MalwareReport
from malspark.reporting.renderers.bundle import bundle_json
from malspark.reporting.renderers.layout import ANALYST, FULL
from malspark.reporting.renderers.markdown import MarkdownRenderer, stored_report_id
from tests.unit.reporting._report_shapes import rich_report

REPORT_ID = "0b6f3c1e-5d2a-4e8f-9a7b-1c2d3e4f5a6b"


def _sealed() -> MalwareReport:
    report = rich_report()
    report.ledger_seal = {"report_id": REPORT_ID}
    return report


def _unsealed() -> MalwareReport:
    report = rich_report()
    report.ledger_seal = None
    report.run_summary = {k: v for k, v in (report.run_summary or {}).items() if k != "ledger_seal"}
    return report


def _stored() -> MalwareReport:
    """A report loaded from the stored shape: the seal at the top, none in the run summary."""
    document = rich_report().model_dump(mode="json")
    document["ledger_seal"] = {"report_id": REPORT_ID, "head": "ab" * 32, "entries": 3}
    document["run_summary"] = {
        k: v
        for k, v in (document.get("run_summary") or {}).items()
        if k not in ("ledger_seal", "report_id")
    }
    return MalwareReport.model_validate(document)


class TestTheHelper:
    def test_the_seal_s_id_is_the_report_s(self) -> None:
        assert stored_report_id(_sealed()) == REPORT_ID

    def test_a_report_with_no_seal_has_none(self) -> None:
        assert stored_report_id(_unsealed()) is None


class TestEachSurfaceReadsIt:
    def test_the_bundle_names_the_sealed_id(self) -> None:
        assert json.loads(bundle_json(_sealed()))["report"]["report_id"] == REPORT_ID

    def test_the_bundle_of_an_unsealed_report_names_none(self) -> None:
        assert json.loads(bundle_json(_unsealed()))["report"]["report_id"] is None

    def test_the_analyst_report_links_the_sealed_id(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_sealed())
        assert f"/reports/{REPORT_ID}/stix" in markdown
        assert "{report_id}" not in markdown

    def test_the_full_report_links_the_sealed_id(self) -> None:
        markdown = MarkdownRenderer(layout=FULL).render(_sealed())
        assert f"/reports/{REPORT_ID}/stix" in markdown
        assert "{report_id}" not in markdown

    def test_an_unsealed_report_keeps_the_placeholder(self) -> None:
        for layout in (ANALYST, FULL):
            markdown = MarkdownRenderer(layout=layout).render(_unsealed())
            assert "/reports/{report_id}/stix" in markdown


class TestTheStoredDocument:
    def test_a_stored_document_s_seal_fills_the_route_and_the_bundle(self) -> None:
        report = _stored()
        assert json.loads(bundle_json(report))["report"]["report_id"] == REPORT_ID
        for layout in (ANALYST, FULL):
            markdown = MarkdownRenderer(layout=layout).render(report)
            assert f"/reports/{REPORT_ID}/stix" in markdown
            assert "{report_id}" not in markdown
