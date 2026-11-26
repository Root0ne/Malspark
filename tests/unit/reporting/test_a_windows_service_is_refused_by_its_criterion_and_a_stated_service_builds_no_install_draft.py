"""A Windows service is refused by its criterion, and a stated service builds no install draft.

The catalogue's list of Windows services states its criterion (a service
Microsoft ships as part of Windows, by its service name) and its source,
Microsoft's two system-services pages; it holds every service name the pages
print, one spelling each, and no service another product adds. A service row
the list answers is refused in the criterion's words, which are true of every
entry; the stream and pipe lists keep their own words.

A service row the analysis states and the IOC table publishes is exported to
/iocs and MISP and says so. It builds no Sigma selection on the install event:
the record does not tell a service the sample installed from one that existed
and was changed. Where no Sigma draft is built at all, the sentence that says
why counts it; every other draft keeps its bytes.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.stix_renderer import publishes
from malspark.reporting.stated_host_values import (
    DEFAULT_CATALOGUE,
    NO_STIX_OBJECT,
    benign_catalogue,
    benign_reason,
    host_kinds,
    identifier_answers,
    resolve_data,
    with_held_in,
)

SERVICE_REASON = "a service Microsoft ships as part of Windows"
# A service name no list holds, and other values of their own.
OWN_SERVICE = "ExampleSvc7731"
OWN_FILE = "\\example_data7731.dat"
OWN_TASK = "ExampleTask7731"


def _report(rows: list[tuple[str, str]], verdict: str = "Malware") -> MalwareReport:
    entries = EntryTexts(texts={"ev_0021": json.dumps([value for _, value in rows]).lower()})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_0021"])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict=verdict,
        overall_confidence=0.9,
        malware_category="loader",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return MalwareReportBuilder.attach_detection_signatures(report)


def _shipped() -> dict[str, Any]:
    """The shipped catalogue file, as read from the repository's data."""
    loaded: dict[str, Any] = json.loads(resolve_data(DEFAULT_CATALOGUE).read_text(encoding="utf-8"))
    return loaded


def _sigma(report: MalwareReport) -> dict[str, str]:
    return {rule.name: rule.body for rule in report.detection_signatures if rule.kind == "sigma"}


def _answer(report: MalwareReport, value: str) -> str:
    return next(answer for stated, answer in identifier_answers(report) if stated.value == value)


class TestTheListMeetsItsCriterion:
    def test_every_entry_is_one_name_case_folded(self) -> None:
        entries = _shipped()["windows_services"]["entries"]

        assert len({entry.casefold() for entry in entries}) == len(entries)

    def test_no_service_of_another_product_is_listed(self) -> None:
        listed = benign_catalogue().windows_services

        for name in ("edgeupdate", "edgeupdatem", "microsoftedgeelevationservice"):
            assert name not in listed

    def test_its_source_names_both_microsoft_pages(self) -> None:
        source = _shipped()["windows_services"]["source"]

        assert "Security guidelines for system services in Windows Server 2016" in source
        assert "Guidance on configuring system services" in source

    def test_no_display_name_is_listed(self) -> None:
        entries = _shipped()["windows_services"]["entries"]

        assert not [entry for entry in entries if " " in entry or "(" in entry]

    @pytest.mark.parametrize(
        "name", ["AppReadiness", "wbiosrvc", "STORSVC", "CDPUserSvc", "WebClient", "vmicheartbeat"]
    )
    def test_a_documented_service_name_is_listed_in_any_case(self, name: str) -> None:
        assert name.lower() in benign_catalogue().windows_services


class TestTheRefusalSaysTheCriterion:
    @pytest.mark.parametrize("name", ["AppReadiness", "wbiosrvc", "STORSVC", "Spooler"])
    def test_a_listed_service_is_refused_in_the_criterion_s_words(self, name: str) -> None:
        assert benign_reason(host_kinds()["service"], name) == SERVICE_REASON

    def test_a_stated_row_of_one_is_refused_and_not_exported(self) -> None:
        report = _report([("service", "WbioSrvc"), ("file name", OWN_FILE)])

        assert _answer(report, "WbioSrvc") == f"no: {SERVICE_REASON}"
        assert "WbioSrvc" not in {row.value for row in report.consolidated_iocs}

    def test_the_stream_and_pipe_lists_keep_their_words(self) -> None:
        kinds = host_kinds()

        assert (
            benign_reason(kinds["alternate data stream"], ":Zone.Identifier")
            == "an alternate data stream Windows itself has on every installation"
        )
        assert (
            benign_reason(kinds["named pipe"], "\\\\.\\pipe\\lsarpc")
            == "a named pipe Windows itself has on every installation"
        )


class TestAStatedServiceIsExportedAndBuildsNoInstallDraft:
    def test_it_is_published_and_says_where_it_is_carried(self) -> None:
        report = _report([("service", OWN_SERVICE)])
        (row,) = [row for row in report.consolidated_iocs if row.value == OWN_SERVICE]

        assert publishes(row.published)
        assert row.published.endswith("; no STIX object for this kind; carried by /iocs and MISP")
        assert "Sigma" not in row.published

    def test_misp_exports_it(self) -> None:
        report = _report([("service", OWN_SERVICE)])
        attributes = build_misp_attributes(report, owner="test")

        assert [a for a in attributes if a["value"] == OWN_SERVICE and a["to_ids"]]

    def test_a_kind_a_draft_selects_on_keeps_its_sentence(self) -> None:
        report = _report([("alternate data stream", ":example7731"), ("service", OWN_SERVICE)])

        assert _answer(report, ":example7731").endswith(f"; {NO_STIX_OBJECT}")
        assert NO_STIX_OBJECT == "no STIX object for this kind; carried by /iocs, MISP and Sigma"

    def test_alone_it_builds_no_sigma_draft_and_the_report_says_why(self) -> None:
        report = _report([("service", OWN_SERVICE)])

        assert _sigma(report) == {}
        (item,) = report.drafts_not_built
        assert item.kind == "sigma"
        assert (
            "; the service the analysis states is never selected on: the record does not tell "
            "a service the sample installed from one that existed and was changed"
        ) in item.why

    def test_two_are_counted(self) -> None:
        report = _report([("service", OWN_SERVICE), ("service", "ExampleSvc7732")])

        (item,) = report.drafts_not_built
        assert "; the 2 services the analysis states are never selected on:" in item.why

    def test_beside_another_draft_that_draft_keeps_its_bytes(self) -> None:
        alone = _sigma(_report([("file name", OWN_FILE)]))
        beside = _report([("file name", OWN_FILE), ("service", OWN_SERVICE)])

        assert _sigma(beside) == alone
        assert beside.drafts_not_built == []

    def test_no_selection_on_the_install_event_is_built(self) -> None:
        report = _report([("file name", OWN_FILE), ("service", OWN_SERVICE)])

        for body in _sigma(report).values():
            assert "7045" not in body
            assert OWN_SERVICE not in body

    def test_a_task_of_the_same_shape_keeps_its_creation_draft(self) -> None:
        beside = _sigma(_report([("scheduled task", OWN_TASK), ("service", OWN_SERVICE)]))
        task = _sigma(_report([("scheduled task", OWN_TASK)]))

        assert beside == task
        (body,) = task.values()
        assert yaml.safe_load(body)["detection"]["selection_task"] == {
            "EventID": 4698,
            "TaskName|endswith": [f"\\{OWN_TASK}"],
        }

    def test_a_benign_verdict_still_publishes_nothing(self) -> None:
        report = _report([("service", OWN_SERVICE)], verdict="Benign")

        assert not publishes(_answer(report, OWN_SERVICE))
