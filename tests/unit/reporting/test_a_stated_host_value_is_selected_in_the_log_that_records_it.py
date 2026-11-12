"""A host value the analysis states and the run publishes is selected in the log that records it.

The install folder, the update-list file and the alternate data stream a run's
decoder recovered could reach a Sigma draft only through a sandbox's record,
which named none of them. A value the IOC table publishes as stated by the
analysis is now selected, whole, in the log source that records its kind: a
file and a folder in ``file_event``, a stream in ``create_stream_hash``, a task
in event 4698, a service in event 7045, a pipe in ``pipe_created``, a registry
key in ``registry_event``. A generic name (a task called like an ordinary
updater) never forms a selection alone, and the report says so when nothing
else is left.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.stated_host_values import with_held_in


def _report(rows: list[tuple[str, str]], verdict: str = "Malware") -> MalwareReport:
    entries = EntryTexts(texts={"ev_0021": json.dumps([value for _, value in rows]).lower()})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_0021"])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64), platform="windows"),
        verdict=verdict,
        overall_confidence=0.9,
        malware_category="loader",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return MalwareReportBuilder.attach_detection_signatures(report)


def _sigma(report: MalwareReport) -> dict[str, dict[str, Any]]:
    return {
        rule.name: yaml.safe_load(rule.body)
        for rule in report.detection_signatures
        if rule.kind == "sigma"
    }


def _by_source(report: MalwareReport) -> dict[str, dict[str, Any]]:
    out = {}
    for body in _sigma(report).values():
        source = body["logsource"]
        out[source.get("category") or source.get("service")] = body
    return out


class TestTheRunsValues:
    def test_a_file_a_folder_and_a_stream_are_selected_whole(self) -> None:
        drafts = _by_source(
            _report(
                [
                    ("file name", "\\update_data.dat"),
                    ("folder", "Custom_update"),
                    ("alternate data stream", ":wtfbbq"),
                ]
            )
        )

        assert drafts["file_event"]["detection"] == {
            "selection_file": {"TargetFilename|endswith": ["\\update_data.dat"]},
            "selection_folder": {"TargetFilename|contains": ["\\Custom_update\\"]},
            "condition": "1 of selection_*",
        }
        assert drafts["create_stream_hash"]["detection"] == {
            "selection_stream": {"TargetFilename|endswith": [":wtfbbq"]},
            "condition": "selection_stream",
        }

    def test_a_generic_task_name_alone_makes_no_selection_and_says_why(self) -> None:
        report = _report([("scheduled task", "Updater")])

        assert _sigma(report) == {}
        (item,) = report.drafts_not_built
        assert "the value the analysis states is a name ordinary software also uses" in item.why

    def test_a_generic_name_is_left_out_beside_a_selected_value(self) -> None:
        drafts = _by_source(
            _report([("scheduled task", "Updater"), ("scheduled task", "ExampleTask7731")])
        )

        assert drafts["security"]["detection"]["selection_task"] == {
            "EventID": 4698,
            "TaskName|endswith": ["\\ExampleTask7731"],
        }


class TestEveryKind:
    def test_a_service_a_pipe_and_a_registry_key(self) -> None:
        report = _report(
            [
                ("service", "ExampleSvc7731"),
                ("named pipe", "\\\\.\\pipe\\examplepipe_7731"),
                ("registry key", "HKCU\\Software\\ExampleVendor7731"),
            ]
        )
        drafts = _by_source(report)

        assert drafts["system"]["detection"]["selection_service"] == {
            "EventID": 7045,
            "ServiceName": ["ExampleSvc7731"],
        }
        assert drafts["pipe_created"]["detection"]["selection_pipe"] == {
            "PipeName": ["\\examplepipe_7731"]
        }
        assert drafts["registry_event"]["detection"]["selection_registry"] == {
            "TargetObject|contains": ["\\Software\\ExampleVendor7731"]
        }

    def test_each_draft_has_its_own_name_and_id(self) -> None:
        report = _report([("file name", "\\update_data.dat"), ("service", "ExampleSvc7731")])
        rules = [rule for rule in report.detection_signatures if rule.kind == "sigma"]

        assert len({rule.name for rule in rules}) == len(rules) == 2
        assert len({yaml.safe_load(rule.body)["id"] for rule in rules}) == 2
        assert all(rule.compile_error is None for rule in rules)

    def test_a_published_path_of_another_source_selects_as_it_did(self) -> None:
        # A path the code passes to its argument is published on its chain;
        # the drafts over stated values read only the analysis's rows.
        from malspark.reporting.models import BoundValue

        report = _report([])
        report.bound_values = [
            BoundValue(
                value="C:\\ProgramData\\ExampleVendor7731\\x.dat",
                kind="path",
                role="file_path",
                api="CreateFileW",
                argument=1,
                entry="ev_0021",
            )
        ]
        report.consolidated_iocs = build_consolidated_iocs(report)
        assert any(
            row.source == "call_argument" and row.published for row in report.consolidated_iocs
        )
        report = MalwareReportBuilder.attach_detection_signatures(report)

        assert _sigma(report) == {}

    def test_a_mutex_gets_no_draft(self) -> None:
        assert _sigma(_report([("mutex", "examplemutex_7731")])) == {}

    def test_a_benign_verdict_drafts_nothing(self) -> None:
        assert _sigma(_report([("file name", "\\update_data.dat")], verdict="Benign")) == {}

    def test_a_path_is_selected_past_its_known_folders(self) -> None:
        drafts = _by_source(_report([("file path", "%APPDATA%\\ExampleVendor7731\\run.dll")]))

        assert drafts["file_event"]["detection"]["selection_file"] == {
            "TargetFilename|endswith": ["\\ExampleVendor7731\\run.dll"]
        }
