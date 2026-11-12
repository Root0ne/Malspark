"""A host value the analysis states is exported when code finds it whole in an entry it cites.

The report model's identifier table listed the install folder, the update-list
file, the alternate data stream and the scheduled task a run's own decoder
recovered, each citing the decoder's entry; none of them reached `/iocs`, MISP
or STIX, because a value only an analysis stated was no source for a host
kind. The model now types each row with a closed vocabulary and says what the
evidence shows the sample doing with it; code checks every value: found whole
in an entry the row cites, no template, not every host's, created or written,
under a verdict that publishes. A row that passes is exported as source
``analysis`` with the entries holding it; every other row prints its reason.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, publishes
from malspark.reporting.stated_host_values import (
    GENERIC_NOTE,
    MAX_STATED_ROWS,
    MAX_VALUE_CHARS,
    NO_STIX_OBJECT,
    benign_reason,
    component_in,
    held_in_cited,
    identifier_answers,
    is_template,
    typed_kind,
    with_held_in,
)

SHA256 = "6" * 64
# A decoder's entry as a run's ledger holds it: each decoded text a JSON string.
DECODED = json.dumps(
    {
        "results": [
            {"text": text}
            for text in (
                "Custom_update",
                "\\update_data.dat",
                ":wtfbbq",
                "Updater",
                "Update_%x",
                "AppData",
                "C:\\Windows\\System32\\cmd.exe",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                "runnung",
            )
        ]
    }
).lower()
OTHER = json.dumps({"strings": ["OtherMarker"]}).lower()
ENTRIES = EntryTexts(texts={"ev_0021": DECODED, "ev_0030": OTHER})


def _row(kind: str, value: str, use: str = "creates/writes", cites: Any = ("ev_0021",)) -> Any:
    return HostIdentifier(kind=kind, value=value, use=use, evidence_refs=list(cites))


def _report(rows: list[Any], verdict: str = "Malware", confidence: Any = 0.9) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict=verdict,
        overall_confidence=confidence,
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(rows, ENTRIES)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _answer(row: Any, **over: Any) -> str:
    ((_, answer),) = identifier_answers(_report([row], **over))
    return answer


def _analysis_rows(report: MalwareReport) -> dict[str, Any]:
    return {row.value: row for row in report.consolidated_iocs if row.source == "analysis"}


class TestTheRunsRowsThatAreExported:
    @pytest.mark.parametrize(
        ("kind", "stated", "table_kind", "exported"),
        [
            ("folder", "Custom_update", "folder", "Custom_update"),
            ("file name", "\\update_data.dat", "path", "update_data.dat"),
            ("alternate data stream", ":wtfbbq", "ads", ":wtfbbq"),
            ("scheduled task", "Updater", "scheduled_task", "Updater"),
        ],
    )
    def test_is_a_row_of_the_ioc_table_stated_by_the_analysis(
        self, kind: str, stated: str, table_kind: str, exported: str
    ) -> None:
        rows = _analysis_rows(_report([_row(kind, stated)]))

        row = rows[exported]
        assert row.kind == table_kind
        assert publishes(row.published)
        assert row.published.startswith(
            f"yes: stated by the analysis ({kind}, creates/writes), found whole in ev_0021"
        )
        assert row.context == "stated by the analysis"

    def test_a_generic_task_name_carries_the_false_positive_note(self) -> None:
        assert GENERIC_NOTE in _answer(_row("scheduled task", "Updater"))
        assert GENERIC_NOTE not in _answer(_row("folder", "Custom_update"))

    def test_a_kind_stix_has_no_object_for_says_so(self) -> None:
        assert NO_STIX_OBJECT in _answer(_row("alternate data stream", ":wtfbbq"))
        assert NO_STIX_OBJECT not in _answer(_row("file name", "\\update_data.dat"))

    def test_the_export_carries_a_file_name_and_a_mutex_and_no_task(self) -> None:
        report = _report(
            [
                _row("file name", "\\update_data.dat"),
                _row("mutex", "runnung"),
                _row("scheduled task", "Updater"),
            ]
        )

        patterns = [
            obj["pattern"]
            for obj in ExtendedSTIXRenderer().render(report).model_dump(mode="json")["objects"]
            if obj["type"] == "indicator"
        ]
        assert "[file:name = 'update_data.dat']" in patterns
        assert "[mutex:name = 'runnung']" in patterns
        assert not any("Updater" in pattern for pattern in patterns)

    def test_misp_types_each_kind(self) -> None:
        report = _report(
            [
                _row("file name", "\\update_data.dat"),
                _row("scheduled task", "Updater"),
                _row("alternate data stream", ":wtfbbq"),
            ]
        )

        typed = {
            item["value"]: item["type"]
            for item in build_misp_attributes(report, report.consolidated_iocs, owner="x")
        }
        assert typed["update_data.dat"] == "filename"
        assert typed["Updater"] == "windows-scheduled-task"
        # MISP has no type for a stream: a text attribute, typed in its comment.
        assert typed[":wtfbbq"] == "text"


class TestTheRunsRowsThatAreRefused:
    @pytest.mark.parametrize(
        ("row", "reason"),
        [
            (_row("folder", "AppData"), "no: a Windows known folder"),
            (
                _row("file path", "C:\\Windows\\System32\\cmd.exe"),
                "no: a program Windows installs, in the folder Windows keeps it in",
            ),
            (
                _row(
                    "registry key",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                ),
                "no: a registry key every Windows installation has",
            ),
            (
                _row("file name", "Update_%x"),
                "no: it holds a format placeholder, so it is a template no log records whole",
            ),
            (
                _row("template", "Update_%x"),
                "no: the analysis typed it a template, which no log records whole",
            ),
            (
                _row("folder", "AppData", use="reads/checks"),
                "no: the analysis says the sample only reads or checks it",
            ),
        ],
    )
    def test_with_its_reason(self, row: Any, reason: str) -> None:
        report = _report([row])

        assert _analysis_rows(report) == {}
        ((_, answer),) = identifier_answers(report)
        assert answer.startswith(reason)

    @pytest.mark.parametrize(
        ("kind", "value", "reason"),
        [
            ("file path", "C:\\ExampleVendor7731\\", "no: names a directory or a root, not a file"),
            ("file name", "files/bp.dat", "no: written with a folder, it is not a file name"),
        ],
    )
    def test_a_value_of_the_wrong_shape(self, kind: str, value: str, reason: str) -> None:
        entries = EntryTexts(texts={"ev_0001": json.dumps([value]).lower()})
        row = _row(kind, value, cites=["ev_0001"])
        row.held_in = held_in_cited(entries, row)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
            verdict="Malware",
            overall_confidence=0.9,
            technical_analysis=TechnicalAnalysis(host_identifiers=[row]),
        )

        assert row.held_in == ["ev_0001"]
        ((_, answer),) = identifier_answers(report)
        assert answer == reason

    def test_a_value_only_part_of_a_longer_one_in_the_cited_entry(self) -> None:
        # ``update_data`` is inside ``\\update_data.dat``, never a value of its own.
        assert _answer(_row("file name", "update_data")) == (
            "no: its whole value is in none of the entries it cites"
        )

    def test_a_value_whole_only_in_an_entry_the_row_does_not_cite(self) -> None:
        row = _row("mutex", "runnung", cites=["ev_0030"])

        assert _answer(row) == "no: its whole value is in none of the entries it cites"

    def test_a_benign_verdict_exports_nothing(self) -> None:
        report = _report([_row("folder", "Custom_update")], verdict="Benign")

        assert _analysis_rows(report) == {}
        ((_, answer),) = identifier_answers(report)
        assert answer == "no: the verdict is Benign, which publishes no malicious indicator"

    def test_a_verdict_stated_with_no_confidence_exports_nothing(self) -> None:
        assert _answer(_row("folder", "Custom_update"), confidence=None) == (
            "no: the judge stated no verdict with a confidence"
        )

    def test_a_legacy_free_text_kind_is_read_and_refused_with_its_reason(self) -> None:
        row = HostIdentifier(kind="Folder name", value="Custom_update", evidence_refs=["ev_0021"])

        report = _report([row])

        assert report.technical_analysis.host_identifiers[0].kind == "Folder name"
        assert _analysis_rows(report) == {}
        ((_, answer),) = identifier_answers(report)
        assert "free-text kind" in answer

    def test_a_row_stored_without_a_use_is_refused(self) -> None:
        row = HostIdentifier(kind="folder", value="Custom_update", evidence_refs=["ev_0021"])

        assert "states no use" in _answer(row)

    def test_a_row_with_no_recorded_check_is_refused(self) -> None:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
            verdict="Malware",
            overall_confidence=0.9,
            technical_analysis=TechnicalAnalysis(
                host_identifiers=[_row("folder", "Custom_update")]
            ),
        )

        ((_, answer),) = identifier_answers(report)
        assert (
            answer == "no: no whole-value check against its cited entries is recorded for this row"
        )

    def test_the_sandbox_s_copy_of_the_sample_is_refused(self) -> None:
        kind = typed_kind("file path")
        copy = f"C:\\Users\\Admin\\AppData\\Local\\Temp\\{SHA256}.dll"

        assert benign_reason(kind, copy, frozenset({SHA256})).startswith("the sandbox's copy")

    def test_a_system_program_out_of_its_folder_is_kept(self) -> None:
        kind = typed_kind("file path")

        assert benign_reason(kind, "C:\\Users\\Public\\svchost.exe") == ""
        assert benign_reason(kind, "%APPDATA%\\Custom_update\\x.dll") == ""


class TestEveryExportedKind:
    @pytest.mark.parametrize(
        ("kind", "value", "table_kind"),
        [
            ("named pipe", "examplepipe_7731", "named_pipe"),
            ("service", "ExampleSvc7731", "service"),
            ("registry value", "HKCU\\Software\\ExampleVendor7731\\state", "registry_value"),
            ("registry key", "HKCU\\Software\\ExampleVendor7731", "registry"),
            ("file path", "%APPDATA%\\ExampleVendor7731\\run.dll", "path"),
        ],
    )
    def test_is_exported_under_its_table_kind(self, kind: str, value: str, table_kind: str) -> None:
        entries = EntryTexts(texts={"ev_0001": json.dumps([value]).lower()})
        row = _row(kind, value, cites=["ev_0001"])
        row.held_in = held_in_cited(entries, row)
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
            verdict="Malware",
            overall_confidence=0.9,
            technical_analysis=TechnicalAnalysis(host_identifiers=[row]),
        )

        (row,) = [r for r in build_consolidated_iocs(report) if r.source == "analysis"]
        assert (row.kind, row.value) == (table_kind, value)
        assert publishes(row.published)

    def test_an_environment_folder_is_no_placeholder(self) -> None:
        assert not is_template("%APPDATA%\\Custom_update")
        assert is_template("%APPDATA%\\Update_%x")
        assert is_template("%s%d.dll") and is_template("{0}.dat")
        assert not is_template("100%% sure")


class TestTheVocabulary:
    def test_the_model_s_schema_names_the_kinds_and_uses_and_not_the_check(self) -> None:
        schema = HostIdentifier.model_json_schema()["properties"]

        assert "scheduled task" in schema["kind"]["enum"]
        assert schema["use"]["enum"] == ["creates/writes", "reads/checks", "not shown"]
        assert "held_in" not in schema

    def test_a_kind_word_is_read_whole_and_any_other_is_free_text(self) -> None:
        assert typed_kind("Scheduled  Task").word == "scheduled task"
        assert typed_kind("Scheduled task name") is None

    def test_the_check_is_code_s_whatever_the_model_wrote(self) -> None:
        row = HostIdentifier(
            kind="folder", value="NotThere", use="creates/writes", held_in=["ev_0021"]
        )

        assert with_held_in([row], ENTRIES)[0].held_in == []
        assert with_held_in([row], None)[0].held_in is None

    def test_a_stored_row_dumps_as_it_did(self) -> None:
        row = HostIdentifier(kind="String", value="x", evidence_refs=["ev_1"])

        assert row.model_dump() == {
            "kind": "String",
            "value": "x",
            "purpose": "",
            "evidence_refs": ["ev_1"],
        }

    def test_a_stored_report_keeps_its_ioc_table(self) -> None:
        row = HostIdentifier(kind="Folder name", value="Custom_update", evidence_refs=["ev_0021"])
        report = _report([row])

        assert [r.source for r in report.consolidated_iocs] == ["identity"]

    def test_the_identifier_table_prints_each_answer(self) -> None:
        text = MarkdownRenderer().render(
            _report([_row("folder", "Custom_update"), _row("folder", "AppData")])
        )

        assert "| Kind | Value | Purpose | Evidence | Published |" in text
        assert "no: a Windows known folder" in text
        assert "yes: stated by the analysis (folder, creates/writes)" in text


class TestWholeInAPath:
    def test_a_folder_name_is_whole_as_a_component_of_a_path(self) -> None:
        text = json.dumps("C:\\Users\\x\\AppData\\Roaming\\Custom_update\\Update_1.dll").lower()
        entries = EntryTexts(texts={"ev_0001": text})

        assert held_in_cited(entries, _row("folder", "Custom_update", cites=["ev_0001"])) == [
            "ev_0001"
        ]
        # A mutex's name is not read inside a path.
        assert held_in_cited(entries, _row("mutex", "Custom_update", cites=["ev_0001"])) == []

    def test_a_longer_component_holds_no_folder(self) -> None:
        assert not component_in("custom_update", "c:\\x\\custom_update2\\y")
        assert not component_in("custom_update", "c:\\x\\custom_update.exe")
        assert component_in("custom_update", "c:/x/custom_update/y")

    def test_a_value_s_own_escapes_are_not_read(self) -> None:
        # The entry writes ``\\Registry\\Machine\\``; the row's ``\\x5c`` is an escape.
        entries = EntryTexts(texts={"ev_0001": json.dumps("\\Registry\\Machine\\").lower()})
        row = _row("registry key", "\\Registry\\Machine\\x5c", cites=["ev_0001"])

        assert held_in_cited(entries, row) == []


class TestTheBounds:
    def test_a_value_past_the_bound_is_refused_unread(self) -> None:
        row = _row("folder", "A" * (MAX_VALUE_CHARS + 1))

        assert "longer than" in _answer(row)

    def test_a_row_past_the_bound_is_refused(self) -> None:
        rows = [_row("folder", f"Folder{i}") for i in range(MAX_STATED_ROWS + 1)]
        report = _report(rows)

        assert "beyond the first" in identifier_answers(report)[-1][1]


class TestTheReadersOfModelTextAreLinear:
    @pytest.mark.parametrize(
        "text",
        ["%" * 200_000, "%1." * 70_000, "{1:" * 70_000, "%" + "0" * 200_000, "%" + "-" * 200_000],
    )
    def test_the_template_reader(self, text: str) -> None:
        started = time.perf_counter()
        is_template(text)
        assert time.perf_counter() - started < 2.0

    def test_the_component_reader(self) -> None:
        text = "\\custom_update" * 50_000 + "x"
        started = time.perf_counter()
        assert component_in("custom_update", text)
        component_in("custom_update\\", "custom_update" * 50_000)
        assert time.perf_counter() - started < 2.0

    def test_the_catalogue_reader(self) -> None:
        kind = typed_kind("file path")
        started = time.perf_counter()
        benign_reason(kind, "\\a" * 100_000 + "\\cmd.exe")
        benign_reason(typed_kind("registry key"), "HKLM\\" * 50_000)
        assert time.perf_counter() - started < 2.0

    def test_the_whole_value_check(self) -> None:
        big = json.dumps({"results": [{"text": f"value{i}"} for i in range(50_000)]}).lower()
        entries = EntryTexts(texts={"ev_0001": big})
        rows = [_row("mutex", f"value{i}", cites=["ev_0001"]) for i in range(0, 50_000, 500)]
        started = time.perf_counter()
        with_held_in(rows, entries)
        assert all(row.held_in == ["ev_0001"] for row in rows)
        assert time.perf_counter() - started < 10.0
