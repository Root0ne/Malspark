"""A stated host value stands on a delimited value, one answer, and nothing every host holds.

A review of the first build found that a common word of a tool's prose
grounded a host value ("injects into explorer process" held a mutex
``explorer``), that a URL's path held a folder, that a generic name still
became a YARA string and an IDS-flagged MISP attribute, that the identifier
table could say "yes" for a value the IOC table refused under the same kind,
that the prompt-only path asked the model for the field code writes and never
showed the vocabulary, that values every Windows installation holds were
exported, that a registry value and a rooted folder had no STIX object they
have, that Sigma values were not escaped, and that a stream written after its
file's name was never held. Each is fixed by a general rule; these tests hold
the rules against prose, key-value and URL entries as well as JSON strings.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml
from stix2validator import ValidationOptions, validate_instance

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.detection_signatures import sigma_literal
from malspark.reporting.misp import build_misp_attributes
from malspark.reporting.models import (
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    indicator_pattern,
    pattern_values,
    publishes,
)
from malspark.reporting.stated_host_values import (
    GENERIC_NOTE,
    benign_reason,
    held_in_cited,
    identifier_answers,
    is_generic,
    typed_kind,
    with_held_in,
)

SHA256 = "6" * 64


def _held(kind: str, value: str, text: str) -> list[str]:
    entries = EntryTexts(texts={"ev_1": text.lower()})
    row = HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_1"])
    return held_in_cited(entries, row)


def _report(
    rows: list[tuple[str, str]], text: str, *, file_name: str | None = None, **over: Any
) -> MalwareReport:
    entries = EntryTexts(texts={"ev_1": text.lower()})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_1"])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256=SHA256), file_name=file_name, platform="windows"
        ),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="loader",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
        **over,
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _decoded(*values: str) -> str:
    return json.dumps({"results": [{"text": value} for value in values]})


class TestAValueIsHeldOnlyWhereDelimited:
    @pytest.mark.parametrize(
        ("kind", "value", "text"),
        [
            ("mutex", "explorer", "The sample injects into explorer process and waits."),
            ("service", "Windows", "The Windows service manager starts it."),
            ("scheduled task", "Updater", "The sample installs an updater, which runs at logon."),
            ("folder", "Startup", "It drops a link in the startup folder."),
            ("file name", "x.dat", "It deletes x.dat."),
            # One end delimited is not enough: a quote closes the text, a space opens it.
            ("scheduled task", "Updater", "It then runs updater"),
            ("scheduled task", "Updater", "updater runs it"),
            # A name inside a path is the path's: a mutex is no folder.
            ("mutex", "explorer", "HKCU\\Software\\Microsoft\\Windows\\Explorer\\Advanced"),
        ],
    )
    def test_a_word_of_running_text_holds_nothing(self, kind: str, value: str, text: str) -> None:
        assert _held(kind, value, json.dumps({"summary": text})) == []

    @pytest.mark.parametrize(
        ("kind", "value", "text"),
        [
            ("scheduled task", "Updater", _decoded("Updater")),
            ("scheduled task", "Updater", "TaskName=Updater\nAuthor=x"),
            ("service", "ExampleSvc7731", "ServiceName: ExampleSvc7731"),
            ("folder", "Custom_update", json.dumps("C:\\Users\\a\\AppData\\Custom_update\\x.dll")),
            ("folder", "Custom_update", "C:/Users/a/AppData/Custom_update/x.dll"),
            ("file name", "\\update_data.dat", _decoded("\\update_data.dat")),
        ],
    )
    def test_a_delimited_value_is_held(self, kind: str, value: str, text: str) -> None:
        assert _held(kind, value, text) == ["ev_1"]

    @pytest.mark.parametrize(
        ("kind", "value"),
        [("folder", "files"), ("file name", "x.dll"), ("folder", "update")],
    )
    def test_a_url_s_path_holds_no_host_folder_or_file(self, kind: str, value: str) -> None:
        text = json.dumps(
            {"urls": ["https://evil.example/files/x.dll", "http://a.example/update?x=1"]}
        )

        assert _held(kind, value, text) == []

    def test_a_stream_written_after_its_file_s_name_is_held(self) -> None:
        text = json.dumps({"path": "c:\\x\\a.exe:wtfbbq"})

        assert _held("alternate data stream", ":wtfbbq", text) == ["ev_1"]
        assert _held("alternate data stream", ":wtfbb", text) == []


class TestAGenericNameIsNeverAMatcherAlone:
    def _generic(self) -> MalwareReport:
        report = _report(
            [("mutex", "update"), ("scheduled task", "Updater")], _decoded("update", "Updater")
        )
        report.attribution.family = "ExampleFamily"
        report.attribution.family_grounded = True
        return MalwareReportBuilder.attach_detection_signatures(report)

    def test_it_is_published_with_the_note(self) -> None:
        rows = {r.value: r for r in self._generic().consolidated_iocs if r.source == "analysis"}

        assert publishes(rows["update"].published) and GENERIC_NOTE in rows["update"].published

    def test_no_yara_string_and_no_sigma_selection(self) -> None:
        report = self._generic()

        for rule in report.detection_signatures:
            assert '"update"' not in rule.body.lower()
            assert rule.kind != "sigma"

    def test_misp_lists_it_without_the_ids_flag(self) -> None:
        report = self._generic()
        typed = {
            a["value"]: a
            for a in build_misp_attributes(report, report.consolidated_iocs, owner="x")
        }

        assert typed["update"]["to_ids"] is False
        assert typed["Updater"]["to_ids"] is False

    def test_stix_mints_no_indicator_for_it(self) -> None:
        patterns = [
            obj.get("pattern", "")
            for obj in ExtendedSTIXRenderer()
            .render(self._generic())
            .model_dump(mode="json")["objects"]
        ]

        assert not any("'update'" in pattern for pattern in patterns)


class TestOneAnswerPerKindAndValue:
    def test_a_refused_tool_row_becomes_the_analysis_row(self) -> None:
        report = _report(
            [("mutex", "xyzMutex77")],
            json.dumps({"strings": ["xyzmutex77"]}),
            static=StaticAnalysis(
                interesting_strings=[StringIOC(value="xyzMutex77", kind="mutex")]
            ),
        )

        (row,) = [r for r in report.consolidated_iocs if r.value == "xyzMutex77"]
        assert (row.kind, row.source) == ("mutex", "analysis")
        assert publishes(row.published)
        ((_, answer),) = identifier_answers(report)
        assert answer == row.published
        patterns = [
            obj.get("pattern", "")
            for obj in ExtendedSTIXRenderer().render(report).model_dump(mode="json")["objects"]
        ]
        assert "[mutex:name = 'xyzMutex77']" in patterns
        analyst = MarkdownRenderer().render(report)
        assert "xyzMutex77" in analyst


class TestWhatEveryWindowsHostHolds:
    @pytest.mark.parametrize(
        ("kind", "value"),
        [
            ("file path", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
            ("file path", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"),
            ("folder", "C:\\PROGRA~1"),
            ("folder", "C:\\Windows. "),
            ("folder", "C:\\Windows\\System32\\drivers\\etc"),
            ("mutex", "Global"),
            ("registry key", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler"),
            (
                "registry value",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
            ),
            ("alternate data stream", ":Zone.Identifier"),
            ("alternate data stream", ":$DATA"),
            ("service", "Spooler"),
            ("named pipe", "\\\\.\\pipe\\lsass"),
        ],
    )
    def test_is_refused(self, kind: str, value: str) -> None:
        assert benign_reason(typed_kind(kind), value) != ""

    @pytest.mark.parametrize(
        ("kind", "value"),
        [
            ("file path", "C:\\Users\\Public\\svchost.exe"),
            ("folder", "C:\\PROGRA~1\\ExampleVendor7731"),
            ("mutex", "Global\\examplemutex_7731"),
            ("registry key", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ExampleSvc7731"),
            ("service", "ExampleSvc7731"),
            ("named pipe", "\\\\.\\pipe\\examplepipe_7731"),
        ],
    )
    def test_a_value_of_its_own_is_kept(self, kind: str, value: str) -> None:
        assert benign_reason(typed_kind(kind), value) == ""

    def test_the_sample_s_submitted_name_is_refused(self) -> None:
        report = _report(
            [("file path", "C:\\Users\\a\\AppData\\Local\\Temp\\invoice_7731.exe")],
            json.dumps("C:\\Users\\a\\AppData\\Local\\Temp\\invoice_7731.exe"),
            file_name="invoice_7731.exe",
        )

        ((_, answer),) = identifier_answers(report)
        assert answer == "no: the sample's own file name, as it was submitted"

    def test_a_namespace_is_read_past_for_the_generic_check(self) -> None:
        assert is_generic(typed_kind("mutex"), "Global\\Updater")


class TestARegistryKeyIsGenericOnlyUnderAWindowsKey:
    def test_under_a_run_key(self) -> None:
        kind = typed_kind("registry value")

        assert is_generic(kind, "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
        assert not is_generic(kind, "HKCU\\Software\\ExampleVendor7731\\Config")


class TestStix:
    def test_a_registry_value_and_a_rooted_folder_have_objects(self) -> None:
        value = "HKCU\\Software\\ExampleVendor7731\\state"
        pattern = indicator_pattern("registry_value", value)

        assert pattern == (
            "[windows-registry-key:key = 'HKCU\\\\Software\\\\ExampleVendor7731' AND "
            "windows-registry-key:values[*].name = 'state']"
        )
        assert [(v.kind, v.value) for v in pattern_values(pattern)] == [("registry_value", value)]
        assert indicator_pattern("folder", "C:\\ExampleVendor7731") == (
            "[directory:path = 'C:\\\\ExampleVendor7731']"
        )
        assert indicator_pattern("folder", "ExampleVendor7731") is None

    def test_the_export_carries_them(self) -> None:
        value = "HKCU\\Software\\ExampleVendor7731\\state"
        folder = "C:\\ExampleVendor7731"
        report = _report([("registry value", value), ("folder", folder)], _decoded(value, folder))

        bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")
        patterns = [obj.get("pattern", "") for obj in bundle["objects"]]
        result = validate_instance(bundle, ValidationOptions(version="2.1"))
        assert result.is_valid, [str(error) for error in result.errors]
        assert indicator_pattern("registry_value", value) in patterns
        assert indicator_pattern("folder", folder) in patterns
        answers = [a for _, a in identifier_answers(report)]
        assert not any("no STIX object" in a for a in answers)


class TestSigmaValuesAreLiteral:
    @pytest.mark.parametrize(
        ("value", "written"),
        [
            ("a*b?.dat", "a\\*b\\?.dat"),
            ("\\Software\\Classes\\*\\shell", "\\Software\\Classes\\\\\\*\\shell"),
            ("plain\\path", "plain\\path"),
        ],
    )
    def test_escaped(self, value: str, written: str) -> None:
        assert sigma_literal(value) == written

    def test_a_draft_writes_them_escaped(self) -> None:
        report = _report([("file name", "a*b?.dat")], _decoded("a*b?.dat"))
        report = MalwareReportBuilder.attach_detection_signatures(report)

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        selection = yaml.safe_load(rule.body)["detection"]["selection_file"]
        assert selection == {"TargetFilename|endswith": ["\\a\\*b\\?.dat"]}
