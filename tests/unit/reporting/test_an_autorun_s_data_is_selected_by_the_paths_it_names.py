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

from malspark.reporting import detection_signatures as ds
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
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


def _recorded(
    mods: list[RegistryMod],
    persistence: list[PersistenceMechanism],
    table: list[ConsolidatedIOC] | None = None,
) -> MalwareReport:
    """A report holding a sandbox's registry records, its IOC table built, or as stored."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        dynamic=DynamicBehavior(registry_mods=mods),
        persistence=persistence,
    )
    report.consolidated_iocs = build_consolidated_iocs(report) if table is None else table
    return MalwareReportBuilder.attach_detection_signatures(report)


EVIL = "C:\\Users\\a\\AppData\\Roaming\\evil7731.exe"


class TestOnlyAWriteNamesAProgram:
    def test_data_a_sample_read_from_a_key_a_persistence_record_names_names_none(self) -> None:
        # The key is admitted on the analyst's record of it; the sandbox only read it.
        report = _recorded(
            [RegistryMod(hive="HKCU", key=RUN, operation="query", new_value=EVIL)],
            [PersistenceMechanism(kind="registry_run", target=RUN, payload="")],
        )

        assert _sigma(report) == []
        assert report.drafts_not_built

    def test_data_under_a_common_key_no_row_admits_names_none(self) -> None:
        # The IOC table as a stored report holds it, read back by the replay:
        # no row of it names the key the value was written under.
        written = RegistryMod(
            hive="HKCU", key=RUN, operation="modify", value_name="w", new_value=EVIL
        )
        other = ConsolidatedIOC(
            type="File path", kind="path", value="C:\\Users\\a\\other7731.txt", source="sandbox"
        )

        report = _recorded([written], [], [other])

        assert _sigma(report) == []
        assert report.drafts_not_built

    def test_a_payload_under_a_common_key_no_row_admits_names_none(self) -> None:
        # A mechanism whose key has no row of its own: the table carries a
        # Run key's mechanism only, and no sandbox wrote this one.
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="winlogon_helper",
                    target="HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    payload=EVIL,
                )
            ],
        )

        assert _sigma(report) == []


class TestWhatTheDataNames:
    @pytest.mark.parametrize(
        ("data", "selected"),
        [
            # A switch and an address are no files.
            ("cmd.exe /c C:\\ProgramData\\evil7731.exe -config7731.ini 10.0.0.7", "\\evil7731.exe"),
            # A file named bare is written bare on the command line.
            ("rundll32.exe evil7731.dll,Start", "evil7731.dll"),
            # A file no process runs as its image is read where the data is.
            ("C:\\Users\\a\\AppData\\Roaming\\page7731.hta", "\\page7731.hta"),
        ],
    )
    def test_each_file_it_names_is_selected_where_the_data_is(
        self, data: str, selected: str
    ) -> None:
        detection = _detection(_sandboxed([_written("r", data)]))

        assert detection["selection_payload"] == {"Details|contains": [selected]}
        assert "selection_persistence" not in detection

    @pytest.mark.parametrize(
        ("data", "image"),
        [
            (f"{EVIL} C:\\x\\cfg7731.dat", "\\evil7731.exe"),
            ("evil7731.exe /x", "\\evil7731.exe"),
            (
                "\\\\?\\C:\\Users\\a\\AppData\\Roaming\\svchost.exe",
                "\\AppData\\Roaming\\svchost.exe",
            ),
        ],
    )
    def test_a_program_of_the_sample_s_own_is_the_image_and_all_it_says(
        self, data: str, image: str
    ) -> None:
        detection = _detection(_sandboxed([_written("r", data)]))

        assert detection["selection_persistence"] == {"Image|endswith": [image]}
        assert "selection_payload" not in detection

    def test_a_system_program_left_out_is_recorded_once_with_the_catalogue_s_reason(self) -> None:
        report = _sandboxed([_written("r", "rundll32.exe C:\\Users\\a\\evil7731.dll,Start")])

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        assert [(v.value, v.why) for v in rule.values_left_out] == [
            (RUN_TARGET, "a registry key or value every Windows installation has"),
            ("\\rundll32.exe", "a file Windows ships, in the folder Windows keeps it in"),
        ]
        assert "persistence:\\evil7731.dll" in rule.source_evidence

    def test_a_payload_printed_as_a_name_windows_ships_alone_says_so(self) -> None:
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="registry_run",
                    target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    payload="%APPDATA%\\cmd.exe",
                )
            ],
        )

        assert _sigma(report) == []
        (item,) = report.drafts_not_built
        assert ds.NAME_ALONE_REASON in item.why
        assert "in the folder Windows keeps it in" not in item.why

    def test_a_task_s_program_with_a_space_in_its_folder_is_its_image(self) -> None:
        # A target that is a file, which the sandbox recorded: read as a path,
        # not as words of a command line.
        program = "C:\\Program Files\\Vendor7731\\up7731.exe"
        report = _report(
            [],
            persistence=[PersistenceMechanism(kind="scheduled_task", target=program, payload="")],
            sandbox_rows=[
                ConsolidatedIOC(type="File path", kind="path", value=program, source="sandbox")
            ],
        )

        (body,) = _sigma(report)
        assert body["detection"]["selection_persistence"] == {"Image|endswith": ["\\up7731.exe"]}


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
