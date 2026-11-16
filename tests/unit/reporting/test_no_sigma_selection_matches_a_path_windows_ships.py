"""No Sigma selection matches a path Windows ships, under the selection's own operator.

Each earlier fix closed the inputs a review named, and the next review found
new ones: a payload under ``%SystemRoot%`` printed ``Image|endswith:
\\System32\\cmd.exe``, an unquoted path with a space printed ``contains:
host.exe``, a stated ``System32\\`` folder printed ``contains: \\System32\\``;
each fires on every host. This is the net under all of them: forms built from
every program the platform's catalogue says Windows ships, as a stated path, a
persistence payload and a written autorun's data, and not one printed
selection of any draft matches a path Windows ships the way the rule would
match it (``endswith``: a shipped path ends with the value; ``contains``: a
shipped path holds it; no operator: the value is one). The shipped paths are
built here from the catalogue's names and folders, independently of the
module's own check.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import yaml

from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    PersistenceMechanism,
    RegistryMod,
    SampleIdentity,
)
from malspark.reporting.stated_host_values import benign_catalogue
from tests.unit.reporting.test_a_sigma_selection_that_stands_alone_holds_a_specific_value import (
    _report,
)

pytestmark = pytest.mark.slow

RUN = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
CATALOGUE = benign_catalogue()
NAMES = sorted(CATALOGUE.system_binaries)
# Rows of one report: under the cap a stated draft selects on.
_CHUNK = 60


def _shipped() -> str:
    """Every path the oracle holds Windows ships, one per line, lower case: each catalogue
    name directly under the system root and under every system folder, under the system
    folders the catalogue nests (``System32\\WindowsPowerShell\\v1.0``) and under the .NET
    Framework's, written with a drive and with each environment name of the system root."""
    folders = sorted(CATALOGUE.system_folders)
    chains = [
        "",
        *(f"{folder}\\" for folder in folders),
        *(f"{top}\\{folder}\\" for top in ("system32", "syswow64") for folder in folders),
        *(f"{top}\\windowspowershell\\v1.0\\" for top in ("system32", "syswow64")),
        *(f"microsoft.net\\{fw}\\{v}\\" for fw in ("framework", "framework64") for v in folders),
    ]
    roots = ["c:\\windows\\", "%systemroot%\\", "%windir%\\", "%systemdrive%\\windows\\"]
    paths = [root + chain + name for root in roots for chain in chains for name in NAMES]
    keys = ["\\" + key + "\\" for key in CATALOGUE.registry_keys] + [
        "\\" + value for value in CATALOGUE.registry_values
    ]
    return "\n" + "\n".join(paths + keys) + "\n"


SHIPPED = _shipped()


def _matches(field_name: str, value: str) -> bool:
    """Whether a shipped path matches ``value`` under the field's operator."""
    folded = value.lower().replace("/", "\\")
    if field_name.endswith("|contains"):
        return folded in SHIPPED
    if field_name.endswith("|endswith"):
        return folded + "\n" in SHIPPED
    return "\n" + folded + "\n" in SHIPPED


def _matched(report: MalwareReport) -> list[str]:
    out = []
    for rule in report.detection_signatures:
        if rule.kind != "sigma":
            continue
        for name, selection in yaml.safe_load(rule.body)["detection"].items():
            if not name.startswith("selection_"):
                continue
            for field_name, values in selection.items():
                for value in values if isinstance(values, list) else []:
                    # The YAML holds the Sigma literal; the oracle reads the
                    # text it matches.
                    text = value.replace("\\*", "*").replace("\\?", "?")
                    if _matches(field_name, text):
                        out.append(f"{name} {field_name}: {value}")
    return out


def _sliced(name: str) -> str:
    """``name`` cut by a space where its stem is longest on both sides."""
    stem = name.rsplit(".", 1)[0]
    at = max(1, len(stem) // 2)
    return f"{name[:at]} {name[at:]}"


# The system root as each environment name the catalogue knows for it writes it.
_ROOTS = sorted("\\".join(root) for root in CATALOGUE.system_roots if root[0].startswith("%"))
# Each form a program's name is written in, as a function of the name.
FORMS: dict[str, Callable[[str], str]] = {
    "whole": "C:\\Windows\\System32\\{}".format,
    "whole under the root": "C:\\Windows\\{}".format,
    "whole, 32-bit": "C:\\Windows\\SysWOW64\\{}".format,
    "bare": "{}".format,
    **{f"under {env}": (env + "\\{}").format for env in sorted(CATALOGUE.environment_folders)},
    **{f"under {root}\\System32": (root + "\\System32\\{}").format for root in _ROOTS},
    **{
        f"under {root}\\SysWOW64 with a word": (root + "\\SysWOW64\\{} x").format for root in _ROOTS
    },
    **{
        f"rootless under {folder}": (folder + "\\{}").format
        for folder in sorted(CATALOGUE.system_folders)
    },
    "sliced under a vendor's folder": lambda name: (
        f"C:\\Program Files (x86)\\Vendor7731\\{_sliced(name)}"
    ),
    "sliced under the system folder": lambda name: f"C:\\Windows\\System32\\{_sliced(name)}",
    "sliced with an argument": lambda name: f"C:\\Program Files\\Vendor7731\\{_sliced(name)} /s",
    "quoted with an argument": lambda name: f'"C:\\Windows\\System32\\{name}" /x',
    "quoted under the root's name": lambda name: f'"%SystemRoot%\\System32\\{name}"',
    "with a further file": lambda name: f"%SystemRoot%\\System32\\{name} C:\\Users\\a\\x7731.dll",
    "unquoted with arguments": lambda name: f"C:\\Windows\\System32\\{name} /x -k netsvcs",
    "mixed case": lambda name: f"C:\\WINDOWS\\SyStEm32\\{name.upper()}",
    "mixed case under the root's name": lambda name: f"%SYSTEMROOT%\\system32\\{name.title()}",
    "forward slashes": lambda name: f"C:/Windows/System32/{name}",
    "forward slashes under the root's name": lambda name: f"%windir%/system32/{name}",
}
# A folder Windows keeps its programs in, as a stated folder is written.
FOLDER_FORMS: dict[str, Callable[[str], str]] = {
    "rootless": "{}\\".format,
    "under a vendor's folder": "C:\\Program Files\\{}\\".format,
    "under the root's name": "%SystemRoot%\\{}\\".format,
    "under the root": "C:\\Windows\\{}\\".format,
}


def _chunks() -> list[list[str]]:
    return [NAMES[at : at + _CHUNK] for at in range(0, len(NAMES), _CHUNK)]


def _payload_report(payloads: list[str]) -> MalwareReport:
    report = _bare_report(
        persistence=[
            PersistenceMechanism(kind="registry_run", target=f"HKCU\\{RUN}", payload=payload)
            for payload in payloads
        ]
    )
    return MalwareReportBuilder.attach_detection_signatures(report)


def _written_report(data: list[str]) -> MalwareReport:
    # The record the sandbox's reader makes of a value written to the Run
    # key (``ledger_projection.dynamic_from_ledger``): the key, the value's
    # name and its data.
    report = _bare_report(
        registry_mods=[
            RegistryMod(
                hive="HKCU",
                key=f"HKEY_CURRENT_USER\\{RUN}",
                value_name=f"v{at}",
                operation="modify",
                new_value=text,
            )
            for at, text in enumerate(data)
        ]
    )
    return MalwareReportBuilder.attach_detection_signatures(report)


def _bare_report(**kwargs: Any) -> MalwareReport:
    persistence = kwargs.pop("persistence", [])
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        dynamic=DynamicBehavior(**kwargs),
        persistence=persistence,
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


@pytest.mark.parametrize("form", FORMS)
def test_no_stated_path_prints_a_selection_a_shipped_path_matches(form: str) -> None:
    write = FORMS[form]
    for names in _chunks():
        report = _report([("file path", write(name)) for name in names])

        assert _matched(report) == [], form


@pytest.mark.parametrize("form", FOLDER_FORMS)
def test_no_stated_folder_prints_a_selection_a_shipped_path_matches(form: str) -> None:
    write = FOLDER_FORMS[form]
    report = _report([("folder", write(folder)) for folder in sorted(CATALOGUE.system_folders)])

    assert _matched(report) == [], form


@pytest.mark.parametrize("form", FORMS)
def test_no_persistence_payload_prints_a_selection_a_shipped_path_matches(form: str) -> None:
    report = _payload_report([FORMS[form](name) for name in NAMES])

    assert _matched(report) == [], form


@pytest.mark.parametrize("form", FORMS)
def test_no_written_autorun_prints_a_selection_a_shipped_path_matches(form: str) -> None:
    report = _written_report([FORMS[form](name) for name in NAMES])

    assert _matched(report) == [], form


def test_the_oracle_holds_the_paths_the_reviews_found() -> None:
    assert _matches("Image|endswith", "\\System32\\cmd.exe")
    assert _matches("CommandLine|contains", "host.exe")
    assert _matches("TargetFilename|contains", "\\System32\\")
    assert _matches("TargetObject|contains", "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    assert not _matches("Image|endswith", "\\x7731.exe")
    assert not _matches("TargetFilename|endswith", "\\Users\\Public\\svchost.exe")


class TestTheInputsTheReviewFound:
    @pytest.mark.parametrize(
        ("kind", "stated", "why"),
        [
            ("folder", "System32\\", "a path Windows ships on every host holds it"),
            (
                "folder",
                "C:\\Program Files\\System32\\",
                "a path Windows ships on every host holds it",
            ),
            ("file path", "System32\\cmd.exe", "a path Windows ships on every host ends with it"),
        ],
    )
    def test_a_stated_value_a_shipped_path_matches_is_left_out_and_says_so(
        self, kind: str, stated: str, why: str
    ) -> None:
        report = _report([(kind, stated)])

        assert _matched(report) == []
        assert not [r for r in report.detection_signatures if r.kind == "sigma"]
        (item,) = report.drafts_not_built
        assert why in item.why

    @pytest.mark.parametrize(
        "payload",
        ["%SystemRoot%\\System32\\cmd.exe", "%windir%\\System32\\svchost.exe -k netsvcs"],
    )
    def test_a_payload_windows_ships_under_the_root_s_name_is_left_out_with_its_reason(
        self, payload: str
    ) -> None:
        report = _payload_report([payload])

        assert not [r for r in report.detection_signatures if r.kind == "sigma"]
        (item,) = report.drafts_not_built
        assert "a file Windows ships, in the folder Windows keeps it in" in item.why

    @pytest.mark.parametrize(
        "payload",
        [
            "%SystemRoot%\\System32\\rundll32.exe C:\\Users\\a\\evil7731.dll,Start",
            "%SystemRoot%\\SysWOW64\\rundll32.exe C:\\Users\\a\\evil7731.dll,Start",
        ],
    )
    def test_a_program_windows_ships_under_the_root_s_name_selects_the_path_after_it(
        self, payload: str
    ) -> None:
        report = _payload_report([payload])

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        detection = yaml.safe_load(rule.body)["detection"]
        assert detection["selection_payload"] == {"CommandLine|contains": ["\\evil7731.dll"]}
        assert "selection_persistence" not in detection
        assert ("\\rundll32.exe", "a file Windows ships, in the folder Windows keeps it in") in [
            (v.value, v.why) for v in rule.values_left_out
        ]
