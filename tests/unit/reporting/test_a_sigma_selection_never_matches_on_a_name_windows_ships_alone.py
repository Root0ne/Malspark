"""A Sigma selection never matches on a name Windows ships alone.

A stated path was cut past its drive, the user's profile and an environment
folder, and the catalogue was asked about the stated path, which it passes:
``%APPDATA%\\cmd.exe`` and ``C:\\Users\\Admin\\svchost.exe`` printed ``\\cmd.exe``
and ``\\svchost.exe``, a selection every Windows host matches. The catalogue
is now asked about the form that is printed. A stated path keeps what a log
writes the same on every host past the drive and the user's own name (a
profile's sub-folders, ``Users\\Public``), and a long-path prefix is read off;
where what is left is a name alone that Windows ships, the value is taken out
with a reason that is true of it.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting import detection_signatures as ds
from malspark.reporting.models import PersistenceMechanism
from malspark.reporting.stated_host_values import benign_catalogue
from tests.unit.reporting.test_a_sigma_selection_that_stands_alone_holds_a_specific_value import (
    _report,
    _sigma,
)

RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"


def _values(body: dict[str, Any]) -> list[str]:
    return [
        value
        for name, selection in body["detection"].items()
        if name.startswith("selection_")
        for values in selection.values()
        if isinstance(values, list)
        for value in values
    ]


class TestAStatedPath:
    @pytest.mark.parametrize(
        "stated",
        [
            "%APPDATA%\\cmd.exe",
            "%TEMP%\\svchost.exe",
            "%USERPROFILE%\\svchost.exe",
            "%ProgramData%\\svchost.exe",
            "C:\\Users\\Admin\\svchost.exe",
        ],
    )
    def test_whose_name_alone_is_windows_own_is_taken_out_with_a_true_reason(
        self, stated: str
    ) -> None:
        report = _report([("file path", stated)])

        assert _sigma(report) == []
        (item,) = report.drafts_not_built
        assert ds.NAME_ALONE_REASON in item.why
        assert "in the folder Windows keeps it in" not in item.why
        assert "every Windows host's own" not in item.why

    @pytest.mark.parametrize(
        ("stated", "selected"),
        [
            ("C:\\Users\\Public\\svchost.exe", "\\Users\\Public\\svchost.exe"),
            (
                "\\\\?\\C:\\Users\\a\\AppData\\Roaming\\svchost.exe",
                "\\AppData\\Roaming\\svchost.exe",
            ),
            ("C:\\Users\\Admin\\Desktop\\cmd.exe", "\\Desktop\\cmd.exe"),
        ],
    )
    def test_keeps_what_a_log_writes_the_same_on_every_host(
        self, stated: str, selected: str
    ) -> None:
        (body,) = _sigma(_report([("file path", stated)]))

        assert body["detection"]["selection_file"] == {"TargetFilename|endswith": [selected]}

    @pytest.mark.parametrize(
        ("stated", "selected"),
        [
            ("\\\\?\\C:\\ProgramData\\Vendor7731\\x7731.exe", "\\Vendor7731\\x7731.exe"),
            ("\\\\?\\UNC\\srv7731\\share\\x7731.exe", "\\srv7731\\share\\x7731.exe"),
        ],
    )
    def test_a_long_path_prefix_is_read_off_a_specific_path(
        self, stated: str, selected: str
    ) -> None:
        (body,) = _sigma(_report([("file path", stated)]))

        assert body["detection"]["selection_file"] == {"TargetFilename|endswith": [selected]}

    def test_a_value_left_out_of_a_built_draft_keeps_its_true_reason(self) -> None:
        report = _report(
            [("file path", "C:\\Users\\Admin\\svchost.exe"), ("file path", "%APPDATA%\\x7731.exe")]
        )

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        assert [(v.value, v.why) for v in rule.values_left_out] == [
            ("\\svchost.exe", ds.NAME_ALONE_REASON)
        ]


# Every form a value reaches a selection in that cuts a stated folder: a
# user's own profile, an environment name, a long-path prefix before either.
_STATED_FORMS = (
    "C:\\Users\\Admin\\{}",
    "%APPDATA%\\{}",
    "%TEMP%\\{}",
    "%USERPROFILE%\\{}",
    "\\\\?\\C:\\Users\\Admin\\{}",
    "{}",
)
_PAYLOAD_FORMS = ("{}", "%APPDATA%\\{}", "C:\\Users\\Admin\\{}", "{} /c x7731")
# Rows of one report: under the cap a stated draft selects on.
_CHUNK = 60


def _chunks() -> list[list[str]]:
    names = sorted(benign_catalogue().system_binaries)
    return [names[at : at + _CHUNK] for at in range(0, len(names), _CHUNK)]


class TestNoPathPrintsANameWindowsShipsAlone:
    @pytest.mark.parametrize("form", _STATED_FORMS)
    def test_as_a_stated_path(self, form: str) -> None:
        for names in _chunks():
            report = _report([("file path", form.format(name)) for name in names])

            for body in _sigma(report):
                printed = {value.lower().lstrip("\\") for value in _values(body)}
                assert not printed & set(names), form

    @pytest.mark.parametrize("form", _PAYLOAD_FORMS)
    def test_as_a_persistence_payload(self, form: str) -> None:
        for names in _chunks():
            report = _report(
                [],
                persistence=[
                    PersistenceMechanism(kind="registry_run", target=RUN, payload=form.format(name))
                    for name in names
                ],
            )

            for body in _sigma(report):
                printed = {value.lower().lstrip("\\") for value in _values(body)}
                assert not printed & set(names), form
