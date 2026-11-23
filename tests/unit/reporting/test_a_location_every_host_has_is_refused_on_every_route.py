"""A location every Windows host has is refused on every route that asks the catalogue (T-869).

Three rules of the declared catalogue (``data/host_benign_locations_v1.json``):

* a key exactly one level below the registry key of a service Windows installs,
  named as Windows names the subkeys it keeps a service's settings in (the
  catalogue's own list, with its criterion and source), is every host's for
  both registry kinds; a deeper path, a value right under the service's key,
  such a subkey under a service the catalogue does not list, and a subkey of
  another name are not;
* a path the string sweep holds, and a judge's path asked as the sweep's, is
  asked the catalogue the analysis route asks before a second source publishes
  it: the catalogue's reason refuses it, and every fact the refusal it replaces
  carried stays after it (the row it is from, the second source or the publish
  rule's lookup finding none, a recovery), so one value has one answer on both
  routes;
* the branch that matches a path by its components' names says what it found:
  every component is a drive, a name Windows gives one of its own folders, or
  a user's profile name, the last only right after the users folder under a
  drive; it never calls the path a Windows known folder.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    RegistryMod,
    SampleIdentity,
    TechnicalAnalysis,
)
from malspark.reporting.renderers.stix_renderer import (
    LOOKUP_FOUND_NO_SECOND_SOURCE,
    RECOVERED_BY_EMULATION,
    SECOND_SOURCE,
    SecondSources,
    publish_answer,
    publishes,
)
from malspark.reporting.stated_host_values import (
    KNOWN_NAMES_REASON,
    SERVICE_SUBKEY_REASON,
    SHIPPED_SUBKEY_REASON,
    benign_catalogue,
    benign_reason,
    identifier_answers,
    resolve_data,
    shipped_match,
    typed_kind,
    with_held_in,
)

SUBKEY = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters"


def _document() -> dict[str, Any]:
    """The shipped catalogue file, as read from the repository's data."""
    from malspark.reporting import stated_host_values as shv

    loaded: dict[str, Any] = json.loads(
        resolve_data(shv.DEFAULT_CATALOGUE).read_text(encoding="utf-8")
    )
    return loaded


class TestTheSubkeyListIsTheCatalogues:
    def test_it_is_a_list_of_its_own_with_its_criterion_and_source(self) -> None:
        listed = _document()["service_settings_subkeys"]

        assert str(listed["criterion"]).strip()
        assert str(listed["source"]).strip()
        assert [name.lower() for name in listed["entries"]] == sorted(
            benign_catalogue().service_settings_subkeys
        )

    def test_no_name_of_it_is_written_in_the_code(self) -> None:
        from malspark.reporting import stated_host_values as shv

        source = open(shv.__file__, encoding="utf-8").read().lower()
        for name in _document()["service_settings_subkeys"]["entries"]:
            assert f'"{name.lower()}"' not in source


class TestAServiceSubkey:
    @pytest.mark.parametrize("kind", ["registry key", "registry value"])
    @pytest.mark.parametrize(
        "value",
        [
            SUBKEY,
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters",
            "SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters",
            "HKLM\\SYSTEM\\ControlSet001\\Services\\Spooler\\Parameters",
            "HKLM/SYSTEM/CurrentControlSet/Services/Spooler/Parameters",
            "hklm\\system\\currentcontrolset\\services\\spooler\\PARAMETERS",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters. ",
            "\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters\\",
        ],
    )
    def test_is_refused_in_every_spelling_for_both_registry_kinds(
        self, kind: str, value: str
    ) -> None:
        assert benign_reason(typed_kind(kind), value) == SERVICE_SUBKEY_REASON

    @pytest.mark.parametrize("kind", ["registry key", "registry value"])
    @pytest.mark.parametrize(
        "value",
        [
            # A value below the subkey: the sample's own setting.
            f"{SUBKEY}\\ExampleValue7731",
            # A key two levels below.
            f"{SUBKEY}\\Linkage7731",
            # A value right under the service's key.
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend\\Start",
            # A listed subkey under a service the catalogue does not list.
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ExampleSvc7731\\Parameters",
            # A subkey of a name the list does not hold.
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\ExampleKey7731",
            # The subkey's name under another key.
            "HKLM\\SOFTWARE\\ExampleVendor7731\\Spooler\\Parameters",
        ],
    )
    def test_keeps_today_s_answer(self, kind: str, value: str) -> None:
        assert benign_reason(typed_kind(kind), value) == ""

    def test_the_service_s_own_key_keeps_its_reason(self) -> None:
        assert benign_reason(
            typed_kind("registry key"), "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Spooler"
        ) == ("the registry key of a service Windows installs")

    def test_the_words_claim_only_what_the_catalogue_knows(self) -> None:
        # The catalogue holds a service's name and the names Windows gives
        # settings subkeys, not which service has which subkey: the reason
        # says the key is under the service's key and named as those are.
        assert "under the registry key of a service Windows installs" in SERVICE_SUBKEY_REASON
        assert "named as Windows names" in SERVICE_SUBKEY_REASON
        assert "every Windows installation" not in SERVICE_SUBKEY_REASON


def _stated(rows: list[tuple[str, str]], text: str) -> MalwareReport:
    entries = EntryTexts(texts={"ev_0001": text.lower()})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_0001"])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


class TestTheAnalysisRoute:
    def test_a_stated_service_subkey_is_refused_with_the_reason(self) -> None:
        report = _stated([("registry key", SUBKEY)], json.dumps([f"reg add {SUBKEY} /v x"]))

        ((stated, answer),) = identifier_answers(report)
        assert stated.held_in == ("ev_0001",)
        assert answer == f"no: {SERVICE_SUBKEY_REASON}"

    def test_a_stated_value_below_it_is_published(self) -> None:
        value = f"{SUBKEY}\\ExampleValue7731"
        report = _stated([("registry value", value)], json.dumps([value]))

        ((_, answer),) = identifier_answers(report)
        assert publishes(answer)


def _sandbox(mods: list[RegistryMod]) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        dynamic=DynamicBehavior(registry_mods=mods),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return MalwareReportBuilder.attach_detection_signatures(report)


def _sigma(report: MalwareReport) -> list[dict[str, Any]]:
    return [yaml.safe_load(r.body) for r in report.detection_signatures if r.kind == "sigma"]


class TestTheSigmaBuilderFollows:
    def test_a_draft_whose_only_key_is_a_service_subkey_is_not_built_and_says_why(self) -> None:
        report = _sandbox(
            [
                RegistryMod(
                    hive="HKLM",
                    key="SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters",
                    operation="create",
                )
            ]
        )

        assert _sigma(report) == []
        (item,) = report.drafts_not_built
        assert SERVICE_SUBKEY_REASON in item.why

    def test_a_write_under_it_is_selected_as_the_key_and_the_value_s_name(self) -> None:
        report = _sandbox(
            [
                RegistryMod(
                    hive="HKLM",
                    key="SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters",
                    value_name="ExampleValue7731",
                    operation="modify",
                )
            ]
        )

        (body,) = _sigma(report)
        assert body["detection"]["selection_registry"] == {
            "TargetObject|contains": [
                "\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters\\ExampleValue7731"
            ]
        }

    @pytest.mark.parametrize(
        ("operator", "value"),
        [
            ("contains", "\\spooler\\parameters"),
            ("endswith", "services\\spooler\\parameters"),
            ("", "\\system\\controlset001\\services\\spooler\\parameters"),
        ],
    )
    def test_a_selection_a_service_subkey_matches_names_the_subkey(
        self, operator: str, value: str
    ) -> None:
        from malspark.reporting.detection_signatures import _why_not_specific

        field = "TargetObject" + (f"|{operator}" if operator else "")
        assert shipped_match("key", operator, value)
        why = _why_not_specific("selection_registry", field, value, value)
        assert why.startswith(SERVICE_SUBKEY_REASON) or why.endswith(SERVICE_SUBKEY_REASON)
        if operator:
            # The key itself is the catalogue's own answer; a match says the operator's.
            assert why == SHIPPED_SUBKEY_REASON[operator]
        assert "every Windows installation" not in why

    def test_the_reason_is_one_sentence_built_from_the_catalogue_s_words(self) -> None:
        assert SHIPPED_SUBKEY_REASON == {
            "endswith": f"{SERVICE_SUBKEY_REASON}, ends with it",
            "contains": f"{SERVICE_SUBKEY_REASON}, holds it",
            "": f"it is {SERVICE_SUBKEY_REASON}",
        }
        assert SHIPPED_SUBKEY_REASON["endswith"] == (
            "a key under the registry key of a service Windows installs, named as Windows "
            "names the subkeys it keeps a service's settings in, ends with it"
        )

    def test_a_selection_of_a_value_below_it_is_kept(self) -> None:
        from malspark.reporting.detection_signatures import _why_not_specific

        value = "\\SYSTEM\\CurrentControlSet\\Services\\Spooler\\Parameters\\ExampleValue7731"
        assert _why_not_specific("selection_registry", "TargetObject|contains", value, value) == ""


# A folder every host's catalogue knows by its components' names, and a
# sandbox record that writes it as a whole argument.
TEMP = "D:\\Temp"
# What the refusal says of the row a value with no sweep row of its own is from.
NO_SWEEP_ROW = "its row's source is strings and no row of the string sweep holds it"
OBSERVED = "xcopy d:\\temp e:\\archive7731 /e"


class TestTheStringSweepRoute:
    def test_a_swept_path_a_second_source_holds_is_refused_by_the_catalogue(self) -> None:
        answer = publish_answer(
            "path", TEMP, "strings", None, corroborating=SecondSources(observed=OBSERVED)
        )

        assert not publishes(answer)
        # The catalogue refuses; the row it is from and the second source are facts.
        assert str(answer) == f"no: {KNOWN_NAMES_REASON}; {NO_SWEEP_ROW}; {SECOND_SOURCE}"
        assert LOOKUP_FOUND_NO_SECOND_SOURCE not in str(answer)

    def test_a_swept_path_no_second_source_holds_is_refused_by_the_catalogue(self) -> None:
        answer = publish_answer("path", TEMP, "strings", None, corroborating=SecondSources())

        # The lookup's finding is a fact after the catalogue's reason, never the reason.
        assert str(answer) == (
            f"no: {KNOWN_NAMES_REASON}; {NO_SWEEP_ROW}; {LOOKUP_FOUND_NO_SECOND_SOURCE}"
        )

    @pytest.mark.parametrize("observed", ["", OBSERVED])
    def test_a_recovered_path_keeps_its_recovery_fact(self, observed: str) -> None:
        recovered = f"{RECOVERED_BY_EMULATION} (ev_0903)"
        answer = str(
            publish_answer(
                "path",
                TEMP,
                "strings",
                None,
                corroborating=SecondSources(observed=observed),
                recovered=recovered,
            )
        )

        second = SECOND_SOURCE if observed else LOOKUP_FOUND_NO_SECOND_SOURCE
        assert answer == f"no: {KNOWN_NAMES_REASON}; {NO_SWEEP_ROW}; {second}; {recovered}"

    def test_what_the_record_holds_stays_after_the_reason(self) -> None:
        # The row it is from and each cited holder of a kind that confirms
        # nothing, as the refusal it replaces said them.
        record = SecondSources(
            swept={"d:\\temp": (("iocs_from_file", "ev_0901"),)},
            reads=(("ev_0902", "strings", "rereads", True, frozenset({"d:\\temp"})),),
        )
        answer = str(publish_answer("path", TEMP, "strings", None, corroborating=record))

        assert answer.startswith(
            f"no: {KNOWN_NAMES_REASON}; the row from iocs_from_file (ev_0901) holds it; "
            f"{LOOKUP_FOUND_NO_SECOND_SOURCE}; strings"
        )
        assert "ev_0902" in answer

    def test_a_judge_s_path_asked_as_the_sweep_s_is_refused_by_the_catalogue(self) -> None:
        answer = publish_answer(
            "path",
            TEMP,
            "strings",
            None,
            corroborating=SecondSources(observed=OBSERVED),
            judge_s_value=True,
        )

        assert str(answer) == f"no: {KNOWN_NAMES_REASON}; {NO_SWEEP_ROW}; {SECOND_SOURCE}"

    def test_a_file_windows_ships_on_the_sweep_route_is_refused_by_the_catalogue(self) -> None:
        value = "C:\\Windows\\System32\\cmdkey.exe"
        answer = publish_answer(
            "path", value, "strings", None, corroborating=SecondSources(observed=value.lower())
        )

        assert str(answer).startswith(
            f"no: {benign_reason(typed_kind('file path'), value)}; {NO_SWEEP_ROW}; {SECOND_SOURCE}"
        )

    @pytest.mark.parametrize(
        "value",
        [
            "D:\\Temp\\relay7731.exe",
            "C:\\Users\\Example7731\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\note.txt",
            "C:\\ExampleVendor7731\\relay.exe",
        ],
    )
    def test_a_path_the_catalogue_does_not_know_keeps_today_s_answer(self, value: str) -> None:
        answer = publish_answer(
            "path",
            value,
            "strings",
            None,
            corroborating=SecondSources(observed=f"wrote {value.lower()} once"),
        )

        assert publishes(answer)

    def test_another_source_is_not_asked(self) -> None:
        # A sandbox's path stands on the sandbox's own rule, unchanged.
        answer = publish_answer("path", TEMP, "sandbox", None, kept_by="the judge's indicator")

        assert KNOWN_NAMES_REASON not in str(answer)


class TestSameValueSameAnswer:
    """Each value reaches the catalogue's test on both routes (its shape stands on the sweep's)."""

    @pytest.mark.parametrize(
        ("kind", "value"),
        [
            ("folder", TEMP),
            ("folder", "C:\\Windows\\Temp"),
            ("folder", "D:\\Downloads"),
            ("file path", "C:\\Windows\\System32\\cmdkey.exe"),
            ("file path", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ],
    )
    def test_the_sweep_s_row_and_the_analysis_row_give_the_catalogue_s_reason(
        self, kind: str, value: str
    ) -> None:
        stated = _stated([(kind, value)], json.dumps([value]))
        ((_, analysis),) = identifier_answers(stated)
        swept = publish_answer(
            "path", value, "strings", None, corroborating=SecondSources(observed=value.lower())
        )

        reason = benign_reason(typed_kind(kind), value)
        assert reason
        assert str(analysis) == f"no: {reason}"
        assert str(swept).startswith(f"no: {reason}")


class TestTheNameMatchingBranchSaysWhatItFound:
    @pytest.mark.parametrize(
        "value",
        [
            TEMP,
            "D:\\Downloads",
            "C:\\Windows\\System32\\drivers\\etc",
            "C:\\Users\\Bob",
            "%APPDATA%\\Microsoft\\Windows\\Start Menu",
            "C:\\PROGRA~1",
            "CSIDL_APPDATA",
        ],
    )
    def test_one_wording_for_every_value_it_answers(self, value: str) -> None:
        for kind in ("folder", "file path", "file name"):
            said = benign_reason(typed_kind(kind), value)
            if said:
                assert said == KNOWN_NAMES_REASON
        assert benign_reason(typed_kind("folder"), value) == KNOWN_NAMES_REASON

    @pytest.mark.parametrize(
        "value",
        [
            # The users folder directly under a drive, a letter or its environment name.
            "C:\\Users\\Example7731",
            "%SystemDrive%\\Users\\Example7731",
            # A path written without a drive whose first component is the users
            # folder: the catalogue read the name after it as a profile's before.
            "Users\\Example7731",
        ],
    )
    def test_a_profile_name_right_after_the_users_folder_is_counted(self, value: str) -> None:
        assert benign_reason(typed_kind("folder"), value) == KNOWN_NAMES_REASON

    @pytest.mark.parametrize(
        "value",
        [
            # A folder named Users below another folder is not the users folder.
            "C:\\Temp\\Users\\Example7731",
            "Temp\\Users\\Example7731",
            "\\\\server7731\\share\\Users\\Example7731",
        ],
    )
    def test_a_name_after_another_users_folder_is_no_profile_name(self, value: str) -> None:
        assert benign_reason(typed_kind("folder"), value) == ""
        assert benign_reason(typed_kind("file path"), value) == ""

    def test_it_never_calls_the_path_a_known_folder(self) -> None:
        assert "known folder" not in KNOWN_NAMES_REASON
        assert "every component is a drive" in KNOWN_NAMES_REASON
