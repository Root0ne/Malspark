"""A Sigma selection the rule can match on alone holds a value of its own.

A run's file draft selected on the ransom note it named and, under ``1 of``,
on the folder the note was written into: Word's start-up folder, where every
add-in and template install writes. A selection the condition reaches alone
(any selection under ``1 of``, or a draft's only one) now holds only specific
values: a value the platform's catalogue calls every Windows host's is taken
out whatever recorded it, a sandbox included, and a value matched by
``contains`` that another selected value of the draft holds (a folder a
selected file lies in) is taken out for the narrower one. A selection left
empty is taken out, and a draft left with none is not built and says why. One
function decides, and the builder and the sentence saying why no draft was
built both read it.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from malspark.pipeline.validation import EntryTexts
from malspark.reporting import detection_signatures as ds
from malspark.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from malspark.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    FamilyAttribution,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    ObservedIn,
    PersistenceMechanism,
    RegistryMod,
    SampleIdentity,
    SandboxSignature,
    TechnicalAnalysis,
    TTPMapping,
)
from malspark.reporting.stated_host_values import benign_reason, host_kinds, with_held_in

# A ransom note and the start-up folder it is written into, as a run stated them.
NOTE = "%APPDATA%\\Microsoft\\Word\\STARTUP\\ReadMe7731.txt"
NOTE_NAME = "ReadMe7731.txt"
STARTUP = "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Word\\STARTUP"
# Techniques whose statements name none of the values a file draft selects.
UNRELATED = [
    TTPMapping(
        technique_id="T1055",
        technique_name="Process Injection",
        tactic_name="Defense Evasion",
        evidence_quotes=["Seven WriteProcessMemory rows into defrag.exe (pid 1924)."],
        evidence_roots=["sandbox signature Suspicious use of SetThreadContext"],
    ),
    TTPMapping(
        technique_id="T1082",
        technique_name="System Information Discovery",
        evidence_quotes=["It reads the computer name."],
    ),
]


def _report(
    rows: list[tuple[str, str]],
    *,
    mappings: list[TTPMapping] | None = None,
    keys: list[str] | None = None,
    persistence: list[PersistenceMechanism] | None = None,
    sandbox_rows: list[ConsolidatedIOC] | None = None,
) -> MalwareReport:
    entries = EntryTexts(texts={"ev_0021": json.dumps([value for _, value in rows]).lower()})
    identifiers = [
        HostIdentifier(kind=kind, value=value, use="creates/writes", evidence_refs=["ev_0021"])
        for kind, value in rows
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64), platform="windows"),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="ransomware",
        technical_analysis=TechnicalAnalysis(host_identifiers=with_held_in(identifiers, entries)),
        ttp_mappings=mappings or [],
        dynamic=DynamicBehavior(
            registry_mods=[
                RegistryMod(hive="HKCU", key=key, value_name="x", operation="create")
                for key in keys or []
            ]
        ),
        persistence=persistence or [],
    )
    report.consolidated_iocs = [*build_consolidated_iocs(report), *(sandbox_rows or [])]
    # What the replay's drafts read (``scripts.replay.rules._drafts``).
    return MalwareReportBuilder.attach_detection_signatures(report)


def _sigma(report: MalwareReport) -> list[dict[str, Any]]:
    return [yaml.safe_load(r.body) for r in report.detection_signatures if r.kind == "sigma"]


# The table kind each selection's values are read as.
_SELECTION_KINDS = {
    "selection_registry": "registry",
    "selection_persistence": "path",
    "selection_file": "path",
    "selection_folder": "folder",
    "selection_stream": "ads",
    "selection_task": "scheduled_task",
    "selection_service": "service",
    "selection_pipe": "named_pipe",
}


def _stands_alone(body: dict[str, Any]) -> None:
    """Every selection holds values the catalogue does not call every host's, none of them a
    ``contains`` value another selected value of the rule holds."""
    detection = body["detection"]
    selections = {k: v for k, v in detection.items() if k.startswith("selection_")}
    assert selections
    assert detection["condition"] in ("1 of selection_*", *selections)
    placed = [
        (name, field_name, value)
        for name, selection in selections.items()
        for field_name, values in selection.items()
        if isinstance(values, list)
        for value in values
    ]
    kinds = {kind.table_kind: kind for kind in reversed(list(host_kinds().values()))}
    for at, (name, field_name, value) in enumerate(placed):
        assert benign_reason(kinds[_SELECTION_KINDS[name]], value) == ""
        if field_name.endswith("|contains"):
            assert not any(
                value.lower() in other.lower()
                for where, (_, _, other) in enumerate(placed)
                if where != at
            )


class TestTheStoredValues:
    def test_a_note_and_its_start_up_folder_select_on_the_note(self) -> None:
        report = _report(
            [("file path", NOTE), ("file name", NOTE_NAME), ("folder", STARTUP)],
            mappings=UNRELATED,
        )

        (body,) = _sigma(report)
        assert body["detection"] == {
            "selection_file": {
                "TargetFilename|endswith": ["\\Word\\STARTUP\\ReadMe7731.txt", "\\ReadMe7731.txt"]
            },
            "condition": "selection_file",
        }
        assert "tags" not in body
        assert report.drafts_not_built == []

    @pytest.mark.parametrize(
        ("rows", "detection"),
        [
            (
                [("folder", "Custom_update")],
                {
                    "selection_folder": {"TargetFilename|contains": ["\\Custom_update\\"]},
                    "condition": "selection_folder",
                },
            ),
            (
                [("alternate data stream", ":wtfbbq")],
                {
                    "selection_stream": {"TargetFilename|endswith": [":wtfbbq"]},
                    "condition": "selection_stream",
                },
            ),
            (
                [("file path", NOTE), ("folder", STARTUP)],
                {
                    "selection_file": {
                        "TargetFilename|endswith": ["\\Word\\STARTUP\\ReadMe7731.txt"]
                    },
                    "condition": "selection_file",
                },
            ),
            (
                [("folder", "Custom_update"), ("file name", "update_data.dat")],
                {
                    "selection_file": {"TargetFilename|endswith": ["\\update_data.dat"]},
                    "selection_folder": {"TargetFilename|contains": ["\\Custom_update\\"]},
                    "condition": "1 of selection_*",
                },
            ),
        ],
    )
    def test_each_selection_stands_alone(
        self, rows: list[tuple[str, str]], detection: dict[str, Any]
    ) -> None:
        (body,) = _sigma(_report(rows))

        assert body["detection"] == detection
        _stands_alone(body)

    def test_a_technique_naming_the_selected_folder_tags_the_rule(self) -> None:
        mapping = TTPMapping(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            evidence_quotes=["It writes C:\\ProgramData\\Custom_update\\update_data.dat."],
        )
        (body,) = _sigma(_report([("folder", "Custom_update")], mappings=[*UNRELATED, mapping]))

        assert body["tags"] == ["attack.t1105"]


class TestWhatASandboxRecorded:
    def test_an_image_windows_ships_is_left_out_and_its_own_kept(self) -> None:
        shipped = "C:\\Windows\\System32\\rundll32.exe"
        own = "C:\\Users\\a\\AppData\\Roaming\\ExampleVendor7731\\evil7731.exe"
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(kind="scheduled_task", target="t", payload=shipped),
                PersistenceMechanism(kind="scheduled_task", target="u", payload=own),
            ],
            sandbox_rows=[
                ConsolidatedIOC(type="File path", kind="path", value=v, source="sandbox")
                for v in (shipped, own)
            ],
        )

        (body,) = _sigma(report)
        assert body["detection"] == {
            "selection_persistence": {"Image|endswith": ["\\evil7731.exe"]},
            "condition": "selection_persistence",
        }
        assert body["logsource"] == {"product": "windows", "category": "process_creation"}

    def test_an_autorun_key_beside_an_image_leaves_a_process_draft(self) -> None:
        own = "C:\\Users\\a\\AppData\\Roaming\\ExampleVendor7731\\evil7731.exe"
        report = _report(
            [],
            keys=["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
            persistence=[PersistenceMechanism(kind="scheduled_task", target="u", payload=own)],
            sandbox_rows=[
                ConsolidatedIOC(type="File path", kind="path", value=own, source="sandbox")
            ],
        )

        (body,) = _sigma(report)
        assert set(body["detection"]) == {"selection_persistence", "condition"}
        assert body["logsource"]["category"] == "process_creation"
        assert not any(source.startswith("registry:") for source in _sources(report))


def _sources(report: MalwareReport) -> list[str]:
    return [s for r in report.detection_signatures if r.kind == "sigma" for s in r.source_evidence]


class TestOneDecision:
    def test_a_draft_narrowed_to_nothing_says_why_and_not_that_it_failed(self) -> None:
        report = _report([], keys=["Software\\Microsoft\\Windows\\CurrentVersion\\Run"])

        assert _sigma(report) == []
        (item,) = report.drafts_not_built
        assert ds._SIGMA_DRAFT_RAISED not in item.why
        assert "every Windows installation has" in item.why

    def test_the_builder_and_the_sentence_read_the_same_function(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[dict[str, Any]] = []

        def _nothing(selections: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
            calls.append(selections)
            return {}, []

        monkeypatch.setattr(ds, "selection_specific", _nothing)
        report = _report([("folder", "Custom_update")])

        assert _sigma(report) == []
        (item,) = report.drafts_not_built
        assert item.why == ds._SIGMA_NOTHING_TO_SELECT
        # Once for the build, once for the sentence.
        assert len(calls) == 2


class TestWhatTheRuleSays:
    def test_two_values_every_host_has_are_counted_and_each_reason_said_once(self) -> None:
        report = _report(
            [],
            keys=[
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ],
        )

        (item,) = report.drafts_not_built
        assert item.why.endswith(
            "; the 2 values a sandbox watched or the run publishes are each every Windows "
            "host's own, never selected on: a registry key or value every Windows installation has"
        )

    def test_a_draft_that_raised_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raising(*args: Any, **kwargs: Any) -> Any:
            raise ValueError("x")

        monkeypatch.setattr(ds, "_sigma_rule", _raising)
        (item,) = _report([("folder", "Custom_update")]).drafts_not_built

        assert item.why == ds._SIGMA_DRAFT_RAISED

    def test_a_stated_draft_names_no_sandbox_signature(self) -> None:
        report = _report([("folder", "Custom_update")])
        report.dynamic = DynamicBehavior(
            sandbox_signatures=[SandboxSignature(name="Drops a file", severity=5)]
        )
        report = MalwareReportBuilder.attach_detection_signatures(report)

        (body,) = _sigma(report)
        assert "Drops a file" not in body["description"]

    def test_the_first_draft_names_five_values_of_each_selection(self) -> None:
        keys = [f"Software\\ExampleVendor7731\\Setting{i}" for i in range(7)]

        report = _report([], keys=keys)

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        assert rule.source_evidence == [f"registry:\\{key}" for key in keys[:5]]

    def test_a_value_left_out_is_not_named_as_a_later_detonation_s(self) -> None:
        later = [ObservedIn(detonation="d2")]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="7" * 64)),
            verdict="Malware",
            attribution=FamilyAttribution(family="Fixturelock", family_grounded=True),
            consolidated_iocs=[
                ConsolidatedIOC(
                    type="Path",
                    kind=kind,
                    value=value,
                    source="analysis",
                    published="yes: the analysis stated it",
                    observed_in=later,
                )
                for kind, value in (
                    ("path", "C:\\Users\\Public\\Vendor7731\\drop.exe"),
                    ("folder", "C:\\Users\\Public\\Vendor7731"),
                )
            ],
        )

        (body,) = _sigma(MalwareReportBuilder.attach_detection_signatures(report))
        assert body["detection"]["condition"] == "selection_file"
        assert "drop.exe: observed in detonation 2" in body["description"]
        assert "Vendor7731: observed" not in body["description"]


@pytest.mark.parametrize(
    ("value", "part", "held"),
    [
        ("\\a\\b\\c.txt", "\\a\\b\\", True),
        ("\\a\\b\\c", "\\a\\b", True),
        ("\\software\\vendor7731", "\\vendor7731", True),
        ("\\a\\b10", "\\a\\b1", False),
        ("\\a\\b1\\a\\b\\c", "\\a\\b", True),
        ("x\\a\\b", "a\\b", True),
        ("xa\\b", "a\\b", False),
        ("a\\b", "a\\b", True),
    ],
)
def test_a_value_holds_a_part_only_as_whole_path_components(
    value: str, part: str, held: bool
) -> None:
    assert ds._holds_components(value, part) is held
