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
                RegistryMod(hive="HKCU", key=key, operation="create") for key in keys or []
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

    def test_the_folder_left_out_is_recorded_with_the_draft_and_not_printed(self) -> None:
        from malspark.reporting.renderers.layout import ANALYST
        from malspark.reporting.renderers.markdown import MarkdownRenderer

        report = _report([("file path", NOTE), ("folder", STARTUP)])

        (rule,) = [r for r in report.detection_signatures if r.kind == "sigma"]
        assert [(item.value, item.why) for item in rule.values_left_out] == [
            ("\\Word\\STARTUP\\", ds.CONTAINMENT_REASONS[0])
        ]
        assert rule.model_dump()["values_left_out"] == [
            {"value": "\\Word\\STARTUP\\", "why": ds.CONTAINMENT_REASONS[0]}
        ]
        text = MarkdownRenderer(layout=ANALYST).render(report)
        assert ds.CONTAINMENT_REASONS[0] not in text

    def test_a_draft_that_left_nothing_out_records_nothing(self) -> None:
        (rule,) = [
            r
            for r in _report([("folder", "Custom_update")]).detection_signatures
            if r.kind == "sigma"
        ]

        assert "values_left_out" not in rule.model_dump()

    @pytest.mark.parametrize(
        "quote",
        [
            "It writes the `Custom_update` folder.",
            "It writes C:\\ProgramData\\Custom_update\\update_data.dat.",
            'It creates "\\Custom_update\\".',
        ],
    )
    def test_a_statement_names_a_folder_in_any_form_it_writes_one(self, quote: str) -> None:
        mapping = TTPMapping(technique_id="T1105", technique_name="n", evidence_quotes=[quote])
        (body,) = _sigma(_report([("folder", "Custom_update")], mappings=[mapping]))

        assert body["tags"] == ["attack.t1105"]

    def test_a_statement_quoting_a_key_as_json_names_it(self) -> None:
        mapping = TTPMapping(
            technique_id="T1112",
            technique_name="n",
            evidence_roots=['{"key": "HKCU\\\\Software\\\\ExampleVendor7731\\\\Cfg"}'],
        )
        (body,) = _sigma(
            _report(
                [("registry key", "HKCU\\Software\\ExampleVendor7731\\Cfg")], mappings=[mapping]
            )
        )

        assert body["tags"] == ["attack.t1112"]

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

    def test_the_payload_of_an_autorun_on_the_run_key_is_selected(self) -> None:
        report = _report(
            [],
            persistence=[
                PersistenceMechanism(
                    kind="registry_run",
                    target="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    payload="C:\\Users\\a\\AppData\\Roaming\\ExampleVendor7731\\evil7731.exe",
                )
            ],
        )

        (body,) = _sigma(report)
        assert body["detection"] == {
            "selection_persistence": {"Image|endswith": ["\\evil7731.exe"]},
            "condition": "selection_persistence",
        }


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

        def _nothing(
            selections: dict[str, Any], asked: Any = None
        ) -> tuple[dict[str, Any], list[tuple[str, str]]]:
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


class TestAncestry:
    @pytest.mark.parametrize(
        ("values", "kept"),
        [
            # A parent key beside its subkey, in another case and separator form.
            (["\\Software\\Vendor7731", "/SOFTWARE/VENDOR7731/Cfg"], ["/SOFTWARE/VENDOR7731/Cfg"]),
            # The trailing part of a longer spelling of the same key stays.
            (
                ["\\CLSID\\{1111}", "\\Software\\Classes\\CLSID\\{1111}"],
                ["\\CLSID\\{1111}"],
            ),
            (
                ["\\Software\\Classes\\CLSID\\{1111}", "\\clsid\\{1111}"],
                ["\\clsid\\{1111}"],
            ),
            # The same key said twice is selected once.
            (["\\Software\\Vendor7731", "\\software\\vendor7731\\"], ["\\Software\\Vendor7731"]),
            # Sibling keys, a name inside another name, and a key under another's middle.
            (
                ["\\Software\\V\\Setting1", "\\Software\\V\\Setting10"],
                ["\\Software\\V\\Setting1", "\\Software\\V\\Setting10"],
            ),
            (["\\a\\b", "\\xa\\b"], ["\\a\\b", "\\xa\\b"]),
            (
                ["\\Vendor7731\\Cfg", "\\Vendor7731\\Cfg2"],
                ["\\Vendor7731\\Cfg", "\\Vendor7731\\Cfg2"],
            ),
            (["\\b\\c", "\\a\\b\\c\\d"], ["\\a\\b\\c\\d"]),
        ],
    )
    def test_a_key_is_left_out_only_for_a_key_under_it_or_a_shorter_spelling(
        self, values: list[str], kept: list[str]
    ) -> None:
        narrowed, left_out = ds.selection_specific(
            {"selection_registry": {"TargetObject|contains": values}}
        )

        assert narrowed == {"selection_registry": {"TargetObject|contains": kept}}
        assert [value for value, _ in left_out] == [v for v in values if v not in kept]
        assert all(why in ds.CONTAINMENT_REASONS for _, why in left_out)

    def test_a_folder_a_file_lies_under_is_left_out_but_a_file_name_keeps_it(self) -> None:
        narrowed, left_out = ds.selection_specific(
            {
                "selection_file": {"TargetFilename|endswith": ["\\a7731.dat"]},
                "selection_folder": {"TargetFilename|contains": ["\\Custom_update\\"]},
            }
        )

        assert set(narrowed) == {"selection_file", "selection_folder"}
        assert left_out == []

    def test_a_program_name_or_a_contains_value_s_tail_never_takes_a_value_out(self) -> None:
        selections = {
            "selection_registry": {
                "TargetObject|contains": ["\\Software\\Vendor7731\\evil7731.exe"]
            },
            "selection_persistence": {"Image|endswith": ["\\Vendor7731", "\\evil7731.exe"]},
        }

        narrowed, left_out = ds.selection_specific(selections)

        assert narrowed == selections
        assert left_out == []


class TestAPublishedPath:
    @pytest.mark.parametrize(
        ("stated", "selected"),
        [
            ("C:\\Users\\Admin\\Desktop\\cmd.exe", "\\Desktop\\cmd.exe"),
            ("%APPDATA%\\cmd.exe", "\\cmd.exe"),
            ("C:\\Users\\Admin\\Tools7731\\x7731.exe", "\\Tools7731\\x7731.exe"),
        ],
    )
    def test_keeps_its_folders_where_its_name_alone_is_windows_own(
        self, stated: str, selected: str
    ) -> None:
        assert ds._stated_value("path", stated) == selected

    def test_is_never_refused_as_every_host_s_own(self) -> None:
        report = _report([("file path", "%APPDATA%\\cmd.exe")])

        (body,) = _sigma(report)
        assert body["detection"]["selection_file"] == {"TargetFilename|endswith": ["\\cmd.exe"]}
        assert report.drafts_not_built == []
