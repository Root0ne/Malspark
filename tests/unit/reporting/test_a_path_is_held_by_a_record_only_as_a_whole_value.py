"""A path is held by a record only as a whole value.

A path that stands in a record only as the leading directory of a longer path
names that directory, and the record does not hold it: it is no second source
of the path. A file name that is the last component of a recorded path is held
(the boundary rule's own case). A further component is whatever follows the
separator, unless it is white space or a character no component starts with in
a quoted, listed or bracketed path (a closing bracket among them); a component
opening with a brace, a dollar sign, an opening bracket or a letter outside
ASCII makes the path a leading directory like any other. The build's record of
each entry, the publish rule's reading of an observation and the refusal's
holder clauses read a path the same way; a value of another kind keeps the
boundary rule as it is.
"""

from __future__ import annotations

import pytest

from malspark.agents._indicator_denylists import whole_path_in, whole_value_in
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    DynamicBehavior,
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    SecondSources,
    publish_answer,
    publishes,
    second_source_reads,
)
from malspark.schemas.evidence import LedgerEntry

DIRECTORY = "C:\\Staging"
LONGER = "C:\\Staging\\relay.exe"
FILE_NAME = "relay.exe"
KEY = "HKCU\\Software\\Vendor"
# Further components that open with a character outside a label's.
FURTHER = [
    "{0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d}\\relay.exe",
    "\u00dcn\u00ee\\relay.exe",
    "$tmp\\relay.exe",
    "(1)\\relay.exe",
    "#x",
    "&x",
    "!x",
    "=x",
]


class TestTheTest:
    def test_a_leading_directory_of_a_longer_path_is_not_held(self) -> None:
        text = LONGER.lower()
        assert not whole_path_in(DIRECTORY, text)
        assert not whole_path_in(DIRECTORY, LONGER.replace("\\", "/").lower())
        assert whole_value_in(DIRECTORY.lower(), text)

    def test_the_whole_path_and_its_last_component_are_held(self) -> None:
        text = f"wrote {LONGER.lower()} and left"
        assert whole_path_in(LONGER, text)
        assert whole_path_in(FILE_NAME, text)

    def test_a_directory_written_as_itself_is_held(self) -> None:
        assert whole_path_in(DIRECTORY, f"cwd {DIRECTORY.lower()} set")
        assert whole_path_in(DIRECTORY, f"cwd {DIRECTORY.lower()}\\ set")

    @pytest.mark.parametrize("further", FURTHER)
    def test_a_further_component_opening_with_any_character_makes_a_leading_directory(
        self, further: str
    ) -> None:
        text = f"{DIRECTORY}\\{further}".lower()
        assert not whole_path_in(DIRECTORY, text)
        assert not whole_path_in(DIRECTORY, text.replace("\\", "/"))

    @pytest.mark.parametrize("after", [" ", "\t", '"', "'", "<", ">", "|", "*", "?", ";", ","])
    def test_a_separator_before_a_character_no_component_starts_with_joins_nothing(
        self, after: str
    ) -> None:
        assert whole_path_in(DIRECTORY, f"cwd {DIRECTORY.lower()}\\{after}x")

    @pytest.mark.parametrize(
        "written", ["({d}\\)", "[{d}\\]", "{{{d}\\}}", "{d}\\)", "{d}\\]", "{d}\\}}"]
    )
    def test_a_directory_written_as_itself_before_a_closing_bracket_is_held(
        self, written: str
    ) -> None:
        assert whole_path_in(DIRECTORY, f"cwd {written.format(d=DIRECTORY.lower())} set")

    @pytest.mark.parametrize("opening", ["{x}\\relay.exe", "[1]\\relay.exe", "(1)\\relay.exe"])
    def test_an_opening_bracket_after_the_separator_opens_a_component(self, opening: str) -> None:
        assert not whole_path_in(DIRECTORY, f"({DIRECTORY}\\{opening})".lower())

    def test_another_kind_keeps_the_boundary_rule(self) -> None:
        assert whole_value_in(KEY.lower(), f"{KEY.lower()}\\run")


class TestThePublishRule:
    def test_an_observation_holding_it_only_as_a_leading_directory_is_no_second_source(
        self,
    ) -> None:
        answer = publish_answer(
            "path", DIRECTORY, "strings", None, corroborating=SecondSources(observed=LONGER.lower())
        )
        assert not publishes(answer)

    def test_an_observation_holding_it_whole_is_a_second_source(self) -> None:
        answer = publish_answer(
            "path",
            DIRECTORY,
            "strings",
            None,
            corroborating=SecondSources(observed=f"{DIRECTORY.lower()} {LONGER.lower()}"),
        )
        assert publishes(answer)

    @pytest.mark.parametrize("further", FURTHER[:2])
    def test_an_observation_naming_a_further_component_of_any_letter_is_no_second_source(
        self, further: str
    ) -> None:
        observed = f"{DIRECTORY}\\{further}".lower()
        answer = publish_answer(
            "path", DIRECTORY, "strings", None, corroborating=SecondSources(observed=observed)
        )
        assert not publishes(answer)

    def test_a_section_holding_it_only_as_a_leading_directory_is_not_said_to_print_it(
        self,
    ) -> None:
        held = (("reader", LONGER.lower()),)
        answer = publish_answer(
            "path",
            DIRECTORY,
            "strings",
            None,
            corroborating=SecondSources(rereads=held, uncited=held),
        )
        assert not publishes(answer)
        assert "prints it" not in answer
        whole = (("reader", f"{DIRECTORY.lower()} {LONGER.lower()}"),)
        said = publish_answer(
            "path", DIRECTORY, "strings", None, corroborating=SecondSources(rereads=whole)
        )
        assert "reader prints it in a section" in said

    def test_a_registry_key_held_as_the_start_of_a_longer_key_stays_held(self) -> None:
        answer = publish_answer(
            "registry",
            KEY,
            "strings",
            None,
            corroborating=SecondSources(observed=f"{KEY}\\Run".lower()),
        )
        assert publishes(answer)


def _report(value: str, **over: object) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        overall_confidence=0.8,
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_name="sample.bin"),
        static=StaticAnalysis(interesting_strings=[StringIOC(kind="path", value=value)]),
        sections=[
            EvidenceSection(
                key="findings",
                title="Findings",
                kind="table",
                columns=["Agent", "Finding"],
                rows=[["dynamic", "the sample copies itself"]],
                evidence_ids=["ev_0002"],
                source="finding",
            )
        ],
        evidence_index=[
            EvidenceIndexRow(
                id="ev_0002", agent="dynamic", tool="watcher", source="mcp:example", facts={"v": 1}
            )
        ],
        executive_summary="",
        **over,  # type: ignore[arg-type]
    )


class TestTheBuildSRecord:
    LEDGER = [LedgerEntry(id="ev_0002", agent="dynamic", tool="watcher", output=f"wrote {LONGER}")]

    def test_an_entry_holding_it_only_as_a_leading_directory_records_no_hold(self) -> None:
        report = _report(DIRECTORY)
        assert second_source_reads(report, self.LEDGER) == []
        report.second_source_reads = second_source_reads(report, self.LEDGER)
        (row,) = [r for r in build_consolidated_iocs(report) if r.value == DIRECTORY]
        assert not publishes(row.published)

    def test_a_file_name_its_last_component_is_held(self) -> None:
        report = _report(FILE_NAME)
        (read,) = second_source_reads(report, self.LEDGER)
        assert read.holds == [FILE_NAME]

    def test_a_sandbox_file_record_holding_it_only_as_a_directory_confirms_nothing(self) -> None:
        report = _report(
            DIRECTORY,
            dynamic=DynamicBehavior(file_operations=[{"operation": "write", "path": LONGER}]),
        )
        (row,) = [r for r in build_consolidated_iocs(report) if r.value == DIRECTORY]
        assert not publishes(row.published)
