"""The replay's record says which statement each report-round finding is about.

A narrative or composer finding quoted its sentence inside its message, so a
tool reading the record could not tell a section's findings apart without
showing the text. The record names each finding's place instead: ``statements``,
value-free, in the walk the finding's path already uses. A comparison of two
records reads decisions (codes, entries, counts) and so does not see the place.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from scripts.replay import compare
from scripts.replay import run as replay_cli
from scripts.replay.output import render_record, terminal_safe
from scripts.replay.record import errors

from tests.unit.scripts._replay_tiny import EXPECTED_TOTALS, FIXTURE


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay_cli._replay([FIXTURE], False)[0]


class TestTheStatementOfAFinding:
    def test_a_key_finding_citing_nothing_the_run_holds_names_its_row(
        self, record: dict[str, Any]
    ) -> None:
        (flag,) = [
            f for f in record["narrative"]["flags"] if f["code"] == "narrative.ungrounded_finding"
        ]

        assert flag["statements"] == ["key_findings.1"]

    def test_a_recommendation_naming_an_unpublished_technique_names_its_row(
        self, record: dict[str, Any]
    ) -> None:
        (flag,) = [
            f
            for f in record["narrative"]["flags"]
            if f["code"] == "narrative.unpublished_technique"
        ]

        assert flag["statements"] == ["defensive_recommendations.2"]

    def test_a_composer_citation_names_its_sentence(self, record: dict[str, Any]) -> None:
        (found,) = [
            (section, flag)
            for section, entry in record["composer"]["sections"].items()
            for flag in entry["flags"]
            if flag["code"] == "report.citation_not_evidence"
        ]
        _section, flag = found

        assert flag["statements"]
        assert all(place[0].isalpha() for place in flag["statements"])

    def test_a_schema_finding_names_the_field_it_rejects(self, record: dict[str, Any]) -> None:
        (flag,) = [f for f in record["narrative"]["flags"] if f["code"] == "narrative.schema"]

        assert flag["statements"] == ["defensive_recommendations.2.priority"]

    def test_the_place_holds_no_word_of_the_run_without_the_text(
        self, record: dict[str, Any]
    ) -> None:
        places = [f["statements"] for f in record["narrative"]["flags"] if "statements" in f]
        assert len(places) == 3
        text = json.dumps(places)

        for word in ("XOR", "configuration", "server", "blocklist", "Updater"):
            assert word not in text

    def test_the_decisions_are_those_of_a_run_without_places(self, record: dict[str, Any]) -> None:
        assert any("statements" in f for f in record["narrative"]["flags"])
        assert record["totals"] == EXPECTED_TOTALS

    def test_the_text_is_added_beside_the_place_and_not_instead_of_it(self) -> None:
        shown = replay_cli._replay([FIXTURE], True)[0]

        (flag,) = [
            f for f in shown["narrative"]["flags"] if f["code"] == "narrative.ungrounded_finding"
        ]
        assert flag["statements"] == ["key_findings.1"]
        assert flag["message"]


def _printed(record: dict[str, Any]) -> str:
    """The rendered record with the tree's path, as the renderer writes it, replaced."""
    rules = f"rules from: {terminal_safe(record['rules']['tree'])}"
    return render_record(record).replace(rules, "rules from: <tree>") + "\n"


class TestTheNarrativeIsReplayedInsideItsSchema:
    def test_a_field_only_the_schema_declares_is_written_in_the_place(self, tmp_path: Any) -> None:
        import shutil

        run = tmp_path / "tiny"
        shutil.copytree(FIXTURE, run)
        path = run / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["key_findings"][0]["text"] = "Its strings are XOR-encoded [Foo]."
        path.write_text(json.dumps(report), encoding="utf-8")

        record = replay_cli.replay_run(run)

        places = [
            f["statements"]
            for f in record["narrative"]["flags"]
            if f["code"] == "report.citation_not_evidence"
        ]
        assert places == [["key_findings.0.text"]]


class TestThePrintedRecord:
    def test_without_the_text_the_output_is_what_it_was_with_no_places(
        self, record: dict[str, Any]
    ) -> None:
        expected = (FIXTURE.parent / "tiny_output.txt").read_text(encoding="utf-8")

        assert _printed(record) == expected
        assert " | at " not in _printed(record)

    def test_with_the_text_each_finding_line_ends_with_its_places(self) -> None:
        shown = replay_cli._replay([FIXTURE], True)[0]
        expected = (FIXTURE.parent / "tiny_output_show_text.txt").read_text(encoding="utf-8")

        assert _printed(shown) == expected
        assert (
            "narrative.ungrounded_finding | key_findings.1.evidence_ids | at key_findings.1"
            in expected
        )


class TestTheComparisonReadsDecisions:
    def test_a_place_only_one_record_has_is_no_difference(self, record: dict[str, Any]) -> None:
        assert any("statements" in f for f in record["narrative"]["flags"])
        stripped = json.loads(json.dumps(record))
        for part in (stripped["narrative"], *stripped["composer"]["sections"].values()):
            for flag in part["flags"]:
                flag.pop("statements", None)

        assert compare.flag_keys(record) == compare.flag_keys(stripped)
        assert not compare.differs(compare.diff_records(record, stripped))
        assert not compare.differs(compare.diff_records(stripped, record))

    def test_a_record_stored_without_the_place_loads_as_before(
        self, record: dict[str, Any]
    ) -> None:
        assert any("statements" in f for f in record["narrative"]["flags"])
        stripped = json.loads(json.dumps(record))
        for flag in stripped["narrative"]["flags"]:
            flag.pop("statements", None)

        assert render_record(stripped)
        assert errors(stripped) == []
