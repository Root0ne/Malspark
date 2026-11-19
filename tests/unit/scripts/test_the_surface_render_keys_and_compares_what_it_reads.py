"""The surface render keys each unit by what it is and compares every value a reader is served.

A STIX object's unit holds every value but its id and timestamps, each ref
said as its target's key, and a relationship is keyed by its source, its type
and its target, so one pointed at another technique is another unit. A unit
the build draws without the sandbox report (marked dynamic) is compared like
any other. Every line of the evidence bundle's sections outside a fence is a
unit, the platform's notes and heading tags among them, and so is every block
of the HTML body. A surface neither ref produced is listed and ends the
comparison with its own status unless accepted, as an expectation nothing
matched does. A render whose API or replay scripts came from outside the tree
is refused. The build's clock and every value the builder dates from it are
the stored report's, and the serve mode prints the layout the run's settings
name, the detail's STIX note, the judge-source view, each IOC row's every
field and each layer technique's score and colour.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import SHA256, report, stored_run

_T1027 = "attack-pattern--00000000-0000-4000-8000-000000000027"
_T1105 = "attack-pattern--00000000-0000-4000-8000-000000001105"
_MALWARE = "malware--00000000-0000-4000-8000-0000000000aa"


def _bundle(**changes: Any) -> dict[str, Any]:
    relationship = {
        "type": "relationship",
        "id": "relationship--00000000-0000-4000-8000-0000000000bb",
        "created": "2026-01-02T03:04:05Z",
        "relationship_type": "uses",
        "source_ref": _MALWARE,
        "target_ref": _T1027,
        "confidence": 70,
        "x_malspark_platform_added": False,
        "description": "The sample decodes its configuration.",
    }
    relationship.update(changes)
    return {
        "type": "bundle",
        "objects": [
            {"type": "malware", "id": _MALWARE, "name": "loader", "is_family": False},
            {
                "type": "attack-pattern",
                "id": _T1027,
                "name": "Obfuscated Files or Information",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1027", "description": "a"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": _T1105,
                "name": "Ingress Tool Transfer",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1105"}],
            },
            relationship,
        ],
    }


def _record(*rows: tuple[str, str, str, Any], not_produced: Any = ()) -> dict[str, Any]:
    units = rs._Units("build")
    for surface, key, text, extra in rows:
        units.add(surface, key, text, **(extra or {}))
    return {"run": "r", "units": units.rows, "not_produced": list(not_produced)}


def _stix_record(bundle: dict[str, Any]) -> dict[str, Any]:
    units = rs._Units("build")
    rs._stix_units(bundle, units, dynamic=True)
    return {"run": "r", "units": units.rows, "not_produced": []}


class TestStix:
    def test_a_relationship_is_keyed_by_its_source_its_type_and_its_target(self) -> None:
        keys, _by_id = rs.stix_keys(_bundle()["objects"])
        assert keys[-1] == "relationship malware loader uses attack-pattern T1027"

    def test_a_relationship_pointed_at_another_technique_is_another_unit(self) -> None:
        diff = rs.compare_records(_stix_record(_bundle()), _stix_record(_bundle(target_ref=_T1105)))
        assert sorted((c["change"], c["key"]) for c in diff["changes"]) == [
            ("added", "relationship malware loader uses attack-pattern T1105"),
            ("removed", "relationship malware loader uses attack-pattern T1027"),
        ]

    @pytest.mark.parametrize(
        "changes",
        [{"confidence": 40}, {"x_malspark_platform_added": True}, {"description": "Another."}],
    )
    def test_a_number_a_flag_or_a_text_changed_is_a_change(self, changes: dict[str, Any]) -> None:
        diff = rs.compare_records(_stix_record(_bundle()), _stix_record(_bundle(**changes)))
        [change] = diff["changes"]
        assert change["change"] == "changed" and change["surface"] == "stix"

    def test_an_external_reference_s_text_changed_is_a_change(self) -> None:
        other = _bundle()
        other["objects"][1]["external_references"][0]["description"] = "b"
        [change] = rs.compare_records(_stix_record(_bundle()), _stix_record(other))["changes"]
        assert change["key"] == "attack-pattern T1027"

    def test_ids_and_timestamps_alone_are_no_change(self) -> None:
        other = copy.deepcopy(_bundle(created="2030-01-01T00:00:00Z"))
        renamed = "malware--11111111-1111-4111-8111-111111111111"
        other["objects"][0]["id"] = renamed
        other["objects"][-1]["source_ref"] = renamed
        other["objects"][-1]["id"] = "relationship--22222222-2222-4222-8222-222222222222"
        assert rs.compare_records(_stix_record(_bundle()), _stix_record(other))["changes"] == []

    def test_a_ref_is_said_as_its_target_s_key(self) -> None:
        record = _stix_record(_bundle())
        [unit] = [u for u in record["units"] if u["key"].startswith("relationship")]
        assert json.loads(unit["text"])["target_ref"] == "-> attack-pattern T1027"


class TestDynamicUnitsAreCompared:
    def test_a_changed_dynamic_unit_is_a_change_and_counted_once(self) -> None:
        dynamic = {"group": "fig-network", "dynamic": True}
        a = _record(("html.figure", "fig-network caption", "Network endpoints", dynamic))
        b = _record(("html.figure", "fig-network caption", "Network endpoints (seeded)", dynamic))
        diff = rs.compare_records(a, b)
        [change] = diff["changes"]
        assert change["new"] == "Network endpoints (seeded)"
        assert diff["dynamic_compared"] == 1


class TestBundleLines:
    def _units(self, markdown: str) -> list[dict[str, Any]]:
        units = rs._Units("serve")
        rs._bundle_units(
            {"sections": [{"title": "Observed behaviour", "markdown": markdown}]}, units
        )
        return [u for u in units.rows if u["surface"] == "bundle.lines"]

    def test_every_line_outside_a_fence_is_a_unit_headings_and_notes_among_them(self) -> None:
        markdown = (
            "## Observed behaviour · _Written by the report model_\n\n"
            "_Observed in sandbox:_ a process started.\n"
            "_Measured:_ 3 requests.\n"
            "It wrote a file.\n"
            "```\nquoted tool output\n```\n"
        )
        assert [u["text"] for u in self._units(markdown)] == [
            "## Observed behaviour · _Written by the report model_",
            "_Observed in sandbox:_ a process started.",
            "_Measured:_ 3 requests.",
            "It wrote a file.",
        ]

    def test_a_changed_platform_line_is_a_change(self) -> None:
        a = {"run": "r", "units": self._units("_Measured:_ 3 requests.\n"), "not_produced": []}
        b = {"run": "r", "units": self._units("_Measured (seeded):_ 3 requests.\n")}
        [change] = rs.compare_records(a, {**b, "not_produced": []})["changes"]
        assert change["surface"] == "bundle.lines" and "seeded" in change["new"]


class TestHtmlBody:
    def test_every_block_of_the_body_is_a_unit_and_a_changed_one_a_change(self) -> None:
        def _body(said: str) -> dict[str, Any]:
            units = rs._Units("serve")
            rs.html_units(
                "<header><p>cover</p></header><h2>1. A</h2><p>First.</p>"
                f"<table><tr><th>Field</th><th>Value</th></tr><tr><td>Size</td><td>{said}</td>"
                "</tr></table><figure><figcaption>caption</figcaption></figure>",
                units,
            )
            return {"run": "r", "units": units.rows, "not_produced": []}

        texts = [u["text"] for u in _body("0 bytes")["units"] if u["surface"] == "html.body"]
        assert texts == ["1. A", "First.", "Field | Value", "Size | 0 bytes"]
        [change] = rs.compare_records(_body("0 bytes"), _body("1 byte"))["changes"]
        assert (change["surface"], change["new"]) == ("html.body", "Size | 1 byte")


class TestNotComparedAndStatuses:
    _LACK = {"mode": "build", "surface": "stix", "reason": "this tree has no replay build"}

    def test_a_surface_neither_side_produced_is_listed_and_has_its_own_status(self) -> None:
        a = _record(not_produced=[self._LACK])
        diff = rs.compare_records(a, copy.deepcopy(a))
        assert diff["changes"] == [] and diff["neither"] == 1
        [row] = diff["not_compared"]
        assert row["neither"] is True and row["a"] == row["b"] == self._LACK["reason"]
        assert rs.comparison_status([diff], [], []) == rs.EXIT_NOT_COMPARED
        assert rs.comparison_status([diff], [], [], accept_not_compared=True) == 0
        text = rs.render_comparison([diff], ("A", "B"), [])
        assert "NOT COMPARED [build stix]: produced by neither ref" in text
        assert "no difference: both refs render the same units" not in text

    def test_an_unexercised_expectation_and_an_error_end_with_their_own_status(self) -> None:
        same = rs.compare_records(_record(), _record())
        assert rs.comparison_status([same], [], [{"index": 0}]) == rs.EXIT_UNEXERCISED
        assert rs.comparison_status([same], [], []) == 0
        assert rs.comparison_status([{**same, "errors": [{}]}], [], []) == rs.EXIT_ERROR
        assert rs.comparison_status([same], [{}], [{"index": 0}]) == rs.EXIT_UNEXPECTED


class TestImportsComeFromTheTree:
    def test_an_api_or_replay_imported_from_elsewhere_is_refused(self, tmp_path: Path) -> None:
        tree = tmp_path / "tree"
        inside = {"app": str(tree / "apps" / "api" / "app"), "scripts.replay": None}
        rs.check_imports({"tree": str(tree), "imported_from": inside}, tree)
        for name in ("app", "scripts.replay"):
            moved = {**inside, name: str(tmp_path / "elsewhere" / name)}
            with pytest.raises(RuntimeError, match=f"imported {name} from"):
                rs.check_imports({"tree": str(tree), "imported_from": moved}, tree)
        with pytest.raises(RuntimeError, match="did not say"):
            rs.check_imports({"tree": str(tree)}, tree)


class TestPinnedClock:
    def test_every_value_dated_from_the_build_s_clock_is_the_stored_report_s(self) -> None:
        built = SimpleNamespace(
            generated_at=None,
            front_matter=SimpleNamespace(
                report_date="2030-05-06",
                report_number="MJN20300506-6abc16",
                copyright="© 2030 Malspark",
            ),
            version_history=[SimpleNamespace(date="2030-05-06")],
        )
        clock = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
        rs.pin_clock(built, {"front_matter": {"report_date": "2026-01-03"}}, clock)
        assert built.generated_at == clock
        assert built.front_matter.report_date == "2026-01-03"
        assert built.front_matter.report_number == "MJN20260103-6abc16"
        assert built.front_matter.copyright == "© 2026 Malspark"
        assert built.version_history[0].date == "2026-01-03"

    def test_the_build_s_header_date_and_report_number_are_the_stored_ones(
        self, tmp_path: Path
    ) -> None:
        number = f"MJN20260103-{SHA256[:6]}"
        stored = {
            **report(),
            "front_matter": {"report_date": "2026-01-03", "report_number": number},
        }
        record, _files = rs.render_run(stored_run(tmp_path, malware_report=stored))
        for mode in rs.MODES:
            cover = [
                u["text"]
                for u in record["units"]
                if u["mode"] == mode and u["surface"] == "html.header"
            ]
            assert any(f"Report {number} · 2026-01-03" in said for said in cover), (mode, cover)
        [header] = [
            u
            for u in record["units"]
            if u["mode"] == "build" and u["surface"] == "bundle.index" and u["key"] == "report"
        ]
        assert json.loads(header["text"])["generated_at"] == "2026-01-02T03:04:05+00:00"


@pytest.fixture(scope="module")
def served(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    record, _files = rs.render_run(stored_run(tmp_path_factory.mktemp("served")), modes=("serve",))
    return record


def _texts(record: dict[str, Any], surface: str) -> list[str]:
    return [u["text"] for u in record["units"] if u["surface"] == surface]


class TestServedAsTheApiServes:
    def test_the_layout_is_the_one_the_run_s_settings_name(
        self, tmp_path: Path, served: dict[str, Any]
    ) -> None:
        run = stored_run(tmp_path)
        summary_file = run / "run-summary.json"
        summary = json.loads(summary_file.read_text(encoding="utf-8"))
        summary.setdefault("settings_snapshot", {})["reporting.full_report_in_one_file"] = True
        summary_file.write_text(json.dumps(summary), encoding="utf-8")
        record, _files = rs.render_run(run, modes=("serve",))
        # The analyst report points into the bundle; the single file holds it all.
        pointer = "In the evidence bundle:"
        assert any(pointer in said for said in _texts(served, "report.md"))
        assert not any(pointer in said for said in _texts(record, "report.md"))

    def test_the_detail_s_stix_note_and_the_judge_view_are_units(
        self, served: dict[str, Any]
    ) -> None:
        assert _texts(served, "stix.note") and _texts(served, "stix.judge")
        [envelope] = [
            u
            for u in served["units"]
            if u["surface"] == "stix.judge.notice" and u["key"] == "envelope"
        ]
        assert json.loads(envelope["text"])["published"] is False

    def test_an_ioc_row_and_a_layer_technique_carry_every_field(
        self, served: dict[str, Any]
    ) -> None:
        [row] = [json.loads(t) for t in _texts(served, "iocs.all")]
        assert {"evidence_ids", "tlp", "recovered_by", "publish_answer"} <= set(row)
        # A technique the report's support scores carries its score and colour.
        units = rs._Units("serve")
        layer = {"techniques": [{"techniqueID": "T1027", "score": 2, "color": "#aabbcc"}]}
        rs._layer_units(layer, units)
        [technique] = [u for u in units.rows if u["key"] == "technique T1027"]
        assert json.loads(technique["text"]) == {"color": "#aabbcc", "score": 2}
        changed = rs._Units("serve")
        rs._layer_units({"techniques": [{**layer["techniques"][0], "score": 3}]}, changed)
        diff = rs.compare_records(
            {"run": "r", "units": units.rows, "not_produced": []},
            {"run": "r", "units": changed.rows, "not_produced": []},
        )
        assert [c["key"] for c in diff["changes"]] == ["technique T1027"]
