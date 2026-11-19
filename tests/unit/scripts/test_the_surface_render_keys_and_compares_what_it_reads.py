"""The surface render keys each unit by what it is and compares every value a reader is served.

Every value a surface holds is compared. A STIX object is two units: its id,
and every other property, timestamps included, each ref said as its target's
key; a relationship is keyed by its source, its type and its target, so one
pointed at another technique is another unit. A MISP event, each attribute,
each object and each object attribute are whole JSON units. A unit the build
draws without the sandbox report (marked dynamic) is compared like any other.
Every line of the evidence bundle's sections is a unit, fenced and blank ones
too, and so is every block of the HTML body, each figure's tooltip and each
shown attribute. A rendered file that differs where no unit read from it does
is a change of its own. A surface neither ref produced is listed and ends the
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
            ("added", "relationship malware loader uses attack-pattern T1105 id"),
            ("removed", "relationship malware loader uses attack-pattern T1027"),
            ("removed", "relationship malware loader uses attack-pattern T1027 id"),
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

    def test_an_id_or_a_timestamp_changed_is_a_change(self) -> None:
        other = copy.deepcopy(_bundle(created="2030-01-01T00:00:00Z"))
        renamed = "malware--11111111-1111-4111-8111-111111111111"
        other["objects"][0]["id"] = renamed
        other["objects"][-1]["source_ref"] = renamed
        changes = rs.compare_records(_stix_record(_bundle()), _stix_record(other))["changes"]
        assert sorted(c["key"] for c in changes) == [
            "malware loader id",
            "relationship malware loader uses attack-pattern T1027",
        ]
        [stamp] = [c for c in changes if c["key"].startswith("relationship")]
        assert '"created": "2030-01-01T00:00:00Z"' in stamp["new"]

    def test_the_bundle_s_own_properties_are_a_unit(self) -> None:
        other = {**_bundle(), "id": "bundle--33333333-3333-4333-8333-333333333333"}
        [change] = rs.compare_records(_stix_record(_bundle()), _stix_record(other))["changes"]
        assert change["key"] == "bundle" and "bundle--3333" in change["new"]

    def test_a_ref_is_said_as_its_target_s_key(self) -> None:
        record = _stix_record(_bundle())
        [unit] = [
            u
            for u in record["units"]
            if u["key"].startswith("relationship") and not u["key"].endswith(" id")
        ]
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

    def test_every_line_is_a_unit_fenced_and_blank_ones_too(self) -> None:
        markdown = (
            "## Observed behaviour · _Written by the report model_\n\n"
            "_Observed in sandbox:_ a process started.\n"
            "```\npid=1200 ppid=4 fixture.exe\n```\n"
        )
        assert [u["text"] for u in self._units(markdown)] == [
            "## Observed behaviour · _Written by the report model_",
            "",
            "_Observed in sandbox:_ a process started.",
            "```",
            "pid=1200 ppid=4 fixture.exe",
            "```",
        ]

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("_Measured:_ 3 requests.\n", "_Measured (seeded):_ 3 requests.\n"),
            ("```\npid=1200 ppid=4\n```\n", "```\npid=1200 seeded ppid=4\n```\n"),
        ],
    )
    def test_a_changed_line_is_a_change(self, old: str, new: str) -> None:
        a = {"run": "r", "units": self._units(old), "not_produced": []}
        b = {"run": "r", "units": self._units(new), "not_produced": []}
        [change] = rs.compare_records(a, b)["changes"]
        assert change["surface"] == "bundle.lines" and "seeded" in change["new"]


class TestMisp:
    _EVENT = {
        "Event": {
            "info": "analysis",
            "threat_level_id": "4",
            "Attribute": [{"type": "domain", "value": "a.example", "comment": "c", "uuid": "u"}],
            "Object": [
                {
                    "name": "file",
                    "uuid": "o",
                    "Attribute": [
                        {"object_relation": "sha256", "value": SHA256, "category": "Other"}
                    ],
                }
            ],
        }
    }

    def _record(self, event: dict[str, Any]) -> dict[str, Any]:
        units = rs._Units("build")
        rs._misp_units(event, units)
        return {"run": "r", "units": units.rows, "not_produced": []}

    @pytest.mark.parametrize(
        ("path", "value", "key"),
        [
            (("threat_level_id",), "1", "event"),
            (("Attribute", 0, "uuid"), "v", "attribute domain a.example"),
            (("Object", 0, "uuid"), "p", "object file"),
            (("Object", 0, "Attribute", 0, "category"), "Payload delivery", "object file sha256"),
        ],
    )
    def test_every_field_of_every_part_is_compared(
        self, path: tuple[Any, ...], value: str, key: str
    ) -> None:
        other = copy.deepcopy(self._EVENT)
        held: Any = other["Event"]
        for step in path[:-1]:
            held = held[step]
        held[path[-1]] = value
        [change] = rs.compare_records(self._record(self._EVENT), self._record(other))["changes"]
        assert (change["surface"], change["key"]) == ("misp", key)


class TestHtmlTooltipsAndAttributes:
    _DOCUMENT = (
        '<h2>1. A</h2><figure id="fig-flow"><svg><g><title>1. The sample decodes it. (assessed)'
        "</title><text>1. The sample decodes it.</text></g></svg></figure>"
        '<p><img src="x.png" alt="{alt}"><a href="#n" title="note">1</a></p>'
        "<style>.a {{ color: red; }}</style>"
    )

    def _record(self, alt: str = "a chart", tooltip: str = "") -> dict[str, Any]:
        units = rs._Units("serve")
        document = self._DOCUMENT.format(alt=alt).replace("(assessed)", f"(assessed){tooltip}")
        rs.html_units(document, units)
        return {"run": "r", "units": units.rows, "not_produced": []}

    def test_a_tooltip_is_a_part_of_its_figure_and_each_shown_attribute_a_unit(self) -> None:
        rows = {(u["surface"], u["key"], u["text"]) for u in self._record()["units"]}
        assert ("html.figure", "fig-flow title", "1. The sample decodes it. (assessed)") in rows
        assert ("html.attrs", "1. A | img alt", "a chart") in rows
        assert ("html.attrs", "1. A | a title", "note") in rows
        assert ("html.body", "<style> | block", ".a { color: red; }") in rows

    def test_a_changed_tooltip_or_attribute_is_a_change(self) -> None:
        base = self._record()
        [tooltip] = rs.compare_records(base, self._record(tooltip=" seeded"))["changes"]
        assert (tooltip["surface"], tooltip["key"]) == ("html.figure", "fig-flow title")
        changes = rs.compare_records(base, self._record(alt="another chart"))["changes"]
        assert sorted((c["surface"], c["new"]) for c in changes) == [
            ("html.attrs", "another chart"),
            ("html.tags", '<img src="x.png" alt="another chart">'),
        ]


class TestTheFileIsCompared:
    def _record(self, units: list[dict[str, Any]], html: str) -> dict[str, Any]:
        return {
            "run": "r",
            "units": units,
            "not_produced": [],
            "file_digests": {"serve": {"report.html": rs.digest(html)}},
        }

    def test_a_file_that_differs_where_no_unit_does_is_a_change(self) -> None:
        a = self._record([], '<rect fill="red"/>')
        b = self._record([], '<rect fill="blue"/>')
        diff = rs.compare_records(a, b)
        [change] = diff["changes"]
        assert (change["surface"], change["key"]) == (rs.FILE_SURFACE, "report.html")
        assert diff["compared"] == {f"serve {rs.FILE_SURFACE}": 1}
        assert rs.first_difference('<rect fill="red"/>', '<rect fill="blue"/>') == (
            'line 1: <rect fill="red"/>',
            'line 1: <rect fill="blue"/>',
        )

    def test_a_file_that_differs_is_a_change_even_where_a_unit_shows_a_change(self) -> None:
        old = rs._Units("serve")
        old.add("html.body", "block", "First.", group="1. A")
        new = rs._Units("serve")
        new.add("html.body", "block", "Second.", group="1. A")
        diff = rs.compare_records(
            self._record(old.rows, "<p>First.</p>"), self._record(new.rows, "<p>Second.</p>")
        )
        assert [c["surface"] for c in diff["changes"]] == ["html.body", rs.FILE_SURFACE]
        text = rs.render_comparison([diff], ("A", "B"), [])
        assert "summary: 2 unit(s) compared on 2 surface(s), 2 difference(s)" in text
        assert "serve html.body: 1 compared, changed 1" in text
        assert "excluded from the comparison: nothing" in text


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
