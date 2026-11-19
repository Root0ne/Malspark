"""The surface render turns a stored run into units, and two records into the changes between them.

``scripts.replay.render_surfaces.render_run`` renders a stored run in two modes
(serve: the stored report, as the API renders it; build: the report the replay
rebuilds) and returns one unit per line, field, label, row and object of each
surface, each with the mode that produced it. A surface it cannot produce is
listed with the reason, never left out. A figure's text is read from its SVG
``<text>`` nodes.

``compare_records`` names every unit changed, added or removed between two
records; the command line ends with status 1 on a change no expectation names,
0 when each is expected, and says an expectation nothing matched is
UNEXERCISED.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import compare
from scripts.replay import render_surfaces as rs
from scripts.replay.stored import digests

from tests.unit.scripts._surfaces_render_run import (
    CAPTION,
    LABELS,
    LEGEND,
    SUMMARY,
    stored_run,
)


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], Any]:
    run = stored_run(tmp_path_factory.mktemp("surfaces"))
    record, files = rs.render_run(run)
    return run, record, files


def _units(record: dict[str, Any], mode: str, surface: str) -> list[dict[str, Any]]:
    return [u for u in record["units"] if u["mode"] == mode and u["surface"] == surface]


class TestEachSurfaceIsUnits:
    def test_every_surface_the_run_has_gives_units_in_the_serve_mode(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        assert set(rs.counts(record)["serve"]) == set(rs.SURFACES)
        assert [r for r in record["not_produced"] if r["mode"] == "serve"] == []

    def test_the_build_mode_renders_the_rebuilt_report_and_says_which_mode_made_each_unit(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, files = rendered
        built = rs.counts(record)["build"]
        for surface in ("report.md", "html.header", "iocs.all", "stix", "misp", "rules"):
            assert built.get(surface), surface
        assert {u["mode"] for u in record["units"]} == {"serve", "build"}
        assert "report.md" in files["build"] and "report.html" in files["build"]

    def test_the_stored_report_s_lines_and_rows_are_its_units(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        lines = [u["text"] for u in _units(record, "serve", "report.md")]
        assert any(SUMMARY in line for line in lines) or any(
            "XOR-encoded" in line for line in lines
        )
        assert [u["key"] for u in _units(record, "serve", "mitre")] == ["T1027"]
        assert [u["key"] for u in _units(record, "serve", "stix")] == ["attack-pattern T1027"]
        rules = _units(record, "serve", "rules")
        assert [u["key"] for u in rules] == ["yara fixture_rule"]
        assert rules[0]["text"].startswith("body sha256:")
        comments = [u["text"] for u in _units(record, "serve", "rules.comments")]
        assert "// fixture_rule" in comments and "// the fixture's own rule" in comments
        assert _units(record, "serve", "banner")

    def test_nothing_is_written_into_the_run(self, tmp_path: Path) -> None:
        run = stored_run(tmp_path)
        before = digests(run)
        rs.write_out(tmp_path / "out", [run], ("serve",))
        assert digests(run) == before
        assert (tmp_path / "out" / rs.RECORD_FILE).is_file()
        assert (tmp_path / "out" / "00-run" / "serve" / "report.md").is_file()

    def test_an_out_directory_inside_a_run_is_refused(self, tmp_path: Path) -> None:
        run = stored_run(tmp_path)
        with pytest.raises(SystemExit) as ended:
            rs.main([str(run), "--out", str(run / "surfaces")])
        assert ended.value.code == 2


class TestNotProduced:
    def test_a_column_the_row_lacks_is_not_produced_with_its_reason(self, tmp_path: Path) -> None:
        run = stored_run(tmp_path, stix_bundle=None, mitre_techniques=None)
        record, _files = rs.render_run(run, modes=("serve",))
        lacking = {r["surface"]: r["reason"] for r in record["not_produced"]}
        assert lacking == {
            "stix": "report-byjob.json holds no stix_bundle column",
            "stix.notice": "report-byjob.json holds no stix_bundle column",
            "mitre": "report-byjob.json holds no mitre_techniques column",
        }
        assert not _units(record, "serve", "stix") and not _units(record, "serve", "mitre")

    def test_an_entry_point_the_tree_lacks_is_not_produced_with_its_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import navigator_layer

        monkeypatch.delattr(navigator_layer, "build_layer")
        record, _files = rs.render_run(stored_run(tmp_path), modes=("serve",))
        assert record["not_produced"] == [
            {
                "mode": "serve",
                "surface": "navigator",
                "reason": "this tree's malspark.reporting.navigator_layer has no build_layer",
            }
        ]

    def test_a_surface_that_raises_is_not_produced_and_marked_as_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting import call_map

        def _broken(_entries: Any) -> Any:
            raise RuntimeError("broken")

        monkeypatch.setattr(call_map, "call_map", _broken)
        record, _files = rs.render_run(stored_run(tmp_path), modes=("serve",))
        [row] = record["not_produced"]
        assert row["surface"] == "call_map" and row["error"] is True
        assert row["reason"].startswith("raised: RuntimeError at ")

    def test_a_run_without_a_report_names_every_surface(self, tmp_path: Path) -> None:
        run = tmp_path / "empty"
        run.mkdir()
        record, _files = rs.render_run(run, modes=("serve",))
        assert [r["surface"] for r in record["not_produced"]] == list(rs.SURFACES)
        assert record["units"] == []


class TestFigureText:
    def test_a_figure_s_labels_are_its_svg_text_nodes(self) -> None:
        document = (
            '<h2 id="sec-a">1. A</h2>'
            '<figure id="fig-x"><svg><text x="1">first label</text><rect/>'
            "<text>second <tspan>label</tspan></text></svg>"
            '<figcaption><b>Figure 1.</b> The caption<span class="fig-legend">The legend.'
            "</span></figcaption></figure>"
            "<p><em>A note of the platform.</em></p><p>Prose with <em>emphasis</em>.</p>"
        )
        units = rs._Units("serve")
        rs.html_units(document, units)
        got = [(u["surface"], u["key"], u["text"]) for u in units.rows]
        assert got == [
            ("html.figure", "fig-x label", "first label"),
            ("html.figure", "fig-x label (2)", "second label"),
            ("html.figure", "fig-x legend", "The legend."),
            ("html.figure", "fig-x caption", "Figure 1. The caption"),
            ("html.notes", "1. A | note", "A note of the platform."),
        ]

    def test_the_stored_figure_s_labels_caption_and_legend_are_units(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        figure = {
            u["key"]: u["text"]
            for u in _units(record, "serve", "html.figure")
            if u["group"] == "fig-attack-matrix"
        }
        assert figure["fig-attack-matrix label"] == LABELS[0]
        assert figure["fig-attack-matrix label (2)"] == LABELS[1]
        assert figure["fig-attack-matrix legend"] == LEGEND
        assert figure["fig-attack-matrix caption"].endswith(CAPTION)


def _changed_sentence(record: dict[str, Any]) -> dict[str, Any]:
    other = copy.deepcopy(record)
    for unit in other["units"]:
        if unit["mode"] == "serve" and unit["surface"] == "report.md" and SUMMARY in unit["text"]:
            unit["text"] = unit["text"].replace(SUMMARY, "The sample reads its settings at start.")
            return other
    raise AssertionError("the summary is not a line of the record")


class TestCompare:
    def test_a_changed_sentence_is_one_change_with_both_texts(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        diff = rs.compare_records(record, _changed_sentence(record))
        [change] = diff["changes"]
        assert change["change"] == "changed" and change["surface"] == "report.md"
        assert SUMMARY in change["old"] and "reads its settings" in change["new"]
        assert diff["summary"] == {"serve report.md": {"changed": 1}}
        assert rs.compare_records(record, record)["changes"] == []

    def test_a_line_put_in_is_one_line_added_not_every_line_after_it(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        other = copy.deepcopy(record)
        at = next(i for i, u in enumerate(other["units"]) if u["surface"] == "report.md")
        other["units"].insert(at, {**other["units"][at], "text": "A new first line."})
        changes = rs.compare_records(record, other)["changes"]
        assert [(c["change"], c["new"]) for c in changes] == [("added", "A new first line.")]

    def test_a_surface_one_side_did_not_produce_is_never_equal(
        self, rendered: tuple[Path, dict[str, Any], Any]
    ) -> None:
        _run, record, _files = rendered
        other = copy.deepcopy(record)
        other["units"] = [u for u in other["units"] if u["surface"] != "mitre"]
        other["not_produced"] = [
            *other["not_produced"],
            {"mode": "serve", "surface": "mitre", "reason": "this tree has no mitre"},
            {"mode": "build", "surface": "mitre", "reason": "this tree has no mitre"},
        ]
        diff = rs.compare_records(record, other)
        assert {c["change"] for c in diff["changes"]} == {"removed"}
        assert {(r["mode"], r["b"]) for r in diff["not_compared"]} >= {
            ("serve", "this tree has no mitre")
        }

    def _main(
        self,
        monkeypatch: pytest.MonkeyPatch,
        records: tuple[dict[str, Any], dict[str, Any]],
        argv: list[str],
    ) -> int:
        by_side = {"a-tree": records[0], "b-tree": records[1]}

        def _materialise(_repo: Path, _ref: str, into: Path, **_kwargs: Any) -> Path:
            return into

        def _render_under(tree: Path, _runs: Any, _out: Path, **_kwargs: Any) -> Any:
            return [copy.deepcopy(by_side[tree.name])]

        monkeypatch.setattr(compare, "materialise", _materialise)
        monkeypatch.setattr(rs, "render_under", _render_under)
        return rs.main(argv)

    def test_an_unexpected_change_ends_with_status_1_and_an_expected_one_with_0(
        self,
        rendered: tuple[Path, dict[str, Any], Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        run, record, _files = rendered
        pair = (record, _changed_sentence(record))
        argv = [str(run), "--compare", "A", "B", "--work", str(tmp_path / "work")]
        assert self._main(monkeypatch, pair, argv) == 1
        printed = capsys.readouterr().out
        assert "CHANGED UNEXPECTED" in printed and "reads its settings" in printed
        assert "summary: 1 difference(s), 1 unexpected" in printed

        expect = tmp_path / "expect.json"
        expect.write_text(
            json.dumps(
                [
                    {
                        "surface": "report.md",
                        "old": "decodes its configuration",
                        "new": "reads its settings",
                        "reason": "the summary's sentence is reworded",
                    },
                    {"surface": "stix", "key": "^indicator", "reason": "an indicator is added"},
                ]
            ),
            encoding="utf-8",
        )
        out = tmp_path / "diff.json"
        argv += ["--expect", str(expect), "--json", str(out)]
        assert self._main(monkeypatch, pair, argv) == 0
        printed = capsys.readouterr().out
        assert "CHANGED expected" in printed
        assert "UNEXERCISED expectation 1 [stix]: an indicator is added" in printed
        written = json.loads(out.read_text(encoding="utf-8"))
        assert [e["index"] for e in written["unexercised"]] == [1]
        assert written["runs"][0]["changes"][0]["reason"] == "the summary's sentence is reworded"

    def test_no_difference_is_status_0_and_said(
        self,
        rendered: tuple[Path, dict[str, Any], Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        run, record, _files = rendered
        argv = [str(run), "--compare", "A", "B", "--work", str(tmp_path / "work")]
        assert self._main(monkeypatch, (record, record), argv) == 0
        assert "no difference: both refs render the same units" in capsys.readouterr().out

    def test_an_expectation_without_a_pattern_or_a_reason_is_refused(self, tmp_path: Path) -> None:
        expect = tmp_path / "expect.json"
        for rows in ([{"surface": "stix", "reason": "r"}], [{"surface": "stix", "key": "x"}]):
            expect.write_text(json.dumps(rows), encoding="utf-8")
            with pytest.raises(ValueError):
                rs.read_expectations(expect)

    def test_a_text_with_a_newline_prints_on_the_lines_the_comparison_gives(self) -> None:
        change = {
            "change": "changed",
            "mode": "serve",
            "surface": "stix",
            "group": "",
            "key": "k\nforged",
            "old": "a\nUNEXPECTED",
            "new": "b",
        }
        diff = {"run": "r", "changes": [change], "summary": {"serve stix": {"changed": 1}}}
        text = rs.render_comparison([diff], ("A", "B"), [])
        assert not any(line.startswith(("forged", "UNEXPECTED")) for line in text.splitlines())


def test_the_help_states_the_limits(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        rs.main(["--help"])
    said = " ".join(capsys.readouterr().out.split())
    for limit in rs.LIMITS:
        assert " ".join(limit.split()) in said
    doc = " ".join(str(rs.__doc__).split())
    for words in (
        "serve mode cannot change platform text that was written before rendering and stored",
        "build mode rebuilds without the sandbox report",
        "fields an older build lacked default to empty",
    ):
        assert words in doc
