"""A figure's caption, legend, label and mark name only what the rows it draws give.

No row is removed to make a word true: a network box says where its value was
read from, a line joins the sample only to an endpoint its own processes are
recorded reaching, red means flagged or published for every kind, a key is
printed only for a mark that is drawn, and what a figure leaves out it counts
against the JSON report, which holds every row.
"""

from __future__ import annotations

import re
from html import unescape
from typing import Any

import pytest

from malspark.reporting import figures
from malspark.reporting.figures import (
    _figure_left_out,
    build_code_listings,
    build_entropy_chart,
    build_execution_flow,
    build_infection_chain,
    build_network_graph,
    build_process_tree,
)
from malspark.reporting.models import (
    ConsolidatedIOC,
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    PESection,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
    TTPMapping,
)

_RED = 'stroke="#cf222e"'
_TEXT = re.compile(r"<text\b([^>]*)>(.*?)</text>", re.S)
_EM = 0.62


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), **over)


def _texts(svg: str) -> list[str]:
    return [unescape(body) for _attrs, body in _TEXT.findall(svg)]


def _number(attrs: str, name: str) -> float:
    found = re.search(rf'\b{name}="([0-9.]+)"', attrs)
    assert found is not None, attrs
    return float(found.group(1))


def _rows(svg: str) -> list[tuple[float, float, float]]:
    """Each box of a network figure as ``(x, y, width)``."""
    return [
        (float(x), float(y), float(w))
        for x, y, w in re.findall(r'<rect x="(\d+)" y="(\d+)" width="(\d+)" height="22"', svg)
    ]


class TestANetworkBoxSaysWhereItsValueWasRead:
    _CASES = (
        (NetworkDomain(fqdn="seen.example", source="sandbox"), "network record"),
        (
            NetworkDomain(fqdn="tls.example", source="sandbox", capture_only=True),
            "TLS name only",
        ),
        (NetworkDomain(fqdn="text.example", source="strings"), "text only, no network record"),
        (NetworkDomain(fqdn="listed.example", source="analyst"), "analyst listing only"),
        (NetworkDomain(fqdn="unsaid.example"), "source not recorded"),
    )

    @pytest.mark.parametrize(("row", "word"), _CASES)
    def test_each_domain_carries_the_word_of_its_source(
        self, row: NetworkDomain, word: str
    ) -> None:
        fig = build_network_graph(_report(network=NetworkIOCs(domains=[row])))
        assert fig is not None
        said = _texts(fig.content)
        assert word in said
        for _other, other_word in self._CASES:
            if other_word != word:
                assert other_word not in said

    def test_an_address_a_sandbox_recorded_is_a_network_record(self) -> None:
        fig = build_network_graph(
            _report(network=NetworkIOCs(ips=[NetworkIP(address="203.0.113.7", source="sandbox")]))
        )
        assert fig is not None
        assert "network record" in _texts(fig.content)

    def test_no_word_claims_more_than_the_row(self) -> None:
        fig = build_network_graph(
            _report(network=NetworkIOCs(domains=[row for row, _w in self._CASES]))
        )
        assert fig is not None
        assert "observed" not in fig.caption.lower()
        assert "observed" not in (fig.legend or "").lower()
        assert "file strings" not in fig.content

    def test_every_row_is_drawn_whatever_its_source(self) -> None:
        rows = [row for row, _w in self._CASES]
        fig = build_network_graph(_report(network=NetworkIOCs(domains=rows)))
        assert fig is not None
        said = _texts(fig.content)
        for row in rows:
            assert row.fqdn.replace(".", "[.]") in said

    def test_every_label_fits_its_box(self) -> None:
        long_host = "a" * 70 + ".example"
        fig = build_network_graph(
            _report(
                network=NetworkIOCs(
                    domains=[NetworkDomain(fqdn=long_host, source="strings")],
                    ips=[NetworkIP(address="203.0.113.7", port=65535, sample_process_tree=True)],
                )
            )
        )
        assert fig is not None
        boxes = _rows(fig.content)
        texts = _TEXT.findall(fig.content)
        for attrs, body in texts:
            x, y = _number(attrs, "x"), _number(attrs, "y")
            size = _number(attrs, "font-size")
            inside = [b for b in boxes if b[1] <= y <= b[1] + 22 and b[0] <= x <= b[0] + b[2]]
            if not inside:
                continue  # the sample's own node
            (bx, _by, bw) = inside[0]
            assert x + len(unescape(body)) * size * _EM <= bx + bw, body

    def test_a_source_word_and_a_host_label_pass_the_figure_s_defanger(self) -> None:
        fig = build_network_graph(
            _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="evil.example.net")]))
        )
        assert fig is not None
        assert "evil.example.net" not in fig.content
        assert "evil[.]example[.]net" in _texts(fig.content)

    def test_every_source_word_and_tactic_name_reads_the_same_through_the_defanger(self) -> None:
        from malspark.extractors.capability_matrix import tactic_order

        for word in [w for _row, w in self._CASES] + [n for _t, n in tactic_order()]:
            assert figures._written(word) == word

    def test_every_label_sits_in_a_text_node_never_in_an_attribute(self) -> None:
        fig = build_network_graph(
            _report(network=NetworkIOCs(domains=[row for row, _w in self._CASES]))
        )
        assert fig is not None
        attributes = " ".join(re.findall(r'="([^"]*)"', fig.content))
        for _row, word in self._CASES:
            assert word not in attributes
        assert "example" not in attributes


class TestALineJoinsTheSampleOnlyWhereTheRowSaysSo:
    def test_no_line_and_no_sample_node_when_no_row_names_the_sample_s_processes(self) -> None:
        fig = build_network_graph(
            _report(
                network=NetworkIOCs(
                    domains=[NetworkDomain(fqdn="a.example", source="sandbox")],
                    ips=[
                        NetworkIP(address="203.0.113.7", sample_process_tree=False),
                        NetworkIP(address="198.51.100.9"),
                    ],
                )
            )
        )
        assert fig is not None
        assert "<line" not in fig.content
        assert "sample" not in _texts(fig.content)

    def test_a_line_only_to_the_row_the_sample_s_processes_reached(self) -> None:
        fig = build_network_graph(
            _report(
                network=NetworkIOCs(
                    domains=[NetworkDomain(fqdn="a.example", sample_process_tree=True)],
                    ips=[
                        NetworkIP(address="203.0.113.7", sample_process_tree=False),
                        NetworkIP(address="198.51.100.9", sample_process_tree=True),
                    ],
                )
            )
        )
        assert fig is not None
        assert fig.content.count("<line") == 2
        assert "sample" in _texts(fig.content)
        lines = re.findall(r'<line [^>]*y2="(\d+)"', fig.content)
        tops = [int(y) for _x, y, _w in _rows(fig.content)]
        assert sorted(int(y) - 11 for y in lines) == [tops[0], tops[2]]


class TestRedMeansFlaggedOrPublishedForEveryKind:
    def test_a_published_domain_is_red_and_an_unpublished_one_is_not(self) -> None:
        report = _report(
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn="held.example"), NetworkDomain(fqdn="other.example")]
            ),
            consolidated_iocs=[
                ConsolidatedIOC(
                    type="Domain",
                    value="held.example",
                    kind="domain",
                    is_network=True,
                    published="yes",
                )
            ],
        )
        fig = build_network_graph(report)
        assert fig is not None
        assert fig.content.count(_RED) == 1


class TestAKeyIsPrintedOnlyForAMarkThatIsDrawn:
    def test_a_tree_with_no_injecting_process_prints_no_key(self) -> None:
        fig = build_process_tree(
            _report(dynamic=DynamicBehavior(process_tree=[ProcessNode(pid=1, name="a.exe")]))
        )
        assert fig is not None
        assert fig.legend is None
        assert "#cf222e" not in fig.content

    def test_a_red_node_is_keyed_as_the_injecting_process(self) -> None:
        fig = build_process_tree(
            _report(
                dynamic=DynamicBehavior(
                    process_tree=[
                        ProcessNode(
                            pid=1,
                            name="a.exe",
                            injected_into=[2],
                            children=[ProcessNode(pid=2, ppid=1, name="b.exe")],
                        )
                    ]
                )
            )
        )
        assert fig is not None and fig.legend is not None
        assert "injecting" in fig.legend
        assert "target" not in fig.legend


class TestEntropyIsANumberNotAVerdict:
    def test_neither_the_header_nor_the_legend_interprets_the_value(self) -> None:
        fig = build_entropy_chart(
            _report(
                static=StaticAnalysis(
                    sections=[PESection(name=".data", virtual_address="0x1000", entropy=7.6)]
                )
            )
        )
        assert fig is not None and fig.legend is not None
        said = " ".join(_texts(fig.content)) + " " + fig.legend
        for word in ("packed", "encrypted", "suspicious"):
            assert word not in said
        assert "Section entropy (0–8)" in _texts(fig.content)
        assert "7.60" in _texts(fig.content)


class TestTheChainSaysWhereItsOrderComesFrom:
    def test_neither_caption_nor_legend_says_observed(self) -> None:
        fig = build_infection_chain(
            _report(
                ttp_mappings=[
                    TTPMapping(technique_id="T1204", technique_name="x", tactic="TA0002"),
                    TTPMapping(technique_id="T1071", technique_name="y", tactic="TA0011"),
                ]
            )
        )
        assert fig is not None and fig.legend is not None
        assert fig.caption == "Tactics of the mapped techniques, in ATT&CK order"
        assert "observed" not in fig.caption.lower() and "observed" not in fig.legend.lower()
        assert fig.legend.startswith(
            "Tactics are drawn in ATT&CK order, not the order read from the run: neither the "
            "order nor the arrows come from the run's events."
        )


class TestTheFlowLegendNamesTheTwoMarks:
    def test_it_says_which_mark_each_outline_shows_and_nothing_more(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.reporting.renderers import analyst

        monkeypatch.setattr(
            analyst,
            "flow_steps",
            lambda _r: [("1. a", "observed", "1. a."), ("2. b", "assessed", "2. b.")],
        )
        fig = build_execution_flow(_report())
        assert fig is not None and fig.legend is not None
        assert "marks observed" in fig.legend and "marked assessed" in fig.legend
        assert "sandbox" not in fig.legend and "read from the code" not in fig.legend


class TestAListingCutForStorageIsNeverCalledWhole:
    def test_a_long_listing_from_an_answer_cut_for_storage_prints_no_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(figures.tool_kinds, "reads_code", lambda _o, _w: True)
        monkeypatch.setattr(figures.tool_kinds, "function_parts", lambda _o: [])
        monkeypatch.setattr(figures.tool_kinds, "facts_of", lambda _o: None)
        monkeypatch.setattr(figures, "code_listing", lambda _out, _p, _r: ("x = 1;\n" * 900, True))
        (fig,) = build_code_listings(
            _report(technical_evidence={"static": [{"tool_name": "t", "output": "x"}]})
        )
        assert fig.legend is not None
        assert figures.LISTING_CUT_FOR_STORAGE in fig.legend
        assert "Cut at 4,000 of" in fig.legend
        assert "whole" not in fig.legend

    def test_a_long_listing_from_a_whole_answer_still_points_at_the_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(figures.tool_kinds, "reads_code", lambda _o, _w: True)
        monkeypatch.setattr(figures.tool_kinds, "function_parts", lambda _o: [])
        monkeypatch.setattr(figures.tool_kinds, "facts_of", lambda _o: None)
        monkeypatch.setattr(figures, "code_listing", lambda _out, _p, _r: ("x = 1;\n" * 900, False))
        (fig,) = build_code_listings(
            _report(technical_evidence={"static": [{"tool_name": "t", "output": "x"}]})
        )
        assert fig.legend is not None
        assert "carry the listing whole" in fig.legend


class TestWhatAFigureLeavesOutIsCountedAgainstTheJsonReport:
    def test_the_sentence_holds_what_is_left_out_and_the_whole_count(self) -> None:
        assert _figure_left_out(52, 40, "processes") == (
            " 12 more processes are not drawn; the JSON report holds all 52."
        )
        assert "tables" not in _figure_left_out(1052, 40, "endpoints")
        assert "all 1,052" in _figure_left_out(1052, 40, "endpoints")
