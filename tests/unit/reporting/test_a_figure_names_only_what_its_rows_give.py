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
# Widths in px, the largest over the fonts the figure's width tables cover
# (DejaVu Sans, Inter, Liberation Sans) measured from their font files with
# PIL's ``ImageFont.getlength`` at the size drawn, in both layout engines,
# with FreeType's default hinting and unhinted, rounded up to a tenth.
_W_11 = 9.1  # one "w" at 11 px: "w" * 44 is 396.1 px
_CUT_MARK_11 = 11.0  # "…" at 11 px
_SOURCE_WORD_10 = {
    "network record": 76.2,
    "TLS name only": 74.0,
    "text only, no network record": 142.4,
    "analyst listing only": 94.1,
    "source not recorded": 101.0,
}
# Labels a review found drawn past the source word under the earlier tables,
# each with its width in px at 11 px per font, the larger of PIL's two layout
# engines, hinted (FreeType's default) or unhinted: the whole value, and the
# label the figure now draws for it.
_OVERLAPPING_11 = {
    # Overlapped in DejaVu Sans, hinted (basic engine): 324.0 px.
    "m" * 4 + "v" * 40: (
        {"DejaVu Sans": 324.0, "Inter": 285.91, "Liberation Sans": 276.0},
        "m" * 4 + "v" * 34 + "…",
        {"DejaVu Sans": 293.0, "Inter": 258.2, "Liberation Sans": 251.0},
    ),
    # Overlapped in Inter (raqm engine): 313.31 px.
    "w" * 23 + "-" * 21: (
        {"DejaVu Sans": 291.0, "Inter": 313.31, "Liberation Sans": 268.0},
        "w" * 23 + "-" * 13 + "…",
        {"DejaVu Sans": 270.0, "Inter": 282.4, "Liberation Sans": 247.0},
    ),
    # Overlapped in Inter (raqm engine): 375.76 px.
    "%" * 22 + "J" * 22: (
        {"DejaVu Sans": 301.47, "Inter": 375.76, "Liberation Sans": 352.0},
        "%" * 22 + "J" + "…",
        {"DejaVu Sans": 244.3, "Inter": 258.0, "Liberation Sans": 237.0},
    ),
}
_BRACKET = re.compile(r"\[[.:@]\]")


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

    def test_a_label_of_wide_letters_is_cut_before_its_source_word(self) -> None:
        fig = build_network_graph(
            _report(
                network=NetworkIOCs(
                    domains=[NetworkDomain(fqdn="w" * 60 + ".example", source="strings")]
                )
            )
        )
        assert fig is not None
        (label_attrs, label), (word_attrs, _word) = _TEXT.findall(fig.content)
        label = unescape(label)
        assert label.endswith("…") and set(label[:-1]) == {"w"}
        right = _number(label_attrs, "x") + (len(label) - 1) * _W_11 + _CUT_MARK_11
        assert right <= _number(word_attrs, "x")

    @pytest.mark.parametrize("value", sorted(_OVERLAPPING_11))
    def test_a_label_a_review_found_overlapping_ends_before_its_source_word(
        self, value: str
    ) -> None:
        whole, drawn, widths = _OVERLAPPING_11[value]
        fig = build_network_graph(
            _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn=value, source="strings")]))
        )
        assert fig is not None
        (label_attrs, label), (word_attrs, _word) = _TEXT.findall(fig.content)
        assert unescape(label) == drawn
        start = _number(label_attrs, "x")
        word_at = _number(word_attrs, "x")
        assert max(start + w for w in whole.values()) > word_at - figures._LABEL_PAD
        for font, width in widths.items():
            assert start + width + figures._LABEL_PAD <= word_at, font

    @pytest.mark.parametrize("lead", range(6))
    def test_a_cut_keeps_every_defang_bracket_whole(self, lead: int) -> None:
        host = "a" * lead + "WWW." * 12 + "com"
        fig = build_network_graph(_report(network=NetworkIOCs(domains=[NetworkDomain(fqdn=host)])))
        assert fig is not None
        label = _texts(fig.content)[0]
        assert label.endswith("…")
        kept = label[:-1]
        assert host.replace(".", "[.]").startswith(kept)
        assert "[" not in _BRACKET.sub("", kept) and "]" not in _BRACKET.sub("", kept)

    def test_every_source_word_fits_its_box(self) -> None:
        rows = [row for row, _w in self._CASES]
        fig = build_network_graph(_report(network=NetworkIOCs(domains=rows)))
        assert fig is not None
        boxes = _rows(fig.content)
        words = [(a, unescape(b)) for a, b in _TEXT.findall(fig.content)][1::2]
        assert len(words) == len(boxes)
        for (attrs, word), (bx, _by, bw) in zip(words, boxes, strict=True):
            assert _number(attrs, "x") + _SOURCE_WORD_10[word] <= bx + bw, word

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


class TestAnAddressWithAPortReadsAsOneAddress:
    @pytest.mark.parametrize(
        ("address", "port", "label"),
        [
            ("203.0.113.7", 443, "203[.]0[.]113[.]7:443"),
            ("2001:db8::1", None, "2001[:]db8::1"),
            ("2001:db8::1", 443, "[2001[:]db8::1]:443"),
            ("fe80::1%eth0", 443, "[fe80[:]:1%eth0]:443"),
            ("::ffff:192.0.2.1", 8080, "[[:]:ffff:192.0.2.1]:8080"),
            # Written in brackets already: the pair is kept and not doubled.
            # The inner "[:]" of "::1" is the defang of its first colon.
            ("[2001:db8::1]", 443, "[2001[:]db8::1]:443"),
            ("[::1]", 443, "[[:]:1]:443"),
        ],
    )
    def test_an_address_holding_a_colon_is_bracketed_before_its_port(
        self, address: str, port: int | None, label: str
    ) -> None:
        fig = build_network_graph(
            _report(network=NetworkIOCs(ips=[NetworkIP(address=address, port=port)]))
        )
        assert fig is not None
        assert _texts(fig.content)[0] == label


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

    def test_an_injecting_process_past_the_drawn_rows_prints_no_key_and_is_counted(
        self,
    ) -> None:
        drawn = [ProcessNode(pid=n, name=f"p{n}.exe") for n in range(1, 41)]
        past = ProcessNode(pid=99, name="inj.exe", injected_into=[1])
        fig = build_process_tree(_report(dynamic=DynamicBehavior(process_tree=[*drawn, past])))
        assert fig is not None
        assert fig.legend == "1 more processes are not drawn; the JSON report holds all 41."
        assert "#cf222e" not in fig.content
        assert "inj.exe" not in fig.content

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
