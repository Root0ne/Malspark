"""The tactic order a figure calls "ATT&CK order" is read from the vendored catalogue.

The ATT&CK update script writes each tactic's column position from the
bundle's own matrix; the chain and the matrix place a tactic only by that
position, under the platform's pinned name. A tactic the catalogue gives no
position is never placed: it is counted as not drawn.
"""

from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path
from typing import Any

import pytest

from malspark.extractors import capability_matrix
from malspark.extractors.capability_matrix import tactic_order
from malspark.memory import attck_loader
from malspark.reporting import figures
from malspark.reporting.figures import build_attack_matrix, build_infection_chain
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity, TTPMapping

_TEXT = re.compile(r"<text\b([^>]*)>(.*?)</text>", re.S)
# Each enterprise tactic name's width in px at 11 px, bold (the matrix header)
# and normal (the chain box), measured from the font files of DejaVu Sans and
# DejaVu Sans Bold, the only font the backend image installs, with PIL's
# ``ImageFont.getlength``.
_BOLD_11 = {
    "Reconnaissance": 99.2,
    "Resource Development": 143.5,
    "Initial Access": 81.8,
    "Execution": 60.8,
    "Persistence": 72.3,
    "Privilege Escalation": 122.2,
    "Defense Evasion": 102.3,
    "Defense Impairment": 126.5,
    "Credential Access": 110.2,
    "Discovery": 60.7,
    "Lateral Movement": 112.8,
    "Collection": 61.6,
    "Command and Control": 138.0,
    "Exfiltration": 69.1,
    "Impact": 42.6,
}
_NORMAL_11 = {
    "Reconnaissance": 88.4,
    "Resource Development": 128.0,
    "Initial Access": 71.6,
    "Execution": 54.0,
    "Persistence": 62.9,
    "Privilege Escalation": 107.0,
    "Defense Evasion": 91.5,
    "Defense Impairment": 112.7,
    "Credential Access": 97.8,
    "Discovery": 54.4,
    "Lateral Movement": 100.0,
    "Collection": 54.4,
    "Command and Control": 124.0,
    "Exfiltration": 60.1,
    "Impact": 38.0,
}
# A box keeps as much room right of its text as left of it.
_PAD = 8
_VENDORED = Path(attck_loader.TECHNIQUES_FILE)


def _report(*tactics: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        ttp_mappings=[
            TTPMapping(technique_id=f"T{1000 + n}", technique_name=f"t{n}", tactic=tactic)
            for n, tactic in enumerate(tactics)
        ],
    )


def _texts(svg: str) -> list[str]:
    return [unescape(body) for _attrs, body in _TEXT.findall(svg)]


def _vendored_positions(domain: str) -> dict[str, int]:
    raw: dict[str, Any] = json.loads(_VENDORED.read_text(encoding="utf-8"))
    return {
        row["id"]: row["position"]
        for row in raw["_tactics"][domain].values()
        if isinstance(row.get("position"), int)
    }


class TestTheCatalogueCarriesTheOrder:
    def test_every_enterprise_tactic_the_catalogue_lists_has_a_position(self) -> None:
        raw = json.loads(_VENDORED.read_text(encoding="utf-8"))
        rows = raw["_tactics"]["enterprise"]
        assert rows
        assert all(isinstance(row.get("position"), int) for row in rows.values())

    def test_the_fallback_table_and_the_catalogue_order_the_tactics_alike(self) -> None:
        fallback: list[str] = []
        for tid, _slug, _name in capability_matrix._TACTIC_TABLE:
            if tid not in fallback:
                fallback.append(tid)
        positions = _vendored_positions("enterprise")
        assert sorted(positions, key=lambda tid: positions[tid]) == fallback

    def test_the_loader_reads_the_position_of_each_column(self) -> None:
        attck_loader.reset_caches()
        stealth = attck_loader.tactic_entry("enterprise", "stealth")
        assert stealth is not None
        assert stealth.position == _vendored_positions("enterprise")["TA0005"]


class TestTheAccessor:
    def test_it_follows_the_vendored_positions_under_the_pinned_names(self) -> None:
        order = tactic_order()
        positions = _vendored_positions("enterprise")
        assert [tid for tid, _name in order] == sorted(positions, key=lambda t: positions[t])
        names = dict(order)
        assert names["TA0005"] == "Defense Evasion"
        assert names["TA0004"] == "Privilege Escalation"
        assert names["TA0011"] == "Command and Control"

    def test_it_returns_a_new_tuple_each_time(self) -> None:
        first, second = tactic_order(), tactic_order()
        assert isinstance(first, tuple) and first == second and first is not second

    def test_a_domain_without_positions_has_no_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        unplaced = attck_loader.VendoredTactic(tactic_id="TA0001", shortname="x", name="X")
        monkeypatch.setattr(
            attck_loader, "_technique_table", lambda: ({}, {"enterprise": {"x": unplaced}})
        )
        assert tactic_order() == ()


class TestTheFiguresPlaceATacticByItsPosition:
    def test_chain_and_matrix_follow_the_accessor_for_mappings_in_any_order(self) -> None:
        report = _report("TA0040", "TA0006", "TA0112", "TA0005", "TA0043", "TA0011", "TA0004")
        expected = [
            name for tid, name in tactic_order() if tid in {m.tactic for m in report.ttp_mappings}
        ]
        chain = build_infection_chain(report)
        matrix = build_attack_matrix(report)
        assert chain is not None and matrix is not None
        assert _texts(chain.content) == expected
        headers = [t for t in _texts(matrix.content) if not t.startswith("T1")]
        assert headers == expected

    def test_defense_impairment_lands_between_its_neighbours_and_reconnaissance_leads(
        self,
    ) -> None:
        chain = build_infection_chain(_report("TA0006", "TA0112", "TA0005", "TA0043"))
        assert chain is not None
        assert _texts(chain.content) == [
            "Reconnaissance",
            "Defense Evasion",
            "Defense Impairment",
            "Credential Access",
        ]

    @pytest.mark.parametrize("outside", ["TA9999", "TA0027"])
    def test_a_tactic_without_a_position_is_in_no_box_and_is_counted(self, outside: str) -> None:
        chain = build_infection_chain(_report("TA0002", "TA0011", outside))
        matrix = build_attack_matrix(_report("TA0002", outside))
        assert chain is not None and chain.legend is not None
        assert matrix is not None and matrix.legend is not None
        assert len(_texts(chain.content)) == 2
        assert "1 more tactics are not drawn" in chain.legend
        assert "1 more techniques are not drawn" in matrix.legend

    def test_mapped_tactics_all_outside_the_order_draw_nothing_and_say_nothing(self) -> None:
        report = _report("TA9999", "TA0027", "TA0100")
        assert build_infection_chain(report) is None
        assert build_attack_matrix(report) is None
        assert figures.build_figures(report) == []

    def test_the_figure_code_names_no_tactic_id(self) -> None:
        source = Path(figures.__file__).read_text(encoding="utf-8")
        assert "TA0" not in source

    def test_every_listed_name_fits_the_chain_box_and_the_matrix_header(self) -> None:
        every = [tid for tid, _name in tactic_order()]
        chain = build_infection_chain(_report(*every))
        matrix = build_attack_matrix(_report(*every))
        assert chain is not None and matrix is not None
        for fig in (chain, matrix):
            boxes = [
                (int(x), int(w))
                for x, w in re.findall(
                    r'<rect x="(\d+)" y="\d+" width="(\d+)" height="(?:34|40)"', fig.content
                )
            ]
            headers = [
                (attrs, body)
                for attrs, body in _TEXT.findall(fig.content)
                if not unescape(body).startswith("T1")
            ]
            assert len(boxes) == len(headers) == len(every)
            for (bx, bw), (attrs, body) in zip(boxes, headers, strict=True):
                x = float(re.search(r'\bx="(\d+)"', attrs).group(1))  # type: ignore[union-attr]
                drawn = _BOLD_11 if 'font-weight="bold"' in attrs else _NORMAL_11
                assert x + drawn[unescape(body)] + _PAD <= bx + bw, body

    def test_a_reckoned_width_is_never_below_the_measured_one(self) -> None:
        for name, width in _BOLD_11.items():
            assert figures._label_width(name, 11, "bold") >= width, name
        for name, width in _NORMAL_11.items():
            assert figures._label_width(name, 11) >= width, name
