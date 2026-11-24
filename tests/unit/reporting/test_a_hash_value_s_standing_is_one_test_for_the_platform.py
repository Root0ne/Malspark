"""A hash value's standing by its answer's own figures is one test for the whole platform.

``code_constants.hash_standing`` gives each value an answer of the ``api_hash_resolution``
kind matched its chance by the declared figures (candidates tested, names tried,
algorithms tried) and whether it is held: under the bound; with no candidates or no names
stated, a second value under its algorithm; chance 1 where a figure is too large to
compute with. A drafted YARA rule (``held``), the triage pack's hand-off of names to the
API catalogue and the report's count of names resolved at runtime all read it, and no
other module computes a chance (T-850).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from malspark.reporting.code_constants import (
    CHANCE_BOUND,
    answer_standing,
    chance_of_matches,
    code_constants_from_ledger,
    hash_standing,
    held,
)
from malspark.reporting.ledger_projection import static_from_ledger
from malspark.reporting.models import StaticAnalysis
from malspark.schemas.evidence import LedgerEntry
from malspark.tools import knowledge

SRC = Path(__file__).resolve().parents[3] / "src"

# Synthetic values and names; no stored run holds them.
AT_CHANCE_VALUES = ("0x4d2c9e71", "0x7a61b3c5", "0x2e9f58d3")
# Six values under one algorithm: a count even the wide scan's figures hold.
HELD_VALUES = ("0x6b3d1f87", "0x58c2a94e", "0x39e7c4b2", "0x1fa8d63c", "0x83b5e2d9", "0x92d4f1a6")
AT_CHANCE_NAMES = ("ProbeAlphaW", "ProbeBetaA", "ProbeGammaEx")
HELD_NAMES = (
    "ProbeDeltaW",
    "ProbeEpsilonA",
    "ProbeEtaW",
    "ProbeThetaA",
    "ProbeIotaEx",
    "ProbeKappaW",
)
# A scan whose matches chance explains (a mean near one match per algorithm) and one it
# does not.
WIDE = {"scanned": 257_331, "names": 11_629, "algorithms": 8}
NARROW = {"scanned": 1_303, "names": 11_629, "algorithms": 8}
# The one name an import table holds, and a technique id no catalogue rule names.
IMPORTED = "ProbeOmegaW"
PROBE_TECHNIQUE = "T1999"


def _resolver(
    rows: list[tuple[str, str, str]],
    figures: dict[str, int] | None = None,
    entry: str = "ev_0031",
    **fields: Any,
) -> LedgerEntry:
    """An answer of the built-in resolver's shape: each row a value, its algorithm and name."""
    hits = [
        {
            "value": value,
            "readings": [{"algorithm": algorithm, "set": "exports", "name": name}],
            "occurrences": [{"offset": hex(0x7100 + 0x18 * n)}],
        }
        for n, (value, algorithm, name) in enumerate(rows)
    ]
    structured: dict[str, Any] = {"tool": "resolve_api_hashes", "hits": hits}
    if figures is not None:
        structured["candidates"] = {"scanned": figures["scanned"]}
        structured["names"] = {"dlls": 21, "names": figures["names"], "modules": 90}
        structured["algorithms"] = [f"scheme{n}" for n in range(figures["algorithms"])]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="resolve_api_hashes",
        args={"path": "probe.exe"},
        structured=structured,
        **fields,
    )


def _mixed(figures: dict[str, int] | None = WIDE) -> LedgerEntry:
    """Three values under one algorithm at chance, and six under another the wide scan holds."""
    rows = [(v, "schemeA", n) for v, n in zip(AT_CHANCE_VALUES, AT_CHANCE_NAMES, strict=True)]
    rows += [(v, "schemeB", n) for v, n in zip(HELD_VALUES, HELD_NAMES, strict=True)]
    return _resolver(rows, figures)


class TestTheStandingOfEachValue:
    def test_a_count_chance_explains_is_not_held_and_one_it_does_not_is(self) -> None:
        rows = [(v, "schemeA", n) for v, n in zip(AT_CHANCE_VALUES, AT_CHANCE_NAMES, strict=True)]
        wide = hash_standing(_resolver(rows, WIDE))
        narrow = hash_standing(_resolver(rows, NARROW))
        assert wide is not None and narrow is not None

        expected = chance_of_matches(3, WIDE["scanned"], WIDE["names"], WIDE["algorithms"])
        assert expected >= CHANCE_BOUND
        for value in AT_CHANCE_VALUES:
            stood = wide.of(value)
            assert stood is not None and not stood.held
            assert stood.chance == pytest.approx(expected)
            assert narrow.holds(value)
        assert wide.matched == {"schemeA": 3}
        assert wide.algorithms["schemeA"].held is False

    def test_each_algorithm_is_counted_on_its_own_and_a_value_takes_its_best(self) -> None:
        # Two values under an algorithm the narrow scan holds; one more value is under it
        # and under a second algorithm alone.
        rows = [(HELD_VALUES[0], "schemeB", HELD_NAMES[0]), (HELD_VALUES[1], "schemeB", "x")]
        entry = _resolver(rows, NARROW)
        assert isinstance(entry.structured, dict)
        entry.structured["hits"].append(
            {
                "value": AT_CHANCE_VALUES[0],
                "readings": [
                    {"algorithm": "schemeB", "set": "exports", "name": "y"},
                    {"algorithm": "schemeC", "set": "exports", "name": "z"},
                ],
            }
        )
        standing = hash_standing(entry)
        assert standing is not None

        assert standing.matched == {"schemeB": 3, "schemeC": 1}
        assert standing.holds(AT_CHANCE_VALUES[0]), "held under its best algorithm"
        stood = standing.of(AT_CHANCE_VALUES[0])
        assert stood is not None and stood.chance == standing.algorithms["schemeB"].chance

    def test_an_answer_with_no_figures_keeps_the_test_of_two_under_one_algorithm(self) -> None:
        rows = [(v, "schemeB", n) for v, n in zip(HELD_VALUES, HELD_NAMES, strict=True)]
        rows.append((AT_CHANCE_VALUES[0], "schemeA", AT_CHANCE_NAMES[0]))
        standing = hash_standing(_resolver(rows))
        assert standing is not None

        assert all(standing.holds(v) for v in HELD_VALUES)
        assert not standing.holds(AT_CHANCE_VALUES[0])
        assert {s.chance for s in standing.values.values()} == {None}

    def test_a_figure_too_large_to_compute_with_gives_chance_one(self) -> None:
        entry = _mixed(NARROW)
        assert isinstance(entry.structured, dict)
        entry.structured["candidates"]["scanned"] = "9" * 450
        standing = hash_standing(entry)
        assert standing is not None

        assert {s.chance for s in standing.values.values()} == {1.0}
        assert not any(s.held for s in standing.values.values())

    def test_an_undeclared_tool_of_the_kind_gets_the_same_test(self) -> None:
        # An operator's server declares the kind and nothing else: read at the kind's
        # places, whatever the tool is called.
        entry = _mixed()
        entry.tool = "acme_hashes"
        entry.source = "mcp:acme"
        entry.facts = {"v": 1, "kind": "api_hash_resolution", "display_name": "acme"}
        standing = hash_standing(entry)
        builtin = hash_standing(_mixed())

        assert standing == builtin

    def test_declared_figures_are_read_where_the_declaration_points(self) -> None:
        entry = _mixed(None)
        assert isinstance(entry.structured, dict)
        entry.structured["scan"] = {"tested": WIDE["scanned"], "dictionary": WIDE["names"]}
        entry.source = "mcp:acme"
        entry.facts = {
            "v": 1,
            "kind": "api_hash_resolution",
            "rows": "/hits/*",
            "values": {"candidates_tested": "/scan/tested", "names_tried": "/scan/dictionary"},
        }
        standing = hash_standing(entry)
        assert standing is not None

        stood = standing.of(AT_CHANCE_VALUES[0])
        # No algorithms tried stated: the two its rows state.
        assert stood is not None
        assert stood.chance == pytest.approx(
            chance_of_matches(3, WIDE["scanned"], WIDE["names"], 2)
        )

    def test_an_answer_of_no_kind_a_failed_call_or_an_error_has_no_standing(self) -> None:
        other = LedgerEntry(id="ev_0002", tool="strings", structured={"hits": []})
        failed = _mixed()
        failed.ok = False
        broken = _mixed()
        assert isinstance(broken.structured, dict)
        broken.structured["error"] = "no image"

        assert hash_standing(other) is None
        assert hash_standing(failed) is None
        assert hash_standing(broken) is None

    def test_an_answer_rendered_alone_is_read_at_the_resolver_s_places(self) -> None:
        entry = _mixed()
        assert isinstance(entry.structured, dict)
        assert answer_standing(entry.structured) == hash_standing(entry)


class TestEveryReaderAsksIt:
    def test_the_draft_holds_a_value_on_the_same_chance(self) -> None:
        for figures in (WIDE, NARROW, None):
            entry = _mixed(figures)
            standing = hash_standing(entry)
            assert standing is not None
            for constant in code_constants_from_ledger([entry]):
                stood = standing.of(constant.value)
                assert stood is not None
                assert constant.chance == stood.chance
                assert held(constant) is stood.held

    def test_the_report_counts_only_held_names_as_resolved_at_runtime(self) -> None:
        names = [*AT_CHANCE_NAMES, *HELD_NAMES]
        ledger = [
            LedgerEntry(id="ev_0001", agent="static", tool="pe_info", structured={"imports": []}),
            _mixed(),
            # An agent's own lookup of names of its choosing, passed as plain names.
            LedgerEntry(
                id="ev_0040",
                agent="static",
                tool="api_capability",
                structured=knowledge.api_capability(names),
            ),
        ]
        from malspark.reporting.ledger_projection import _names_resolved_at_runtime

        static = static_from_ledger(ledger)
        assert static is not None
        assert _names_resolved_at_runtime(ledger, static) == set(HELD_NAMES)

    def test_a_value_held_under_one_algorithm_carries_no_name_another_reads_at_chance(
        self,
    ) -> None:
        # The first held value is also read under a second algorithm, which matches it
        # alone: each algorithm keeps its own names.
        entry = _resolver(
            [(v, "schemeB", n) for v, n in zip(HELD_VALUES, HELD_NAMES, strict=True)], WIDE
        )
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"algorithm": "schemeC", "set": "exports", "name": AT_CHANCE_NAMES[0]}
        )
        standing = hash_standing(entry)
        assert standing is not None
        from malspark.reporting.ledger_projection import _names_resolved_at_runtime

        assert _names_resolved_at_runtime([entry], StaticAnalysis()) == set(HELD_NAMES)
        assert standing.holds(HELD_VALUES[0])
        assert standing.reads(HELD_VALUES[0], "schemeB")
        assert not standing.reads(HELD_VALUES[0], "schemeC")

    def test_no_other_module_computes_a_chance_or_a_matched_count(self) -> None:
        # The chance's formula and the figures it is computed on are read in one module;
        # the declarations only name where a tool states them.
        home = SRC / "malspark" / "reporting" / "code_constants.py"
        pattern = re.compile(r"chance_of_matches\(|_Figures\(|lgamma|_standing\(rows")
        computing = [
            str(path.relative_to(SRC))
            for path in SRC.rglob("*.py")
            if path != home and pattern.search(path.read_text(encoding="utf-8"))
        ]
        assert computing == []


def _catalogue(names: list[str], resolved: list[str] | None = None) -> LedgerEntry:
    """An agent's own catalogue answer: each name under one category and one rule of two."""
    rule = {
        "technique_id": PROBE_TECHNIQUE,
        "name": "Probe technique",
        "rule": "probe rule",
        "matched": names,
        "min_apis": 2,
    }
    return LedgerEntry(
        id="ev_0040",
        agent="static",
        tool="api_capability",
        args={"api_names": names, "resolved_names": resolved or []},
        structured={
            "capabilities": [
                {"api": name, "category": "probe_reach", "techniques": [rule]} for name in names
            ],
            "platform": "windows",
            "resolved_at_runtime_from_hashes": resolved or [],
        },
    )


def _imports(*names: str, delayed: tuple[str, ...] = ()) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        agent="static",
        tool="pe_info",
        structured={
            "imports": [{"dll": "probe.dll", "function": n} for n in names],
            "delay_imports": [{"dll": "probe.dll", "function": n} for n in delayed],
        },
    )


class TestANameReadOnlyAtChance:
    """A name read only under values not held, which the import table lacks (finding 1)."""

    def _static(self, catalogue: LedgerEntry) -> StaticAnalysis:
        rows = [(v, "schemeA", n) for v, n in zip(AT_CHANCE_VALUES, AT_CHANCE_NAMES, strict=True)]
        static = static_from_ledger([_imports(IMPORTED), _resolver(rows, WIDE), catalogue])
        assert static is not None
        return static

    def test_asked_about_as_a_plain_name_it_is_counted_in_neither_profile(self) -> None:
        static = self._static(_catalogue(list(AT_CHANCE_NAMES)))

        assert static.api_capabilities == {}
        assert static.api_capabilities_resolved == {}
        assert static.api_capabilities_evidence_ids == []
        assert static.api_capabilities_resolved_evidence_ids == []
        # Its rule hit is not read as a match on imports.
        assert [h for h in static.api_technique_hits if h.get("technique_id")] == []

    def test_a_rule_two_imports_clear_stands_without_the_name_read_at_chance(self) -> None:
        rows = [(AT_CHANCE_VALUES[0], "schemeA", AT_CHANCE_NAMES[0])]
        second = "ProbeSigmaW"
        asked = [IMPORTED, second, AT_CHANCE_NAMES[0]]
        static = static_from_ledger(
            [_imports(IMPORTED, second), _resolver(rows, WIDE), _catalogue(asked)]
        )
        assert static is not None

        # The rule's floor is two names: the two imports clear it, and the row
        # names them alone, as a match on imports.
        [hit] = [h for h in static.api_technique_hits if h.get("technique_id")]
        assert hit["technique_id"] == PROBE_TECHNIQUE
        assert hit["matched_apis"] == [IMPORTED, second]
        assert "resolved_apis" not in hit
        assert static.api_capabilities == {"probe_reach": 2}
        assert static.api_capabilities_resolved == {}

    def test_a_rule_one_import_does_not_clear_is_not_read_with_the_name_read_at_chance(
        self,
    ) -> None:
        rows = [(AT_CHANCE_VALUES[0], "schemeA", AT_CHANCE_NAMES[0])]
        static = static_from_ledger(
            [
                _imports(IMPORTED),
                _resolver(rows, WIDE),
                _catalogue([IMPORTED, AT_CHANCE_NAMES[0]]),
            ]
        )
        assert static is not None

        assert [h for h in static.api_technique_hits if h.get("technique_id")] == []
        assert static.api_capabilities == {"probe_reach": 1}

    def test_a_delay_import_read_at_chance_is_still_an_import(self) -> None:
        rows = [(AT_CHANCE_VALUES[0], "schemeA", AT_CHANCE_NAMES[0])]
        asked = [IMPORTED, AT_CHANCE_NAMES[0]]
        static = static_from_ledger(
            [
                _imports(IMPORTED, delayed=(AT_CHANCE_NAMES[0],)),
                _resolver(rows, WIDE),
                _catalogue(asked),
            ]
        )
        assert static is not None

        assert static.api_capabilities == {"probe_reach": 2}
        assert static.api_capabilities_resolved == {}
        [hit] = [h for h in static.api_technique_hits if h.get("technique_id")]
        assert hit["matched_apis"] == asked

    def test_an_imported_name_beside_it_is_still_an_import(self) -> None:
        static = self._static(_catalogue([*AT_CHANCE_NAMES, IMPORTED]))

        assert static.api_capabilities == {"probe_reach": 1}
        assert static.api_capabilities_resolved == {}
        assert static.api_capabilities_evidence_ids == ["ev_0040"]

    def test_a_name_the_caller_says_it_resolved_is_counted_as_its_answer_marks_it(self) -> None:
        names = list(AT_CHANCE_NAMES)
        static = self._static(_catalogue(names, resolved=names))

        assert static.api_capabilities == {}
        assert static.api_capabilities_resolved == {"probe_reach": 3}
