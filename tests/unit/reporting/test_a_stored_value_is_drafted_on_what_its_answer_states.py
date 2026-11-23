"""A stored value's meaning says what its tool reported; a draft holds it on its answer's figures.

The meaning of a value the sample stores (``reporting.code_constants``) and the comment a
drafted YARA rule writes beside it are in the reader's voice, from the answer's own fields:
the tool's stated name, the algorithm, the names, the set words, how many values the tool
matched under that algorithm, how many results state a seed. They never say a value is a
name hash or a seed (T-872).

A draft holds a value only on what its answer states (``detection_signatures.stored_selection``):

* a seed only where two or more results of its answer state it;
* a hash only where the chance of its algorithm's count of matched values arising by chance,
  over the algorithms tried, is under the bound, by the answer's own figures of candidates
  tested and names tried (declared values of the kind, with built-in defaults); an answer
  that states neither keeps the test of two values under one algorithm;
* a draft that leaves a value out says so in its closing comment, with the test it failed,
  and the rest of the rule is written as before.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Any

import pytest

from malspark.core.declared_reading import facts_record
from malspark.reporting import detection_signatures as drafts
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.code_constants import (
    CHANCE_BOUND,
    LEAST_RESULTS_PER_SEED,
    chance_of_matches,
    code_constants_from_ledger,
    held,
)
from malspark.reporting.detection_signatures import build_detection_rules, stored_selection
from malspark.reporting.follow_up import stored_ledger
from malspark.reporting.models import (
    DetectionRule,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST
from malspark.schemas.evidence import LedgerEntry
from tests.unit.reporting._report_inventory import stored_runs

needs_engine = pytest.mark.skipif(not drafts._YARA_AVAILABLE, reason="yara-python is not installed")

SEED = "0x5b1e0c37"
HASHES = ("0x3c71a2e9", "0x9d4be058", "0x61f3c7a4")
# The figures of a scan whose matches chance explains, and of one it does not.
AT_CHANCE = {"scanned": 250_000, "names": 12_000, "algorithms": 10}
ESTABLISHED = {"scanned": 1_500, "names": 12_000, "algorithms": 10}


def _decoder(*seeds: Any, entry: str = "ev_0021", schemes: bool = True) -> LedgerEntry:
    rows = [
        {
            "text": f"text {n}",
            "offset": hex(0xCE00 + 0x40 * n),
            **({"scheme": "xor8_rolling_header"} if schemes else {}),
            "parameters": {"seed": seed},
        }
        for n, seed in enumerate(seeds)
    ]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="decode_string_blobs",
        args={"path": "sample.exe"},
        structured={"tool": "decode_string_blobs", "results": rows},
    )


def _resolver(
    *values: str,
    names: tuple[str, ...] = ("InternetOpenW",),
    algorithms: tuple[str, ...] | None = None,
    figures: dict[str, int] | None = None,
    entry: str = "ev_0020",
    **fields: Any,
) -> LedgerEntry:
    hits = [
        {
            "value": value,
            "readings": [
                {"set": "exports", "name": name, "algorithm": algorithm}
                for name in names
                for algorithm in ([algorithms[n]] if algorithms else ["crc32_ascii"])
            ],
            "occurrences": [{"offset": hex(0x8400 + 0x20 * n), "section": ".text"}],
        }
        for n, value in enumerate(values)
    ]
    structured: dict[str, Any] = {"tool": "resolve_api_hashes", "hits": hits}
    if figures is not None:
        structured["candidates"] = {"scanned": figures["scanned"], "how": "heuristic"}
        structured["names"] = {"dlls": 27, "names": figures["names"], "modules": 108}
        structured["algorithms"] = [f"algorithm{n}" for n in range(figures["algorithms"])]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="resolve_api_hashes",
        args={"path": "sample.exe"},
        structured=structured,
        **fields,
    )


def _report(*constants_from: LedgerEntry, strings: bool = True) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict="Malware",
        malware_category="loader",
        generated_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn="gate9.example.org", source="sandbox"),
                NetworkDomain(fqdn="relay4.example.net", source="sandbox"),
            ]
            if strings
            else []
        ),
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    report.code_constants = code_constants_from_ledger(list(constants_from))
    return report


def _yara(report: MalwareReport) -> DetectionRule:
    return next(rule for rule in build_detection_rules(report, None) if rule.kind == "yara")


def _drafted(report: MalwareReport) -> list[str]:
    return [item.value for item, _raw in stored_selection(report).used]


class TestTheMeaningSaysWhatTheToolReported:
    def test_a_seed_one_result_states(self) -> None:
        (seed,) = code_constants_from_ledger([_decoder(SEED)])

        assert seed.meaning == (
            "decode_string_blobs read it as the seed in the header of 1 encoded string it "
            "decoded (xor8_rolling_header)"
        )

    def test_a_seed_many_results_state(self) -> None:
        (seed,) = code_constants_from_ledger([_decoder(SEED, SEED, SEED)])

        assert seed.meaning == (
            "decode_string_blobs read it as the seed in the header of 3 encoded strings it "
            "decoded (xor8_rolling_header)"
        )

    def test_a_seed_whose_results_state_no_scheme_names_none(self) -> None:
        (seed,) = code_constants_from_ledger([_decoder(SEED, SEED, schemes=False)])

        assert seed.meaning == (
            "decode_string_blobs read it as the seed in the header of 2 encoded strings it decoded"
        )

    def test_a_hash_under_one_algorithm(self) -> None:
        constants = code_constants_from_ledger([_resolver(*HASHES)])

        assert constants[0].meaning == (
            "resolve_api_hashes read it as the crc32_ascii hash of InternetOpenW (set exports), "
            "one of 3 values it matched under that algorithm"
        )

    def test_a_hash_under_several_algorithms_says_each_count(self) -> None:
        entry = _resolver(*HASHES, "0x5a17c0de", algorithms=("crc32_ascii",) * 3 + ("ror13",))
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"set": "exports", "name": "InternetOpenW", "algorithm": "ror13"}
        )

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as the crc32_ascii hash of InternetOpenW (set exports), "
            "one of 3 values it matched under that algorithm, and as the ror13 hash of "
            "InternetOpenW (set exports), one of 2 values it matched under that algorithm"
        )

    def test_each_algorithm_keeps_its_own_names_and_sets(self) -> None:
        entry = _resolver(*HASHES, "0x5a17c0de", algorithms=("crc32_ascii",) * 3 + ("ror13",))
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"set": "modules", "name": "WININET.DLL", "algorithm": "ror13"}
        )

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as the crc32_ascii hash of InternetOpenW (set exports), "
            "one of 3 values it matched under that algorithm, and as the ror13 hash of "
            "WININET.DLL (set modules), one of 2 values it matched under that algorithm"
        )

    def test_a_name_stated_under_no_algorithm_is_said_as_such(self) -> None:
        entry = _resolver(*HASHES, "0x5a17c0de", algorithms=("crc32_ascii",) * 3 + ("ror13",))
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"] += [
            {"set": "modules", "name": "WININET.DLL", "algorithm": "ror13"},
            {"set": "exports", "name": "HttpOpenRequestW"},
        ]

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning.endswith(
            "and as the ror13 hash of WININET.DLL (set modules), one of 2 values it matched "
            "under that algorithm, and as a hash of HttpOpenRequestW (set exports) with no "
            "algorithm stated"
        )

    def test_readings_that_cannot_be_told_apart_say_the_names_once_for_all(self) -> None:
        # The names are declared outside the readings the algorithms are read in: the row
        # does not say which name went with which algorithm, and the meaning does not either.
        entry = _resolver(*HASHES, "0x5a17c0de", algorithms=("crc32_ascii",) * 3 + ("ror13",))
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"set": "exports", "name": "InternetOpenW", "algorithm": "ror13"}
        )
        for hit in entry.structured["hits"]:
            hit["names"] = ["InternetOpenW", "WININET.DLL"]
        entry.facts = {
            "v": 1,
            "kind": "api_hash_resolution",
            "rows": "/hits/*",
            "values": {"name": "/names/*"},
        }

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as a hash of InternetOpenW, WININET.DLL (set exports) "
            "under crc32_ascii (one of 3 values it matched under it) and ror13 (one of 2 values "
            "it matched under it)"
        )

    def test_a_value_alone_under_one_of_its_algorithms_is_said_to_be_the_only_one(self) -> None:
        entry = _resolver(*HASHES)
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"set": "exports", "name": "InternetOpenW", "algorithm": "djb2"}
        )

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning.endswith(
            "one of 3 values it matched under that algorithm, and as the djb2 hash of "
            "InternetOpenW (set exports), the only value it matched under that algorithm"
        )

    def test_more_algorithms_than_said_are_counted(self) -> None:
        entry = _resolver(*HASHES)
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"] = [
            {"set": "exports", "name": "InternetOpenW", "algorithm": f"a{n}"} for n in range(5)
        ]
        entry.structured["hits"][1]["readings"][0]["algorithm"] = "a0"

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning.endswith(
            "and as the a2 hash of InternetOpenW (set exports), the only value it matched "
            "under that algorithm, and under 2 more algorithms"
        )
        assert meaning.startswith(
            "resolve_api_hashes read it as the a0 hash of InternetOpenW (set exports), one of "
            "2 values it matched under that algorithm, and as the a1 hash"
        )

    def test_several_names_are_listed_and_the_rest_counted(self) -> None:
        names = ("A1", "B2", "C3", "D4", "E5")
        meaning = code_constants_from_ledger([_resolver(*HASHES[:2], names=names)])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as the crc32_ascii hash of A1, B2, C3 and 2 more "
            "(set exports), one of 2 values it matched under that algorithm"
        )

    def test_no_set_word_prints_no_set(self) -> None:
        entry = _resolver(*HASHES[:2])
        assert isinstance(entry.structured, dict)
        for hit in entry.structured["hits"]:
            for reading in hit["readings"]:
                reading.pop("set")

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as the crc32_ascii hash of InternetOpenW, one of 2 "
            "values it matched under that algorithm"
        )

    def test_no_name_stated_is_said(self) -> None:
        meaning = code_constants_from_ledger([_resolver(*HASHES[:2], names=("",))])[0].meaning

        assert meaning == (
            "resolve_api_hashes read it as a crc32_ascii hash with no name stated (set exports), "
            "one of 2 values it matched under that algorithm"
        )

    def test_a_missing_figure_changes_no_word(self) -> None:
        bare = code_constants_from_ledger([_resolver(*HASHES)])
        stated = code_constants_from_ledger([_resolver(*HASHES, figures=ESTABLISHED)])

        assert [c.meaning for c in bare] == [c.meaning for c in stated]

    def test_the_count_is_of_every_value_matched_under_the_algorithm(self) -> None:
        # A plain value is matched and counted, though it is not read itself.
        meaning = code_constants_from_ledger([_resolver(*HASHES[:2], "0x00010000")])[0].meaning

        assert meaning.endswith("one of 3 values it matched under that algorithm")

    def test_a_hostile_tool_name_and_algorithm_are_one_clean_capped_word(self) -> None:
        entry = _resolver(
            *HASHES[:2], algorithms=("crc*/\n`|x" + "Z" * 90,) * 2, source="mcp:foreign"
        )
        entry.facts = {"v": 1, "kind": "api_hash_resolution", "display_name": "ev`il|\nt*" * 20}

        meaning = code_constants_from_ledger([entry])[0].meaning

        assert not any(c in meaning for c in "\r\n`|*{}<>")
        assert "Z" * 65 not in meaning and "ev_il_ t_" in meaning

    @pytest.mark.parametrize(
        "entries",
        [
            [_decoder(SEED)],
            [_decoder(SEED, SEED)],
            [_resolver(*HASHES)],
            [_resolver(*HASHES, figures=AT_CHANCE)],
            [_resolver(*HASHES[:2], names=("",))],
        ],
        ids=["seed-once", "seed-twice", "hash", "hash-at-chance", "hash-no-name"],
    )
    def test_no_meaning_says_what_a_value_is(self, entries: list[LedgerEntry]) -> None:
        for constant in code_constants_from_ledger(entries):
            assert " read it as " in constant.meaning
            assert "a name hash" not in constant.meaning
            assert "the decoder seed" not in constant.meaning
            assert not constant.meaning.startswith(("a ", "the "))


class TestASeedIsDraftedWhereTwoResultsStateIt:
    def test_one_result_is_not_drafted(self) -> None:
        report = _report(_decoder(SEED), _resolver(*HASHES))

        assert _drafted(report) == []

    def test_two_results_are_drafted(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES))

        assert _drafted(report) == [SEED, *HASHES]
        assert LEAST_RESULTS_PER_SEED == 2


class TestAHashIsDraftedOnItsAnswersFigures:
    def test_an_answer_at_chance_level_drafts_no_hash(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=AT_CHANCE))

        assert _drafted(report) == []
        assert stored_selection(report).read == 4

    def test_an_established_answer_drafts_its_hashes(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=ESTABLISHED))

        assert _drafted(report) == [SEED, *HASHES]

    def test_an_answer_stating_no_figure_keeps_the_two_values_test(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES))

        assert _drafted(report) == [SEED, *HASHES]

    def test_an_answer_stating_one_figure_only_keeps_the_two_values_test(self) -> None:
        entry = _resolver(*HASHES, figures=AT_CHANCE)
        assert isinstance(entry.structured, dict)
        entry.structured.pop("names")

        assert _drafted(_report(_decoder(SEED, SEED), entry)) == [SEED, *HASHES]

    def test_the_algorithms_its_rows_state_count_when_none_tried_is_stated(self) -> None:
        # One algorithm in the rows: 0.034 by chance, still not under the bound.
        entry = _resolver(*HASHES, figures=AT_CHANCE)
        assert isinstance(entry.structured, dict)
        entry.structured.pop("algorithms")

        assert _drafted(_report(_decoder(SEED, SEED), entry)) == []

    def test_with_none_tried_stated_every_algorithm_its_rows_name_is_counted(self) -> None:
        # Three algorithms in the rows and no count of them stated: the chance is taken over
        # the three, never over fewer than the rows give.
        entry = _resolver(*HASHES, figures=AT_CHANCE, algorithms=("a0", "a0", "a0"))
        assert isinstance(entry.structured, dict)
        entry.structured.pop("algorithms")
        entry.structured["hits"][0]["readings"] += [
            {"set": "exports", "name": "InternetOpenW", "algorithm": "a1"},
            {"set": "exports", "name": "InternetOpenW", "algorithm": "a2"},
        ]
        entry.structured["hits"][1]["readings"] += [
            {"set": "exports", "name": "InternetOpenW", "algorithm": "a1"},
            {"set": "exports", "name": "InternetOpenW", "algorithm": "a2"},
        ]
        scanned, names = AT_CHANCE["scanned"], AT_CHANCE["names"]

        third = code_constants_from_ledger([entry])[2]

        assert third.chance == pytest.approx(chance_of_matches(3, scanned, names, 3))
        assert third.chance != pytest.approx(chance_of_matches(3, scanned, names, 1))

    def test_a_value_under_two_algorithms_is_held_where_one_of_them_holds_it(self) -> None:
        # Under the established figures three values under one algorithm are far under the
        # bound, one value alone under another is not: the value stands on the first.
        entry = _resolver(*HASHES, figures=ESTABLISHED)
        assert isinstance(entry.structured, dict)
        entry.structured["hits"][0]["readings"].append(
            {"set": "exports", "name": "InternetOpenW", "algorithm": "djb2"}
        )
        report = _report(_decoder(SEED, SEED), entry)
        first = report.code_constants[1]
        scanned, names = ESTABLISHED["scanned"], ESTABLISHED["names"]

        assert chance_of_matches(1, scanned, names, 10) >= CHANCE_BOUND
        assert first.chance == pytest.approx(chance_of_matches(3, scanned, names, 10))
        assert _drafted(report) == [SEED, *HASHES]

    @pytest.mark.parametrize(
        "scanned",
        [
            250_000.0,
            "250000",
            " 250000 ",
            "0x3d090",
            "5000000000",
            5_000_000_000.0,
            "0" * 5000 + "250000",
        ],
        ids=[
            "integral-float",
            "decimal-text",
            "padded-text",
            "hex-text",
            "past-32-bits",
            "past-32-bits-float",
            "long-zero-padded-text",
        ],
    )
    def test_a_figure_is_read_as_stated_in_every_plain_number_form(self, scanned: Any) -> None:
        entry = _resolver(*HASHES, figures=AT_CHANCE)
        assert isinstance(entry.structured, dict)
        entry.structured["candidates"]["scanned"] = scanned

        assert _drafted(_report(_decoder(SEED, SEED), entry)) == []

    @pytest.mark.parametrize(
        "scanned",
        [True, -250_000, math.nan, math.inf, 250_000.5, "250k", "2.5e5", "-250000", 0],
        ids=[
            "bool",
            "negative",
            "nan",
            "inf",
            "fraction",
            "word",
            "exponent",
            "negative-text",
            "zero",
        ],
    )
    def test_what_is_no_count_is_not_stated(self, scanned: Any) -> None:
        entry = _resolver(*HASHES, figures=AT_CHANCE)
        assert isinstance(entry.structured, dict)
        entry.structured["candidates"]["scanned"] = scanned

        assert _drafted(_report(_decoder(SEED, SEED), entry)) == [SEED, *HASHES]

    def test_a_pointer_naming_several_numbers_adds_them(self) -> None:
        def scans(*tested: Any) -> LedgerEntry:
            entry = _resolver(*HASHES, figures=AT_CHANCE, source="mcp:acme")
            assert isinstance(entry.structured, dict)
            entry.structured["scans"] = [{"tested": n} for n in tested]
            entry.facts = {
                "v": 1,
                "kind": "api_hash_resolution",
                "rows": "/hits/*",
                "values": {"candidates_tested": "/scans/*/tested"},
            }
            return entry

        half = AT_CHANCE["scanned"] // 2

        assert _drafted(_report(_decoder(SEED, SEED), scans(half, half))) == []
        # One element that is no count leaves the figure not stated.
        assert _drafted(_report(_decoder(SEED, SEED), scans(half, "many"))) == [SEED, *HASHES]

    @pytest.mark.parametrize(
        "scanned",
        [10**400, "9" * 401, "9" * 5000, "0x" + "f" * 5000],
        ids=["int", "decimal-text", "decimal-text-past-conversion", "hex-text"],
    )
    def test_a_figure_too_large_to_compute_with_holds_no_hash(self, scanned: Any) -> None:
        entry = _resolver(*HASHES, figures=AT_CHANCE)
        assert isinstance(entry.structured, dict)
        entry.structured["candidates"]["scanned"] = scanned

        report = _report(_decoder(SEED, SEED), entry)

        assert [c.chance for c in report.code_constants if c.role == "hash"] == [1.0] * 3
        assert _drafted(report) == []

    def test_a_tool_nobody_declared_values_for_is_read_at_the_kind_s_defaults(self) -> None:
        # A server of the operator's declares the kind and nothing else: its answer in the
        # kind's shape is read where the built-in tool keeps rows, values and figures.
        def foreign(figures: dict[str, int]) -> LedgerEntry:
            entry = _resolver(*HASHES, figures=figures, source="mcp:acme")
            entry.facts = {"v": 1, "kind": "api_hash_resolution", "display_name": "acme"}
            return entry

        chance = _report(_decoder(SEED, SEED), foreign(AT_CHANCE))
        established = _report(_decoder(SEED, SEED), foreign(ESTABLISHED))

        assert chance.code_constants[1].meaning.startswith("acme read it as the crc32_ascii")
        assert _drafted(chance) == []
        assert _drafted(established) == [SEED, *HASHES]

    def test_the_figures_are_read_where_a_declaration_points_them(self) -> None:
        entry = _resolver(*HASHES, source="mcp:acme")
        assert isinstance(entry.structured, dict)
        entry.structured["scan"] = {"tested": AT_CHANCE["scanned"], "dictionary": 12_000}
        entry.structured["tried"] = 10
        entry.facts = {
            "v": 1,
            "kind": "api_hash_resolution",
            "rows": "/hits/*",
            "values": {
                "candidates_tested": "/scan/tested",
                "names_tried": "/scan/dictionary",
                "algorithms_tried": "/tried",
            },
        }
        report = _report(_decoder(SEED, SEED), entry)

        assert [c.chance for c in report.code_constants[1:]] == [
            pytest.approx(chance_of_matches(3, AT_CHANCE["scanned"], 12_000, 10))
        ] * 3
        assert _drafted(report) == []

    def test_the_shipped_declaration_points_at_the_resolver_s_figures(self) -> None:
        # The record the triage pack stores for its resolver, from the shipped data.
        record = facts_record("pack", "resolve_api_hashes")
        assert record is not None
        assert {
            key: record["values"][key]
            for key in ("candidates_tested", "names_tried", "algorithms_tried")
        } == {
            "candidates_tested": "/candidates/scanned",
            "names_tried": "/names/names",
            "algorithms_tried": "/algorithms",
        }

        def shipped(figures: dict[str, int]) -> LedgerEntry:
            entry = _resolver(*HASHES, figures=figures, source="pack")
            entry.facts = record
            return entry

        assert _drafted(_report(_decoder(SEED, SEED), shipped(AT_CHANCE))) == []
        assert _drafted(_report(_decoder(SEED, SEED), shipped(ESTABLISHED))) == [SEED, *HASHES]


class TestTheChanceOfMatches:
    def test_known_values(self) -> None:
        # P(X >= 2 | lambda = 1) = 1 - 2/e, one algorithm.
        assert chance_of_matches(2, 1 << 16, 1 << 16, 1) == pytest.approx(1 - 2 / math.e)
        # P(X >= 1 | lambda) = 1 - exp(-lambda).
        lam = 250_000 * 12_000 / 2**32
        assert chance_of_matches(1, 250_000, 12_000, 1) == pytest.approx(1 - math.exp(-lam))
        # Three matches under one of ten algorithms at lambda 0.698: the union bound.
        tail = 1 - math.exp(-lam) * (1 + lam + lam * lam / 2)
        assert chance_of_matches(3, 250_000, 12_000, 10) == pytest.approx(10 * tail)
        assert chance_of_matches(3, 250_000, 12_000, 10) == pytest.approx(0.3396, abs=1e-4)

    def test_a_far_tail_is_not_lost_to_rounding(self) -> None:
        lam = 1_500 * 12_000 / 2**32
        expected = 10 * sum(
            math.exp(-lam + i * math.log(lam) - math.lgamma(i + 1)) for i in range(9, 14)
        )
        held = chance_of_matches(9, 1_500, 12_000, 10)

        assert 0 < held < 1e-25
        assert held == pytest.approx(expected, rel=1e-6)

    def test_bounds(self) -> None:
        assert chance_of_matches(0, 10, 10, 3) == 1.0
        assert chance_of_matches(1, 1 << 20, 1 << 20, 50) == 1.0
        assert chance_of_matches(4, 0, 100, 3) == 0.0

    def test_a_figure_too_large_to_compute_with_gives_one(self) -> None:
        assert chance_of_matches(3, 10**400, 1, 1) == 1.0
        assert chance_of_matches(3, 10**200, 10**200, 1) == 1.0
        assert chance_of_matches(3, 1, 10**400, 1) == 1.0
        assert chance_of_matches(2, 1 << 20, 1 << 10, 10**400) == 1.0

    def test_the_bound_is_one_named_value(self) -> None:
        assert CHANCE_BOUND == 0.001


SEED_HELD_OUT = "1 read as a seed by fewer than 2 results of its answer"
HASHES_HELD_OUT = (
    "3 read as name hashes under an algorithm whose count of matched values their answer's own "
    "figures do not put under a chance of 0.001 (the Poisson tail times the algorithms tried)"
)
HASHES_READ_BACK = (
    "3 read as name hashes and read back from a stored report, which does not keep their "
    "answer's figures"
)


class TestTheClosingCommentSaysWhatWasTested:
    def test_a_draft_holding_none_says_each_test_and_keeps_its_strings(self) -> None:
        bare = _yara(_report()).body
        report = _report(_decoder(SEED), _resolver(*HASHES, figures=AT_CHANCE))
        body = _yara(report).body

        assert "$d" not in body and "$h" not in body
        assert body == bare + (
            f"\n// 4 stored values the run read are not in this draft ({SEED_HELD_OUT}; "
            f"{HASHES_HELD_OUT}); the report's JSON (code_constants) carries every one."
        )

    def test_a_held_seed_with_hashes_at_chance_says_why_the_seed_is_left_too(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=AT_CHANCE))

        assert stored_selection(report).comment() == (
            f"4 stored values the run read are not in this draft ({HASHES_HELD_OUT}; "
            f"{drafts.NO_STORED_GROUP_FEW_HASHES}); the report's JSON (code_constants) carries "
            "every one."
        )

    def test_held_hashes_without_a_held_seed_say_a_hash_alone_is_no_match(self) -> None:
        report = _report(_decoder(SEED), _resolver(*HASHES, figures=ESTABLISHED))

        assert stored_selection(report).comment() == (
            f"4 stored values the run read are not in this draft ({SEED_HELD_OUT}; "
            f"{drafts.NO_STORED_GROUP_NO_HELD_SEED}); the report's JSON (code_constants) "
            "carries every one."
        )

    def test_a_seed_held_out_beside_a_drafted_one_is_counted_with_its_test(self) -> None:
        report = _report(
            _decoder(SEED, SEED), _decoder("0x5a17c0de", entry="ev_0022"), _resolver(*HASHES)
        )
        chosen = stored_selection(report)

        assert [item.value for item, _raw in chosen.used] == [SEED, *HASHES]
        assert chosen.comment() == (
            f"1 stored value the run read is not in this draft ({SEED_HELD_OUT}); the report's "
            "JSON (code_constants) carries every one."
        )

    def test_held_values_past_the_draft_s_room_are_counted_beside_a_test(self) -> None:
        many = [f"0x{0x4A3B2C10 + n * 0x01020305:08x}" for n in range(14)]
        report = _report(
            _decoder(SEED, SEED), _decoder("0x5a17c0de", entry="ev_0022"), _resolver(*many)
        )
        chosen = stored_selection(report)

        assert [item.value for item, _raw in chosen.used] == [SEED, *many[:12]]
        assert chosen.comment() == (
            f"3 stored values the run read are not in this draft ({SEED_HELD_OUT}; 2 past the "
            "draft's room); the report's JSON (code_constants) carries every one."
        )

    def test_the_reason_for_too_few_hashes_names_no_set(self) -> None:
        # The tool read its hashes in a set of module names: the reason names no set.
        entry = _resolver(*HASHES, names=("WININET.DLL",))
        assert isinstance(entry.structured, dict)
        for hit in entry.structured["hits"]:
            for reading in hit["readings"]:
                reading["set"] = "modules"
        report = _report(_decoder(SEED, SEED), entry)
        for constant in report.code_constants[2:]:
            constant.chance = 1.0
        comment = stored_selection(report).comment()

        assert comment.endswith(
            f"{drafts.NO_STORED_GROUP_FEW_HASHES}); the report's JSON (code_constants) carries "
            "every one."
        )
        assert "function" not in comment

    def test_a_draft_holding_every_value_says_nothing(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=ESTABLISHED))

        assert stored_selection(report).left_out == 0
        assert "not in this draft" not in _yara(report).body

    @needs_engine
    def test_a_rule_that_loses_its_stored_group_compiles_and_keeps_its_strings_clause(
        self,
    ) -> None:
        rule = _yara(_report(_decoder(SEED), _resolver(*HASHES, figures=AT_CHANCE)))

        lines = rule.body.splitlines()

        assert rule.compile_error is None
        assert lines[lines.index("    condition:") + 1].endswith(" or (2 of them)")
        assert '$s0 = "gate9.example.org"' in rule.body


class TestAReportReadBackFromStorageDraftsNoHash:
    """A stored report does not keep its answers' figures, so its hashes are not drafted."""

    def test_the_draft_built_in_process_is_unchanged_and_the_loaded_one_says_why(self) -> None:
        report = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=ESTABLISHED))
        dumped = report.model_dump_json()
        loaded = MalwareReport.model_validate_json(dumped)

        assert _drafted(report) == [SEED, *HASHES]
        assert "chance" not in dumped and "built" not in dumped
        assert _drafted(loaded) == []
        assert stored_selection(loaded).comment() == (
            f"4 stored values the run read are not in this draft ({HASHES_READ_BACK}; "
            f"{drafts.NO_STORED_GROUP_FEW_HASHES}); the report's JSON (code_constants) carries "
            "every one."
        )
        body = _yara(loaded).body
        assert "$h" not in body and f"({HASHES_READ_BACK};" in body

    def test_a_hash_read_back_is_counted_apart_from_one_its_figures_do_not_hold(self) -> None:
        report = _report(
            _decoder(SEED, SEED),
            _resolver(*HASHES, figures=AT_CHANCE),
            _resolver("0x5a17c0de", "0x4a3b2c10", figures=ESTABLISHED, entry="ev_0023"),
        )
        for constant in report.code_constants[4:]:
            constant.built = False

        assert stored_selection(report).why == (
            f"{HASHES_HELD_OUT}; 2 read as name hashes and read back from a stored report, "
            f"which does not keep their answer's figures; {drafts.NO_STORED_GROUP_FEW_HASHES}"
        )


class TestTheAnalystLineReadsTheDraftsComment:
    @pytest.mark.parametrize(
        ("rest", "why"),
        [(1, ""), (1, SEED_HELD_OUT), (3, ""), (3, f"{SEED_HELD_OUT}; 2 past the draft's room")],
        ids=["one-no-reason", "one-with-reason", "several-no-reason", "several-with-reasons"],
    )
    def test_every_form_the_writer_gives_is_read_back(self, rest: int, why: str) -> None:
        comment = drafts.StoredSelection((), rest, why).comment()
        rule = DetectionRule(
            kind="yara", name="r", body=f"rule r {{ condition: true }}\n// {comment}"
        )

        assert drafts.stored_left_out(rule) == (rest, why)


class TestTheAnalystReportSaysWhatTheDraftLeftOut:
    def _analyst_line(self, report: MalwareReport) -> str:
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        return next(line for line in analyst.splitlines() if line.startswith("- **YARA**"))

    def test_its_line_carries_the_draft_s_closing_comment(self) -> None:
        report = _report(_decoder(SEED), _resolver(*HASHES, figures=AT_CHANCE))
        report.detection_signatures = [_yara(report)]

        assert self._analyst_line(report).endswith(
            f" 4 stored values the run read are left out of the draft ({SEED_HELD_OUT}; "
            f"{HASHES_HELD_OUT}); the report's JSON lists every one."
        )

    def test_a_stored_draft_holding_every_value_is_said_to_leave_none_out(self) -> None:
        # A report stored with a draft that drafted every value: its line says what that
        # draft did, whatever today's tests would draft.
        report = _report(_decoder(SEED), _resolver(*HASHES, figures=AT_CHANCE))
        stored = _report(_decoder(SEED, SEED), _resolver(*HASHES, figures=ESTABLISHED))
        report.detection_signatures = [_yara(stored)]

        assert "stored value" not in self._analyst_line(report)


def _stored_reports() -> list[tuple[str, MalwareReport]]:
    """Each stored run whose ledger states hashes with figures, as a report of its values."""
    base = stored_runs()
    if base is None:
        pytest.skip("the stored runs are not on this machine")
    out: list[tuple[str, MalwareReport]] = []
    for evidence in sorted([*base.glob("*/evidence.json"), *base.glob("*/*/evidence.json")]):
        items = json.loads(evidence.read_text())
        ledger, _unread = stored_ledger(items["items"] if isinstance(items, dict) else items)
        report = _report()
        report.code_constants = code_constants_from_ledger(ledger)
        if any(c.role == "hash" and c.chance is not None for c in report.code_constants):
            out.append((str(evidence.parent.relative_to(base)), report))
    return out


@pytest.mark.parametrize("explained", [True, False], ids=["matches-chance-explains", "not"])
def test_a_stored_answer_s_figures_decide_alike_for_every_bound_near_the_one_held(
    explained: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Over the stored answers of each kind: one decision for every bound from 1e-6 to 0.1."""
    from malspark.reporting import code_constants

    def of_kind(report: MalwareReport) -> bool:
        chances = [c.chance for c in report.code_constants if c.chance is not None]
        return min(chances) >= 0.1 if explained else max(chances) <= 1e-6

    found = [(run, report) for run, report in _stored_reports() if of_kind(report)]
    if not found:
        pytest.skip("no stored run states hashes of this kind")
    for run, report in found:
        hashes = [c for c in report.code_constants if c.role == "hash"]
        for bound in (1e-6, 1e-4, 1e-3, 1e-2, 0.1):
            monkeypatch.setattr(code_constants, "CHANCE_BOUND", bound)
            assert [held(c) for c in hashes] == [not explained] * len(hashes), (run, bound)
