"""The triage pack hands the API catalogue only names read under a value its answer holds.

The pack's resolver answer states its own figures (candidates scanned, names and
algorithms tried). A value whose algorithm's count of matches those figures put at
chance level (``code_constants.hash_standing``) is not handed to the catalogue as a name
resolved at runtime: with no held value no catalogue call is made and no entry is
recorded. The resolver's own pack line says, for each algorithm whose values are not
held, what the tool reported and why the names are not handed on, in the words a YARA
draft's closing comment uses, and does not open by saying those values name functions;
the line of an answer whose values are all held is as it was. An agent's own catalogue
call with names of its choosing is answered as before (T-850).
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from malspark.agents.evidence_recorder import EvidenceRecorder
from malspark.pipeline import triage_pack
from malspark.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    run_pack,
)
from malspark.reporting.code_constants import CHANCE_BOUND, answer_standing
from malspark.reporting.detection_signatures import STORED_HASHES_NOT_HELD
from malspark.schemas.evidence import EvidenceCounter
from malspark.tools import api_hashes, knowledge

from ..tools.synthetic_pe import TEXT_RVA, SyntheticPE

# Synthetic values and names; no stored run holds them.
AT_CHANCE = (
    ("0x4d2c9e71", "ProbeAlphaW"),
    ("0x7a61b3c5", "ProbeBetaA"),
    ("0x2e9f58d3", "ProbeGammaEx"),
)
# Six values under one algorithm: a count the wide scan's figures put under the bound too.
HELD = (
    ("0x6b3d1f87", "ProbeDeltaW"),
    ("0x58c2a94e", "ProbeEpsilonA"),
    ("0x39e7c4b2", "ProbeEtaW"),
    ("0x1fa8d63c", "ProbeThetaA"),
    ("0x83b5e2d9", "ProbeIotaEx"),
    ("0x92d4f1a6", "ProbeKappaW"),
)
# A scan whose matches chance explains, and one it does not.
WIDE = 257_331
NARROW = 1_303
NAMES = 11_629
ALGORITHMS = 8
OPENING = "values the file holds name Windows functions or modules"
REASON = STORED_HASHES_NOT_HELD.format(
    n=3, what="name hashes", bound=f"{CHANCE_BOUND:g}", its="their"
)


def _hit(value: str, name: str, algorithm: str, n: int) -> dict[str, Any]:
    return {
        "value": value,
        "readings": [
            {"algorithm": algorithm, "set": "exports", "name": name, "dlls": ["probe.dll"]}
        ],
        "occurrences": [{"rva": hex(0x6E3C10 + 0x10 * n), "function": None}],
    }


def _answer(scanned: int, held: bool = False) -> dict[str, Any]:
    """Three values under ``schemeA``, and with ``held`` six more under ``schemeB``."""
    hits = [_hit(v, name, "schemeA", n) for n, (v, name) in enumerate(AT_CHANCE)]
    if held:
        hits += [_hit(v, name, "schemeB", 9 + n) for n, (v, name) in enumerate(HELD)]
    return {
        "tool": "resolve_api_hashes",
        "image_base": "0x7f3d0000",
        "function_table": "none",
        "algorithms": [f"scheme{n}" for n in range(ALGORITHMS)],
        "names": {"dlls": 21, "names": NAMES, "modules": 90},
        "candidates": {"scanned": scanned, "how": "heuristic"},
        "hits": hits,
        "total": len(hits),
        "page_offset": 0,
        "next_offset": None,
    }


def _sample(tmp_path: Path) -> str:
    image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x200)])
    image.put("text", 0x40, b"\x3d" + struct.pack("<I", zlib.crc32(b"ProbeZeta")))
    target = tmp_path / "probe.exe"
    target.write_bytes(image.build())
    return str(target)


def _pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: dict[str, Any]) -> Any:
    monkeypatch.setattr(api_hashes, "resolve_api_hashes", lambda path, **_: answer)
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=_sample(tmp_path),
        sha256="b" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
    )
    return run_pack(recorder, inputs)


def _handed(result: Any) -> list[Any]:
    return [
        e for e in result.entries if e.tool == "api_capability" and e.args.get("resolved_names")
    ]


def _resolver_line(result: Any, room: int = 0) -> str:
    block = pack_block(pack_entries(result.entries), room)
    return next(line for line in block.splitlines() if "] resolved hashes:" in line)


class TestTheHandOff:
    def test_names_at_chance_level_are_not_handed_and_no_entry_is_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _pack(tmp_path, monkeypatch, _answer(WIDE))

        assert any(e.tool == "resolve_api_hashes" and e.ok for e in result.entries)
        assert _handed(result) == []

    def test_names_read_under_a_held_value_are_handed_as_before(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _pack(tmp_path, monkeypatch, _answer(NARROW))

        (lookup,) = _handed(result)
        assert lookup.args["resolved_names"] == [name for _v, name in AT_CHANCE]

    def test_only_the_held_algorithm_s_names_are_handed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _pack(tmp_path, monkeypatch, _answer(WIDE, held=True))

        (lookup,) = _handed(result)
        assert lookup.args["resolved_names"] == [name for _v, name in HELD]
        assert lookup.structured["resolved_at_runtime_from_hashes"] == [n for _v, n in HELD]

    def test_without_a_standing_nothing_is_handed(self) -> None:
        answer = _answer(NARROW)
        assert triage_pack._resolved_not_imported(answer, [], None) == []
        standing = answer_standing(answer)
        assert triage_pack._resolved_not_imported(answer, ["ProbeBetaA"], standing) == [
            "ProbeAlphaW",
            "ProbeGammaEx",
        ]


class TestTheResolverLine:
    def test_an_algorithm_not_held_is_said_with_the_draft_s_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        line = _resolver_line(_pack(tmp_path, monkeypatch, _answer(WIDE)))

        assert OPENING not in line
        assert (
            "] resolved hashes: 3 values the file holds equal hashes of Windows function or "
            "module names under schemeA (257,331 candidate values scanned, 8 algorithms over "
            "11,629 function names of 21 DLLs and 90 module names): "
            f"{REASON}, so their names are not handed to the API catalogue; each as value"
        ) in line
        assert "all 3 shown" in line

    def test_a_held_algorithm_keeps_its_words_beside_the_one_not_held(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        line = _resolver_line(_pack(tmp_path, monkeypatch, _answer(WIDE, held=True)))

        assert f"] resolved hashes: 6 {OPENING} (257,331 candidate values scanned" in line
        assert (
            "module names); 3 values the file holds equal hashes of Windows function or module "
            f"names under schemeA: {REASON}, so their names are not handed to the API catalogue; "
            "each as value" in line
        )

    def test_a_line_of_held_values_is_as_it_was(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        line = _resolver_line(_pack(tmp_path, monkeypatch, _answer(NARROW)))

        assert (
            f"] resolved hashes: 3 {OPENING} (1,303 candidate values scanned, 8 algorithms" in line
        )
        assert "not handed" not in line and "equal hashes" not in line

    def test_the_line_fit_to_a_smaller_room_says_it_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Lone hits are said as a count before any hit is left out.
        answer = _answer(WIDE)
        answer["lone_hits"] = [
            _hit(f"{0x5A000000 + n:#010x}", "x", f"lone{n}", n) for n in range(9)
        ]
        result = _pack(tmp_path, monkeypatch, answer)
        entry = next(e for e in result.entries if e.tool == "resolve_api_hashes")
        whole = _resolver_line(result)

        shorter = triage_pack._within_room(entry, len(whole) - 40)
        assert shorter is not None
        assert triage_pack.LONE_HITS_ROOM_SENTENCE in shorter
        assert OPENING not in shorter
        assert f"{REASON}, so their names are not handed to the API catalogue" in shorter


class TestEachAlgorithmKeepsItsNames:
    def test_a_value_held_under_one_algorithm_does_not_hand_on_another_s_reading(self) -> None:
        # The first held value is also read under a second algorithm that matches it alone.
        answer = _answer(WIDE, held=True)
        answer["hits"][3]["readings"].append(
            {"algorithm": "schemeC", "set": "exports", "name": "ProbeLambdaA", "dlls": ["p.dll"]}
        )
        standing = answer_standing(answer)

        assert standing.holds(HELD[0][0])
        assert triage_pack._resolved_not_imported(answer, [], standing) == [
            name for _v, name in HELD
        ]


def _rendered(answer: dict[str, Any], room: int | None = None) -> str:
    """The resolver's line body for an answer rendered alone, in ``room`` characters."""
    return triage_pack._resolved_hashes(answer, max_chars=room)


def _smallest(answer: dict[str, Any]) -> tuple[int, str]:
    """The smallest room the line prints in, and what it prints there."""
    whole = len(_rendered(answer))
    for room in range(1, whole + 1):
        said = _rendered(answer, room)
        if said:
            return room, said
    raise AssertionError("the line prints in no room")


class TestTheLineInATightRoom:
    def test_a_line_with_values_not_held_sheds_its_values_before_itself(self) -> None:
        answer = _answer(WIDE, held=True)
        room, said = _smallest(answer)
        subject = "3 values the file holds equal hashes of Windows function or module names"

        assert said == (
            f"6 {OPENING}; {subject} under schemeA: {REASON}, so their names are not handed to "
            "the API catalogue"
        )
        assert room == len(said)
        # Every fitted form carries the reason, and the values go first.
        for tried in range(room, len(_rendered(answer)) + 1, 7):
            fitted = _rendered(answer, tried)
            assert f"{REASON}, so their names are not handed to the API catalogue" in fitted
        assert "0 of 9 shown" in _rendered(answer, room + 140)
        assert "each as value" not in _rendered(answer, room + 140)

    def test_a_line_of_held_values_keeps_its_smallest_form(self) -> None:
        _room, said = _smallest(_answer(NARROW))

        assert said.startswith(f"3 {OPENING} (1,303 candidate values scanned")
        assert "each as value" in said and "0 of 3 shown" in said


class TestAValueThatIsNoNumber:
    def test_it_is_said_to_be_none_beside_an_algorithm_that_holds_three(self) -> None:
        answer = _answer(NARROW)
        answer["hits"].append(_hit("0x1ffffffff", "ProbeMuW", "schemeA", 7))
        answer["total"] = 4
        said = _rendered(answer)

        assert f"3 {OPENING} (1,303 candidate values scanned" in said
        assert (
            "; 1 value the file holds equal hashes of Windows function or module names under "
            "schemeA: 1 stated as no 32-bit value, so its name is not handed to the API catalogue"
        ) in said
        assert "names nothing else" not in said

    def test_the_fallback_without_figures_keeps_its_words(self) -> None:
        answer = _answer(NARROW)
        del answer["candidates"]
        answer["hits"].append(_hit("0x5e17a3c9", "ProbeNuA", "schemeZ", 8))
        answer["total"] = 4

        assert (
            "under schemeZ: 1 under an algorithm that names nothing else in the file, so its "
            "name is not handed to the API catalogue"
        ) in _rendered(answer)


class TestAnAgentsOwnCall:
    def test_names_of_its_choosing_are_answered_and_never_refused(self) -> None:
        names = [name for _v, name in AT_CHANCE]
        answer = knowledge.api_capability([], resolved_names=names)

        assert answer["resolved_at_runtime_from_hashes"] == names
        assert [row["obtained"] for row in answer["capabilities"]] == [
            knowledge.RESOLVED_AT_RUNTIME
        ] * 3
