"""A cited entry holds a value its text writes as bytes, where chance cannot explain it.

The citation check asks a value cited to an entry that does not hold it. A
cited entry also holds a value its text writes as bytes: a token of hex pairs
(spaced or not, in either case), a JSON array of numbers 0-255, or a run of
``\\xNN`` escapes written at a byte-escape level, decoded as UTF-8 or as
UTF-16LE, holding the value whole, where the chance of such a holding among
that entry's byte runs is under the platform's one chance bound. A run the
entry's own call wrote, or the answer's echo of it, holds nothing. A run's end
bounds a value only where the run ends its JSON string or array, or the text;
a line break, a column gap or a split between two rows bounds nothing. The
question names the byte reading where it read a place. Only this test of the
cited entry reads bytes: every other reader of an entry's text is unchanged.
"""

from __future__ import annotations

import json
import math
import random
from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts, wrong_entry_citations
from malspark.reporting.code_constants import CHANCE_BOUND, chance_of_spelling
from malspark.schemas.evidence import LedgerEntry
from malspark.utils.written_bytes import ByteRun, byte_runs, chance_in

# An invented switch, its bytes, and a longer value that begins with it.
SWITCH = "/Apply"
SWITCH_HEX = SWITCH.encode().hex()
LONGER_HEX = b"/ApplyMe".hex()
HOLDER = json.dumps({"strings": [{"text": f"schedule {SWITCH} now"}, {"text": "cmd"}]})


def _entry(entry_id: str, output: str, args: dict[str, Any] | None = None) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool="t", output=output, args=args or {}
    )


def _texts(cited: str, args: dict[str, Any] | None = None) -> EntryTexts:
    return EntryTexts.from_ledger([_entry("ev_0001", cited, args), _entry("ev_0002", HOLDER)])


def _asked(cited: str, args: dict[str, Any] | None = None, value: str = SWITCH) -> list[Any]:
    sentence = f"It is started with `{value}` [ev_0001]."
    return wrong_entry_citations({"body": sentence}, _texts(cited, args), prose=("body",))


def _spaced(hexed: str) -> str:
    return " ".join(hexed[at : at + 2] for at in range(0, len(hexed), 2))


def _wide(text: str) -> str:
    return text.encode("utf-16-le").hex()


class TestEachShapeHoldsABoundedValue:
    @pytest.mark.parametrize(
        "cited",
        [
            json.dumps({"hex": SWITCH_HEX}),
            json.dumps({"hex": _spaced(SWITCH_HEX)}),
            json.dumps({"hex": SWITCH_HEX.upper()}),
            json.dumps({"hex": _spaced(SWITCH_HEX).upper()}),
            json.dumps({"data": list(SWITCH.encode())}),
            json.dumps({"literal": "".join(f"\\x{byte:02x}" for byte in SWITCH.encode())}),
            json.dumps({"hex": _wide(SWITCH)}),
            json.dumps({"hex": "0000" + _wide(SWITCH) + "0000"}),
            json.dumps({"hex": "00" + SWITCH_HEX + "00"}),
            f"00 {_spaced(SWITCH_HEX)} 00",
        ],
        ids=[
            "hex",
            "spaced",
            "upper",
            "spaced-upper",
            "array",
            "escapes",
            "utf16le",
            "utf16le-in-nul",
            "nul-bounded",
            "plain-text",
        ],
    )
    def test_a_cited_entry_writing_the_value_as_bytes_is_not_asked(self, cited: str) -> None:
        assert _asked(cited) == []

    def test_the_same_entry_without_the_bytes_is_asked(self) -> None:
        assert len(_asked(json.dumps({"hex": "00112233"}))) == 1

    def test_bytes_of_a_longer_value_hold_nothing(self) -> None:
        (found,) = _asked(json.dumps({"hex": LONGER_HEX}))

        assert "and as the bytes its text writes;" in found.message

    def test_a_three_byte_value_in_a_large_random_dump_is_asked(self) -> None:
        rng = random.Random(888)
        dump = bytearray(rng.randrange(256) for _ in range(80_000))
        dump[40_000:40_005] = b"\x00cmd\x00"

        assert len(_asked(json.dumps({"hex": dump.hex()}), value="cmd")) == 1


class TestTheCallsOwnBytesHoldNothing:
    @pytest.mark.parametrize(
        ("args", "cited"),
        [
            ({"pattern": _spaced(SWITCH_HEX)}, {"pattern": _spaced(SWITCH_HEX), "matches": []}),
            (
                {"rule": f"rule a {{ strings: $a = {{ {_spaced(SWITCH_HEX).upper()} }} }}"},
                {"rule": f"rule a {{ strings: $a = {{ {_spaced(SWITCH_HEX).upper()} }} }}"},
            ),
            (
                {"regex": "".join(f"\\x{byte:02x}" for byte in SWITCH.encode())},
                {"regex": "".join(f"\\x{byte:02x}" for byte in SWITCH.encode()), "hits": 0},
            ),
            ({"query": SWITCH_HEX}, {"query": SWITCH_HEX, "found": False}),
            ({"query": SWITCH_HEX}, {"searched_for": SWITCH_HEX, "found": False}),
        ],
        ids=["pattern", "rule", "regex", "query", "echo-under-another-key"],
    )
    def test_a_pattern_echoed_back_is_no_holding(
        self, args: dict[str, Any], cited: dict[str, Any]
    ) -> None:
        assert len(_asked(json.dumps(cited), args)) == 1


class TestOnlyARealEndBoundsTheValue:
    @pytest.mark.parametrize(
        "cited",
        [
            {"dump": f"00401000  41 42 {_spaced(SWITCH_HEX)}\n00401010  4d 65 00"},
            {"dump": f"{_spaced(SWITCH_HEX)}  4d 65 00"},
            {"rows": [{"hex": "0000" + SWITCH_HEX}, {"hex": "4d6500"}]},
        ],
        ids=["line-break", "column-gap", "row-split"],
    )
    def test_an_end_inside_one_answer_bounds_nothing(self, cited: dict[str, Any]) -> None:
        assert len(_asked(json.dumps(cited))) == 1

    def test_the_end_of_a_json_string_bounds_the_value(self) -> None:
        assert _asked(json.dumps({"rows": [{"hex": "0000" + SWITCH_HEX}]})) == []


class TestTheEscapeLevel:
    @pytest.mark.parametrize(
        "cited",
        [
            json.dumps({"literal": "".join(f"\\\\x{byte:02x}" for byte in SWITCH.encode())}),
            "".join(f"\\\\x{byte:02x}" for byte in SWITCH.encode()),
        ],
        ids=["json", "plain"],
    )
    def test_an_escaped_backslash_before_x_writes_no_byte(self, cited: str) -> None:
        assert len(_asked(cited)) == 1

    def test_a_byte_escape_in_plain_text_is_read(self) -> None:
        assert _asked("".join(f"\\x{byte:02x}" for byte in SWITCH.encode())) == []


def _one_place_chance(value: str, symbols: int = 256) -> float:
    return chance_in([ByteRun(bytes(len(value.encode())), symbols, True, True)], value)


class TestTheChanceBound:
    def test_the_chance_of_one_place_counts_each_letter_in_both_cases(self) -> None:
        # Three letters, four bytes: 2**3 / 256**4; one letter, four bytes: 2 / 256**4.
        assert _one_place_chance("/run") == pytest.approx(-math.expm1(-(2**3) / 256**4))
        assert _one_place_chance("C:\\a") == pytest.approx(-math.expm1(-(2**2) / 256**4))

    @pytest.mark.parametrize(
        ("value", "held", "refused"),
        [
            ("cmd", None, 4_096),
            ("C:\\", 4_096, 65_536),
            ("/run", 65_536, 1_048_576),
            ("/run", 530_000, 545_000),
            ("C:\\a", 1_070_000, 1_080_000),
        ],
    )
    def test_short_values_are_refused_by_the_bound_at_their_size(
        self, value: str, held: int | None, refused: int
    ) -> None:
        def chance(size: int) -> float:
            return chance_in([ByteRun(bytes(size), 256, True, True)], value)

        if held is not None:
            assert chance(held) < CHANCE_BOUND
        assert chance(refused) >= CHANCE_BOUND

    def test_a_decimal_only_token_has_ten_symbols_a_digit(self) -> None:
        (run,) = byte_runs(json.dumps({"size": "646972"}))
        assert run.symbols == 100
        (wider,) = byte_runs(json.dumps({"size": "64697a"}))
        assert wider.symbols == 256
        assert chance_in([run], "dir") == pytest.approx(-math.expm1(-(2**3) / 100**3))

    def test_a_json_number_is_read_as_a_decimal_token(self) -> None:
        (run,) = byte_runs(json.dumps({"size": 646972}))
        assert (run.data, run.symbols) == (b"dir", 100)

    def test_the_arithmetic_is_the_platform_s_one_poisson_tail(self) -> None:
        assert chance_of_spelling([(1000, 8, 3, 256)]) == pytest.approx(
            -math.expm1(-1000 * 8 / 256**3)
        )
        assert chance_of_spelling([]) == 0.0


class TestTheQuestionNamesTheByteReading:
    def test_bytes_read_without_a_find_are_named_and_nothing_is_said_absent(self) -> None:
        (found,) = _asked(json.dumps({"hex": LONGER_HEX}))

        assert found.message.startswith(
            "'/Apply' was not found as a whole value in the answer of ev_0001 (t), which the "
            "sentence cites, read as written, as JSON writes it or as the triage pack quotes "
            "it, and as the bytes its text writes; it was found"
        )
        assert " is not in " not in found.message

    def test_an_entry_writing_no_bytes_is_said_read_as_text(self) -> None:
        (found,) = _asked(json.dumps({"s": "nothing of the kind"}))

        assert "the bytes" not in found.message


class TestOnlyTheCitedEntryTestReadsBytes:
    def test_the_lookup_offers_no_byte_holder_and_holds_reads_text_alone(self) -> None:
        texts = EntryTexts.from_ledger([_entry("ev_0001", json.dumps({"hex": SWITCH_HEX}))])

        assert texts.holds("ev_0001", SWITCH, fields=True) is False
        assert texts.holds("ev_0001", SWITCH, fields=True, as_bytes=True) is True
        assert texts.holding(SWITCH, fields=True) == []
        assert texts.may_hold(SWITCH, fields=True) == set()
