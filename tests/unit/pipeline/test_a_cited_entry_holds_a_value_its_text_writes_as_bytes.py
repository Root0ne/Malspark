"""A cited entry holds a value its text writes as bytes, where chance cannot explain it.

The citation check asks a value cited to an entry that does not hold it. A
cited entry also holds a value its text writes as bytes: a token of hex pairs
(spaced or not, in either case), a JSON array of numbers 0-255, or a run of
``\\xNN`` escapes written at a byte-escape level, decoded as UTF-8 or as
UTF-16LE, holding the value whole, where the chance of such a holding among
that entry's byte runs is under the platform's one chance bound. A run the
entry's own call wrote, or the answer's echo of it, holds nothing: a run its
arguments write as bytes, and a run equal to the UTF-8 or UTF-16LE bytes of
one of its string arguments. A run's end bounds a value only where the run
ends its JSON string or array, or the text; a line break, a column gap or a
split between two rows, at any depth, bounds nothing. The question names the
byte reading where it read a place, and where the bytes write the value whole
but chance alone explains it, says so. Only this test of the cited entry reads
bytes: every other reader of an entry's text is unchanged.
"""

from __future__ import annotations

import json
import math
import random
import time
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


def _large_dump_writing(value: bytes) -> str:
    rng = random.Random(888)
    dump = bytearray(rng.randrange(256) for _ in range(80_000))
    dump[40_000 : 40_002 + len(value)] = b"\x00" + value + b"\x00"
    return dump.hex()


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
        assert len(_asked(json.dumps({"hex": _large_dump_writing(b"cmd")}), value="cmd")) == 1


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
            ({"pattern": SWITCH}, {"pattern_hex": SWITCH_HEX, "hits": 0}),
            ({"pattern": SWITCH}, {"pattern": SWITCH_HEX, "hits": 0}),
            ({"pattern": SWITCH}, {"bytes": list(SWITCH.encode()), "matches": []}),
            ({"pattern": SWITCH}, {"pattern_hex": _wide(SWITCH), "hits": 0}),
            ({"pattern": SWITCH}, {"pattern_hex": SWITCH.lower().encode().hex(), "hits": 0}),
            ({"search": {"strings": [SWITCH]}}, {"searched": [list(SWITCH.encode())], "hits": 0}),
        ],
        ids=[
            "pattern",
            "rule",
            "regex",
            "query",
            "echo-under-another-key",
            "text-as-hex",
            "text-as-hex-same-key",
            "text-as-array",
            "text-as-utf16le-hex",
            "text-lower-cased-as-hex",
            "nested-text-as-array",
        ],
    )
    def test_a_pattern_echoed_back_is_no_holding(
        self, args: dict[str, Any], cited: dict[str, Any]
    ) -> None:
        assert len(_asked(json.dumps(cited), args)) == 1

    def test_a_run_holding_the_call_s_text_with_other_bytes_around_it_still_holds(self) -> None:
        cited = {"hits": [{"offset": 16, "hex": "00" + SWITCH_HEX + "00"}]}

        assert _asked(json.dumps(cited), {"pattern": SWITCH}) == []


class TestOnlyARealEndBoundsTheValue:
    @pytest.mark.parametrize(
        "cited",
        [
            {"dump": f"00401000  41 42 {_spaced(SWITCH_HEX)}\n00401010  4d 65 00"},
            {"dump": f"{_spaced(SWITCH_HEX)}  4d 65 00"},
            {"rows": [{"hex": "0000" + SWITCH_HEX}, {"hex": "4d6500"}]},
            {"reads": [{"r": {"hex": "0000" + SWITCH_HEX}}, {"r": {"hex": "4d6500"}}]},
            {"reads": [{"r": ["0000" + SWITCH_HEX]}, {"r": ["4d6500"]}]},
            {
                "reads": [
                    {"r": [{"s": {"hex": "0000" + SWITCH_HEX}}]},
                    {"r": [{"s": {"hex": "4d6500"}}]},
                ]
            },
        ],
        ids=[
            "line-break",
            "column-gap",
            "row-split",
            "nested-row-split",
            "row-split-in-a-list",
            "deep-row-split",
        ],
    )
    def test_an_end_inside_one_answer_bounds_nothing(self, cited: dict[str, Any]) -> None:
        assert len(_asked(json.dumps(cited))) == 1

    @pytest.mark.parametrize(
        "cited",
        [
            {"rows": [{"hex": "0000" + SWITCH_HEX}]},
            {"reads": [{"r": {"hex": "0000" + SWITCH_HEX}}]},
            {"reads": [{"r": {"hex": "0000" + SWITCH_HEX}}, {"r": {"size": "4d6500"}}]},
        ],
        ids=["one-row", "one-nested-row", "next-row-elsewhere"],
    )
    def test_the_end_of_a_json_string_bounds_the_value(self, cited: dict[str, Any]) -> None:
        assert _asked(json.dumps(cited)) == []


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

    def test_an_escaped_backslash_before_x_in_plain_text_writes_no_byte(self) -> None:
        # ``\\x00`` writes a backslash and ``x00``, no byte: the run of escapes after it
        # begins inside the text, and its start bounds nothing.
        escapes = "".join(f"\\x{byte:02x}" for byte in SWITCH.encode())

        assert len(_asked("\\\\x00" + escapes + "\\x00")) == 1
        assert _asked("\\x00" + escapes + "\\x00") == []

    def test_a_byte_escape_in_plain_text_is_read(self) -> None:
        assert _asked("".join(f"\\x{byte:02x}" for byte in SWITCH.encode())) == []


def _one_place_chance(value: str, symbols: int = 256) -> float:
    return chance_in([ByteRun(bytes(len(value.encode())), symbols, True, True)], value)


class TestTheChanceBound:
    def test_the_chance_of_one_place_counts_each_letter_in_both_cases(self) -> None:
        # Three letters, four bytes: 2**3 / 256**4; one letter, four bytes: 2 / 256**4.
        assert _one_place_chance("/run") == pytest.approx(-math.expm1(-(2**3) / 256**4))
        assert _one_place_chance("C:\\a") == pytest.approx(-math.expm1(-(2**2) / 256**4))

    def test_every_cased_letter_counts_in_both_cases_and_an_uncased_one_does_not(self) -> None:
        # ``é`` has two cases, ``·`` none: four letters of six bytes, two of five.
        assert _one_place_chance("/café") == pytest.approx(
            -math.expm1(-(2**4) / 256**6), rel=1e-9, abs=0
        )
        assert _one_place_chance("/a·b") == pytest.approx(
            -math.expm1(-(2**2) / 256**5), rel=1e-9, abs=0
        )

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

    def test_bytes_holding_the_value_whole_by_chance_are_said_to_hold_it(self) -> None:
        (found,) = _asked(json.dumps({"hex": _large_dump_writing(b"cmd")}), value="cmd")

        assert found.message.startswith(
            "'cmd' was not found as a whole value in the answer of ev_0001 (t), which the "
            "sentence cites, read as written, as JSON writes it or as the triage pack quotes "
            "it; the bytes the text of ev_0001 (t) writes hold it whole, but at its length and "
            "among so many bytes chance alone would put it there at least as often as the "
            "platform's chance bound allows, so that is not counted as holding it; it was found "
            "whole in ev_0002 (t). Cite"
        )
        assert "as the bytes its text writes" not in found.message

    def test_bytes_holding_one_of_two_values_whole_by_chance_say_so_of_that_value(self) -> None:
        cited = json.dumps({"hex": _large_dump_writing(b"cmd")})
        sentence = f"It runs `cmd` with `{SWITCH}` [ev_0001]."

        (found,) = wrong_entry_citations({"body": sentence}, _texts(cited), prose=("body",))

        assert (
            "read as written, as JSON writes them or as the triage pack quotes them; the bytes "
            "the text of ev_0001 (t) writes hold 'cmd' whole, but at its length and among so "
            "many bytes chance alone would put it there at least as often as the platform's "
            "chance bound allows, so that is not counted as holding it;"
        ) in found.message
        assert "as the bytes its text writes" not in found.message

    def test_the_label_says_what_bytes_holding_the_value_by_chance_hold(self) -> None:
        (found,) = _asked(json.dumps({"hex": _large_dump_writing(b"cmd")}), value="cmd")

        assert found.labels == (
            '"cmd" was not found whole in the text of ev_0001; the bytes ev_0001 writes hold it '
            "whole, but at its length and among so many bytes chance alone would put it there "
            "at least as often as the platform's chance bound allows, so that is not counted as "
            "holding it; it was found whole in ev_0002 (t)",
        )

    def test_the_label_names_the_one_of_two_values_bytes_hold_by_chance(self) -> None:
        cited = json.dumps({"hex": _large_dump_writing(b"cmd")})
        sentence = f"It runs `cmd` with `{SWITCH}` [ev_0001]."

        (found,) = wrong_entry_citations({"body": sentence}, _texts(cited), prose=("body",))

        (label,) = found.labels
        assert (
            'not found whole in the text of ev_0001; the bytes ev_0001 writes hold "cmd" whole, '
            "but at its length and among so many bytes chance alone would put it there at least "
            "as often as the platform's chance bound allows, so that is not counted as holding it; "
        ) in label
        assert f'hold "{SWITCH}" whole' not in label

    def test_the_label_of_bytes_that_do_not_hold_the_value_says_nothing_of_bytes(self) -> None:
        (found,) = _asked(json.dumps({"hex": LONGER_HEX}))

        assert all("the bytes" not in label for label in found.labels)
        assert all("not found whole in ev_0001; " in label for label in found.labels)

    def test_a_value_inside_a_run_whose_bytes_hold_it_by_chance_is_said_both(self) -> None:
        cited = json.dumps({"hex": _large_dump_writing(b"cmd"), "s": "xcmdy"})

        (found,) = _asked(cited, value="cmd")

        assert "only inside a longer run of text" in found.message
        assert (
            "; the bytes the text of ev_0001 (t) writes hold it whole, but at its length and "
            "among so many bytes chance alone would put it there at least as often as the "
            "platform's chance bound allows, so that is not counted as holding it; "
        ) in found.message

    def test_the_chance_of_an_entry_s_bytes_holding_a_value_is_read_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.utils import written_bytes

        reads: list[str] = []
        chance_in_ = written_bytes.chance_in

        def counted(runs: Any, spelling: str, spellings: Any) -> float:
            reads.append(spelling)
            return chance_in_(runs, spelling, spellings)

        monkeypatch.setattr(written_bytes, "chance_in", counted)

        (found,) = _asked(json.dumps({"hex": _large_dump_writing(b"cmd")}), value="cmd")

        assert found.labels and "the bytes" in found.message
        assert len(reads) == 1

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


def _odd_separators(size: int) -> str:
    rng = random.Random(888)
    separators = [" ", "  ", "\t", ":", "-", " ,", "\n", "|"]
    out: list[str] = []
    written = 0
    while written < size:
        out.append(f"{rng.randrange(256):02x}{rng.choice(separators)}")
        written += len(out[-1])
    return "".join(out)


class TestNoReadingIsMoreThanLinear:
    @pytest.mark.parametrize(
        "cited",
        [
            "\\" * 1_000_000,
            json.dumps({"s": "\\" * 500_000}),
            "\\" * 1_000_000 + "x41",
            _odd_separators(1_000_000),
            json.dumps({"hex": _odd_separators(1_000_000)}),
            json.dumps([at % 256 for at in range(250_000)]),
        ],
        ids=[
            "backslashes",
            "json-backslashes",
            "backslashes-then-an-escape",
            "odd-separators",
            "json-odd-separators",
            "number-array",
        ],
    )
    def test_a_megabyte_is_read_in_bounded_time(self, cited: str) -> None:
        # Each takes well under a second; the ceiling is generous so a slow runner passes.
        started = time.perf_counter()
        byte_runs(cited)
        _asked(cited)

        assert time.perf_counter() - started < 5.0
