"""The call map says of a function's listing only what the entry reading proves (T-776).

``listed_in`` names every entry a call listed the function in, whatever the
ledger keeps of it now; ``read`` says a model was shown some of its listing
(an entry keeps text of it, or was blanked after its model read it), and
``read_by`` follows it. What the ledger keeps is said in the row's ``notes``
alone, each with the entry it is about (``schemas.entry_reading``): a
listing kept in part, empty, with no recorded extent or not in the ledger's
text (a function no member of a cut answer keyed by address can be), and an
answer that also reads as a failure; every note names the store's copy where
one is held, the answer whole only where the stored part is the answer. A
number in a note is one the kept value or the entry's recorded cut confirms. A row whose
every listing is kept whole carries no ``notes``. Every address and tool
name here is a neutral synthetic value, read by the tools' declared kinds.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from malspark.reporting.call_map import _entry_readings, _kept, call_map
from malspark.schemas import entry_reading as reading
from malspark.schemas.evidence import LedgerEntry

BASE = 0x2470000
_BATCH = {"v": 1, "kind": "decompile_batch", "reader": "listing"}
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
ONE, TWO, THREE = BASE + 0x1000, BASE + 0x2000, BASE + 0x3000


def _code(address: int, body: str = "  return a;") -> str:
    return f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n"


def _batch(entry_id: str, answer: dict[str, Any], **kw: Any) -> LedgerEntry:
    asked = ",".join(key for key in answer if key.startswith("0x"))
    return LedgerEntry(
        id=entry_id,
        tool="lift_many",
        agent="reader_one",
        args={"functions": asked},
        output=json.dumps(answer),
        facts=_BATCH,
        **kw,
    )


def _rows(found: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["address"]: f for f in found["functions"]}


def test_a_listing_kept_in_part_is_read_and_says_how_much_is_kept() -> None:
    cut = _code(TWO)[:20]
    found = call_map(
        [
            _batch(
                "ev_0003",
                {
                    hex(ONE): _code(ONE),
                    hex(TWO): cut,
                    "shortened": {f"/{hex(TWO)}": {"kept_chars": 20, "omitted_chars": 980}},
                    "truncated": True,
                },
                truncated=True,
            )
        ]
    )

    rows = _rows(found)
    assert rows[hex(TWO)]["read"] is True
    assert rows[hex(TWO)]["listed_in"] == ["ev_0003"]
    assert rows[hex(TWO)]["notes"] == ["in part: 20 of 1,000 characters (ev_0003)"]
    assert "notes" not in rows[hex(ONE)]


def test_a_listing_kept_at_no_character_is_not_read() -> None:
    found = call_map(
        [
            _batch(
                "ev_0004",
                {
                    hex(ONE): _code(ONE),
                    hex(TWO): "",
                    "shortened": {f"/{hex(TWO)}": {"kept_chars": 0, "omitted_chars": 700}},
                    "truncated": True,
                },
                truncated=True,
            )
        ]
    )

    row = _rows(found)[hex(TWO)]
    assert row["read"] is False
    assert row["listed_in"] == ["ev_0004"] and row["read_by"] == []
    assert row["notes"] == ["kept at 0 characters (ev_0004)"]


def test_a_listing_whose_extent_the_entry_did_not_record_says_so() -> None:
    found = call_map(
        [
            _batch(
                "ev_0005",
                {
                    hex(ONE): _code(ONE),
                    hex(TWO): _code(TWO),
                    hex(THREE): _code(THREE)[:30],
                    "shortened": {
                        f"/{hex(ONE)}": {"kept_chars": 10, "omitted_chars": 5},
                        "others": {"paths": 1, "omitted": 0, "omitted_chars": 40},
                    },
                    "truncated": True,
                },
                truncated=True,
            )
        ]
    )

    rows = _rows(found)
    for address in (TWO, THREE):
        assert rows[hex(address)]["read"] is True
        assert rows[hex(address)]["notes"] == ["extent not recorded (ev_0005)"]


def _blanked(entry_id: str, **kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        agent="reader_one",
        args={"address": hex(ONE)},
        output="",
        truncated=True,
        facts=_DECOMPILE,
        **kw,
    )


_SPILLED = {"key": "jobs/1/answer", "sha256": "0" * 64, "bytes": 10}


def test_a_listing_left_out_before_any_model_read_it_is_listed_and_not_read() -> None:
    found = call_map([_blanked("ev_0006", stage="triage_pack")])

    for row in found["functions"]:
        assert row["read"] is False
        assert row["listed_in"] == ["ev_0006"] and row["read_by"] == []
        assert row["notes"] == [
            "not in the ledger's text: the byte budget left it out before any model read it "
            "(ev_0006)"
        ]


def test_a_listing_blanked_after_its_model_read_it_is_read() -> None:
    found = call_map([_blanked("ev_0016", blanked_by="agent")])

    for row in found["functions"]:
        assert row["read"] is True
        assert row["listed_in"] == ["ev_0016"] and row["read_by"] == ["reader_one"]
        assert row["notes"] == [
            "not in the ledger's text: the byte budget left it out after a model read it (ev_0016)"
        ]


def test_a_listing_not_kept_names_the_store_s_copy_only_where_one_is_held() -> None:
    held = _blanked("ev_0017", stage="triage_pack", spilled=[{"part": "output", **_SPILLED}])
    found = call_map([held])

    for row in found["functions"]:
        assert row["notes"] == [
            "not in the ledger's text: the byte budget left it out before any model read it; "
            "the store holds the answer whole (ev_0017)"
        ]


def _in_part(entry_id: str, **kw: Any) -> LedgerEntry:
    return _batch(
        entry_id,
        {
            hex(ONE): _code(ONE),
            hex(TWO): _code(TWO)[:20],
            "shortened": {f"/{hex(TWO)}": {"kept_chars": 20, "omitted_chars": 980}},
            "truncated": True,
        },
        truncated=True,
        **kw,
    )


def test_a_listing_kept_in_part_names_the_store_s_copy_only_where_one_is_held() -> None:
    stored = _rows(call_map([_in_part("ev_0018", spilled=[{"part": "answer", **_SPILLED}])]))
    plain = _rows(call_map([_in_part("ev_0019")]))

    assert stored[hex(TWO)]["notes"] == [
        "in part: 20 of 1,000 characters; the store holds the answer whole (ev_0018)"
    ]
    assert plain[hex(TWO)]["notes"] == ["in part: 20 of 1,000 characters (ev_0019)"]
    assert "notes" not in stored[hex(ONE)]


def test_a_listing_in_an_answer_that_also_reads_as_a_failure_is_in_its_text() -> None:
    for error in ("1 of 3 functions failed to decompile", {"code": "partial", "message": "1 of 3"}):
        found = call_map(
            [_batch("ev_0020", {"error": error, hex(ONE): _code(ONE), hex(TWO): _code(TWO)})]
        )

        for row in found["functions"]:
            assert row["read"] is True
            assert row["listed_in"] == ["ev_0020"] and row["read_by"] == ["reader_one"]
            assert row["notes"] == ["the answer also reads as a failure (ev_0020)"]


@pytest.mark.parametrize(
    ("value", "row"),
    [
        (_code(TWO), {"kept_chars": None, "omitted_chars": 5}),
        (_code(TWO), {"kept_chars": "abc"}),
        (_code(TWO)[:10], {"kept_chars": 10**30, "omitted_chars": -5}),
        (_code(TWO)[:10], {"kept": 5, "omitted": 3}),
        (_code(TWO)[:10], {"kept_chars": 10, "omitted_chars": 0}),
        (_code(TWO)[:10], {"kept_chars": 10}),
        (_code(TWO)[:10], {"kept_chars": 12, "omitted_chars": 40}),
        (_code(TWO)[:10], {"kept_chars": True, "omitted_chars": 40}),
        (_code(TWO)[:10], {"kept_chars": "10", "omitted_chars": 40}),
    ],
)
def test_a_count_the_kept_value_does_not_confirm_prints_no_number(
    value: str, row: dict[str, Any]
) -> None:
    found = call_map(
        [
            _batch(
                "ev_0021",
                {hex(ONE): _code(ONE), hex(TWO): value, "shortened": {f"/{hex(TWO)}": row}},
                truncated=True,
            )
        ]
    )

    listed = _rows(found)[hex(TWO)]
    assert listed["read"] is True and listed["listed_in"] == ["ev_0021"]
    assert listed["notes"] == ["extent not recorded (ev_0021)"]


def test_one_listing_whole_in_one_entry_and_in_part_in_another() -> None:
    whole = _batch("ev_0022", {hex(ONE): _code(ONE), hex(TWO): _code(TWO)})
    found = call_map([whole, _in_part("ev_0023")])

    row = _rows(found)[hex(TWO)]
    assert row["read"] is True
    assert row["listed_in"] == ["ev_0022", "ev_0023"]
    assert row["notes"] == ["in part: 20 of 1,000 characters (ev_0023)"]


def test_a_repeat_is_read_through_the_entry_that_holds_its_answer() -> None:
    held = _in_part("ev_0007")
    repeat = LedgerEntry(
        id="ev_0008",
        tool="lift_many",
        agent="reader_two",
        args=held.args,
        output="Same call as ev_0007; its answer is held there.",
        repeated_of="ev_0007",
        facts=_BATCH,
    )
    read = _entry_readings([held, repeat])("ev_0008")

    assert read is not None
    assert read.states == (reading.REPEAT, reading.SHORTENED)
    assert read.holder == "ev_0007"
    shown, note = _kept(read, TWO, [], ())
    assert (shown, note) == (True, "in part: 20 of 1,000 characters")
    # A repeat holds no listing of its own: the call map names the holder alone.
    row = _rows(call_map([held, repeat]))[hex(TWO)]
    assert row["listed_in"] == ["ev_0007"]
    assert row["notes"] == ["in part: 20 of 1,000 characters (ev_0007)"]


def _member(state: str, **kw: Any) -> reading.MemberReading:
    return reading.MemberReading(hex(ONE), f"/{hex(ONE)}", state, **kw)


def _read(states: tuple[str, ...], *members: reading.MemberReading, **kw: Any) -> Any:
    return reading.EntryReading("ev_0030", states[0], states, members=members, **kw)


_STORE = ("answer",)
_ANSWER = [{"part": "answer", **_SPILLED}]
_OUTPUT = [{"part": "output", **_SPILLED}]
_WHOLE = "the store holds the answer whole"
_OUTPUT_HELD = "the store holds the entry's output"
_MARK = "\n\n[OUTPUT TRUNCATED]"


def _single(entry_id: str, output: str, **kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        agent="reader_one",
        args={"address": hex(ONE)},
        output=output,
        facts=_DECOMPILE,
        **kw,
    )


def _asked(entry_id: str, output: str, *asked: int, **kw: Any) -> LedgerEntry:
    """A batch asked for ``asked``, whatever its answer holds."""
    return LedgerEntry(
        id=entry_id,
        tool="lift_many",
        agent="reader_one",
        args={"functions": ",".join(hex(a) for a in asked)},
        output=output,
        facts=_BATCH,
        **kw,
    )


_KEPT = _code(ONE)[:20] + _MARK
_BUT_ONE = {
    hex(TWO): _code(TWO),
    "shortened": {f"/{hex(ONE)}": {"kept_chars": 0, "omitted_chars": 9}},
}

_NO_ROW = {
    hex(TWO): _code(TWO)[:5],
    "shortened": {f"/{hex(TWO)}": {"kept_chars": 5, "omitted_chars": 9}},
}


def _e2(member: str, row: dict[str, Any], **kw: Any) -> LedgerEntry:
    answer = {hex(ONE): member, hex(TWO): _code(TWO), "shortened": {f"/{hex(ONE)}": row}}
    return _batch("ev_0050", answer, truncated=True, **kw)


# One row per state of the reading, each on an entry built as a run records
# it and read through ``call_map``: (entry, read, note) of the row of ONE.
# ``listed_in`` names the entry in every row and ``read_by`` follows ``read``.
BUILT = [
    ("E1 whole", _single("ev_0050", _code(ONE)), True, None),
    (
        "E9 one page",
        _single("ev_0050", json.dumps({"code": _code(ONE), "has_more": True, "next_offset": 100})),
        True,
        None,
    ),
    (
        "E5c structure dropped",
        _single("ev_0050", _code(ONE), spilled=[{"part": "structured", **_SPILLED}]),
        True,
        None,
    ),
    (
        "E6 failed by its answer's form",
        _batch("ev_0050", {"error": "1 of 2 failed", hex(ONE): _code(ONE)}),
        True,
        "the answer also reads as a failure",
    ),
    (
        "E6 failed by its answer's form, its answer held",
        _batch("ev_0050", {"error": "1 of 2 failed", hex(ONE): _code(ONE)}, spilled=_ANSWER),
        True,
        f"the answer also reads as a failure; {_WHOLE}",
    ),
    (
        "E5a blanked before any model read it",
        _blanked("ev_0050", stage="triage_pack"),
        False,
        "not in the ledger's text: the byte budget left it out before any model read it",
    ),
    (
        "E5a, its answer held",
        _blanked("ev_0050", stage="triage_pack", spilled=_ANSWER),
        False,
        f"not in the ledger's text: the byte budget left it out before any model read it; {_WHOLE}",
    ),
    (
        "E5b, its output held, nothing cut before",
        _blanked("ev_0050", blanked_by="agent", spilled=_OUTPUT),
        True,
        f"not in the ledger's text: the byte budget left it out after a model read it; {_WHOLE}",
    ),
    (
        "E5b, the output held of an entry already cut",
        _blanked("ev_0050", blanked_by="agent", spilled=_OUTPUT, chars_dropped=40),
        True,
        "not in the ledger's text: the byte budget left it out after a model read it; "
        f"{_OUTPUT_HELD}",
    ),
    (
        "E5b, the output and the answer held",
        _blanked("ev_0050", blanked_by="agent", spilled=[*_OUTPUT, *_ANSWER], chars_dropped=40),
        True,
        f"not in the ledger's text: the byte budget left it out after a model read it; {_WHOLE}",
    ),
    (
        "E3 one listing, its drop recorded",
        _single("ev_0050", _KEPT, truncated=True, chars_dropped=40),
        True,
        f"in part: {len(_KEPT) - len(_MARK)} of {len(_KEPT) + 40} characters",
    ),
    (
        "E3 one listing summarised, its drop recorded",
        _single("ev_0050", "The routine returns its argument.", truncated=True, chars_dropped=90),
        True,
        "extent not recorded",
    ),
    (
        "E3 one listing cut to a head and a tail, its drop recorded",
        _single("ev_0050", _code(ONE)[:9] + _MARK + "}\n", truncated=True, chars_dropped=40),
        True,
        "extent not recorded",
    ),
    (
        "E3 one listing, its drop recorded, its answer held",
        _single("ev_0050", _KEPT, truncated=True, chars_dropped=40, spilled=_ANSWER),
        True,
        f"in part: {len(_KEPT) - len(_MARK)} of {len(_KEPT) + 40} characters; {_WHOLE}",
    ),
    (
        "E3 one listing, no drop recorded",
        _single("ev_0050", _KEPT, truncated=True),
        True,
        "extent not recorded",
    ),
    (
        "E3 one listing, no drop recorded, its answer held",
        _single("ev_0050", _KEPT, truncated=True, spilled=_ANSWER),
        True,
        f"extent not recorded; {_WHOLE}",
    ),
    (
        "E3 two listings in one text",
        _asked(
            "ev_0050", (_code(ONE) + _code(TWO))[:50], ONE, TWO, truncated=True, chars_dropped=40
        ),
        True,
        "extent not recorded",
    ),
    (
        "E2 M1 whole",
        _batch("ev_0050", {hex(ONE): _code(ONE), **_NO_ROW}, truncated=True),
        True,
        None,
    ),
    (
        "E2 M2 in part, its answer held",
        _e2(_code(ONE)[:5], {"kept_chars": 5, "omitted_chars": 9}, spilled=_ANSWER),
        True,
        f"in part: 5 of 14 characters; {_WHOLE}",
    ),
    ("E2 M3 empty", _e2("", {"kept_chars": 0, "omitted_chars": 9}), False, "kept at 0 characters"),
    (
        "E2 M4 extent not recorded, its answer held",
        _e2(_code(ONE), {"kept_chars": 3, "omitted_chars": 9}, spilled=_ANSWER),
        True,
        f"extent not recorded; {_WHOLE}",
    ),
    (
        "E2, the function no member of the keyed answer",
        _asked("ev_0050", json.dumps(_BUT_ONE), ONE, TWO, truncated=True),
        False,
        "not in the ledger's text",
    ),
    (
        "E2, the function no member of the keyed answer, its answer held",
        _asked("ev_0050", json.dumps(_BUT_ONE), ONE, TWO, truncated=True, spilled=_ANSWER),
        False,
        f"not in the ledger's text; {_WHOLE}",
    ),
    (
        "E2, no container of members found",
        _asked(
            "ev_0050",
            json.dumps(
                {
                    "result": {"lines": 1, "code": _code(ONE)[:5]},
                    "shortened": {"/result/code": {"kept_chars": 5, "omitted_chars": 9}},
                }
            ),
            ONE,
            truncated=True,
        ),
        True,
        "extent not recorded",
    ),
]


@pytest.mark.parametrize(
    ("entry", "shown", "note"), [row[1:] for row in BUILT], ids=[row[0] for row in BUILT]
)
def test_each_state_of_a_built_entry_gives_its_row(
    entry: LedgerEntry, shown: bool, note: str | None
) -> None:
    row = _rows(call_map([entry]))[hex(ONE)]

    assert row["listed_in"] == ["ev_0050"]
    assert row["read"] is shown
    assert row["read_by"] == (["reader_one"] if shown else [])
    assert row.get("notes") == ([f"{note} (ev_0050)"] if note is not None else None)


def test_a_function_a_shortened_batch_was_asked_for_and_does_not_hold_is_not_read() -> None:
    for answer in (_BUT_ONE, _NO_ROW):
        row = _rows(call_map([_asked("ev_0051", json.dumps(answer), ONE, TWO, truncated=True)]))

        assert row[hex(ONE)]["read"] is False and row[hex(ONE)]["read_by"] == []
        assert row[hex(ONE)]["listed_in"] == ["ev_0051"]
        assert row[hex(ONE)]["notes"] == ["not in the ledger's text (ev_0051)"]


def test_a_batch_keyed_by_names_and_addresses_keeps_the_extent_of_an_asked_address_unsaid() -> None:
    answer = {
        hex(TWO): _code(TWO)[:5],
        "helper": _code(THREE),
        "shortened": {f"/{hex(TWO)}": {"kept_chars": 5, "omitted_chars": 9}},
    }
    entry = LedgerEntry(
        id="ev_0052",
        tool="lift_many",
        agent="reader_one",
        args={"functions": f"{hex(ONE)},{hex(TWO)},helper"},
        output=json.dumps(answer),
        truncated=True,
        facts=_BATCH,
    )

    row = _rows(call_map([entry]))[hex(ONE)]
    assert row["read"] is True and row["listed_in"] == ["ev_0052"]
    assert row["notes"] == ["extent not recorded (ev_0052)"]


# An offset and a virtual address 64 KiB apart several times over: one
# function where the run read no image base (``validation._one_function``).
_OFFSET = 0x10A000
_VA = BASE + _OFFSET


def _keyed(entry_id: str, keys: tuple[str, str], *asked: str, **kw: Any) -> LedgerEntry:
    """A shortened batch asked for ``asked``, keyed by ``keys``: the first whole, the second cut."""
    answer = {
        keys[0]: _code(int(keys[0], 16)),
        keys[1]: _code(int(keys[1], 16))[:5],
        "shortened": {f"/{keys[1]}": {"kept_chars": 5, "omitted_chars": 9}},
    }
    return LedgerEntry(
        id=entry_id,
        tool="lift_many",
        agent="reader_one",
        args={"functions": ",".join(asked)},
        output=json.dumps(answer),
        truncated=True,
        facts=_BATCH,
        **kw,
    )


@pytest.mark.parametrize(
    ("keys", "asked"),
    [
        ((hex(_VA), hex(_VA + 0x1000)), (hex(_OFFSET), hex(_OFFSET + 0x1000))),
        ((hex(_OFFSET), hex(_OFFSET + 0x1000)), (hex(_VA), hex(_VA + 0x1000))),
    ],
    ids=["asked by offset, keyed by address", "asked by address, keyed by offset"],
)
def test_with_no_image_base_a_function_keyed_by_its_other_address_is_not_said_absent(
    keys: tuple[str, str], asked: tuple[str, str]
) -> None:
    rows = _rows(call_map([_keyed("ev_0053", keys, *asked, spilled=_ANSWER)]))

    for address in asked:
        assert rows[address]["read"] is True
        assert rows[address]["read_by"] == ["reader_one"]
        assert rows[address]["listed_in"] == ["ev_0053"]
        assert rows[address]["notes"] == [f"extent not recorded; {_WHOLE} (ev_0053)"]


_SPELLINGS = [
    (key, ask)
    for key in (f"{_VA:#x}", f"0x{_VA:X}", f"{_VA:x}", f"{_VA:X}", f"0X{_VA:x}")
    for ask in (f"{_OFFSET:#x}", f"0x{_OFFSET:X}", f"{_OFFSET:x}", f"{_OFFSET:X}")
]


@pytest.mark.parametrize(("key", "ask"), _SPELLINGS, ids=[f"{k}-{a}" for k, a in _SPELLINGS])
def test_an_address_in_any_spelling_is_not_said_absent_from_its_other_address(
    key: str, ask: str
) -> None:
    keys = (key, f"{_VA + 0x1000:#x}")
    row = _rows(call_map([_keyed("ev_0054", keys, ask, hex(_VA + 0x1000))]))[hex(_OFFSET)]

    assert row["read"] is True and row["listed_in"] == ["ev_0054"]
    assert row["notes"] == ["extent not recorded (ev_0054)"]


def _base_read(base: int) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        tool="file_header",
        agent="reader_two",
        args={},
        output=json.dumps({"image_base": hex(base)}),
    )


def test_with_an_image_base_read_only_that_base_joins_an_offset_to_its_address() -> None:
    keys = (hex(_VA), hex(_VA + 0x1000))
    asked = (hex(_OFFSET), hex(_OFFSET + 0x1000))
    joined = _rows(call_map([_base_read(BASE), _keyed("ev_0055", keys, *asked)]))
    other = 0x400000
    apart = _rows(call_map([_base_read(other), _keyed("ev_0055", keys, *asked)]))

    assert "notes" not in joined[hex(_VA)]
    assert joined[hex(_VA + 0x1000)]["notes"] == ["in part: 5 of 14 characters (ev_0055)"]
    # The offsets are spelled by the base read, which is not the one the keys sit on.
    for address in (_OFFSET + other, _OFFSET + 0x1000 + other):
        row = apart[hex(address)]
        assert row["read"] is False and row["read_by"] == []
        assert row["listed_in"] == ["ev_0055"]
        assert row["notes"] == ["not in the ledger's text (ev_0055)"]


def test_with_no_image_base_an_address_no_key_can_be_is_not_in_the_ledger_s_text() -> None:
    keys = (hex(_VA), hex(_VA + 0x1000))
    asked = (hex(_OFFSET + 0x234), hex(_VA + 0x1000))
    row = _rows(call_map([_keyed("ev_0056", keys, *asked)]))[hex(_OFFSET + 0x234)]

    assert row["read"] is False and row["read_by"] == []
    assert row["listed_in"] == ["ev_0056"]
    assert row["notes"] == ["not in the ledger's text (ev_0056)"]


# The states no entry the call map lists can be in, read by ``_kept`` alone:
# an answer not shown and one failed by ``ok`` are never listed
# (``function_map``, ``function_callees._shown``), nor is a repeat (its
# holder is listed instead) or an entry the ledger lacks; the call map hands
# no shown length (E11); and no answer of a kind that counts its own gaps is
# a code listing (E10).
TABLE = [
    ("E10 whole with gaps", _read((reading.WHOLE_WITH_GAPS,)), True, None),
    ("E11 shown in part", _read((reading.SHOWN_IN_PART, reading.WHOLE)), True, None),
    ("E8 absent", _read((reading.ABSENT,)), True, "extent not recorded"),
    ("E7 repeat, holder not given", _read((reading.REPEAT,)), True, "extent not recorded"),
    (
        "E7 repeat, holder not given, its answer held",
        _read((reading.REPEAT,), stored=_STORE, answer_stored_whole=True),
        True,
        f"extent not recorded; {_WHOLE}",
    ),
    (
        "E4 not shown",
        _read((reading.NOT_SHOWN,), stored=_STORE, answer_stored_whole=True),
        False,
        f"not in the ledger's text: the conversation had no room for it; {_WHOLE}",
    ),
    (
        "E6 failed by ok",
        _read((reading.FAILED,)),
        True,
        "the answer also reads as a failure",
    ),
]


@pytest.mark.parametrize(
    ("read", "shown", "note"), [row[1:] for row in TABLE], ids=[row[0] for row in TABLE]
)
def test_each_state_no_listed_entry_is_in_gives_its_row(
    read: reading.EntryReading, shown: bool, note: str | None
) -> None:
    assert _kept(read, ONE, [], (), alone=True) == (shown, note)


def test_a_listing_kept_whole_carries_no_note() -> None:
    found = call_map(
        [_batch("ev_0009", {hex(ONE): _code(ONE, f"  FUN_{TWO:x}(a);"), hex(TWO): _code(TWO)})]
    )

    for row in found["functions"]:
        assert "notes" not in row
        assert row["read"] is True
