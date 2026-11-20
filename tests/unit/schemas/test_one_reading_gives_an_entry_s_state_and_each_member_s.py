"""One reading gives an entry's state and each member's state from the entry's own fields.

``schemas.entry_reading.entry_reading`` reads the fields an entry carries —
``repeated_of``, ``ok`` and its answer's failure form, the record of an answer
not shown, an empty output with ``truncated`` and the stage that blanked it,
``chars_dropped``, the shortener's map, ``spilled``, the answer's own paging
markers and gap fields — and never the tool's name, its server or its source.
Every state is reachable, the precedence decides the one that governs, the
states that stand beside it are kept, and an entry that fits no state does not
exist.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from malspark.agents.mcp_client import TRUNCATION_MARKER
from malspark.agents.output_shortening import our_key_in, shorten_json_document
from malspark.schemas import entry_reading as reading_module
from malspark.schemas.entry_reading import (
    ABSENT,
    BLANKED_READ,
    BLANKED_UNREAD,
    CUT_AS_TEXT,
    ENTRY_STATES,
    FAILED,
    MEMBER_EMPTY,
    MEMBER_IN_PART,
    MEMBER_NOT_KEPT,
    MEMBER_STATES,
    MEMBER_UNMEASURED,
    MEMBER_WHOLE,
    NOT_SHOWN,
    ONE_PAGE,
    REPEAT,
    SHORTENED,
    SHOWN_IN_PART,
    STRUCTURE_DROPPED,
    WHOLE,
    WHOLE_WITH_GAPS,
    entry_reading,
)
from malspark.schemas.evidence import LedgerEntry, not_shown_record
from tests.tool_name_reads import findings


def _routine(address: int, callee: int, pad: int) -> str:
    return (
        f"undefined8 FUN_{address:08x}(void)\n{{\n  FUN_{callee:08x}();\n"
        + "  x = x + 1;\n" * pad
        + "  return 0;\n}\n"
    )


def _entry(output: str = "", **fields: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": "ev_0001",
        "stage": "analysis",
        "agent": "static",
        "tool": "t",
        "args": {},
        "ok": True,
        "output": output,
        "truncated": False,
        "chars_dropped": 0,
        "repeated_of": None,
        "structured": None,
    }
    entry.update(fields)
    return entry


def _shortened(document: dict[str, Any], limit: int) -> dict[str, Any]:
    whole = json.dumps(document)
    result = shorten_json_document(whole, limit)
    assert result.shortened
    return _entry(
        result.text,
        truncated=True,
        chars_dropped=len(whole) - len(result.text),
        structured=json.loads(result.text),
    )


def _cut(text: str, at: int) -> dict[str, Any]:
    return _entry(text[:at] + TRUNCATION_MARKER, truncated=True, chars_dropped=len(text) - at)


_BATCH = {
    "0x401000": _routine(0x401000, 0x403000, 5),
    "0x402000": _routine(0x402000, 0x403000, 5),
    "0x403000": _routine(0x403000, 0x405000, 400),
}
_SPILLED_OUTPUT = [{"part": "output", "key": "evidence/job/ab", "bytes": 9, "sha256": "ab"}]


# One entry per state, built from the fields that decide it.
_EACH_STATE: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    REPEAT: (_entry("same answer as ev_0000", repeated_of="ev_0000"), {}),
    FAILED: (_entry("", ok=False, error="the server refused"), {}),
    NOT_SHOWN: (_entry(not_shown_record(12_000), truncated=True), {}),
    BLANKED_UNREAD: (
        _entry("", truncated=True, stage="triage_pack", agent="pipeline", spilled=_SPILLED_OUTPUT),
        {},
    ),
    BLANKED_READ: (_entry("", truncated=True, stage="triage", agent="triage"), {}),
    CUT_AS_TEXT: (_cut(json.dumps(_BATCH), json.dumps(_BATCH).index('"0x403000"') + 40), {}),
    SHORTENED: (_shortened({"strings": [f"s{i}" * 40 for i in range(200)]}, 2_000), {}),
    STRUCTURE_DROPPED: (
        _entry(
            "a prose answer",
            spilled=[{"part": "structured", "key": "k", "bytes": 4, "sha256": "cd"}],
        ),
        {},
    ),
    ONE_PAGE: (_entry(json.dumps({"rows": [1, 2, 3], "next_offset": 3})), {}),
    WHOLE_WITH_GAPS: (_entry(json.dumps({"rows": [], "calls_unnamed": {"0x1000": 2}})), {}),
    SHOWN_IN_PART: (_entry("a" * 100), {"shown_chars": 40}),
    WHOLE: (_entry(json.dumps(_BATCH)), {}),
}


class TestEveryStateIsReachable:
    @pytest.mark.parametrize("state", [s for s in ENTRY_STATES if s != ABSENT])
    def test_the_fields_that_decide_a_state_give_it(self, state: str) -> None:
        entry, options = _EACH_STATE[state]

        reading = entry_reading(entry, **options)

        assert reading.state == state
        assert reading.states[0] == state

    def test_no_entry_reads_as_absent(self) -> None:
        reading = entry_reading(None)

        assert reading.state == ABSENT and reading.states == (ABSENT,)

    def test_a_ledger_entry_and_its_dump_read_alike(self) -> None:
        for state, (entry, options) in _EACH_STATE.items():
            model = LedgerEntry.model_validate(entry)

            assert (
                entry_reading(model, **options).states == entry_reading(entry, **options).states
            ), state


class TestPrecedence:
    def test_a_page_that_reports_its_own_gaps_is_governed_by_the_page(self) -> None:
        entry = _entry(json.dumps({"rows": [1], "next_offset": 1, "calls_unnamed": {"0x10": 1}}))

        reading = entry_reading(entry)

        assert reading.state == ONE_PAGE
        assert reading.states == (ONE_PAGE, WHOLE_WITH_GAPS)
        assert reading.gaps == {"calls_unnamed": {"0x10": 1}}

    def test_a_shortened_answer_with_its_top_level_flag_has_paging_unknown(self) -> None:
        reading = entry_reading(_EACH_STATE[SHORTENED][0])

        assert reading.state == SHORTENED
        assert reading.paging_unknown is True
        assert ONE_PAGE not in reading.states

    def test_a_shortened_answer_that_names_its_next_page_is_also_a_page(self) -> None:
        document = {"strings": [f"s{i}" * 40 for i in range(200)], "next_offset": 200}

        reading = entry_reading(_shortened(document, 2_000))

        assert reading.states == (SHORTENED, ONE_PAGE)

    def test_the_counts_beside_the_map_are_not_read_as_a_page(self) -> None:
        document = {"strings": [f"s{i}" * 40 for i in range(200)], "total": 200}

        reading = entry_reading(_shortened(document, 2_000))

        assert reading.states == (SHORTENED,)

    def test_a_repeat_is_read_through_the_entry_that_holds_its_answer(self) -> None:
        holder = _entry(json.dumps({"rows": [1], "next_offset": 1}), id="ev_0000")
        repeat = _entry("served again", repeated_of="ev_0000")

        alone = entry_reading(repeat)
        through = entry_reading(repeat, holder=holder)

        assert alone.states == (REPEAT,) and alone.holder == "ev_0000"
        assert through.state == REPEAT
        assert through.states == (REPEAT, ONE_PAGE)
        assert through.holder_reading is not None and through.holder_reading.state == ONE_PAGE

    def test_a_guard_s_answer_names_no_holder(self) -> None:
        reading = entry_reading(_entry("answered by the guard", repeated_of="ev_0001"))

        assert reading.state == REPEAT and reading.holder == ""

    def test_a_failure_governs_a_blanked_output(self) -> None:
        entry = _entry("", ok=False, truncated=True, stage="triage_pack")

        assert entry_reading(entry).states == (FAILED,)

    def test_an_answer_that_is_only_an_error_line_is_failed(self) -> None:
        assert entry_reading(_entry("Error: binary not loaded")).state == FAILED

    def test_an_entry_shown_in_part_and_whole_in_the_ledger_is_both(self) -> None:
        reading = entry_reading(_entry("a" * 100), shown_chars=40)

        assert reading.states == (SHOWN_IN_PART, WHOLE)

    def test_a_reader_that_shows_it_all_sees_it_whole(self) -> None:
        assert entry_reading(_entry("a" * 100), shown_chars=100).states == (WHOLE,)

    def test_a_dropped_structure_stands_beside_a_page(self) -> None:
        entry = _entry(
            json.dumps({"rows": [1], "has_more": True}),
            spilled=[{"part": "structured", "key": "k", "bytes": 4, "sha256": "cd"}],
        )

        assert entry_reading(entry).states == (STRUCTURE_DROPPED, ONE_PAGE)

    def test_a_cut_without_a_count_is_still_cut_as_text(self) -> None:
        entry = _entry("the first part of a long prose answer…", truncated=True)

        assert entry_reading(entry).state == CUT_AS_TEXT

    def test_gap_fields_at_zero_are_not_gaps_and_a_missing_one_is_unknown(self) -> None:
        reading = entry_reading(
            _entry(json.dumps({"rows": [], "calls_unnamed": {}, "undecoded_functions": 0}))
        )

        assert reading.states == (WHOLE,)
        assert reading.gaps_zero == frozenset({"calls_unnamed", "undecoded_functions"})
        assert not reading.gap_unknown("calls_unnamed")
        assert reading.gap_unknown("imports_cut")


class TestBlankedEntries:
    def test_the_pack_s_budget_blanks_before_any_model_read_it(self) -> None:
        for fields in ({"stage": "triage_pack"}, {"agent": "pipeline"}, {"blanked_by": "pack"}):
            entry = _entry("", truncated=True, **{"stage": "analysis", **fields})

            assert entry_reading(entry).state == BLANKED_UNREAD, fields

    def test_an_agent_s_budget_blanks_after_its_model_read_it(self) -> None:
        for fields in (
            {"stage": "triage", "agent": "triage"},
            {"stage": "triage_pack", "blanked_by": "agent"},
        ):
            entry = _entry("", truncated=True, **fields)

            assert entry_reading(entry).state == BLANKED_READ, fields

    def test_the_store_s_whole_copy_of_a_blanked_answer_is_named_with_its_digest(self) -> None:
        entry, _ = _EACH_STATE[BLANKED_UNREAD]

        reading = entry_reading(entry)

        assert reading.stored == ("output",)
        assert reading.members == () and reading.members_not_kept is None
        assert reading.member("0x401000") is not None
        assert reading.member("0x401000").state == MEMBER_NOT_KEPT  # type: ignore[union-attr]

    def test_a_reference_whose_upload_failed_names_no_kept_copy(self) -> None:
        entry = _entry(
            "", truncated=True, spilled=[{"part": "output", "bytes": 9, "reason": "store down"}]
        )

        assert entry_reading(entry).stored == ()

    def test_an_empty_answer_never_blanked_is_whole(self) -> None:
        assert entry_reading(_entry("")).state == WHOLE


class TestMembers:
    def test_every_member_of_a_whole_batch_is_whole(self) -> None:
        reading = entry_reading(_entry(json.dumps(_BATCH)))

        assert [(m.key, m.state) for m in reading.members] == [
            (key, MEMBER_WHOLE) for key in _BATCH
        ]
        assert reading.members_not_kept == 0
        assert reading.member("0x409000") is None

    def test_a_member_its_row_keeps_in_part_is_k_of_t(self) -> None:
        document = {"0x401000": "a" * 600, "0x402000": "b" * 6_000}

        reading = entry_reading(_shortened(document, 2_000))

        cut = reading.member("0x402000")
        assert cut is not None and cut.state == MEMBER_IN_PART
        assert cut.unit == "characters" and cut.total == 6_000 and 0 < (cut.kept or 0) < 6_000
        assert reading.member("0x401000").state == MEMBER_WHOLE  # type: ignore[union-attr]

    def test_rows_taken_off_a_list_are_counted_and_unnamed(self) -> None:
        rows = [
            {"address": "0x401000", "code": _routine(0x401000, 0x402000, 20)},
            {"address": "0x403000", "code": _routine(0x403000, 0x402000, 20)},
            {"address": "0x402000", "code": _routine(0x402000, 0x405000, 400)},
            {"address": "0x404000", "code": _routine(0x404000, 0x401000, 400)},
        ]

        entry = _shortened({"results": rows}, 3_000)
        reading = entry_reading(entry)

        book = entry["structured"][our_key_in(entry["structured"])]
        assert book == {"/results": {"kept": 2, "omitted": 2}}
        assert [(m.key, m.state) for m in reading.members] == [
            ("0", MEMBER_WHOLE),
            ("1", MEMBER_WHOLE),
        ]
        assert reading.members_not_kept == 2
        assert reading.member("3").state == MEMBER_NOT_KEPT  # type: ignore[union-attr]

    def test_no_member_left_empty_by_the_shortener_reads_as_holding_text(self) -> None:
        document = {
            f"0x{0x401000 + i * 0x100:x}": _routine(0x401000 + i * 0x100, 0x400000, 40 + 3 * i)
            for i in range(40)
        }

        entry = _shortened(document, len(json.dumps(document)) // 12)
        reading = entry_reading(entry)

        kept = entry["structured"]
        book = kept[our_key_in(kept)]
        assert "others" in book
        assert len(reading.members) == 40
        for member in reading.members:
            text = kept[member.key]
            row = book.get(member.path)
            if text == "":
                assert member.state == MEMBER_EMPTY, member
            elif row is not None:
                assert member.state == MEMBER_IN_PART, member
            else:
                assert member.state == MEMBER_UNMEASURED, member
        assert reading.members_not_kept == 0

    def test_a_cut_batch_keeps_its_closed_members_whole_and_the_rest_unknown(self) -> None:
        text = json.dumps(_BATCH)

        reading = entry_reading(_cut(text, text.index('"0x403000"') - 2))

        assert reading.state == CUT_AS_TEXT
        assert [(m.key, m.state) for m in reading.members] == [
            ("0x401000", MEMBER_WHOLE),
            ("0x402000", MEMBER_WHOLE),
        ]
        assert reading.members_not_kept is None
        assert reading.member("0x403000").state == MEMBER_NOT_KEPT  # type: ignore[union-attr]

    def test_the_member_a_cut_falls_in_is_empty_before_its_text_and_unmeasured_after(
        self,
    ) -> None:
        text = json.dumps(_BATCH)
        opening = text.index('"0x403000"') + len('"0x403000": "')

        before = entry_reading(_cut(text, opening))
        after = entry_reading(_cut(text, opening + 30))
        at_the_colon = entry_reading(_cut(text, opening - 2))

        assert before.member("0x403000").state == MEMBER_EMPTY  # type: ignore[union-attr]
        assert after.member("0x403000").state == MEMBER_UNMEASURED  # type: ignore[union-attr]
        assert at_the_colon.member("0x403000").state == MEMBER_EMPTY  # type: ignore[union-attr]

    def test_a_cut_list_of_rows_reads_the_row_the_cut_fell_in(self) -> None:
        text = json.dumps({"tool": "x", "results": [{"code": "a" * 50}, {"code": "b" * 50}]})

        reading = entry_reading(_cut(text, text.index("bbb") + 10))

        assert [(m.key, m.state) for m in reading.members] == [
            ("0", MEMBER_WHOLE),
            ("1", MEMBER_UNMEASURED),
        ]
        assert reading.members_not_kept is None

    def test_the_call_s_argument_names_do_not_decide_the_members(self) -> None:
        text = json.dumps(_BATCH)
        cut = _cut(text, text.index('"0x403000"') - 2)

        readings = [
            entry_reading({**cut, "args": {name: list(_BATCH)}})
            for name in ("functions", "targets", "addresses")
        ]

        assert len({(r.states, r.members, r.members_not_kept) for r in readings}) == 1

    def test_the_rows_of_a_page_are_whole_and_later_pages_are_not_kept(self) -> None:
        reading = entry_reading(_entry(json.dumps({"rows": ["a", "b"], "next_offset": 2})))

        assert [(m.key, m.state) for m in reading.members] == [
            ("0", MEMBER_WHOLE),
            ("1", MEMBER_WHOLE),
        ]
        assert reading.member("2").state == MEMBER_NOT_KEPT  # type: ignore[union-attr]

    def test_an_answer_of_no_member_shape_has_no_members(self) -> None:
        document = {"image_base": "0x400000", "rows": [{"offset": "0x1000"}], "meta": {"a": 1}}

        assert entry_reading(_entry(json.dumps(document))).members == ()


class TestTheToolIsNotRead:
    @pytest.mark.parametrize(
        ("tool", "server", "source"),
        [
            ("batch_decompile", "ghidra", "provider:ghidra"),
            ("get_pseudocode", "idapro", None),
            ("hexrays_pseudocode", "idapro", None),
            ("batch_decompile_v2", "custom", "mcp:custom"),
            ("function_index", "pipeline", "pack"),
        ],
    )
    def test_the_same_answer_reads_the_same_under_any_tool(
        self, tool: str, server: str, source: str | None
    ) -> None:
        text = json.dumps(_BATCH)
        entries = [
            _entry(text),
            _cut(text, text.index('"0x403000"') + 40),
            _entry("", truncated=True, stage="triage_pack"),
            _entry(json.dumps({"rows": [], "calls_unnamed": {"0x1": 1}})),
        ]
        reference = [entry_reading(entry) for entry in entries]

        renamed = [
            entry_reading({**entry, "tool": tool, "server": server, "source": source})
            for entry in entries
        ]

        assert renamed == reference

    def test_the_module_reads_no_tool_by_its_name(self) -> None:
        source = Path(reading_module.__file__).read_text(encoding="utf-8")

        assert findings(source, "schemas/entry_reading.py") == []


# Every combination of the fields the reading keys on.
_OUTPUTS = {
    "empty": "",
    "prose": "a prose answer of a few words",
    "error line": "Error: binary not loaded",
    "error envelope": json.dumps({"error": {"code": "E", "message": "refused"}}),
    "not shown": not_shown_record(9_000),
    "batch": json.dumps(_BATCH),
    "cut batch": json.dumps(_BATCH)[:300] + TRUNCATION_MARKER,
    "cut at a key": json.dumps(_BATCH)[:2] + TRUNCATION_MARKER,
    "page": json.dumps({"rows": ["a", "b"], "total": 9}),
    "gaps": json.dumps({"rows": [], "undecoded_functions": 3}),
    "page and gaps": json.dumps({"rows": ["a"], "has_more": True, "unplaced": {"t": 1}}),
    "shortened": _EACH_STATE[SHORTENED][0]["output"],
    "shortened folded": json.dumps(
        {
            "shortened": {"/a": {"kept_chars": 0, "omitted_chars": 9}, "others": {"paths": 1}},
            "truncated": True,
            "a": "",
            "b": "",
            "c": "x",
        }
    ),
    "list": json.dumps(["a", "b"]),
    "scalar json": "4",
}
_SPILLED: dict[str, list[dict[str, Any]] | None] = {
    "none": None,
    "output": _SPILLED_OUTPUT,
    "answer": [{"part": "answer", "key": "k", "bytes": 3, "sha256": "ef"}],
    "structured": [{"part": "structured", "key": "k", "bytes": 3, "sha256": "ef"}],
    "failed upload": [{"part": "output", "bytes": 3, "reason": "store down"}],
}


def _combinations() -> list[tuple[Any, ...]]:
    return list(
        itertools.product(
            list(_OUTPUTS),
            (None, "ev_0000", "ev_0001"),
            (True, False),
            (True, False),
            (0, 120),
            (("analysis", "static"), ("triage_pack", "pipeline")),
            list(_SPILLED),
            (False, True),
            (None, 5),
            (False, True),
        )
    )


class TestNoEntryFitsNoState:
    def test_every_combination_gets_exactly_one_state_and_no_exception(self) -> None:
        holder = _entry(json.dumps({"rows": [1], "next_offset": 1}), id="ev_0000")
        seen: set[str] = set()
        for (
            output,
            repeated_of,
            ok,
            truncated,
            dropped,
            (stage, agent),
            spilled,
            structured,
            shown,
            with_holder,
        ) in _combinations():
            text = _OUTPUTS[output]
            entry = _entry(
                text,
                repeated_of=repeated_of,
                ok=ok,
                truncated=truncated,
                chars_dropped=dropped,
                stage=stage,
                agent=agent,
                spilled=_SPILLED[spilled],
                structured=_parsed(text) if structured else None,
            )

            reading = entry_reading(
                entry, holder=holder if with_holder else None, shown_chars=shown
            )

            assert reading.state in ENTRY_STATES
            assert reading.states and reading.states[0] == reading.state
            assert len(set(reading.states)) == len(reading.states)
            assert list(reading.states) == sorted(reading.states, key=ENTRY_STATES.index)
            exclusive = {FAILED, NOT_SHOWN, BLANKED_UNREAD, BLANKED_READ, CUT_AS_TEXT, SHORTENED}
            own = reading.states[1:] if reading.state == REPEAT else reading.states
            assert len(exclusive & set(own)) <= 1
            assert all(member.state in MEMBER_STATES for member in reading.members)
            seen.add(reading.state)
        assert seen == set(ENTRY_STATES) - {ABSENT}


def _parsed(text: str) -> Any:
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict | list) else None
