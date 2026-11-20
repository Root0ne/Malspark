"""One reading gives an entry's state and each member's state from the entry's own fields.

``schemas.entry_reading.entry_reading`` reads the fields an entry carries —
``repeated_of``, ``ok`` and its answer's failure form, the record of an answer
not shown, an empty output with ``truncated`` and the stage that blanked it,
``chars_dropped``, the shortener's map, ``spilled``, the answer's own paging
markers and the coverage counts of its declared kind — and never the tool's
name, its server or its source. Every state is reachable, the precedence
decides the one that governs, the states that stand beside it are kept, an
entry that fits no state does not exist, and where the entry cannot tell
whether it holds all the reading says unknown, never whole.
"""

from __future__ import annotations

import ast
import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from malspark.agents.function_map import _INDEX_KIND
from malspark.agents.mcp_client import TRUNCATION_MARKER
from malspark.agents.output_shortening import our_key_in, shorten_json_document
from malspark.analysis import behaviour_code, directed_text
from malspark.pipeline.function_claims import function_facts
from malspark.schemas import entry_reading as reading_module
from malspark.schemas.answer_completeness import completeness_line, read_answer
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
from malspark.tools import artefact_index, upx
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


# The record a tool of the index's declared kind stores.
_INDEX_FACTS = {"v": 1, "kind": _INDEX_KIND}


def _indexed(document: Any, **fields: Any) -> dict[str, Any]:
    return _entry(json.dumps(document), source="pack", facts=_INDEX_FACTS, **fields)


# Each kind whose own reader reads coverage fields, and the one definition it reads them by.
_COVERED_KINDS = {
    _INDEX_KIND: artefact_index.COVERAGE_FIELDS,
    behaviour_code.KIND: behaviour_code.COVERAGE_FIELDS,
    directed_text.KIND: directed_text.COVERAGE_FIELDS,
    upx.KIND: upx.COVERAGE_FIELDS,
}


def _of_kind(kind: str, document: Any) -> dict[str, Any]:
    return _entry(json.dumps(document), source="pack", facts={"v": 1, "kind": kind})


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
    WHOLE_WITH_GAPS: (_indexed({"rows": [], "calls_unnamed": {"0x1000": 2}}), {}),
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
        entry = _indexed({"rows": [1], "next_offset": 1, "calls_unnamed": {"0x10": 1}})

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

        assert entry_reading(entry).states == (ONE_PAGE, STRUCTURE_DROPPED)

    def test_a_cut_without_a_count_is_still_cut_as_text(self) -> None:
        entry = _entry("the first part of a long prose answer…", truncated=True)

        assert entry_reading(entry).state == CUT_AS_TEXT

    def test_gap_fields_at_zero_are_not_gaps_and_a_missing_one_is_unknown(self) -> None:
        given = {
            "rows": [],
            "calls_unnamed": {},
            "undecoded_functions": 0,
            "unplaced": {},
            "absent": {},
            "imports_cut": "",
        }
        zero = entry_reading(_indexed(given))
        left_out = entry_reading(_indexed({"rows": [], "calls_unnamed": {}}))

        assert zero.states == (WHOLE,)
        assert zero.gaps_zero == frozenset(artefact_index.COVERAGE_FIELDS)
        assert not zero.gap_unknown("calls_unnamed") and not zero.gaps_unknown
        assert zero.gap_unknown("errors")
        assert left_out.states == (WHOLE,) and left_out.gaps_unknown
        assert left_out.gap_unknown("undecoded_functions")


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
            _indexed({"rows": [], "calls_unnamed": {"0x1": 1}}),
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
    "page and gaps": json.dumps({"rows": ["a"], "has_more": True, "calls_unnamed": {"0x1": 1}}),
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
            (None, _INDEX_FACTS),
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
            facts,
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
                facts=facts,
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


_STRINGS = [f"s{i}" for i in range(6)]


class TestALaterPageIsAPage:
    @pytest.mark.parametrize("word", ["offset", "page_offset", "skip", "start_index"])
    @pytest.mark.parametrize(
        "beside",
        [
            {},
            {"next_offset": None},
            {"next_offset": 106},
            {"total": 106},
            {"total": 300},
            {"truncated": False},
        ],
    )
    def test_a_paged_mapping_s_own_start_after_the_first_row_makes_a_page(
        self, word: str, beside: dict[str, Any]
    ) -> None:
        for start, nested in itertools.product((1, 100), (False, True)):
            page = {"strings": _STRINGS, word: start, **beside}
            document = {"tool": "t", "result": page} if nested else page

            reading = entry_reading(_entry(json.dumps(document)))

            assert ONE_PAGE in reading.states, (start, nested)
            assert reading.members_not_kept is None
            missing = reading.member(str(len(_STRINGS)))
            assert missing is not None and missing.state == MEMBER_NOT_KEPT

    @pytest.mark.parametrize("word", ["offset", "page_offset", "skip", "start_index"])
    def test_a_start_at_the_first_row_alone_is_no_page(self, word: str) -> None:
        reading = entry_reading(_entry(json.dumps({"strings": _STRINGS, word: 0})))

        assert reading.states == (WHOLE,) and reading.members_not_kept == 0

    def test_the_line_agents_read_does_not_read_the_start(self) -> None:
        last = {"strings": _STRINGS, "total": 106, "page_offset": 100, "next_offset": None}

        line = completeness_line(last, args={"offset": 100}, text_chars=len(json.dumps(last)))
        held = read_answer(last, args={"offset": 100})

        assert entry_reading(_entry(json.dumps(last))).state == ONE_PAGE
        assert line == "" and not held.partial and not held.capped
        assert held.starts == [(100, True)]

    @pytest.mark.parametrize(
        "output",
        [
            "Rows 120 to 519 of 1,162; the next page starts at 520.",
            json.dumps(_STRINGS),
            json.dumps({"strings": _STRINGS}),
            "",
        ],
    )
    def test_only_the_call_s_offset_argument_leaves_the_paging_unknown(self, output: str) -> None:
        for start in (1, 120):
            reading = entry_reading(_entry(output, args={"offset": start, "limit": 400}))

            assert ONE_PAGE not in reading.states
            assert reading.paging_unknown is True
            assert reading.members_not_kept is None
        assert entry_reading(_entry(output, args={"offset": 0})).paging_unknown is False

    @pytest.mark.parametrize(
        "paging",
        [
            {"limit": 6},
            {"page_size": 6},
            {"total": 60},
            {"page": 3},
            {"pages": 10},
            {"has_more": False},
            {"next_offset": None},
            {"cursor": "c"},
        ],
    )
    @pytest.mark.parametrize("word", ["offset", "page_offset", "skip", "start_index"])
    def test_a_start_in_a_paging_block_beside_the_rows_makes_a_page(
        self, word: str, paging: dict[str, Any]
    ) -> None:
        for start in (1, 54):
            document = {"rows": _STRINGS, "paging": {word: start, **paging}}

            reading = entry_reading(_entry(json.dumps(document)))

            assert ONE_PAGE in reading.states, (start, paging)
            assert reading.paging_unknown is False and reading.members_not_kept is None

    @pytest.mark.parametrize(
        "block",
        [
            {"offset": 4096},
            {"offset": 4096, "present": True, "size": 10},
            {"page_offset": 4096, "length": 10, "name": "x"},
        ],
    )
    def test_a_start_in_a_block_with_no_paging_word_is_no_signal(
        self, block: dict[str, Any]
    ) -> None:
        document = {"rows": _STRINGS, "overlay": block}

        reading = entry_reading(_entry(json.dumps(document)))
        argued = entry_reading(_entry(json.dumps(document), args={"offset": 50}))

        assert reading.states == (WHOLE,)
        assert reading.paging_unknown is False and reading.members_not_kept == 0
        assert argued.states == (WHOLE,) and argued.paging_unknown is True

    def test_an_own_start_at_the_first_row_is_read_over_the_argument(self) -> None:
        document = {"strings": _STRINGS, "offset": 0}

        reading = entry_reading(_entry(json.dumps(document), args={"offset": 50}))

        assert reading.states == (WHOLE,) and reading.paging_unknown is False


class TestGapsAreReadOnlyWhereTheKindCountsThem:
    @pytest.mark.parametrize("kind", sorted(_COVERED_KINDS))
    def test_every_coverage_field_the_kind_s_reader_reads_is_a_gap(self, kind: str) -> None:
        fields = _COVERED_KINDS[kind]
        for name in fields:
            reported = entry_reading(_of_kind(kind, {"rows": [], name: 3}))
            zero = entry_reading(_of_kind(kind, {"rows": [], name: 0}))

            assert reported.gap_fields is fields
            assert reported.states == (WHOLE_WITH_GAPS,) and reported.gaps == {name: 3}
            assert zero.states == (WHOLE,) and name in zero.gaps_zero

    @pytest.mark.parametrize("kind", sorted(_COVERED_KINDS))
    def test_a_kind_s_gaps_are_read_from_its_reader_s_one_definition(self, kind: str) -> None:
        assert reading_module._coverage_counts(_of_kind(kind, {})) is _COVERED_KINDS[kind]

    @pytest.mark.parametrize(
        "facts", [None, {"v": 1, "kind": "unclassified"}, {"v": 1, "kind": "strings"}]
    )
    def test_an_answer_whose_kind_counts_no_gap_has_its_gaps_unknown(
        self, facts: dict[str, Any] | None
    ) -> None:
        covered = {name for fields in _COVERED_KINDS.values() for name in fields}
        names = [*sorted(covered), "errors", "skipped", "missing"]
        documents: list[dict[str, Any]] = [{"rows": [], **dict.fromkeys(names, 3)}, {"rows": []}]
        for document in documents:
            entry = _entry(json.dumps(document), source="mcp:x", facts=facts)

            reading = entry_reading(entry)

            assert reading.states == (WHOLE,)
            assert reading.gap_fields == () and reading.gaps == {}
            assert reading.gaps_unknown
            assert all(reading.gap_unknown(name) for name in names)

    def test_the_module_holds_no_word_of_a_gap_field(self) -> None:
        tree = ast.parse(Path(reading_module.__file__).read_text(encoding="utf-8"))
        texts = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        covered = {name for fields in _COVERED_KINDS.values() for name in fields}

        # An entry state's own name may spell a field; no other text of the module does.
        assert not (texts - set(ENTRY_STATES)) & covered

    def test_the_index_s_head_says_every_gap_the_reading_reads(self) -> None:
        document = {
            "rows": [{"address": "0x401000"}],
            "calls_unnamed": {},
            "undecoded_functions": 2,
            "unplaced": {"hashes": 3},
            "absent": {"rules": "no: not joined"},
            "imports_cut": "import table cut at 512",
        }

        head = artefact_index.head_text(document, 1)
        reading = entry_reading(_indexed(document))

        assert reading.states == (WHOLE_WITH_GAPS,)
        assert set(reading.gaps) == {"undecoded_functions", "unplaced", "absent", "imports_cut"}
        assert reading.gaps_zero == {"calls_unnamed"}
        for said in ("rules: no: not joined", "2 functions", "hashes 3", "cut at 512"):
            assert said in head

    def test_the_kind_s_reader_reads_the_same_counts(self) -> None:
        document = {"image_base": "0x400000", "rows": [], "calls_unnamed": {"0x401000": 2}}
        entry = LedgerEntry.model_validate(
            _indexed(document, tool="index", stage="analysis", agent="static")
        )

        facts = function_facts([entry], None)

        assert entry_reading(entry).gaps == {"calls_unnamed": {"0x401000": 2}}
        assert facts.unnamed == {0x1000: 2}


class TestAFullPageUnderABoundingArgument:
    @pytest.mark.parametrize("name", ["limit", "k", "max_results", "packet_limit", "page_size"])
    def test_a_primary_list_as_long_as_a_bounding_argument_leaves_the_paging_unknown(
        self, name: str
    ) -> None:
        for document in (_STRINGS, {"query": "q", "matches": _STRINGS}):
            full = entry_reading(_entry(json.dumps(document), args={name: len(_STRINGS)}))
            short = entry_reading(_entry(json.dumps(document), args={name: len(_STRINGS) + 1}))

            assert full.states == (WHOLE,) and full.paging_unknown is True
            assert full.members_not_kept is None
            assert full.member(str(len(_STRINGS))).state == MEMBER_NOT_KEPT  # type: ignore[union-attr]
            assert short.paging_unknown is False and short.members_not_kept == 0

    @pytest.mark.parametrize("name", ["n", "count", "length", "buffer_size", "size"])
    def test_a_numeric_argument_that_bounds_nothing_keeps_the_reading(self, name: str) -> None:
        for document in (_STRINGS, {"query": "q", "matches": _STRINGS}):
            reading = entry_reading(_entry(json.dumps(document), args={name: len(_STRINGS)}))

            assert reading.states == (WHOLE,)
            assert reading.paging_unknown is False and reading.members_not_kept == 0

    def test_a_marker_beside_the_full_page_decides_instead(self) -> None:
        document = {"matches": _STRINGS, "has_more": False}

        reading = entry_reading(_entry(json.dumps(document), args={"limit": len(_STRINGS)}))

        assert reading.paging_unknown is False and reading.members_not_kept == 0


class TestTheStatesAreCounted:
    def test_there_are_five_member_states_and_the_module_says_five(self) -> None:
        doc = reading_module.__doc__ or ""

        assert len(MEMBER_STATES) == len(set(MEMBER_STATES)) == 5
        assert "There are five." in doc
        assert [f"M{n}" in doc for n in range(1, 7)] == [True] * 5 + [False]

    def test_a_sentence_takes_every_state_and_a_dropped_structure_stands_after_the_gaps(
        self,
    ) -> None:
        entry = _indexed(
            {"rows": [], "calls_unnamed": {"0x10": 1}},
            spilled=[{"part": "structured", "key": "k", "bytes": 4, "sha256": "cd"}],
        )

        reading = entry_reading(entry)

        order = ENTRY_STATES.index
        assert order(ONE_PAGE) < order(WHOLE_WITH_GAPS) < order(STRUCTURE_DROPPED)
        assert reading.states == (WHOLE_WITH_GAPS, STRUCTURE_DROPPED)
        assert "most restrictive cell over ALL" in " ".join((reading_module.__doc__ or "").split())


class TestEdgesOfTheReading:
    def test_an_entry_cut_as_text_that_is_still_a_document_has_its_pages_and_gaps_read(
        self,
    ) -> None:
        document = {"rows": ["a", "b", "c"], "next": "t", "calls_unnamed": {"0x10": 1}}
        for fields in ({"truncated": True}, {"chars_dropped": 40}):
            entry = _indexed(document, **fields)

            reading = entry_reading(entry)

            assert reading.states == (CUT_AS_TEXT, ONE_PAGE, WHOLE_WITH_GAPS), fields

    def test_a_repeat_held_by_a_repeat_gives_each_state_once(self) -> None:
        for holder_fields in ({"repeated_of": "ev_0000"}, {"repeated_of": "ev_0002"}):
            holder = _entry("served again", id="ev_0002", **holder_fields)
            repeat = _entry("served again", repeated_of="ev_0002")

            reading = entry_reading(repeat, holder=holder)

            assert reading.states == (REPEAT,)

    @pytest.mark.parametrize(
        "value", ["abc", [1], {"x": 1}, None, True, -5, 1e300, float("inf"), "12"]
    )
    def test_a_tool_s_own_key_in_the_shortener_s_shape_never_raises(self, value: Any) -> None:
        for row in (
            {"kept": value, "omitted": value},
            {"kept_chars": value, "omitted_chars": value},
        ):
            document = {"a": "x", "b": ["y"], "shortened": {"/a": row, "/b": {"omitted": value}}}
            others = {**document, "shortened": {"others": {"omitted": value}}}
            for held in (document, others):
                entry = _entry("{}", structured=held)

                reading = entry_reading(entry)

                assert reading.state in ENTRY_STATES

    def test_a_shortened_batch_whose_container_is_not_found_keeps_its_members_unknown(
        self,
    ) -> None:
        document = {
            f"0x{0x401000 + i * 4:x}": {"code": _routine(0x401000 + i * 4, 0x400000, 60), "n": i}
            for i in range(8)
        }

        entry = _shortened(document, len(json.dumps(document)) // 4)
        reading = entry_reading(entry)

        assert reading.state == SHORTENED and reading.members == ()
        assert reading.members_not_kept is None
        assert reading.member("0x401004").state == MEMBER_NOT_KEPT  # type: ignore[union-attr]


class TestANumberIsOneTheKeptValueConfirms:
    @pytest.mark.parametrize(
        ("value", "row", "state"),
        [
            ("a" * 10, {"kept_chars": 10, "omitted_chars": 40}, MEMBER_IN_PART),
            (["y"] * 2, {"kept": 2, "omitted": 3}, MEMBER_IN_PART),
            ("", {"kept_chars": 5, "omitted_chars": 40}, MEMBER_EMPTY),
            ([], {"kept": 0, "omitted": 3}, MEMBER_EMPTY),
            ("a" * 10, {"kept_chars": 0, "omitted_chars": 40}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": None, "omitted_chars": 5}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": "abc"}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": 10**30, "omitted_chars": -5}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": 10, "omitted_chars": 0}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": 12, "omitted_chars": 40}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept": 10, "omitted": 3}, MEMBER_UNMEASURED),
            (["y"] * 2, {"kept_chars": 2, "omitted_chars": 3}, MEMBER_UNMEASURED),
            ("a" * 10, {"kept_chars": True, "omitted_chars": 40}, MEMBER_UNMEASURED),
        ],
    )
    def test_a_member_is_in_part_only_where_its_kept_value_confirms_its_row(
        self, value: Any, row: dict[str, Any], state: str
    ) -> None:
        document = {"rows": [value, "whole"], "shortened": {"/rows/0": row}}
        entry = _entry(json.dumps(document), truncated=True, structured=document)

        member = entry_reading(entry).member("0")

        assert member is not None and member.state == state
        if state == MEMBER_IN_PART:
            assert member.kept == len(value)
            assert member.unit == ("characters" if isinstance(value, str) else "elements")

    def test_a_member_nested_however_deep_is_read_without_the_interpreter_s_stack(self) -> None:
        deep: Any = "x"
        empty: Any = ""
        for _ in range(100_000):
            deep, empty = [deep], {"n": empty}

        assert reading_module._holds_text(deep) is True
        assert reading_module._holds_text(empty) is False


class TestAnAnswerNestedPastTheDecoder:
    @pytest.mark.parametrize(
        ("opening", "state"),
        [
            ('{"error": "boom", "n": ', FAILED),
            ('{"tool_error": "boom", "n": ', FAILED),
            ('{"error": {"code": "x"}, "n": ', FAILED),
            ('{"error": "  ", "n": ', WHOLE),
            ('{"n": ', WHOLE),
        ],
    )
    def test_it_is_read_as_failed_by_the_error_key_it_opens_with(
        self, opening: str, state: str
    ) -> None:
        output = opening + "[" * 30_000 + "]" * 30_000 + "}"

        assert entry_reading(_entry(output)).state == state


class TestWhatTheStoreAndTheCutRecord:
    _ANSWER = [{"part": "answer", "key": "evidence/job/cd", "bytes": 9, "sha256": "cd"}]

    @pytest.mark.parametrize(
        ("fields", "whole"),
        [
            ({"spilled": _ANSWER}, True),
            ({"spilled": _SPILLED_OUTPUT}, True),
            ({"spilled": _SPILLED_OUTPUT, "chars_dropped": 40}, False),
            ({"spilled": _SPILLED_OUTPUT, "not_shown": True}, False),
            ({"spilled": [*_SPILLED_OUTPUT, *_ANSWER], "chars_dropped": 40}, True),
            ({}, False),
        ],
    )
    def test_the_store_holds_the_answer_whole_only_where_the_stored_part_is_the_answer(
        self, fields: dict[str, Any], whole: bool
    ) -> None:
        read = entry_reading(_entry(truncated=True, **fields))

        assert read.state in (BLANKED_READ, BLANKED_UNREAD)
        assert read.answer_stored_whole is whole

    def test_a_text_cut_records_its_extent_only_where_it_records_its_drop(self) -> None:
        head = "int f(void) { return 0; }"
        kept = head + TRUNCATION_MARKER

        # The cut mark is the platform's, not the answer's: the kept head alone is counted.
        assert entry_reading(_entry(kept, truncated=True, chars_dropped=40)).text_extent == (
            len(head),
            len(kept) + 40,
        )
        assert entry_reading(_entry(kept, truncated=True)).text_extent is None
        assert entry_reading(_entry(kept)).text_extent is None

    @pytest.mark.parametrize(
        "kept",
        [
            "The routine returns zero.",
            "int f(void) {" + TRUNCATION_MARKER + "}",
            TRUNCATION_MARKER,
        ],
        ids=["a summary", "a head and a tail", "the mark alone"],
    )
    def test_a_text_cut_not_ending_with_a_kept_head_and_the_mark_records_no_extent(
        self, kept: str
    ) -> None:
        read = entry_reading(_entry(kept, truncated=True, chars_dropped=400))

        assert read.state == CUT_AS_TEXT
        assert read.text_extent is None
