"""A stated count of calls is read against the calls the cited entry's code writes.

A sentence that states how many times a routine calls another ("calls the
mixer eight times", "three calls of the decoder") can be read against the
code the entry it cites holds: the number of places that code writes
``name(``, the routine's own definition not counted. Where the two differ the
model is asked once, with the fact alone — what the sentence states and what
the code writes, in which functions — and states the number the code shows or
says what its number counts (calls per loop iteration, distinct callers,
executions). Only a number attached to a count of calls is read; callers,
references, "once" and "twice" count other things. Nothing is rewritten.
"""

from __future__ import annotations

import json

from malspark.pipeline.validation import (
    ASKED_BY_VALUE,
    CALL_COUNT_DIFFERS_CODE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    EntryTexts,
    call_count_violations,
    feedback_text,
)
from malspark.schemas.evidence import LedgerEntry

# An invented routine that calls an invented mixer four times.
CODE = (
    "void FUN_00401200(ulonglong *block)\n"
    "{\n"
    "  int i;\n"
    "  for (i = 0; i < 2; i = i + 1) {\n"
    "    FUN_00401900(block, 2, i);\n"
    "    FUN_00401900(block + 2, 4, i);\n"
    "  }\n"
    "  FUN_00401900(block, 8, 0);\n"
    "  FUN_00401900(block, 8, 1);\n"
    "  return;\n"
    "}\n"
)


def _texts() -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            LedgerEntry(
                id="ev_0095",
                agent="code",
                server="code",
                tool="decompile_function",
                args={"address": "0x401200"},
                output=json.dumps({"name": "FUN_00401200", "code": CODE}),
            ),
            LedgerEntry(
                id="ev_0096",
                agent="code",
                server="code",
                tool="strings",
                output=json.dumps({"strings": ["mixer"]}),
            ),
        ]
    )


def _body(sentence: str) -> list:
    return call_count_violations({"body": sentence}, _texts(), prose=("body",))


class TestTheCheck:
    def test_a_count_the_code_does_not_write_is_asked(self) -> None:
        sentence = "The routine calls the mixer FUN_00401900 three times per block [ev_0095]."

        (found,) = _body(sentence)

        assert found.code == CALL_COUNT_DIFFERS_CODE
        assert found.quoted == (sentence,)

    def test_the_count_the_code_writes_asks_nothing(self) -> None:
        assert _body("The routine calls FUN_00401900 four times [ev_0095].") == []

    def test_digits_and_the_nouns_of_calls_are_read(self) -> None:
        assert len(_body("It makes 3 calls to FUN_00401900 [ev_0095].")) == 1
        assert len(_body("FUN_00401900 has five call sites in the routine [ev_0095].")) == 1

    def test_callers_references_once_and_twice_are_not_read(self) -> None:
        assert _body("FUN_00401900 has two callers [ev_0095].") == []
        assert _body("FUN_00401900 has three references [ev_0095].") == []
        assert _body("The routine calls FUN_00401900 twice [ev_0095].") == []
        assert _body("The routine calls FUN_00401900 once per byte [ev_0095].") == []

    def test_an_identifier_the_cited_code_does_not_call_is_not_read(self) -> None:
        assert _body("The mixer is called three times [ev_0096].") == []

    def test_an_address_is_read_as_the_routine_s_name(self) -> None:
        (found,) = _body("The routine calls 0x401900 three times [ev_0095].")

        assert found.code == CALL_COUNT_DIFFERS_CODE

    def test_its_code_is_kept_with_a_finding_only(self) -> None:
        assert CALL_COUNT_DIFFERS_CODE in KEPT_WITH_A_FINDING
        assert CALL_COUNT_DIFFERS_CODE not in MARKED_IN_PLACE
        assert CALL_COUNT_DIFFERS_CODE not in ASKED_BY_VALUE


class TestTheFindingAndItsQuestion:
    def test_the_message_states_what_the_sentence_and_the_code_say(self) -> None:
        (found,) = _body(
            "The routine calls the mixer FUN_00401900 three times per block [ev_0095]."
        )

        assert found.message == (
            "The text states 'three times' for FUN_00401900, citing ev_0095; the code in "
            "ev_0095 (decompile_function) writes 4 calls of FUN_00401900 (in FUN_00401200), "
            "its own definition not counted."
        )

    def test_the_question_asks_for_the_number_or_what_it_counts(self) -> None:
        (found,) = _body(
            "The routine calls the mixer FUN_00401900 three times per block [ev_0095]."
        )

        assert found.shown == (
            "Read the cited code again: if your number counts something else (calls per loop "
            "iteration, distinct callers, executions), say what it counts; otherwise state the "
            "number the code shows."
        )
        assert found.shown in feedback_text([found])
        assert "Read the cited code" not in found.message


class TestWhereItIsAsked:
    def test_a_composer_section_is_asked(self) -> None:
        from malspark.reporting.composer import ReportComposer, _ProseOut
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        composer = object.__new__(ReportComposer)
        composer._grounding = _grounding()
        composer._items = None
        payload = {
            "body": "The routine calls FUN_00401900 three times [ev_0095].",
            "evidence_refs": [],
        }

        found = composer._section_findings(
            payload, _ProseOut, ("body",), _texts(), ["ev_0095"], None, None
        )

        assert CALL_COUNT_DIFFERS_CODE in {v.code for v in found}
