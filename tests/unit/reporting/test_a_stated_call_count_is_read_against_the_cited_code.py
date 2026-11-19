"""A stated count of calls is read against the calls the cited entry's code writes.

A sentence that states how many times a routine calls another ("calls the
mixer FUN_00401900 eight times", "FUN_00401900 is called three times", "three
calls of FUN_00401900") names the routine it counts in the count's own words;
that count can be read against the code the entry it cites holds: the number
of places that code writes ``name(``, the routine's own definition not
counted. Only an entry whose tool lists code is read. Where the two differ the
model is asked once, with the fact alone — what the sentence states and what
the code writes, in which functions — and states the number the code shows or
says what its number counts (calls per loop iteration, executions). A count
of callers or call sites counts places across the whole image, not the calls
one function's code writes, and is not read; neither are references, "once"
and "twice". Nothing is rewritten.
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
            # A tool that lists no code, whose answer still writes a name and
            # a bracket: a field describing a layout, three times.
            LedgerEntry(
                id="ev_0097",
                agent="code",
                server="code",
                tool="decode_blobs",
                output=json.dumps(
                    {
                        "results": [
                            {"layout": "seed (4), length (2), text", "text": t}
                            for t in ("one", "two", "three")
                        ]
                        + [{"note": "FUN_00401900(block) is listed here"}]
                    }
                ),
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
        assert len(_body("FUN_00401900 is called five times in the routine [ev_0095].")) == 1

    def test_callers_call_sites_references_once_and_twice_are_not_read(self) -> None:
        assert _body("FUN_00401900 has two callers [ev_0095].") == []
        assert _body("FUN_00401900 has five call sites [ev_0095].") == []
        assert _body("There are 3 call sites of FUN_00401900 [ev_0095].") == []
        assert _body("FUN_00401900 has three references [ev_0095].") == []
        assert _body("The routine calls FUN_00401900 twice [ev_0095].") == []
        assert _body("The routine calls FUN_00401900 once per byte [ev_0095].") == []

    def test_an_identifier_the_cited_code_does_not_call_is_not_read(self) -> None:
        assert _body("The mixer is called three times [ev_0096].") == []

    def test_the_routine_counted_is_the_one_the_count_names(self) -> None:
        """A name elsewhere in the sentence is not what the count counts."""
        assert _body("FUN_00401900 mixes the block; the decoder has 3 call sites [ev_0095].") == []
        assert _body("The decoder (3 call sites) reaches FUN_00401900 [ev_0095].") == []
        assert _body("FUN_00401900 runs 3 times per block [ev_0095].") == []

    def test_a_routine_another_word_governs_is_not_read(self) -> None:
        """A pronoun or a preposition between the verb and a name leaves the phrase naming
        nothing: the routine counted is not the one written there."""
        assert _body("FUN_00401900 is called by FUN_00401200 3 times [ev_0095].") == []
        assert _body("FUN_00401900 is called from FUN_00401200 3 times [ev_0095].") == []
        assert _body("FUN_00401900 was called by FUN_00401200 three times [ev_0095].") == []
        assert _body("The mixer FUN_00401900 makes 5 calls to it in FUN_00401200 [ev_0095].") == []
        assert _body("The block calls it via FUN_00401900 3 times [ev_0095].") == []
        assert _body("The routine calls them within FUN_00401900 3 times [ev_0095].") == []

    def test_a_number_is_read_whole(self) -> None:
        assert _body("The routine makes 1,000 calls to FUN_00401900 [ev_0095].") == []
        assert _body("The routine calls FUN_00401900 2.5 times per block [ev_0095].") == []
        assert _body("The routine makes 1000 calls to FUN_00401900 [ev_0095].") == []

    def test_a_number_inside_a_longer_token_is_not_read(self) -> None:
        """A count is a token of its own: digits ending a name, a hex number, a range or a
        compound number word are not read as it."""
        assert _body("The RC4 calls to FUN_00401900 mix the block [ev_0095].") == []
        assert _body("The RC2 calls to FUN_00401900 mix the block [ev_0095].") == []
        assert _body("The SHA256 calls to FUN_00401900 mix the block [ev_0095].") == []
        assert _body("The Win32 calls to FUN_00401900 mix the block [ev_0095].") == []
        assert _body("It makes 0x10 calls to FUN_00401900 [ev_0095].") == []
        assert _body("It makes 3-4 calls to FUN_00401900 [ev_0095].") == []
        assert _body("It makes 4-5 calls to FUN_00401900 [ev_0095].") == []
        assert _body("It makes twenty-one calls to FUN_00401900 [ev_0095].") == []

    def test_a_count_in_brackets_is_read(self) -> None:
        (found,) = _body("The mixer is busy (3 calls to FUN_00401900) [ev_0095].")

        assert found.message.startswith("The text states '3 calls' and names FUN_00401900; ")

    def test_an_entry_stored_cut_is_not_read(self) -> None:
        """A listing the platform stored cut may write more lines than it holds here: it is
        not counted and not named, and where every cited listing is cut nothing is asked."""
        cut = LedgerEntry(
            id="ev_0099",
            agent="code",
            server="code",
            tool="decompile_function",
            output=json.dumps({"code": CODE}),
            truncated=True,
        )
        whole = _texts()
        texts = EntryTexts.from_ledger([*whole.entries.values(), cut])

        assert (
            call_count_violations(
                {"body": "The routine calls FUN_00401900 three times [ev_0099]."},
                texts,
                prose=("body",),
            )
            == []
        )
        (found,) = call_count_violations(
            {"body": "The routine calls FUN_00401900 three times [ev_0095, ev_0099]."},
            texts,
            prose=("body",),
        )
        assert "ev_0099" not in found.message

    def test_an_entry_that_lists_no_code_is_not_read(self) -> None:
        assert _body("The routine calls seed 2 times [ev_0097].") == []
        assert _body("The routine calls FUN_00401900 three times [ev_0097].") == []

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
            "The text states 'three times' and names FUN_00401900; ev_0095 "
            "(decompile_function) writes 'FUN_00401900(' on 4 lines, letter case and spaces "
            "before the bracket aside."
        )

    def test_the_message_names_only_the_entries_whose_code_was_read(self) -> None:
        (found,) = _body(
            "The routine calls the mixer FUN_00401900 three times per block [ev_0095, ev_0097]."
        )

        assert "ev_0097" not in found.message
        assert "ev_0095 (decompile_function) writes 'FUN_00401900(' on 4 lines" in found.message

    def test_the_message_states_the_name_the_text_writes_and_what_the_code_writes(self) -> None:
        """An address the text names is stated as written, beside the name the code writes."""
        (found,) = _body("The routine calls 0x401900 three times [ev_0095].")

        assert found.message.startswith("The text states 'three times' and names 0x401900; ")
        assert "writes 'FUN_00401900(' on 4 lines" in found.message

    def test_every_line_writing_the_name_and_a_bracket_is_counted_in_the_message(self) -> None:
        """A prototype, a comment and a string that write the name and a bracket are lines
        that write them: the message counts what the lines hold, not what they mean."""
        code = (
            "void FUN_00401900(int a);\n"
            "void FUN_00401200(void)\n"
            "{\n"
            "  /* FUN_00401900(x) mixes */\n"
            "  FUN_00401900(1); FUN_00401900(2);\n"
            "}\n"
        )
        texts = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0098",
                    agent="code",
                    server="code",
                    tool="decompile_function",
                    output=json.dumps({"code": code}),
                )
            ]
        )

        (found,) = call_count_violations(
            {"body": "The routine calls FUN_00401900 nine times [ev_0098]."},
            texts,
            prose=("body",),
        )

        assert "writes 'FUN_00401900(' on 3 lines" in found.message

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

    def test_the_narrative_s_structured_answer_is_read(self) -> None:
        from malspark.pipeline.validation import ValidationTally
        from malspark.reporting.narrative_agent import NarrativeAgent, NarrativeOutput
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        agent = object.__new__(NarrativeAgent)
        agent._items = None
        agent._report = None
        agent.validation_tally = ValidationTally()
        output = NarrativeOutput.model_construct(
            executive_summary="The routine calls FUN_00401900 three times [ev_0095].",
            key_findings=[],
            defensive_recommendations=[],
        )

        agent._kept_with_ungrounded_recorded(
            output, _grounding(), ["ev_0095"], ["ev_0095"], _texts()
        )

        assert CALL_COUNT_DIFFERS_CODE in {row["code"] for row in agent.validation_tally.unresolved}

    def test_an_agreement_rewrite_is_accepted(self) -> None:
        """Any finding on an agreement rewrite refuses it, and a refused rewrite of a
        closing sentence leaves the sentence out: the count is not read there."""
        from malspark.reporting.section_agreement import _rewrite_violations

        found = _rewrite_violations(
            "The routine calls FUN_00401900 three times per loop [ev_0095].",
            ["ev_0095"],
            None,
            _texts(),
        )

        assert found == []

    def test_a_question_round_answer_is_read(self) -> None:
        import asyncio

        from malspark.reporting.question_round import answer_questions
        from tests.unit.reporting.test_a_question_asked_of_the_run_is_answered import (
            LEDGER,
            QUESTIONS,
            _reply,
            _report,
            _Reporter,
        )

        stated = _reply(
            1,
            "established",
            answer="The routine calls FUN_00401900 three times [ev_0095].",
            evidence_ids=["ev_0095"],
        )
        fixed = _reply(
            1,
            "established",
            answer="The routine's code writes four calls of FUN_00401900 [ev_0095].",
            evidence_ids=["ev_0095"],
        )
        reporter = _Reporter({"answers": [stated]}, {"answers": [fixed]})

        result = asyncio.run(
            answer_questions(
                reporter, _report(), QUESTIONS[:1], ledger=LEDGER, evidence_texts=_texts()
            )
        )

        assert result.tally.by_code.get(CALL_COUNT_DIFFERS_CODE) == 1
