"""A quoted value its cited entry holds only in the echo of the call's own arguments is asked once.

A tool's stored answer may repeat the call it answers: a search answer carries
the pattern it was given. Read whole, such an answer holds every term of the
query, matched or not. A quoted value that a cited entry holds only inside
what its call was asked for, never in what the answer found, is asked about
once: the fact is that the answer does not hold it, and the question asks the
model to say what the answer holds or to state the value without attributing
it to the entry. A value that is the whole of an argument is the call's own
target and is not asked; a value the sentence names as absent is not asked; an
entry whose text is not the whole answer says nothing of what it lacks. The
sentence is never rewritten.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.validation import (
    ASKED_BY_VALUE,
    KEPT_WITH_A_FINDING,
    MARKED_IN_PLACE,
    VALUE_ONLY_IN_CALL_ARGUMENTS_CODE,
    EntryTexts,
    cited_row_text,
    echoed_argument_citations,
    feedback_text,
    raised_only_in_retry,
    record_flagged_statements,
)
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.schemas.evidence import LedgerEntry

# Invented terms of an invented search: one the answer matched, two it did not.
PATTERN = "re:(?i)(lanternfish|quillwort|marrowgate)"
MATCHED = "lanternfish"
QUILL = "quillwort"
MARROW = "marrowgate"


def _entry(entry_id: str, tool: str, output: str, **over: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id, agent="static", server="static", tool=tool, output=output, **over
    )


def _search_answer() -> str:
    return json.dumps(
        {
            "pattern": PATTERN,
            "strings": [{"offset": 4096, "text": f"the {MATCHED} table is ready"}],
            "total_matched": 1,
        }
    )


def _texts(*extra: LedgerEntry, truncated: bool = False) -> EntryTexts:
    return EntryTexts.from_ledger(
        [
            _entry(
                "ev_0030",
                "strings",
                _search_answer(),
                args={"pattern": PATTERN},
                truncated=truncated,
            ),
            _entry("ev_0027", "process_tree", json.dumps({"processes": ["host.exe"]})),
            *extra,
        ]
    )


def _body(sentence: str, texts: EntryTexts | None = None) -> list[Any]:
    return echoed_argument_citations({"body": sentence}, texts or _texts(), prose=("body",))


class TestTheCheck:
    def test_a_term_held_only_in_the_echoed_pattern_is_asked(self) -> None:
        sentence = f"The string evidence contains the term '{QUILL}' [ev_0030]."

        (found,) = _body(sentence)

        assert found.code == VALUE_ONLY_IN_CALL_ARGUMENTS_CODE
        assert found.values == (QUILL,)
        assert found.quoted == (sentence,)

    def test_two_terms_of_one_sentence_are_one_question(self) -> None:
        sentence = (
            f"The string evidence contains the terms '{QUILL}' and '{MARROW}' [ev_0030], but "
            "neither appears in an observed command line [ev_0027]."
        )

        (found,) = _body(sentence)

        assert found.values == (QUILL, MARROW)

    def test_a_term_the_answer_found_is_not_asked(self) -> None:
        assert _body(f"The string evidence contains the term '{MATCHED}' [ev_0030].") == []

    def test_a_value_that_is_the_whole_argument_is_the_call_s_target(self) -> None:
        texts = EntryTexts.from_ledger(
            [
                _entry(
                    "ev_0040",
                    "strings",
                    json.dumps({"pattern": QUILL, "strings": [], "total_matched": 0}),
                    args={"pattern": QUILL},
                )
            ]
        )

        assert _body(f"A string search for '{QUILL}' ran [ev_0040].", texts) == []

    def test_a_match_equal_to_the_argument_is_the_answer_s_and_is_not_asked(self) -> None:
        # The answer found the very text it was asked for: only the leaf under the
        # call's own argument key is an echo; the match row is what the answer holds.
        searched = f"{MATCHED} delete {QUILL}"
        texts = EntryTexts.from_ledger(
            [
                _entry(
                    "ev_0060",
                    "strings",
                    json.dumps({"pattern": searched, "strings": [{"text": searched}]}),
                    args={"pattern": searched},
                )
            ]
        )

        assert _body(f"The string evidence holds 'delete {QUILL}' [ev_0060].", texts) == []

    def test_a_value_named_as_absent_is_not_asked(self) -> None:
        sentence = f"The string evidence does not contain '{QUILL}' [ev_0030]."

        assert _body(sentence) == []

    def test_a_value_no_cited_entry_holds_is_left_to_the_other_checks(self) -> None:
        assert _body(f"The string evidence contains the term '{QUILL}' [ev_0027].") == []

    def test_an_entry_whose_text_is_not_the_whole_answer_is_not_read_for_absence(self) -> None:
        sentence = f"The string evidence contains the term '{QUILL}' [ev_0030]."

        assert _body(sentence, _texts(truncated=True)) == []

    def test_an_echo_in_a_text_answer_is_masked_as_written(self) -> None:
        argument = r"re:cmd\.exe|loom /c|wmic"
        texts = EntryTexts.from_ledger(
            [
                _entry(
                    "ev_0050",
                    "grep",
                    f'searched "{json.dumps(argument)[1:-1]}" and {argument}\nline 1: wmic.bat',
                    args={"pattern": argument},
                )
            ]
        )

        (found,) = _body("The routine runs 'loom /c' [ev_0050].", texts)

        assert found.values == ("loom /c",)

    def test_a_row_string_is_read_under_its_row_s_citations(self) -> None:
        row = {"name": f"Wipe through '{QUILL}'", "evidence_refs": ["ev_0030"]}

        (found,) = echoed_argument_citations({"commands": [row]}, _texts())

        assert found.quoted == (cited_row_text(row["name"], row),)


class TestTheFindingAndItsQuestion:
    def test_the_message_states_the_fact(self) -> None:
        (found,) = _body(f"The string evidence contains the term '{QUILL}' [ev_0030].")

        assert found.message == (
            f"'{QUILL}' is not in the answer of ev_0030 (strings), which the text cites for it; "
            "it stands only in what that call was asked for."
        )

    def test_several_values_are_stated_together(self) -> None:
        (found,) = _body(f"It holds '{QUILL}' and '{MARROW}' [ev_0030].")

        assert found.message == (
            f"'{QUILL}', '{MARROW}' are not in the answer of ev_0030 (strings), which the text "
            "cites for them; they stand only in what that call was asked for."
        )

    def test_the_instruction_is_in_the_question_sent_alone(self) -> None:
        (found,) = _body(f"The string evidence contains the term '{QUILL}' [ev_0030].")

        assert found.shown == (
            "Say what the entry's answer holds, or state the value without attributing it to "
            "the entry."
        )
        assert "Say what" not in found.message
        assert found.shown in feedback_text([found])

    def test_the_mark_names_the_value_and_the_entry(self) -> None:
        (found,) = _body(f"The string evidence contains the term '{QUILL}' [ev_0030].")

        assert found.labels == (f'"{QUILL}" is only in what ev_0030 was asked for',)

    def test_its_code_sets_are_its_sibling_s(self) -> None:
        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in KEPT_WITH_A_FINDING
        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in MARKED_IN_PLACE
        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in ASKED_BY_VALUE

    def test_a_retry_that_keeps_the_value_in_a_new_sentence_was_asked(self) -> None:
        (asked,) = _body(f"The string evidence contains the term '{QUILL}' [ev_0030].")
        (again,) = _body(f"The answer lists '{QUILL}' [ev_0030].")
        (new,) = _body(f"The answer lists '{MARROW}' [ev_0030].")

        assert not raised_only_in_retry(again, [asked])
        assert raised_only_in_retry(new, [asked])


class TestTheReport:
    def test_a_kept_sentence_is_printed_as_written_with_the_mark_after_it(self) -> None:
        sentence = f"The string evidence contains the term '{QUILL}' [ev_0030]."
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            technical_analysis=TechnicalAnalysis(
                evasion_antiforensics=TechnicalSubsection(title="Evasion", body=sentence)
            ),
        )
        record_flagged_statements(report, _body(sentence))

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "string evidence contains" in line)
        assert "[ev_0030]" in line
        assert "held only in what the call was asked for" in line
        assert "is only in what ev_0030 was asked for" in line


class TestWhereItIsAsked:
    def test_a_composer_section_is_asked(self) -> None:
        from malspark.reporting.composer import ReportComposer, _ProseOut
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        composer = object.__new__(ReportComposer)
        composer._grounding = _grounding()
        composer._items = None
        payload = {"body": f"It holds '{QUILL}' [ev_0030].", "evidence_refs": []}

        found = composer._section_findings(
            payload, _ProseOut, ("body",), _texts(), ["ev_0030", "ev_0027"], None, None
        )

        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in {v.code for v in found}

    def test_the_narrative_s_structured_answer_is_read(self) -> None:
        from malspark.pipeline.validation import ValidationTally
        from malspark.reporting.narrative_agent import NarrativeAgent, NarrativeOutput
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        agent = object.__new__(NarrativeAgent)
        agent._items = None
        agent._report = None
        agent.validation_tally = ValidationTally()
        output = NarrativeOutput.model_construct(
            executive_summary=f"The strings hold '{QUILL}' [ev_0030].",
            key_findings=[],
            defensive_recommendations=[],
        )

        agent._kept_with_ungrounded_recorded(
            output, _grounding(), ["ev_0030"], ["ev_0030"], _texts()
        )

        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in {
            row["code"] for row in agent.validation_tally.unresolved
        }

    def test_an_agreement_rewrite_is_read(self) -> None:
        from malspark.reporting.section_agreement import _rewrite_violations

        found = _rewrite_violations(
            f"The strings hold '{QUILL}' [ev_0030].", ["ev_0030"], None, _texts()
        )

        assert VALUE_ONLY_IN_CALL_ARGUMENTS_CODE in {v.code for v in found}
