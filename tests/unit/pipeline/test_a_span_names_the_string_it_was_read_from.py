"""A finding's place is the string its check read, not every string equal to it.

A check matches inside a string of the answer; the place names that string and the
sentence of it the match stands in. A string equal to it somewhere else, a row
with the same value whose citation is right, a field the check never read, is not
named, and a text repeated through the answer costs no more to place than distinct
texts. A field name is written only where the schema declares it at that place.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel

from malspark.pipeline.validation import (
    EntryTexts,
    Violation,
    answer_of,
    citation_violations,
    cited_id_violations,
    locate_statements,
    placed,
    stated_value_violations,
    technique_name_violations,
    wrong_entry_citations,
)
from malspark.schemas.evidence import LedgerEntry
from tests.linear_cost import assert_scales
from tests.unit.pipeline.test_a_finding_names_its_statement import MARKER, _Body, _texts


class _Row(BaseModel):
    key: str
    value: str
    evidence_refs: list[str]


class _Rows(BaseModel):
    items: list[_Row]


class _Finding(BaseModel):
    text: str


class _Narrative(BaseModel):
    executive_summary: str
    key_findings: list[_Finding]


class TestOneStringOnePlace:
    def test_two_rows_with_the_same_value_name_only_the_wrong_one(self) -> None:
        value = MARKER  # one string object in both rows
        payload = {
            "items": [
                {"key": "k", "value": value, "evidence_refs": ["ev_0012"]},
                {"key": "k", "value": value, "evidence_refs": ["ev_0011"]},
            ]
        }

        with answer_of(_Rows):
            (found,) = wrong_entry_citations(payload, _texts())

        assert found.statements == ("items.1.value",)

    def test_the_same_string_in_a_field_the_check_did_not_read_is_not_named(self) -> None:
        said = "It cites [Foo]."
        payload = {"executive_summary": said, "notes": said}

        (found,) = citation_violations(payload, ["ev_0011"], prose=("executive_summary",))

        assert found.statements == ("executive_summary",)

    def test_the_same_sentence_in_two_fields_the_check_read_is_named_in_each(self) -> None:
        said = "It cites [Foo]."
        payload = {"a": said, "b": said, "c": said}

        (found,) = citation_violations(payload, ["ev_0011"], prose=("a", "b"))

        assert found.statements == ("a", "b")

    def test_only_the_row_that_matched_is_named_among_identical_rows(self) -> None:
        said = "It pads, T1027 (Binary Padding)."
        payload = {"rows": [said, "Plain.", said]}

        (found,) = technique_name_violations(payload)

        assert found.statements == ("?.0", "?.2")

    def test_equal_sentences_in_two_fields_a_check_matched_in_are_both_named(self) -> None:
        said = f'Holds "{MARKER}" [ev_0011].'
        payload = {"body": said, "text": said, "notes": f'Holds "{MARKER}" [ev_0012].'}

        (found,) = wrong_entry_citations(payload, _texts(), prose=("body",))

        assert found.statements == ("body", "?")


class TestPlacesInTheOrderOfTheAnswer:
    def test_an_item_in_two_fields_is_named_in_the_answers_order_not_the_prose_order(self) -> None:
        payload = {"executive_summary": "A [Foo].", "key_findings": [{"text": "B [Foo]."}]}

        with answer_of(_Narrative):
            (found,) = citation_violations(
                payload, ["ev_0011"], prose=("key_findings", "executive_summary")
            )

        assert found.statements == ("executive_summary", "key_findings.0.text")


class TestEveryRowAndSentenceTheFindingIsAbout:
    def test_every_unheld_row_of_a_stated_value_finding_is_named(self) -> None:
        payload = {
            "items": [
                {"key": "a", "value": "zzzq1", "evidence_refs": ["ev_0011"]},
                {"key": "b", "value": "zzzq2", "evidence_refs": ["ev_0011"]},
            ]
        }

        (found,) = stated_value_violations(payload, _texts())

        assert found.statements == ("items.0.value", "items.1.value")

    def test_a_cited_id_finding_names_its_row(self) -> None:
        entries = EntryTexts.from_ledger(
            [
                LedgerEntry(
                    id="ev_0011",
                    agent="p",
                    server="p",
                    tool="imports",
                    output='{"a": "VirtualAlloc"}',
                ),
                LedgerEntry(
                    id="ev_0012",
                    agent="p",
                    server="p",
                    tool="strings",
                    output='{"a": "kernel32.dll"}',
                ),
            ]
        )
        payload = {
            "functions": [
                {"id": "kernel32.dll", "evidence_refs": ["ev_0012"]},
                {"id": "VirtualAlloc", "evidence_refs": ["ev_0012"]},
            ]
        }

        (found,) = cited_id_violations(payload, entries)

        assert found.statements == ("?.1.?",)

    def test_a_wrong_citation_written_in_two_sentences_names_both(self) -> None:
        body = f'Holds "{MARKER}" [ev_0011]. Ok. Again "{MARKER}" [ev_0011].'

        (found,) = wrong_entry_citations({"body": body}, _texts(), prose=("body",))

        assert found.statements == ("body#0", "body#2")


class TestASpanResolvesToTheSentencesItCovers:
    @staticmethod
    def _at(text: str, begin: int, end: int) -> tuple[str, ...]:
        payload = placed({"body": text})
        violation = Violation(code="c", message="m", about=((payload["body"], begin, end),))
        with answer_of(_Body):
            (found,) = locate_statements([violation])
        return found.statements

    def test_a_span_that_is_a_whole_sentence_names_that_sentence_only(self) -> None:
        text = "One here. Two here. Three here."

        assert self._at(text, 10, 19) == ("body#1",)

    def test_a_span_that_starts_at_a_sentence_names_that_sentence_not_the_one_before(self) -> None:
        text = "One here. Two here. Three here."

        assert self._at(text, 10, 11) == ("body#1",)
        assert self._at(text, 0, 1) == ("body#0",)

    def test_a_span_ending_where_a_sentence_ends_does_not_name_the_next(self) -> None:
        text = "One here. Two here. Three here."

        assert self._at(text, 4, 9) == ("body#0",)

    def test_a_span_across_two_sentences_names_both(self) -> None:
        text = "One here. Two here. Three here."

        assert self._at(text, 5, 15) == ("body#0", "body#1")


class TestACodeSpanIsMaskedAtItsOwnWidth:
    def test_many_code_spans_before_a_citation_do_not_move_its_place(self) -> None:
        body = "`x` ok. " * 30 + "It cites [Foo]."

        (found,) = citation_violations({"body": body}, ["ev_0011"], prose=("body",))

        assert found.statements == ("body#30",)


class TestAFieldNameIsWrittenWhereTheSchemaDeclaresIt:
    def test_a_top_level_field_nested_where_it_is_not_declared_is_a_question_mark(self) -> None:
        payload = {"key_findings": [{"executive_summary": "Bad [Foo]."}]}

        with answer_of(_Narrative):
            (found,) = citation_violations(
                payload, ["ev_0011"], prose=("executive_summary", "key_findings")
            )

        assert found.statements == ("key_findings.0.?",)

    def test_a_field_named_by_a_check_is_written_at_the_top_level_only(self) -> None:
        payload = {"x": {"body": "Bad [Foo]."}}

        (found,) = citation_violations(payload, ["ev_0011"], prose=("x", "body"))

        assert found.statements == ("x.?",)

    def test_a_declared_name_nested_under_itself_is_not_declared_there(self) -> None:
        payload = {"key_findings": [{"key_findings": "It pads, T1027 (Binary Padding)."}]}

        with answer_of(_Narrative):
            (found,) = technique_name_violations(payload)

        assert found.statements == ("key_findings.0.?",)


class TestIdenticalStringsCostNoMoreThanDistinctOnes:
    def test_many_identical_key_findings_are_checked_for_citations_in_proportion(self) -> None:
        def build(size: int) -> dict[str, Any]:
            return {"key_findings": [{"text": "Same item [Foo]."} for _ in range(size)]}

        def call(payload: dict[str, Any]) -> None:
            (found,) = citation_violations(payload, ["ev_0011"], prose=("key_findings",))
            assert len(found.statements) <= 65

        assert_scales(build, 500, call, factor=8)

    def test_many_identical_key_findings_are_checked_for_technique_names_in_proportion(
        self,
    ) -> None:
        def build(size: int) -> dict[str, Any]:
            return {
                "key_findings": [{"text": "It pads, T1027 (Binary Padding)."} for _ in range(size)]
            }

        def call(payload: dict[str, Any]) -> None:
            (found,) = technique_name_violations(payload)
            assert found.statements

        assert_scales(build, 250, call, factor=8)


def test_a_place_is_written_from_declared_names_positions_and_marks_only() -> None:
    payload = {"evil_example_com_4444": ["It pads, T1027 (Binary Padding)."]}

    (found,) = technique_name_violations(payload)

    assert all(re.fullmatch(r"\?\.\d+|\?", place) for place in found.statements)
