"""A finding about a rewrite or a reply is placed in the answer it is about.

The agreement round's rewrite is read as a report round reads its prose, and
its finding names the row of the answer it stands in (``sentences.1.rewrite``),
with the sentence's number after it. The question round reads each reply's
answer text; a reply keeps the position it has in the answer whether or not the
rows before it are replies.
"""

from __future__ import annotations

from malspark.pipeline.validation import answer_of, citation_violations
from malspark.reporting.question_round import QuestionRoundOutput, _answer_prose
from malspark.reporting.section_agreement import rewrites_violations


def test_a_rewrite_finding_is_placed_in_its_row_of_the_answer() -> None:
    payload = {
        "sentences": [
            "a row that is no object",
            {
                "passage": "x.0",
                "sentence": "s",
                "decision": "rewrite",
                "rewrite": "Fine sentence. Bad cite [Foo].",
            },
        ]
    }

    (found,) = rewrites_violations(payload, ["ev_0011"], None, None, ())

    assert found.path == "sentences.1.rewrite"
    assert found.statements == ("sentences.1.rewrite#1",)


def test_a_reply_keeps_its_position_after_a_row_that_is_no_reply() -> None:
    payload = {
        "answers": [
            "not a reply",
            {"question": 1, "answer": "Fine. It cites [Foo].", "evidence_ids": []},
        ]
    }

    prose = _answer_prose(payload)
    with answer_of(QuestionRoundOutput):
        (found,) = citation_violations(prose, ["ev_0011"], prose=("answers",))

    assert len(prose["answers"]) == 2
    assert found.statements == ("answers.1.answer#1",)


class TestEachRoundRunsItsChecksInsideItsSchema:
    """A place spells a field name the round's schema declares, on every path a round checks."""

    def test_the_narrative_loop_s_checks(self) -> None:
        from malspark.reporting.narrative_agent import NarrativeAgent
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        agent = object.__new__(NarrativeAgent)
        agent._items = None
        payload = {
            "executive_summary": "Plain.",
            "key_findings": [{"text": "It cites [Foo].", "evidence_ids": []}],
        }

        found = [
            violation
            for check in agent._validators(
                _grounding(), ["ev_0011"], ["ev_0011"], None, None, None, [""]
            )  # type: ignore[arg-type]
            for violation in check(payload)
        ]

        assert [v.statements for v in found if v.code == "report.citation_not_evidence"] == [
            ("key_findings.0.text",)
        ]

    def test_the_narrative_s_structured_answer(self) -> None:
        from malspark.pipeline.validation import ValidationTally
        from malspark.reporting.narrative_agent import NarrativeAgent, NarrativeOutput
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        agent = object.__new__(NarrativeAgent)
        agent._items = None
        agent.validation_tally = ValidationTally()
        output = NarrativeOutput.model_construct(
            executive_summary="Plain.",
            key_findings=[{"text": "It cites [Foo].", "evidence_ids": []}],
            defensive_recommendations=[],
        )

        agent._kept_with_ungrounded_recorded(output, _grounding(), ["ev_0011"], ["ev_0011"])  # type: ignore[arg-type]

        (row,) = agent.validation_tally.unresolved
        assert row["statements"] == "key_findings.0.text"

    def test_a_composer_section_s_checks_on_both_paths(self) -> None:
        from malspark.reporting.composer import ReportComposer, _HostIdentifiersOut
        from tests.unit.pipeline.test_a_finding_names_its_statement import _grounding

        composer = object.__new__(ReportComposer)
        composer._grounding = _grounding()
        composer._items = None
        payload = {
            "identifiers": [
                {"kind": "k", "value": "see ev_0099", "use": "u", "evidence_refs": ["ev_0011"]}
            ]
        }

        for answer_read in (None, "{}"):
            found = composer._section_findings(
                payload, _HostIdentifiersOut, (), None, ["ev_0011"], None, None, answer_read
            )
            places = [v.statements for v in found if v.code == "report.citation_not_evidence"]
            assert places == [("identifiers.0.value",)], answer_read
