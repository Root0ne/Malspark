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
