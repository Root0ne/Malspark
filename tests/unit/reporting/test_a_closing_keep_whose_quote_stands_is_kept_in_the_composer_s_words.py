"""A closing keep whose quote stands whole in its source is kept in the composer's words.

Where the agreement round kept a closing sentence on a quote standing whole in one sentence of
a section 5 passage, and the keep was refused only by the test of the words the sentence
denies something of, the source's sentence was printed in its place. Moved into another
section, a sentence opening on a word that points back ("Neither is attributed to a
process…") lost what it pointed to, and the closing sentence lost its other clauses; a list of
opening words decided which sentences could move, and no word list can tell what a sentence
refers to. Now the composer's sentence is kept as written, with its own record
(``KEPT_ON_ITS_QUOTE_CODE``, counted ``kept_on_quote``); the source's sentence is not moved
(T-736). The texts quote one stored run's sentences as examples; the second shape is made up.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting import section_agreement
from malspark.reporting.models import MalwareReport
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    KEEP_UNQUOTED_CODE,
    KEPT_ON_ITS_QUOTE_CODE,
    agreement_violations,
    apply_rows,
    passages_of,
)
from tests.unit.reporting.test_a_kept_closing_sentence_whose_quote_stands_in_the_body_is_not_lost import (  # noqa: E501
    BRANCH,
    DECODINGS,
    GATED,
    UNEXAMINED,
    _keep,
    _limitations,
    _report,
)

# A source sentence pointing back to the one before it, and a closing sentence quoting it.
NEITHER = (
    "Neither is attributed to a process, and the sandbox host list does not contain either "
    "address [ev_0028]."
)
OWNER = (
    "The owner of the two largest port-80 conversations is not established, so they are not "
    "treated as command-and-control traffic [ev_0028]."
)


def _applied(report: MalwareReport, row: dict[str, Any]) -> tuple[dict[str, int], list[Any]]:
    passages = passages_of(report)
    refused = [v.code for v in agreement_violations({"sentences": [row]}, passages)]
    assert KEEP_UNQUOTED_CODE in refused
    return apply_rows({"sentences": [row]}, passages)


@pytest.mark.parametrize(
    ("sentence", "source", "quote", "holding"),
    [
        (
            GATED,
            "command_and_control",
            "and no option-gated or argument-gated branch was exercised",
            BRANCH,
        ),
        (UNEXAMINED, "string_resolution", "referenced by no code and were not reviewed", DECODINGS),
    ],
)
def test_the_composer_s_sentence_stands_as_written_with_its_own_record(
    sentence: str, source: str, quote: str, holding: str
) -> None:
    report = _report()
    counts, records = _applied(report, _keep("limitations", sentence, source, quote))
    assert sentence in _limitations(report)
    assert holding not in _limitations(report)
    assert counts["kept_on_quote"] == 1 and counts["dropped"] == 0
    assert "replaced" not in counts
    assert DROPPED_CODE not in [v.code for v in records]
    (record,) = [v for v in records if v.code == KEPT_ON_ITS_QUOTE_CODE]
    assert record.answered and record.path == "sentences.0" and not record.stood
    assert record.message.startswith("The agreement question keeps a sentence of 11. Limitations")
    assert record.message.endswith(
        f" as written on {source}, quoting {quote!r}, which stands whole in one sentence there, "
        "though the keep was refused only on the words of what the sentence denies something "
        f"of ({KEEP_UNQUOTED_CODE}): {sentence!r} stands as written."
    )


def test_a_source_sentence_pointing_back_moves_nowhere_and_the_closing_sentence_stands() -> None:
    report = _report(limitations=OWNER)
    ta = report.technical_analysis
    assert ta is not None and ta.command_and_control is not None
    ta.command_and_control.body = f"Two flows carry 189 KB and 172 KB [ev_0028]. {NEITHER}"
    row = _keep("limitations", OWNER, "command_and_control", "Neither is attributed to a process")
    counts, records = _applied(report, row)
    assert _limitations(report) == OWNER
    assert counts["kept_on_quote"] == 1
    assert [v.code for v in records] == [KEPT_ON_ITS_QUOTE_CODE]


def test_no_word_list_decides_what_a_sentence_refers_to() -> None:
    assert not hasattr(section_agreement, "_POINTING_OPENERS")
    assert not hasattr(section_agreement, "_stands_alone")
    assert not hasattr(section_agreement, "KEPT_IN_SOURCE_WORDS_CODE")
