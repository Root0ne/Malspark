"""The agreement round's retry names a passage only as the question's list writes it.

The retry printed each held sentence no row listed under the locator ``held.<passage id>``,
in the place a row's own finding prints ``sentences.N``: a token in the shape of a passage id
that no list writes. A model copied it as the row's passage, and the round refused every
such row as naming an unknown passage, so each sentence counted as not answered. The same
line quoted the sentence cut at the finding limit while it asked for the sentence whole.
Now a held sentence's finding is located by its passage as the list writes it
(``[<id>]``), the retry quotes the sentence whole, and its record keeps the bounded copy
(T-736). Every address, entry and name here is a neutral synthetic value.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from malspark.reporting.section_agreement import (
    HELD_UNLISTED_CODE,
    UNREAD_STANDING_CODE,
    passages_of,
    prompt_text,
)
from tests.unit.reporting import (
    test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger as on_names,
)
from tests.unit.reporting import (
    test_an_absence_the_ledger_contradicts_is_rewritten_in_every_section as on_listings,
)

FIRST = "The gate reads a host mode [ev_0107]."
# Held on a name the run holds, and longer than a finding's bounded copy.
_LONG_HELD = (
    f"The runtime result of `{on_names.CALLED}` that the gate reads on every start, before it "
    "chooses between the quiet mode and the loud mode and before it stores the chosen mode in "
    "the slot that the later checks read again, is not known."
)
# Calls listed code not read, and longer than a finding's bounded copy.
_LONG_UNREAD = (
    "The body of 0x2800 that performs the registration of the scheduled task under the name "
    "the caller passes, together with the trigger it sets and the account it runs under, is "
    "not read, so the task is not confirmed [ev_0002]."
)
_LINE = re.compile(r"- \[(?P<code>[^\]]+)\](?: \((?P<at>[^)]*)\))? ")
_ROW = re.compile(r"sentences\.\d+(?:\.\w+)?")


def _listed(prompt: str) -> set[str]:
    """Every id the question's list writes, as it writes it: ``[<id>]``."""
    return set(re.findall(r"^\s*-? ?\[([^\]\s]+)\]", prompt, flags=re.MULTILINE))


def _on_names() -> tuple[Any, Any, str]:
    def report() -> Any:
        return on_names._report(FIRST, background=f"{FIRST} {_LONG_HELD}")

    reporter = on_names._Reporter({"sentences": []}, {"sentences": []})
    done = on_names._ask(report(), reporter)
    return done, reporter, prompt_text(passages_of(report(), entries=on_names._ledger()))


def _on_listings() -> tuple[Any, Any, str]:
    report = on_listings._report(section_5=_LONG_UNREAD)
    passages = passages_of(report, entries=on_listings._ledger())
    task = on_listings._listed_id(passages, on_listings.TASK)
    row = {
        "passage": "limitations",
        "sentence": on_listings.LIMIT_UNREAD,
        "sources": [task],
        "decision": "rewrite",
        "rewrite": on_listings.LIMIT_REWRITE,
    }
    done, reporter = on_listings._ask(
        on_listings._report(section_5=_LONG_UNREAD), {"sentences": [row]}, {"sentences": [row]}
    )
    return done, reporter, prompt_text(passages)


_ROUNDS = {"held on a name": (_on_names, HELD_UNLISTED_CODE, _LONG_HELD)}
_ROUNDS["calling listed code not read"] = (_on_listings, UNREAD_STANDING_CODE, _LONG_UNREAD)


@pytest.mark.parametrize("case", list(_ROUNDS.values()), ids=list(_ROUNDS))
def test_no_feedback_line_carries_an_id_the_question_does_not_list(case: Any) -> None:
    ask, code, _held = case
    _done, reporter, prompt = ask()
    assert len(reporter.asked) == 2
    # The first question is the same question.
    assert str(reporter.asked[0][-1].content) == str(reporter.asked[1][1].content)
    listed = _listed(prompt)
    feedback = str(reporter.asked[1][-1].content)
    assert "held." not in feedback
    lines = [_LINE.match(line) for line in feedback.splitlines() if line.startswith("- [")]
    assert lines and all(lines)
    assert code in {m["code"] for m in lines if m}
    for found in lines:
        assert found is not None
        at = found["at"]
        if at is None or _ROW.fullmatch(at):
            continue
        # A held sentence's finding names its passage in square brackets, as the list does.
        assert at.startswith("[") and at.endswith("]"), at
        assert at[1:-1] in listed, at


@pytest.mark.parametrize("case", list(_ROUNDS.values()), ids=list(_ROUNDS))
def test_the_retry_quotes_a_held_sentence_whole_and_its_record_keeps_the_bounded_copy(
    case: Any,
) -> None:
    ask, code, held = case
    assert len(held) > 200
    done, reporter, _prompt = ask()
    feedback = str(reporter.asked[1][-1].content)
    (line,) = [
        line
        for line in feedback.splitlines()
        if line.startswith(f"- [{code}]") and held[:60] in line
    ]
    assert repr(held) in line
    # The record of the same finding, left after the retry, keeps the bounded copy.
    (record,) = [
        r for r in done.tally.unresolved if r["code"] == code and held[:60] in r["message"]
    ]
    assert repr(held) not in record["message"]
    assert "…" in record["message"]
