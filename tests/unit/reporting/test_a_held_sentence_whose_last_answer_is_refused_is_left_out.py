"""A sentence the ledger's own lines hold never prints as it was refused.

The agreement question holds a sentence that denies something of a name the run
holds, a limitations sentence naming a failed call a later call redid, and one
saying such a call failed (T-600). Where the round's last answer for such a
sentence was still refused, the sentence printed as it stood: a body sentence
was never left out, and a closing one only on some refusals, the route by which
a closing section said otherwise than the body. Now a held sentence whose last
answer the checks refuse is left out, of the body as of a closing section, and
recorded with the dropped code, what holds it and every code refusing the
answer; the question and every refusal of an answer for it say so. Where the
platform already leaves such a closing sentence out, that end stands with its own
record, and a drop of a held body sentence is an answer. Every other refused
answer ends as before. Every address, entry and name here is a neutral
synthetic value.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.pipeline.validation import EntryTexts
from malspark.reporting.models import KeyFinding, MalwareReport
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import MarkdownRenderer
from malspark.reporting.section_agreement import (
    DROPPED_CODE,
    _uncited,
    agreement_violations,
    apply_rows,
    passages_of,
    rewrites_violations,
)
from tests.unit.reporting.test_a_denial_of_a_name_the_run_holds_is_read_against_the_ledger import (
    _SAYS_FAILED,
    _TRUE,
    _UNKNOWN,
    CALLED,
    _ask,
    _ledger,
    _report,
    _Reporter,
    _row,
)

# A sentence of the same passage no gate holds, which stays where it stands.
FIRST = "The gate reads a host mode [ev_0107]."
_LEFT_OUT = "If no answer for it passes the checks, it is left out of the report."
# The limitations label once the paragraph is held to the failed calls, as a record cuts it.
_HELD_LIMITATIONS = (
    "11. Limitations, the composed paragraph (each sentence saying a call failed or a reading "
    "could not be made is held to the failed calls, the tools not run, the recorded "
    "limitations and the open questi…"
)


def _left_out(label: str, why: str, sentence: str) -> str:
    return (
        f"The agreement question leaves a sentence of {label} out of the section ({why}): "
        f"{sentence!r}."
    )


# Each held sentence, the passage it stands in, its last answer, and the record of it
# left out: the hold named, then every code refusing the answer.
_REFUSED: dict[str, tuple[str, str, dict[str, Any], str]] = {
    "closing on a name, a keep on a reason": (
        "limitations",
        _UNKNOWN,
        _row(_UNKNOWN, "keep", [], reason="no source states it"),
        # A closing keep on no source a check accepts is one the platform leaves out on its
        # own: that end and its record stand.
        _left_out(
            "11. Limitations",
            "kept on no source a check accepts: no source, because 'no source states it': "
            "agreement.keep_unquoted",
            _UNKNOWN,
        ),
    ),
    "closing on a name, the same words cited": (
        "limitations",
        _UNKNOWN,
        _row(_UNKNOWN, "rewrite", ["ledger.1"], rewrite=_UNKNOWN.rstrip(".") + " [ev_0109]."),
        # So is a closing rewrite on a source that passed no check.
        "The agreement question lists a sentence of 11. Limitations as saying otherwise than "
        f"ledger.1, and no rewrite of it passed the checks: it is left out of the section: "
        f"{_UNKNOWN!r}.",
    ),
    "body on a name, a keep on a reason": (
        "introduction",
        _UNKNOWN,
        _row(_UNKNOWN, "keep", [], reason="no source states it"),
        _left_out(
            "12.3 Background",
            "its last answer, a keep, was refused; held on what ledger.1 holds lines on: "
            "agreement.keep_unquoted",
            _UNKNOWN,
        ),
    ),
    "body on a name, a rewrite on no source of it": (
        "introduction",
        _UNKNOWN,
        _row(
            _UNKNOWN,
            "rewrite",
            ["failed.1"],
            rewrite=f"Routine 0x5a10 calls `{CALLED}`, whose result is unset.",
        ),
        _left_out(
            "12.3 Background",
            "no rewrite of it passed the checks; held on what ledger.1 holds lines on: "
            "agreement.unknown_source, agreement.rewrite_ungrounded",
            _UNKNOWN,
        ),
    ),
    "body on a name, a drop": (
        "introduction",
        _UNKNOWN,
        _row(_UNKNOWN, "drop", [], reason="the lines shown say otherwise"),
        # A drop of it is an answer: left out as the round dropped it.
        _left_out(
            "12.3 Background",
            "the round dropped it; held on what ledger.1 holds lines on; its reason: the lines "
            "shown say otherwise",
            _UNKNOWN,
        ),
    ),
    "to a redone call, a keep on a reason": (
        "limitations",
        _TRUE,
        _row(_TRUE, "keep", [], reason="no source"),
        _left_out(
            _HELD_LIMITATIONS,
            "the ledger says otherwise: agreement.keep_unquoted, agreement.failure_redone",
            _TRUE,
        ),
    ),
    "to a redone call, a rewrite on no source": (
        "limitations",
        _TRUE,
        _row(
            _TRUE,
            "rewrite",
            [],
            rewrite="Routine 0x5a10 holds a host-mode check and returns [ev_0101].",
        ),
        _left_out(
            _HELD_LIMITATIONS,
            "the ledger says otherwise; no rewrite of it passed the checks; held to the redone "
            "calls it names (redone by ev_0107): agreement.unknown_source, "
            "agreement.failure_redone, agreement.rewrite_cites_elsewhere, "
            "agreement.rewrite_ungrounded",
            _TRUE,
        ),
    ),
    "says a call failed, a keep quoting the failed call": (
        "limitations",
        _SAYS_FAILED,
        _row(_SAYS_FAILED, "keep", ["inv.1"], quote="no function there"),
        _left_out(
            _HELD_LIMITATIONS,
            "the ledger says otherwise: agreement.failure_redone",
            _SAYS_FAILED,
        ),
    ),
    "says a call failed, a rewrite citing no redo": (
        "limitations",
        _SAYS_FAILED,
        _row(
            _SAYS_FAILED,
            "rewrite",
            ["inv.1"],
            rewrite="Routine 0x5a10 holds no network call [ev_0101].",
        ),
        f"The agreement question lists a sentence of {_HELD_LIMITATIONS} as saying otherwise "
        f"than inv.1, and no rewrite of it passed the checks: it is left out of the section: "
        f"{_SAYS_FAILED!r}.",
    ),
}


def _held_in(pid: str, sentence: str) -> MalwareReport:
    """The report with ``sentence`` after a sentence no gate holds, in ``pid``."""
    if pid == "introduction":
        return _report(FIRST, background=f"{FIRST} {sentence}")
    return _report(f"{FIRST} {sentence}")


@pytest.mark.parametrize("case", list(_REFUSED))
def test_a_held_sentence_whose_last_answer_is_refused_is_left_out(case: str) -> None:
    pid, sentence, row, record = _REFUSED[case]
    report = _held_in(pid, sentence)
    ledger = _ledger()
    counts, found = apply_rows(
        {"sentences": [{**row, "passage": pid}]},
        passages_of(report, entries=ledger),
        citable=[str(e.id) for e in ledger],
        entries=EntryTexts.from_ledger(ledger),
    )
    # Left out, the rest of its passage as it stood, and recorded whole: the section it
    # was left out of is the record's subject, which the run summary counts.
    ta = report.technical_analysis
    assert ta is not None and ta.analyst_limitations is not None
    assert (report.intro_background if pid == "introduction" else ta.analyst_limitations.body) == (
        FIRST
    )
    assert counts["dropped"] == 1 and counts["kept"] == counts["rewritten"] == 0
    assert counts["not_applied"] == counts["held_kept"] == 0
    assert [(v.code, v.subject, v.message) for v in found] == [(DROPPED_CODE, pid, record)]


def test_every_refusal_of_a_held_sentence_says_it_is_left_out() -> None:
    report = _held_in("introduction", _UNKNOWN)
    ledger = _ledger()
    passages = passages_of(report, entries=ledger)
    # A rewrite's prose finding, read apart from the rows, says it too.
    rewrite = _row(
        _UNKNOWN,
        "rewrite",
        ["ledger.1"],
        rewrite=f"Routine 0x5a10 calls `{CALLED}` [ev_0199]; its result at run time is unset.",
    )
    answer = {"sentences": [{**rewrite, "passage": "introduction"}]}
    prose = rewrites_violations(answer, [str(e.id) for e in ledger], None, None, passages)
    assert prose and all(v.message.endswith(_LEFT_OUT) for v in prose), prose
    # So does every row finding, the refused drop's among them, each once.
    for row in (
        _row(_UNKNOWN, "keep", [], reason="no source states it"),
        rewrite,
    ):
        answered = {"sentences": [{**row, "passage": "introduction"}]}
        found = [
            v for v in agreement_violations(answered, passages) if v.path.startswith("sentences.")
        ]
        assert found and all(v.message.count(_LEFT_OUT) == 1 for v in found), found
        assert all(v.message.endswith(_LEFT_OUT) for v in found), found
    # A sentence no gate holds is told nothing of it.
    plain = _row(FIRST, "drop", [], reason="x")
    answered = {"sentences": [{**plain, "passage": "introduction"}]}
    found = [v for v in agreement_violations(answered, passages) if v.path.startswith("sentences.")]
    assert found and not any(_LEFT_OUT in v.message for v in found)


def test_the_printed_report_leaves_the_sentence_out_and_lists_its_record() -> None:
    report = _held_in("introduction", _UNKNOWN)
    # A key finding whose only sentence is held: the item it stood in goes with it.
    report.key_findings = [KeyFinding(text=_UNKNOWN), KeyFinding(text=FIRST)]
    keep = {"sentences": [_row(_UNKNOWN, "keep", [], reason="no source states it")]}
    rows = {
        "sentences": [
            {**keep["sentences"][0], "passage": "introduction"},
            {**keep["sentences"][0], "passage": "key_findings.1"},
        ]
    }
    done = _ask(report, _Reporter(rows, rows))
    assert done.summary["dropped"] == 2
    assert report.intro_background == FIRST and report.key_findings[0].text == ""
    records = [r for r in done.tally.unresolved if r["code"] == DROPPED_CODE]
    assert {r["subject"] for r in records} == {"introduction", "key_findings.1"}
    report.run_summary = {"validation": {"retries": 1, "unresolved": done.tally.unresolved}}
    # The analyst report prints neither the sentence nor an empty item, and counts the
    # finding left out of its section.
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    assert _uncited(_UNKNOWN).rstrip(".") not in analyst
    assert "\n- -\n" not in analyst and "\n- \n" not in analyst
    assert "_1 sentence of this section was left out" in analyst
    # The bundle prints the passages without it: the sentence stands only in the findings it
    # lists, a record of it left out among them for each passage.
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    printed = [line for line in bundle.splitlines() if _UNKNOWN.rstrip(".") in line]
    assert all(line.startswith("- `agreement.") for line in printed), printed
    left = [line for line in printed if line.startswith("- `agreement.dropped`")]
    assert len(left) == 2 and any("12.3 Background" in line for line in left), left


def test_a_citation_inside_a_code_span_leaves_the_name_whole() -> None:
    # A code span is one name: a citation inside it leaves nothing between its parts.
    assert _uncited("No call to `Query[ev_0109]HostMode` is shown.") == (
        f"No call to `{CALLED}` is shown."
    )
    assert _uncited("`Query[ev_0109]Host` and Mode[ev_0107]is") == "`QueryHost` and Mode is"
    # Outside a span, or in one never closed, it parts two words as before.
    assert _uncited(f"`{CALLED}` and Query[ev_0109]Host") == f"`{CALLED}` and Query Host"
    assert _uncited("an `open Query[ev_0109]Host") == "an `open Query Host"
