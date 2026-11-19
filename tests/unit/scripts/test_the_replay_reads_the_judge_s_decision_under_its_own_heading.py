"""The replay reads the passages under THE JUDGE'S DECISION as the judge's, never as facts.

The round's prompt shows the judge's decision under a heading of its own, between the facts
and section 5 (T-717). The replay reads every heading the round writes, so a passage under
the judge's heading is the round's own judge passage: its kind, its text as shown (a judge
passage, like a fact, is not quoted) and no writer, never a fact of the heading before it.
Every value here is a neutral synthetic one.
"""

from __future__ import annotations

from scripts.replay.agreement_names import _passages

from malspark.reporting.section_agreement import FACT, JUDGE, SECTION_5

_PROMPT = "\n".join(
    [
        "FACTS THE PLATFORM STATES",
        "-------------------------",
        '- [bound.1] decoded text passed to an API argument (cites ev_0103): "quietmode": '
        '"passed to QueryHostMode"',
        "THE JUDGE'S DECISION",
        "--------------------",
        "- [judge.verdict] the judge's verdict: Malicious, high",
        "- [judge.technique.T1057] a technique the judge did not publish: T1057 Process "
        'Discovery: "no entry shows it [ev_0101]"',
        "SECTION 5, WRITTEN FROM THE CODE AND THE TOOL ANSWERS",
        "-----------------------------------------------------",
        "- [string_resolution] 5. Technical analysis, 'Strings' (cites ev_0103): \"Routine "
        '0x5b20 reads a byte [ev_0103]."',
    ]
)


def test_a_passage_under_the_judge_s_heading_is_a_judge_passage() -> None:
    shown = {p.id: p for p in _passages(_PROMPT)}

    assert shown["bound.1"].kind == FACT
    verdict = shown["judge.verdict"]
    assert verdict.kind == JUDGE
    assert verdict.text == "Malicious, high"
    assert verdict.write is None
    assert shown["judge.technique.T1057"].kind == JUDGE
    # Shown as the round writes it, its quoted reason as quoted.
    assert shown["judge.technique.T1057"].text == (
        'T1057 Process Discovery: "no entry shows it [ev_0101]"'
    )
    # The heading after it is read as before.
    assert shown["string_resolution"].kind == SECTION_5


def test_the_kinds_the_replay_reads_are_the_round_s_own_headings() -> None:
    from scripts.replay.agreement_names import _KINDS

    from malspark.reporting.section_agreement import _HEADINGS

    assert {heading: kind for kind, heading in _HEADINGS} == _KINDS
