"""The efficiency block says each count of its record in whole words, and nothing for no record.

``analysis.efficiency.efficiency_lines`` prints the run's own counts at the end
of the run summary appendix: what each agent's requests were made of, the
evidence nothing cites, the calls that found nothing new, the rows read back,
the reads outside a tool loop and the run fingerprint. Each sentence is pinned
whole here, by the part of the record it is written from (T-770), so a change
of wording is a change this file sees.
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.efficiency import efficiency_lines
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.markdown import MarkdownRenderer


def _code(text: str) -> str:
    return f"`{text}`"


def _lines(**parts: Any) -> list[str]:
    lines: list[str] = efficiency_lines({"v": 2, **parts}, _code)
    return lines


ALL_PARTS = {
    "system_prompt": 100,
    "task": 200,
    "pack": 50,
    "run_state": 10,
    "tool_answers": 400,
    "peer_reports": 30,
    "retries": 4,
    "own_turns": 106,
    "tool_definitions": 100,
}


def test_each_agent_s_input_is_said_by_part_with_the_tokens_reported() -> None:
    inputs = {
        "unit": "characters",
        "loops": [
            {
                "agent": "static",
                "kind": "tool loop",
                "requests": 3,
                "parts": ALL_PARTS,
                "reported_requests": 2,
                "input_tokens": 900,
            },
            {"agent": "static", "kind": "revision", "requests": 1},
            {"agent": "dynamic", "kind": "verdict", "requests": 1, "parts": {"task": 0}},
            {"agent": "dynamic", "kind": "revision", "requests": 2},
        ],
        "calls": {"static": 4, "reporter": 1, "judge": 2},
        "peer_reports": [
            {
                "excerpted": 2,
                "excerpt_chars": 300,
                "excerpted_whole_chars": 1200,
                "whole": 1,
                "whole_chars": 800,
            },
            {"excerpted": 1, "excerpt_chars": 1000, "excerpted_whole_chars": 4000},
        ],
    }

    assert _lines(inputs=inputs) == [
        "Input of `static`: 1 tool loop and 1 kind of single call, 4 requests, 1,000 characters "
        "in all — system prompt 10% (100), task and data 20% (200), pack 5% (50), run state 1% "
        "(10), tool answers 40% (400), peer reports 3% (30), turns after the first answer "
        "(retries, questions, notices) <1% (4), own earlier turns 11% (106), tool definitions "
        "10% (100). The provider reported 900 input tokens for 2 of the 4 requests; the token "
        "ledger holds 4 model calls of this agent.",
        "Input of `dynamic`: 2 kinds of single call, 3 requests, 0 characters in all. The "
        "provider reported no input tokens for these requests.",
        "Not measured by part (model calls in the token ledger): `reporter` (1), `judge` (2).",
        "Peer reports shown to the named revisions: 3 excerpts of 1,300 characters, for reports "
        "of 5,200 characters whole, and 1 whole report of 800 characters.",
        "Every part is a character count: no provider reports the tokens of each part of a "
        "prompt, only its total, which is given as reported.",
    ]
    assert _lines(inputs={"loops": [], "calls": {}}) == []


def test_the_evidence_nothing_cites_is_said_with_who_made_it_and_the_failed_calls() -> None:
    head = (
        "Evidence nothing cites: {} of the {} whose tool answered are named by no claim, "
        "finding or artifact of an analyst's final answer"
    )

    assert _lines(uncited={"entries": 1, "uncited": 0, "failed": 0}) == [
        head.format(0, "1 ledger entry") + "; no call failed."
    ]
    assert _lines(
        uncited={
            "entries": 5,
            "uncited": 2,
            "by_agent": {"pack": 1, "pipeline": 1},
            "by_tool": {"strings": 2},
            "failed": 2,
        }
    ) == [
        head.format(2, "5 ledger entries")
        + " (by maker: the triage pack 1, the pipeline 1; by tool: `strings` 2); 2 failed "
        "calls not counted as evidence."
    ]
    assert _lines(uncited={"entries": 3, "uncited": 0}) == [
        head.format(0, "3 ledger entries") + "."
    ]


def test_the_calls_that_found_nothing_new_are_said_by_their_maker() -> None:
    calls = {
        "repeated": 1,
        "refused": 0,
        "run_again": 1,
        "retried_after_failure": 2,
        "same_call_elsewhere": 0,
        "by_agent": {
            "pack": {"run_again": 1},
            "pipeline": {"retried_after_failure": 2},
            "static": {"repeated": 1, "refused": 0},
            "dynamic": {"refused": 1, "same_call_elsewhere": 1},
            "other": {"repeated": 0},
        },
        "by_tool": {"strings": {"repeated": 1, "run_again": 1}, "capa": {"refused": 2}},
    }

    assert _lines(calls=calls) == [
        "Tool calls that found nothing new: 1 answered from an earlier identical call without "
        "running, 0 refused by a guard with no tool run, 1 run again by the maker of an "
        "earlier identical call and 0 identical to a call another maker ran first; besides "
        "them, 2 retried after the maker's own earlier identical call failed. By who made them "
        "— the triage pack: 1 run again after its own earlier identical call; the pipeline: 2 "
        "retried after its own earlier identical call failed; `static`: 1 answered from its "
        "earlier identical call without running; `dynamic`: 1 refused by a guard with no tool "
        "run, 1 identical to a call another maker ran first (by tool: `capa` 2, `strings` 2)."
    ]


def test_the_rows_read_back_and_the_reads_outside_a_loop_are_said() -> None:
    assert _lines(
        rows_read={
            "reads": 3,
            "by_agent": {"static": {"reads": 3, "rows": 2, "pack_rows": 1}},
            "unfound": 1,
        }
    ) == [
        "Rows read back by id (read_evidence): 3 reads — `static` 3 reads of 2 rows (1 of them "
        "pack rows); 1 read named no row the ledger holds."
    ]
    assert _lines(rows_read={"reads": 0}) == ["Rows read back by id (read_evidence): none."]

    head = "Entries read by id outside a tool loop (read_evidence, not filed)"
    assert _lines(ledger_reads={"reads": 0, "unfound": 1, "refused": 2}) == [
        f"{head}: none; 1 read named no entry the ledger holds; 2 repeated reads refused."
    ]
    assert _lines(ledger_reads={"reads": 1, "by_call": {"verdict": 1}}) == [
        f"{head}: 1 read — `verdict` 1 read."
    ]
    assert _lines(ledger_reads={"reads": 2}) == [f"{head}: 2 reads."]


def test_the_fingerprint_is_said_with_its_components_and_what_it_could_not_hold() -> None:
    fingerprint = {
        "sha256": "f" * 64,
        "components": {
            "prompts": "a" * 64,
            "tools": "b" * 64,
            "servers": "c" * 64,
            "settings": "d" * 64,
        },
        "unread": ["tool servers"],
        "not_attached": {"judge": ["vt"], "mediator": []},
        "not_resolved": ["helper"],
        "parts": {
            "servers": {
                "analysis": {"name": "analysis-mcp", "version": "1.0"},
                "vt": {"not_attached": True},
                "bare": {},
            }
        },
    }

    assert _lines(fingerprint=fingerprint) == [
        f"Run fingerprint: `{'f' * 64}` (sha256 of its components: system prompts as set up "
        "`aaaaaaaaaaaa`; tool definitions as bound `bbbbbbbbbbbb`; server names and versions "
        "`cccccccccccc`; masked settings `dddddddddddd`); not in it, as the job could not give "
        "them: tool servers.",
        "Not attached in this run, so recorded from their declared settings with no version "
        "and no tool definitions: `judge`: `vt`; `mediator`: no server.",
        "Not resolved for the fingerprint, being no analyst of the active profile and reached "
        "only when an agent delegates to it (its definition is in the settings): `helper`.",
        "Tool servers as they gave themselves at attach: `analysis` as `analysis-mcp` version "
        "`1.0`; `vt` not attached in this run (its declared settings only); `bare`, no version "
        "given. A tool's own version is not reported over MCP.",
    ]
    assert _lines(fingerprint={"sha256": "f" * 64}) == [f"Run fingerprint: `{'f' * 64}`."]


def test_a_record_of_a_stopped_run_says_its_counts_may_be_incomplete() -> None:
    assert _lines(partial_reason="the job was cancelled") == [
        "These counts may be incomplete: the job was cancelled, and what the step it stopped "
        "in did may not be counted."
    ]
    assert efficiency_lines(None, _code) == []
    assert efficiency_lines({"not_built": "the record could not be read"}, _code) == []


def test_the_report_heads_the_block_with_its_intro_sentence() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"final_decision": "Malware", "efficiency": {"v": 2, "rows_read": {}}},
    )

    assert (
        "\n**Efficiency:** counted by code from what this run recorded — the requests its "
        "agents sent, its token ledger and its evidence ledger; no figure here is a model's.\n"
    ) in MarkdownRenderer().render(report)
