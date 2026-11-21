"""The run summary says each figure it prints in whole sentences, as the record holds it.

What the models spent, a rested tool server, each measured generation rate and
each call timeout sized from it, the analysts' last-round confidence and a
debate that measured no agreement: each is pinned here word for word under
the record that prints it, with the record that prints nothing beside it
(T-770).
"""

from __future__ import annotations

from typing import Any

from malspark.analysis.run_summary import (
    _part_clause,
    _unreported_clause,
    generation_lines,
    server_rest_sentence,
    tokens_sentence,
)


def _rendered(run_summary: dict[str, Any]) -> str:
    from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
    from malspark.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        run_summary={"final_decision": "Malware", **run_summary},
    )
    return str(MarkdownRenderer().render(report))


# ---------------------------------------------------------------------------
# What the models spent
# ---------------------------------------------------------------------------


def test_the_spend_says_each_part_a_provider_reported_with_the_calls_it_covers() -> None:
    tokens = {
        "llm_calls": 3,
        "unreported_calls": 1,
        "unreported": [{"agent": "judge", "call": "verdict", "model": "m2"}],
        "input_tokens": 1200,
        "output_tokens": 80,
        "cached_input_tokens": 300,
        "cached_calls": 2,
        "cache_write_input_tokens": 120,
        "cache_write_calls": 1,
        "reasoning_tokens": 40,
        "reasoning_calls": 1,
        "cost": 0.0123,
        "cost_calls": 2,
    }
    assert tokens_sentence(tokens) == (
        "Tokens: 1,200 in and 80 out over 3 model calls; not reported for 1 of them (judge: "
        "verdict on m2); 300 of the input read from the prompt cache (reported for 2 calls); "
        "120 of the input written to the prompt cache (reported for 1 call); 40 of the output "
        "reasoning (reported for 1 call); a cost of 0.0123 USD as the provider reported it for "
        "2 calls."
    )


def test_a_spend_no_call_reported_names_the_calls_and_counts_nothing() -> None:
    tokens = {
        "llm_calls": 1,
        "unreported_calls": 1,
        "unreported": [{"agent": "static", "call": "verdict"}],
    }
    assert tokens_sentence(tokens) == (
        "Tokens: not reported by the provider for any of 1 model call (static: verdict)."
    )
    assert tokens_sentence(None) is None


def test_the_calls_that_reported_nothing_are_each_said_once_with_their_count() -> None:
    rows = [
        {"agent": "judge", "call": "verdict", "model": "m2"},
        {"agent": "judge", "call": "verdict", "model": "m2"},
        {"agent": "", "call": "", "model": ""},
        "not a row",
    ]
    assert _unreported_clause(rows) == " (judge: verdict on m2 ×2, an unnamed agent: a call)"
    assert _unreported_clause(["not a row"]) == ""
    assert _unreported_clause(None) == ""


def test_a_part_of_the_spend_is_said_only_where_a_call_reported_it() -> None:
    held = {"reasoning_tokens": 5, "reasoning_calls": 1}
    assert _part_clause(held, "reasoning_tokens", "reasoning_calls", "of the output reasoning") == (
        "; 5 of the output reasoning (reported for 1 call)"
    )
    assert (
        _part_clause({**held, "reasoning_calls": 0}, "reasoning_tokens", "reasoning_calls", "x")
        == ""
    )
    assert (
        _part_clause({**held, "reasoning_tokens": True}, "reasoning_tokens", "reasoning_calls", "x")
        == ""
    )


# ---------------------------------------------------------------------------
# A rested tool server
# ---------------------------------------------------------------------------


def test_a_rested_server_is_said_with_its_rest_its_failures_and_its_last_reason() -> None:
    row = {
        "server": "analysis",
        "label": "Analysis MCP",
        "failures": 1,
        "cooldown_s": 59.6,
        "reason": " timed out ",
    }
    assert server_rest_sentence(row) == (
        "Tool server Analysis MCP (analysis) was rested for 60 s after 1 call in a row it did "
        "not answer (the last: timed out)."
    )
    bare = {"server": "analysis", "label": "analysis", "failures": 2, "cooldown_s": 5}
    assert server_rest_sentence(bare) == (
        "Tool server analysis was rested for 5 s after 2 calls in a row it did not answer."
    )


# ---------------------------------------------------------------------------
# Generation rates and the timeouts sized from them
# ---------------------------------------------------------------------------

GENERATION: dict[str, Any] = {
    "margin": 1.5,
    "models": {
        "m1": {
            "tokens_per_second": 57.0,
            "tokens": 570,
            "seconds": 10.0,
            "calls": 2,
            "sources": ["server timings"],
            "prompt_tokens_per_second": 400.0,
            "prompt_tokens": 4000,
            "prompt_seconds": 10.0,
            "prompt_sources": [],
        },
        "m2": {"tokens_per_second": None, "prompt_tokens_per_second": None},
        "m3": "not a row",
    },
    "timeouts": {
        "a:unlimited": {"configured_s": None, "derived_s": None, "applied_s": None},
        "b:configured": {
            "configured_s": 60.0,
            "derived_s": None,
            "applied_s": 60.0,
            "budget": "4096 tokens — the section cap",
        },
        "c:read": {
            "configured_s": 120.0,
            "derived_s": 491.4,
            "applied_s": 491.4,
            "max_tokens": 8192,
            "tokens_per_second": 20.0,
            "prompt_tokens": 24000,
            "prompt_tokens_per_second": 100.0,
        },
        "d:whole": {
            "configured_s": None,
            "derived_s": 307.2,
            "applied_s": 307.2,
            "max_tokens": 8192,
            "tokens_per_second": 40.0,
        },
        "e": "not a row",
    },
}


def test_each_rate_and_each_timeout_is_said_with_its_arithmetic() -> None:
    assert generation_lines(GENERATION) == [
        "Generation rate of `m1`: 57.00 tokens/s (570 tokens over 10.0s in 2 call(s); from "
        "server timings)",
        "Prompt reading rate of `m1`: 400.00 tokens/s (4000 tokens over 10.0s; from unknown)",
        "Timeout of `a:unlimited`: none of its own — no time limit is configured and no rate is "
        "measured for its model yet (or there is no output budget), so the request's own "
        "timeout bounds it",
        "Output budget of `b:configured`: 4096 tokens — the section cap",
        "Timeout of `b:configured`: 60s, the configured value (no rate measured for its model "
        "yet, or no output budget)",
        "Timeout of `c:read`: 491s — the larger of 120s configured and (24000 prompt tokens "
        "read at 100.00 tokens/s + 8192 tokens written at 20.00 tokens/s) × 1.5 = 491s",
        "Timeout of `d:whole`: 307s — 8192 tokens at 40.00 tokens/s (prompt read included) "
        "× 1.5 = 307s",
    ]


def test_a_models_name_is_written_by_the_callers_writers_and_nothing_measured_says_nothing() -> (
    None
):
    lines = generation_lines(
        {"models": {"m1": GENERATION["models"]["m1"]}},
        model_name=lambda name: f"<{name}>",
        code=lambda text: f"[{text}]",
    )
    assert lines[0].startswith("Generation rate of [<m1>]: 57.00 tokens/s")
    assert generation_lines(None) == []
    assert generation_lines({"models": {}, "timeouts": {}}) == []


# ---------------------------------------------------------------------------
# The debate's figures in the report
# ---------------------------------------------------------------------------


def test_the_last_round_confidence_is_named_as_the_analysts_and_said_only_where_stored() -> None:
    negotiation = {"rounds_completed": 3, "termination_reason": "consensus"}
    text = _rendered({"negotiation": {**negotiation, "final_confidence": 0.75}})
    assert "\n- Mean analyst claim confidence (last round): 0.750\n" in text
    assert "Mean analyst claim confidence" not in _rendered({"negotiation": negotiation})


def test_a_debate_that_measured_no_agreement_says_so_and_names_no_cause() -> None:
    text = _rendered(
        {"negotiation": {"rounds_completed": 0, "termination_reason": "not_applicable"}}
    )
    assert "**Analyst agreement:** not applicable; no agreement was measured _(Measured)_." in text
    assert "\n- Consensus: not applicable; no agreement was measured.\n" in text
    agreed = _rendered({"negotiation": {"rounds_completed": 2, "termination_reason": "consensus"}})
    assert "no agreement was measured" not in agreed
