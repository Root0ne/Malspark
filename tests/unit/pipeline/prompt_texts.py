"""Print, as JSON, the prompt texts built from one fixture state.

Run as a script by ``test_a_prompt_is_one_text_under_two_hash_seeds.py``,
once per hash seed. No model is called and nothing leaves the process: each
model is a stand-in that records the messages it is sent and answers a fixed
text. The state is ``written_orders``': four analysts on one debate line, a
ledger with an image base, rule scans naming two sub-techniques, a mediation
with lines whose marks were not read, and a PE importing two python libraries.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import written_orders as state  # noqa: E402 - the fixture state, beside this script

ANALYST_ANSWER = (
    "CLAIM: It decodes its strings.\nEVIDENCE: ev_0002\nCONFIDENCE: 0.5\nTECHNIQUE: T1027\n"
)


def _uuid(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


# A closed bundle crediting an analyst with a technique only the scans named.
CREDITED = {
    "type": "bundle",
    "id": f"bundle--{_uuid(99)}",
    "x_malspark_assessment": {
        "verdict": "Malware",
        "confidence": 0.9,
        "severity": {"rating": "High", "rationale": "It injects code."},
    },
    "objects": [
        {"type": "malware", "id": f"malware--{_uuid(0)}", "name": "x", "is_family": False},
        {
            "type": "attack-pattern",
            "id": f"attack-pattern--{_uuid(1)}",
            "name": "Process Injection",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
        },
        {
            "type": "relationship",
            "id": f"relationship--{_uuid(2)}",
            "relationship_type": "uses",
            "source_ref": f"malware--{_uuid(0)}",
            "target_ref": f"attack-pattern--{_uuid(1)}",
            "x_malspark_confidence": 0.9,
            "x_malspark_evidence_basis": "static",
            "x_malspark_contributing_agents": ["dynamic"],
        },
    ],
}


class _Model:
    """Records each message list as one text and answers the next fixed text."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.sent: list[str] = []

    def invoke(self, messages: Any, **_: Any) -> Any:
        from langchain_core.messages import AIMessage

        self.sent.append("\n".join(str(getattr(m, "content", m)) for m in messages))
        return AIMessage(content=self.answers.pop(0) if self.answers else ANALYST_ANSWER)

    async def ainvoke(self, messages: Any, **_: Any) -> Any:
        return self.invoke(messages)


def _reports() -> dict[str, str]:
    return {name: isr.to_text_summary() for name, isr in state.debate_isrs().items()}


def debate_directive() -> dict[str, Any]:
    """The revision directive one analyst is sent, assembled as the revision round does."""
    from malspark.pipeline.debate_facts import (
        contested_input,
        facts_naming,
        ledger_count_facts,
        place_facts,
        place_facts_for,
        with_ledger_facts,
        with_place_facts,
    )

    names = list(state.DEBATERS)
    lines = [state.DEBATE_LINE]
    isrs, ledger = state.debate_isrs(), state.debate_ledger()
    finding = f"The analysts disagree.\n\nContradictions: {state.DEBATE_LINE}\nConfidence: 0.4"
    counts = ledger_count_facts(lines, isrs, ledger, names)
    places = place_facts(lines, isrs, ledger, names)
    shown: dict[str, Any] = {}
    for name in names:
        feedback, peers = contested_input(
            name, finding, lines, names, _reports(), {}, isrs=isrs, revision_round=1
        )
        shown[name] = {
            "directive": with_place_facts(
                with_ledger_facts(feedback, facts_naming(name, counts)),
                place_facts_for(name, places, names),
                can_read=True,
            ),
            "peers": {peer: str(text) for peer, text in peers.items()},
        }
    return shown


def _mediation_history() -> list[Any]:
    from malspark.pipeline.debate_facts import ledger_count_facts, place_facts

    names = list(state.DEBATERS)
    lines = [state.DEBATE_LINE]
    isrs, ledger = state.debate_isrs(), state.debate_ledger()
    return [
        state.mediation(
            ledger_facts=ledger_count_facts(lines, isrs, ledger, names),
            place_facts=place_facts(lines, isrs, ledger, names),
        )
    ]


def judge_prompts() -> dict[str, list[str]]:
    """The mediation prompt, and the verdict prompt with its retry, as the judge sends them."""
    from malspark.agents.judge_agent import JudgeAgent
    from malspark.pipeline.evidence_summary import summarise

    mediator = _Model("No contradictions remain.\n\nCONTRADICTIONS:\nnone\n\nCONFIDENCE: 0.9")
    asyncio.run(
        JudgeAgent(llm=mediator).mediate(
            reports=_reports(),
            history=_mediation_history(),
            isr_reports=state.debate_isrs(),
            reputation_asked=True,
        )
    )
    answer = json.dumps(CREDITED)
    judge = _Model(answer, answer)
    asyncio.run(
        JudgeAgent(llm=judge).give_verdict(
            reports=_reports(),
            history=_mediation_history(),
            isr_reports=state.debate_isrs(),
            evidence_summary=summarise(state.debate_isrs(), state.asserting_ledger()),
            technique_sources=state.technique_sources(),
        )
    )
    return {"mediation": mediator.sent, "verdict": judge.sent}


def analyst_chunk() -> dict[str, Any]:
    """The static chunk as the analyst node writes it, and the analyst's first prompt over it."""
    from malspark.agents.static_analyst import StaticAnalyst
    from malspark.loaders.binary_chunker import ChunkStrategy, TextChunk
    from malspark.pipeline.nodes import _augment_static_chunks_with_path

    content = json.dumps({"file": {"sha256": "a" * 64, "name": "sample.exe"}})
    chunk = TextChunk(
        index=0,
        total=1,
        strategy=ChunkStrategy.SLIDING_WINDOW,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="static",
    )
    with tempfile.TemporaryDirectory() as folder:
        sample = Path(folder) / "sample.exe"
        sample.write_bytes(b"MZ" + b"\0" * 510)
        run = {"static_sample_path": "/data/samples/sample.exe", "sample_path": str(sample)}
        (written,) = state.with_imports(lambda: _augment_static_chunks_with_path([chunk], run))
    model = _Model()
    StaticAnalyst(llm=model, name="static").analyze_isr(written.content)
    return {"chunk": written.content, "prompt": model.sent[:1]}


def main() -> None:
    # The service container logs to standard output, where the JSON goes.
    logging.disable(logging.CRITICAL)
    print(
        json.dumps(
            {
                "debate_directive": debate_directive(),
                "judge": judge_prompts(),
                "analyst": analyst_chunk(),
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
