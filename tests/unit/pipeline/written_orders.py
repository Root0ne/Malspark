"""Print, as JSON, the orders the record and the console write from a set.

Run as a script by
``test_an_order_the_report_writes_is_the_same_under_every_hash_seed.py``,
once per hash seed: each process salts string hashes its own way, so a list
taken from a set in iteration order differs between two runs of this file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "src"), str(ROOT / "apps" / "api")]

BASE = 0x180000000

# Cited in this written order, which is neither sorted nor issue order.
CITED = ("ev_0007", "ev_0003", "ev_0012", "ev_0001", "ev_0009", "ev_0005")


def _ledger() -> list[Any]:
    from malspark.schemas.evidence import LedgerEntry

    # One function per entry, each its own root.
    return [
        LedgerEntry(
            id=f"ev_{n:04d}",
            tool="decompile_function",
            agent="static",
            args={"address": hex(BASE + 0x1000 + 0x100 * n)},
        )
        for n in range(1, 13)
    ]


def _claim(said: str) -> Any:
    from malspark.schemas.isr_models import ClaimEvidence

    return ClaimEvidence(
        technique_id="T1027",
        claim=f"The code decodes its strings ({said}).",
        evidence_ref=said,
        confidence=0.9,
    )


def corroboration_lists() -> dict[str, Any]:
    from malspark.pipeline.validation import corroboration, technique_sources
    from malspark.schemas.isr_models import AgentISR

    # ev_0100..ev_0102 are cited and never filed: each gives a reason, not a root.
    said = "; ".join(f"read at {eid}" for eid in CITED) + "; ev_0101; ev_0100; ev_0102"
    # A later statement's roots follow the earlier one's, lower ids or not.
    later = "read at ev_0011 and ev_0002"
    isr = AgentISR(agent_id="static", domain="static", claims=[_claim(said), _claim(later)])
    rows = corroboration({"static": isr}, _ledger())
    row = rows.get("T1027") or {}
    return {
        "evidence_roots": row.get("evidence_roots") or [],
        "roots_not_read": row.get("roots_not_read") or [],
        # The sources in the order the statements cite them, each statement sorted.
        "sources": list(technique_sources({"static": isr}, _ledger()).get("T1027") or {}),
    }


def dropped_values() -> list[str]:
    from malspark.pipeline.claim_drops import values_as_written

    claim = 'It reads "Alpha", "bravo", "charlie", "delta" and "echo" at 0x401000 (T1027).'
    return list(values_as_written(claim, "T1027").values())


def platform_warnings() -> list[str]:
    from malspark.qa.fp_linter import lint_report

    report = SimpleNamespace(
        executive_summary=(
            "Persistence through the Windows registry, PowerShell, macOS launch agents, "
            "cloud auth tokens and Azure."
        ),
    )
    return [w.message for w in lint_report(report, "linux") if w.rule == "C3"]


def missing_models() -> str | None:
    from malspark.llm.ollama_provider import OllamaProvider

    block = SimpleNamespace(expert_model="qwen-b", judge_model="qwen-a")
    return OllamaProvider._missing(SimpleNamespace(llm=SimpleNamespace(ollama=block)), ["other"])


def server_status() -> str:
    from langchain_core.tools import StructuredTool

    from app.services import settings_probes
    from malspark.providers.servers import ServerRegistry

    reasons = [
        "mcp server 'network' unavailable: timeout",
        "mcp server 'network' refused one tool",
        "mcp server 'network' answered without a listing",
    ]

    async def _atools_for(self: Any, role: str, job_id: str, **_ctx: Any) -> Any:
        tool = StructuredTool.from_function(func=lambda: "x", name="extract_dns", description="d")
        return ([tool], list(reasons)) if role == "network" else ([], [])

    async def _atools_for_ref(self: Any, ref: Any, job_id: str, **_ctx: Any) -> Any:
        return [], []

    async def _answered(provider: str, *, model: str, **_body: Any) -> tuple[bool, str]:
        return True, f"{model!r} answered"

    ServerRegistry.atools_for = _atools_for  # type: ignore[method-assign]
    ServerRegistry.atools_for_ref = _atools_for_ref  # type: ignore[method-assign]
    settings_probes.complete_one_turn = _answered  # type: ignore[assignment]
    result = asyncio.run(settings_probes.probe_agent({"name": "network", "settings": {}}))
    servers = (result.details or {}).get("servers") or []
    return str(next(s["status"] for s in servers if s["key"] == "network"))


def main() -> None:
    # The service container logs to standard output, where the JSON goes.
    logging.disable(logging.CRITICAL)
    print(
        json.dumps(
            {
                "corroboration": corroboration_lists(),
                "dropped_values": dropped_values(),
                "platform_warnings": platform_warnings(),
                "missing_models": missing_models(),
                "server_status": server_status(),
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
