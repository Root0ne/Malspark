"""Print, as JSON, the orders the record and the console write from a set.

Run as a script by
``test_an_order_the_report_writes_is_the_same_under_every_hash_seed.py``,
once per hash seed: each process salts string hashes its own way, so a list
taken from a set in iteration order differs between two runs of this file.
With the argument ``models`` it prints what a model reads instead
(``test_what_a_model_reads_is_ordered_the_same_under_every_hash_seed.py``).
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
    isr = AgentISR(
        agent_id="static", domain="static", revision_round=0, claims=[_claim(said), _claim(later)]
    )
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


# Four analysts whose names are of one length, named on one debate line in an
# order that is not sorted. Each one's claim cites its own count entry and
# writes one of two functions, the two of each pair in its two spellings.
DEBATERS = ("triage", "static", "script", "memory")
PLACES = {"triage": "0x1000", "static": "0x401000", "script": "0x402000", "memory": "0x2000"}
DEBATE_LINE = (
    "[analysts: triage, static, script, memory] triage claim 1 and static claim 1 read the "
    "decoder, script claim 1 and memory claim 1 read the writer: 3 matches against 4 matches"
)
# Lines whose marks were not read, in the order the mediator wrote them.
UNREAD = ("zeta reads the key", "alpha reads the key", "mu reads the key", "kappa reads the key")
# A PE's imports, three python libraries among them.
IMPORTS = ("KERNEL32.dll", "python312.dll", "python3.dll", "python311.dll")
# The interpreter's library beside a library whose name starts with the same word.
INTERPRETER_AND_EXTENSION = ("pywintypes39.dll", "pythoncom39.dll", "python39.dll")


def debate_ledger() -> list[Any]:
    from malspark.schemas.evidence import LedgerEntry

    # An image base joins each offset to its virtual address.
    entries = [
        LedgerEntry(
            id="ev_0001", tool="identify_file", agent="pipeline", output='{"image_base": 4194304}'
        ),
        LedgerEntry(
            id="ev_0002", tool="decompile_function", agent="static", args={"address": "0x401000"}
        ),
        LedgerEntry(
            id="ev_0003", tool="decompile_function", agent="static", args={"address": "0x402000"}
        ),
    ]
    entries.extend(
        LedgerEntry(
            id=f"ev_{6 + n:04d}", tool="yara_scan", agent=name, structured={"match_count": 3}
        )
        for n, name in enumerate(DEBATERS)
    )
    return entries


def debate_isrs() -> dict[str, Any]:
    from malspark.schemas.isr_models import AgentISR, ClaimEvidence

    return {
        name: AgentISR(
            agent_id=name,
            domain=name,
            revision_round=0,
            claims=[
                ClaimEvidence(
                    technique_id="T1027",
                    claim=f"It decodes its strings at {PLACES[name]}.",
                    evidence_ref=f"ev_{6 + n:04d}",
                    confidence=0.8,
                )
            ],
        )
        for n, name in enumerate(DEBATERS)
    }


def debate_facts() -> dict[str, list[str]]:
    from malspark.pipeline.debate_facts import ledger_count_facts, place_facts

    lines = [DEBATE_LINE]
    return {
        "counts": ledger_count_facts(lines, debate_isrs(), debate_ledger(), list(DEBATERS)),
        "places": place_facts(lines, debate_isrs(), debate_ledger(), list(DEBATERS)),
    }


def asserting_ledger() -> list[Any]:
    from malspark.schemas.evidence import LedgerEntry

    # One rule scan names both sub-techniques of T1055; two others name one each.
    capa = {"capabilities": [{"attck": "T1055.012"}, {"attck": "T1055.001"}]}
    sigma = {"matches": [{"title": "x", "tags": ["attack.t1055.012"], "matched_fields": []}]}
    yara = {"matches": [{"rule": "r", "meta": {"technique_id": "T1055.001"}, "tags": []}]}
    return [
        LedgerEntry(id="ev_0001", tool="capa", agent="pipeline", structured=capa),
        LedgerEntry(id="ev_0002", tool="sigma_match_sandbox", agent="pipeline", structured=sigma),
        LedgerEntry(id="ev_0003", tool="yara_scan", agent="pipeline", structured=yara),
    ]


def technique_sources() -> dict[str, list[str]]:
    from malspark.pipeline.evidence_summary import collect

    return {tid: [s for s, _c in rows] for tid, rows in collect({}, asserting_ledger()).items()}


def credit_question() -> list[str]:
    from malspark.pipeline.validation import credit_without_claim_violations

    credit = SimpleNamespace(
        type="relationship",
        id="relationship--1",
        x_malspark_technique_id="T1055",
        x_malspark_contributing_agents=["dynamic"],
        source_ref="",
        target_ref="",
    )
    bundle = SimpleNamespace(objects=[credit])
    return [v.message for v in credit_without_claim_violations(bundle, technique_sources())]


class _Import:
    def __init__(self, dll: str) -> None:
        self.dll = dll.encode()


def with_imports(read: Any, imports: tuple[str, ...] = IMPORTS) -> Any:
    """``read()`` with the PE parser answering ``imports`` for any image."""
    import pefile

    class _Image:
        """The one part of a parsed PE the toolchain reading looks at: its imports."""

        def __init__(self, data: Any = None, fast_load: bool = False) -> None:
            self.DIRECTORY_ENTRY_IMPORT = [_Import(dll) for dll in imports]

    held = pefile.PE
    pefile.PE = _Image
    try:
        return read()
    finally:
        pefile.PE = held


def language_lines() -> list[str | None]:
    from malspark.extractors.sample_identity import _detect_language_or_compiler

    blob = b"MZ" + b"\0" * 510
    return [
        with_imports(lambda: _detect_language_or_compiler(blob), imports)
        for imports in (IMPORTS, INTERPRETER_AND_EXTENSION)
    ]


def mediation(**fields: Any) -> Any:
    from malspark.pipeline.state import AgentArgument

    return AgentArgument(
        agent_name="mediator",
        finding="The analysts disagree.",
        status="error",
        contradictions=[DEBATE_LINE],
        unread_marks=list(UNREAD),
        **fields,
    )


def history_text() -> str:
    from malspark.agents.judge_agent import negotiation_history_text

    return negotiation_history_text([mediation()])


def model_reads() -> dict[str, Any]:
    return {
        "debate_facts": debate_facts(),
        "credit_question": credit_question(),
        "language_lines": language_lines(),
        "history_text": history_text(),
    }


def main() -> None:
    # The service container logs to standard output, where the JSON goes.
    logging.disable(logging.CRITICAL)
    if sys.argv[1:] == ["models"]:
        print(json.dumps(model_reads(), indent=1))
        return
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
