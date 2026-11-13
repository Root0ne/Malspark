"""The source names only the platform itself writes on a ledger entry.

A ledger entry records where its tool's declaration lives (``source``). Two
names are the platform's own: ``pack`` (the triage pack's steps, written by
the ``pipeline`` agent) and ``sandbox`` (the in-process sandbox source). An
entry that holds one of them is read as the platform's own read: a further
detonation's mark is taken only from such an entry
(``analysis.detonation_reads``). So a provider that is not built into the
platform may not declare either (``providers.registry`` refuses it at
registration; ``agents.prompt_fragments.provider_source`` records such a
provider's tools under its own block).
"""

from __future__ import annotations

# The agent the triage pack's entries are written under.
PIPELINE_AGENT = "pipeline"
# The triage pack's own steps.
PACK_SOURCE = "pack"
# The in-process sandbox source (``providers.sandbox_tools``).
SANDBOX_SOURCE = "sandbox"

RESERVED_SOURCES = frozenset({PACK_SOURCE, SANDBOX_SOURCE})


def reserved_source_refusal(source: object, provider: str) -> str:
    """Why ``provider`` may not declare ``source``; ``""`` where it may."""
    if str(source or "") not in RESERVED_SOURCES:
        return ""
    return (
        f"provider {provider!r} declares its tools under {source!r}, a source name only the "
        f"platform writes ({', '.join(sorted(RESERVED_SOURCES))}); a provider that is not "
        "built into the platform declares them under its own block (provider:<id>) or a "
        "tool server's (mcp:<key>)"
    )
