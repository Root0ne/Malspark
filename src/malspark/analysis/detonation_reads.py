"""Whether a ledger entry is the platform's read of a further detonation of the sample.

The one rule every reader of such an entry asks: the pack, the citation
index, the report's sections and the ledger projection
(:func:`later_detonation_name`).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def later_detonation_name(entry: Any) -> str:
    """The further detonation (``d2``…) a ledger entry is the platform's read of; ``""`` else.

    The one rule every reader of such an entry asks (the pack, the citation
    index, the report's sections, the ledger projection). Only the platform writes such a read: the
    pack's own read of a detonation that came back (agent ``pipeline``,
    source ``pack``; ``pipeline.detonations.platform_reads``) or a call of the
    platform's in-process sandbox source (``providers.sandbox_tools``), whose
    answer states the detonation and its launch (``DetonationRecord.stated``).
    The source is the one the recorder filed, never read from the answer; a
    tool answer of any other source that carries a ``detonation`` key is the
    tool's own. The name is taken only where it is a detonation's name in the
    one form the citation checks know (``sandbox_sections.QUALIFIER_RE``,
    whole); anything else is no later detonation.
    """
    from malspark.agents.prompt_fragments import SANDBOX_FAMILY
    from malspark.analysis.sandbox_sections import QUALIFIER_RE
    from malspark.pipeline.triage_pack import PACK_SOURCE, PIPELINE

    if isinstance(entry, Mapping):
        data, source, agent = entry.get("structured"), entry.get("source"), entry.get("agent")
    else:
        data = getattr(entry, "structured", None)
        source, agent = getattr(entry, "source", None), getattr(entry, "agent", None)
    if not isinstance(data, Mapping) or "launched_with" not in data:
        return ""
    if not (source == SANDBOX_FAMILY or (source == PACK_SOURCE and agent == PIPELINE)):
        return ""
    name = data.get("detonation")
    if not isinstance(name, str) or QUALIFIER_RE.fullmatch(f"{name}/") is None:
        return ""
    return name.lower()
