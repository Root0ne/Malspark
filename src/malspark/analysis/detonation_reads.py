"""Whether a ledger entry is the platform's read of a detonation of the sample, and of which.

The one rule every reader of such an entry asks: the pack, the citation
index, the report's sections and the ledger projection
(:func:`later_detonation_name`), and the report's marks
(:func:`own_detonation_read`).
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from typing import Any

from malspark.core.platform_sources import PACK_SOURCE, PIPELINE_AGENT, SANDBOX_SOURCE


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
    from malspark.analysis.sandbox_sections import QUALIFIER_RE

    data = _field(entry, "structured")
    if not isinstance(data, Mapping) or "launched_with" not in data:
        return ""
    if not _platform_source(entry):
        return ""
    name = data.get("detonation")
    if not isinstance(name, str) or QUALIFIER_RE.fullmatch(f"{name}/") is None:
        return ""
    return name.lower()


def own_detonation_read(entry: Any) -> bool:
    """Whether a ledger entry, or its index row, is the platform's read of the job's own detonation.

    The same source and agent test as :func:`later_detonation_name`'s, no
    later detonation's name, and a tool the platform reads a detonation with:
    a reader of the in-process sandbox source
    (``providers.sandbox_tools.DETONATION_READERS``) or the sandbox report's
    section index, the tools ``pipeline.detonations.platform_reads`` reads a
    later one with. So a pack's static step and a request for a detonation
    observed none. The tool's declared kind, or its lack of one, plays no part.
    """
    if later_detonation_name(entry) or not _platform_source(entry):
        return False
    return _field(entry, "tool") in _detonation_tools()


def _field(entry: Any, name: str) -> Any:
    return entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, None)


def _platform_source(entry: Any) -> bool:
    """Whether the recorder filed ``entry`` under the platform's sandbox source or the pack."""
    source, agent = str(_field(entry, "source") or ""), str(_field(entry, "agent") or "")
    return source == SANDBOX_SOURCE or (source == PACK_SOURCE and agent == PIPELINE_AGENT)


@cache
def _detonation_tools() -> frozenset[str]:
    """The sandbox source's readers of a detonation, and a sandbox report's section index."""
    from malspark.analysis.sandbox_sections import SECTIONS_TOOL
    from malspark.providers.sandbox_tools import DETONATION_READERS

    return frozenset([*DETONATION_READERS, SECTIONS_TOOL])
