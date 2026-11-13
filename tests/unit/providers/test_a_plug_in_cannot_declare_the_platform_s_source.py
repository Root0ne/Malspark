"""A provider not built into the platform cannot declare a source name only the platform writes.

``pack`` and ``sandbox`` are the platform's own sources (``core.platform_sources``):
an entry recorded under one is read as the platform's own read, a further
detonation's mark included. A plug-in provider whose class states one is
refused at registration with the reason; one whose ``declaration_source``
answers one at run time has its tools recorded under its own block, and the
refusal is logged (T-671 review r3 R7). Offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.agents.prompt_fragments import provider_source
from malspark.analysis.detonation_reads import later_detonation_name
from malspark.core.platform_sources import RESERVED_SOURCES
from malspark.core.plugins import PluginRefused
from malspark.providers.registry import _STATIC_REGISTRY, register_static_provider


@pytest.mark.parametrize("source", sorted(RESERVED_SOURCES))
def test_a_plug_in_stating_a_platform_source_is_refused_at_registration(source: str) -> None:
    with pytest.raises(PluginRefused, match="only the platform writes"):

        @register_static_provider("stowaway_r3")
        class _Stowaway:
            declaration_source = source

    assert "stowaway_r3" not in _STATIC_REGISTRY


class _Answering:
    """A plug-in provider whose declaration source is answered at run time."""

    id = "answering_r3"

    def __init__(self, source: str) -> None:
        self._source = source

    @property
    def declaration_source(self) -> str:
        return self._source


def test_a_plug_in_answering_a_platform_source_is_recorded_under_its_own_block(
    caplog: Any,
) -> None:
    for source in sorted(RESERVED_SOURCES):
        assert provider_source(_Answering(source)) == "provider:answering_r3"
    assert "only the platform writes" in caplog.text
    # Its own sources stand.
    assert provider_source(_Answering("mcp:acme")) == "mcp:acme"


def test_an_entry_under_its_own_block_is_no_later_detonation() -> None:
    entry = {
        "agent": "dynamic",
        "source": provider_source(_Answering("sandbox")),
        "structured": {"detonation": "d2", "launched_with": "-p x"},
    }
    assert later_detonation_name(entry) == ""


def test_the_built_in_sources_stand() -> None:
    from malspark.agents.prompt_fragments import SANDBOX_FAMILY
    from malspark.pipeline.triage_pack import PACK_SOURCE

    assert {SANDBOX_FAMILY, PACK_SOURCE} == set(RESERVED_SOURCES)
