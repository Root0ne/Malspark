"""No entry written for a plug-in provider carries a source name only the platform writes.

Every place where a provider's declared source becomes the source of a
recorded entry takes it through ``provider_source``: the tools a built-in role
or a prompt role attaches are stamped with it, and the entries the report
node writes for an evidence-only provider are recorded under it. A plug-in
provider whose ``declaration_source`` answers ``pack`` or ``sandbox`` at run
time has its entries recorded under its own block on each of those paths
(T-671 review r4 F1b). Offline.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from malspark.agents.prompt_fragments import PROVIDER_FAMILY, provider_source, stamp_source
from malspark.agents.tool_pinning import declared_source_of
from malspark.analysis.detonation_reads import later_detonation_name
from malspark.core.platform_sources import RESERVED_SOURCES
from malspark.providers.base import EvidenceAnswer, StaticEvidenceBundle
from malspark.schemas.evidence import EvidenceCounter
from tests.unit.pipeline.test_report_error_channel import (  # noqa: F401
    _initial_state,
    fake_container,
)

OWN = "provider:answering_r4"


class _Tool:
    """A provider's tool as an attach hands it over."""

    def __init__(self) -> None:
        self.name = "answer"
        self.metadata: dict[str, Any] = {}

    def model_copy(self, update: dict[str, Any]) -> _Tool:
        copy = _Tool()
        copy.metadata = dict(update["metadata"])
        return copy


class _Answering:
    """A plug-in evidence-only provider whose declaration source is answered at run time."""

    __module__ = "malspark.providers.static.plug_in"
    id = "answering_r4"

    def __init__(self, source: str) -> None:
        self._source = source
        self.capabilities = MagicMock(provides_evidence=True, provides_tools=True)

    @property
    def declaration_source(self) -> str:
        return self._source

    def open(self, _context: Any) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return [_Tool()]

    def collect_evidence(self, _sample_path: str) -> StaticEvidenceBundle:
        # Read as a later detonation's read were it recorded under the platform's source.
        payload = {"capabilities": [{"name": "x"}], "detonation": "d2", "launched_with": "-p x"}
        return StaticEvidenceBundle(
            entries=(EvidenceAnswer(tool="answer", kind="capability_rules", payload=payload),)
        )


async def _report_node_entries(container: Any, source: str) -> list[dict[str, Any]]:
    from malspark.pipeline.nodes import make_report_node

    container.is_mock = False
    container.get_narrative_agent.return_value = None
    container.get_report_composer.return_value = None
    container.get_static_provider.return_value = _Answering(source)
    container.get_evidence_counter.return_value = EvidenceCounter()
    state = {**_initial_state(), "sample_path": "/tmp/sample.bin", "evidence_ledger": []}
    result = await make_report_node(container)(state)  # type: ignore[arg-type]
    return list(result.get("evidence_ledger") or [])


@pytest.mark.asyncio
@pytest.mark.parametrize("source", sorted(RESERVED_SOURCES))
async def test_the_report_node_records_a_plug_in_s_entries_under_its_own_block(
    fake_container: Any,  # noqa: F811
    source: str,
) -> None:
    entries = await _report_node_entries(fake_container, source)
    assert entries
    for entry in entries:
        assert entry["source"] == OWN, entry
        assert later_detonation_name(entry) == ""


@pytest.mark.asyncio
async def test_a_plug_in_s_own_source_stands_on_the_report_node(
    fake_container: Any,  # noqa: F811
) -> None:
    entries = await _report_node_entries(fake_container, "mcp:acme")
    assert entries and {entry["source"] for entry in entries} == {"mcp:acme"}


@pytest.mark.asyncio
@pytest.mark.parametrize("source", sorted(RESERVED_SOURCES))
async def test_no_path_records_a_plug_in_under_a_platform_source(
    fake_container: Any,  # noqa: F811
    source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from malspark.agents import composition

    provider = _Answering(source)
    written: dict[str, set[str]] = {}
    # The tools a built-in role attaches (``StaticAnalyst``, ``DynamicAnalyst``).
    attached = stamp_source(
        provider.get_tools(), PROVIDER_FAMILY, declared=provider_source(provider)
    )
    written["role"] = {str(declared_source_of(tool)) for tool in attached}
    # The tools a prompt role opens by reference (``composition._provider_tools``).
    monkeypatch.setattr(composition, "opens_provider_by_reference", lambda _definition: True)
    container = MagicMock()
    container.get_static_provider.return_value = provider
    opened = composition._provider_tools(container, MagicMock(), provider.id)
    written["prompt role"] = {str(declared_source_of(tool)) for tool in opened}
    # The entries the report node writes for an evidence-only provider.
    written["report node"] = {
        entry["source"] for entry in await _report_node_entries(fake_container, source)
    }
    assert written == {"role": {OWN}, "prompt role": {OWN}, "report node": {OWN}}
