"""A provider shows the tool server it drives through a handle of its own (T-668).

The disassembler and decompiler providers reach their tool servers through
their own connections, which the job's server registry never sees, so a run's
record of its tools listed none of them. One hook on the provider base,
``own_tool_server``, answers what such a provider attached — the server's key,
the name and version it gave at its attach, and its capability manifest where
it has one — and the record reads it as it reads the registry's servers.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.core.config import MCPServerConfig
from malspark.providers.base import (
    SandboxProvider,
    ServerOfItsOwn,
    StaticJobContext,
    StaticProvider,
)
from malspark.providers.static.generic_mcp import GenericMCPStaticProvider
from malspark.tools.capabilities import ServerCapabilities


def test_every_provider_has_the_hook_and_by_default_nothing_to_report() -> None:
    assert issubclass(StaticProvider, ServerOfItsOwn)
    assert issubclass(SandboxProvider, ServerOfItsOwn)
    from malspark.providers.static.null import NullStaticProvider

    assert NullStaticProvider().own_tool_server() is None


class TestAProviderOnItsOwnHandle:
    def _provider(self) -> GenericMCPStaticProvider:
        return GenericMCPStaticProvider(MCPServerConfig(enabled=True, command="my-mcp"), label="X")

    def test_nothing_is_reported_before_the_handle_attached(self) -> None:
        assert self._provider().own_tool_server() is None

    def test_the_attached_server_and_its_manifest_are_reported(self) -> None:
        provider = self._provider()
        handle = provider._handle
        handle.server_info = {"name": "r2mcp", "version": "1.2.0"}
        handle.attached_once = True
        manifest = {"server": "x", "version": "1.2.0", "tools": [], "requirements": []}
        handle.capabilities = ServerCapabilities.from_payload("x", manifest)
        held = provider.own_tool_server()
        assert held == {
            "server": handle.name,
            "server_info": {"name": "r2mcp", "version": "1.2.0"},
            "manifest": handle.capabilities.to_dict(),  # type: ignore[union-attr]
        }

    def test_a_server_without_a_manifest_reports_its_name_and_version(self) -> None:
        provider = self._provider()
        provider._handle.server_info = {"name": "r2mcp"}
        held = provider.own_tool_server()
        assert held is not None
        assert held["manifest"] is None


class _Client:
    """A stand-in for the decompiler's HTTP client: it attaches and lists no tool."""

    server_info: dict[str, str] = {}

    def __init__(self, **kwargs: Any) -> None:
        pass

    async def initialize(self) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return []

    async def aclose(self) -> None:
        return None


class TestTheDecompilerProvider:
    def test_its_server_is_reported_once_attached_and_after_it_closes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.providers.static.ghidra import GhidraStaticProvider, http_client

        monkeypatch.setattr(http_client, "GhidraHTTPClient", _Client)
        cfg = MCPServerConfig(enabled=True, transport="http", url="http://ghidra.invalid:1")
        provider = GhidraStaticProvider(cfg, None, None)  # type: ignore[arg-type]
        assert provider.own_tool_server() is None
        provider.open(StaticJobContext())
        # Over HTTP the server gives no name or version: the record says not reported.
        assert provider.own_tool_server() == {
            "server": provider.id,
            "server_info": {},
            "manifest": None,
        }
        provider.close()
        assert provider.own_tool_server() is not None
