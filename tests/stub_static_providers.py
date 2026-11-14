"""Static providers made up for a test: no server, no decompiler, one tool each.

``registered(ids)`` registers one provider class per id for the length of a
``with`` block and forgets each again after it. Every provider offers the same
one tool, ``read_sample(path)``, so a second provider on one agent has its tool
offered under a prefixed name; the tool answers with the provider's id and the
path it was given, and each class keeps the paths its tool and its pre-loop
open were given (``read_paths``, ``opened_paths``). A provider asks for a
mirror of the sample (``needs_sample_mirror``), as a disassembler does.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, ClassVar

from langchain_core.tools import StructuredTool

from malspark.providers import registry
from malspark.providers.base import StaticCapabilities, StaticJobContext, StaticProvider

TOOL = "read_sample"


class StubStaticProvider(StaticProvider):
    """One made-up provider; ``registered`` makes a subclass per id."""

    read_paths: ClassVar[list[str]]
    opened_paths: ClassVar[list[str | None]]

    @classmethod
    def from_settings(cls, cfg: Any) -> StubStaticProvider:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(provides_tools=True, needs_sample_mirror=True)

    def open(self, job: StaticJobContext) -> None:
        self.job = job

    def open_sample(self, path: str | None = None) -> bool:
        type(self).opened_paths.append(path)
        return True

    def get_tools(self) -> list[Any]:
        owner = type(self)

        def read_sample(path: str) -> str:
            """Read the sample at ``path``."""
            owner.read_paths.append(path)
            return f"{owner.id} read {path}: the sample's bytes are here."

        return [StructuredTool.from_function(func=read_sample, name=TOOL)]


@contextmanager
def registered(*ids: str) -> Iterator[dict[str, type[StubStaticProvider]]]:
    """One ``StubStaticProvider`` class per id, registered for the block, by id."""
    classes: dict[str, type[StubStaticProvider]] = {}
    try:
        for provider_id in ids:
            cls = type(
                f"Stub_{provider_id}",
                (StubStaticProvider,),
                {"read_paths": [], "opened_paths": [], "title": f"Stub {provider_id}"},
            )
            registry.register_static_provider(provider_id)(cls)
            classes[provider_id] = cls
        yield classes
    finally:
        for provider_id in classes:
            registry.forget_static_provider(provider_id)
