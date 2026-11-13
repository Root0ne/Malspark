"""A provider is built into the platform only where the registry recorded its class.

"Built in" is a fact the registry records: the exact class objects the
platform's own provider modules registered as it imported them. Nothing a
class says of itself makes it built in: not a ``__module__`` naming the
platform, nor being a subclass of a built-in provider. Registration and
``provider_source`` read that one decision, so such a class stating or
answering a source name only the platform writes is refused at registration
or recorded under its own block (T-671 review r4 F1a). Offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.agents.prompt_fragments import provider_source
from malspark.core.platform_sources import RESERVED_SOURCES
from malspark.core.plugins import PluginRefused
from malspark.providers import registry
from malspark.providers.registry import (
    is_built_in_class,
    register_sandbox_provider,
    register_static_provider,
)

# A plug-in shipped under the platform's own package name.
PLATFORM_NAMED = "malspark.providers.static.plug_in"


def _built_ins() -> list[tuple[str, type]]:
    registry.discover_providers()
    out: list[tuple[str, type]] = []
    for kind, held in (
        ("static", registry._STATIC_REGISTRY),
        ("sandbox", registry._SANDBOX_REGISTRY),
    ):
        out += [(kind, held[name]) for name in sorted(registry.built_in_ids(kind))]
    return out


def _register(kind: str) -> Any:
    return register_static_provider if kind == "static" else register_sandbox_provider


def test_every_built_in_class_is_built_in_and_states_no_platform_source() -> None:
    assert _built_ins()
    for _kind, cls in _built_ins():
        assert is_built_in_class(cls), cls
        stated = cls.__dict__.get("declaration_source")
        assert not (isinstance(stated, str) and stated in RESERVED_SOURCES), cls


@pytest.mark.parametrize("source", sorted(RESERVED_SOURCES))
@pytest.mark.parametrize("kind", ["static", "sandbox"])
def test_a_class_naming_the_platform_s_module_is_refused(kind: str, source: str) -> None:
    spoof = type("Spoof", (), {"__module__": PLATFORM_NAMED, "declaration_source": source})
    assert not is_built_in_class(spoof)
    with pytest.raises(PluginRefused, match="only the platform writes"):
        _register(kind)("spoof_r4")(spoof)
    assert "spoof_r4" not in registry._STATIC_REGISTRY
    assert "spoof_r4" not in registry._SANDBOX_REGISTRY


@pytest.mark.parametrize("module", [PLATFORM_NAMED, __name__])
def test_a_plug_in_subclass_of_a_built_in_is_refused(module: str) -> None:
    for kind, base in _built_ins():
        for source in sorted(RESERVED_SOURCES):
            sub = type(
                f"PlugIn{base.__name__}",
                (base,),
                {"__module__": module, "declaration_source": source},
            )
            assert not is_built_in_class(sub), base
            with pytest.raises(PluginRefused, match="only the platform writes"):
                _register(kind)("subclass_r4")(sub)
            assert "subclass_r4" not in registry._STATIC_REGISTRY
            assert "subclass_r4" not in registry._SANDBOX_REGISTRY


def _answering(bases: tuple[type, ...], module: str, source: str) -> Any:
    """An instance of a class whose declaration source is answered at run time."""
    cls = type(
        "Answering",
        bases,
        {
            "__module__": module,
            "id": "answering_r4",
            "declaration_source": property(lambda _self: source),
        },
    )
    return cls.__new__(cls)


@pytest.mark.parametrize("source", sorted(RESERVED_SOURCES))
def test_a_class_naming_the_platform_s_module_answering_a_platform_source_has_its_own_block(
    source: str, caplog: Any
) -> None:
    assert provider_source(_answering((), PLATFORM_NAMED, source)) == "provider:answering_r4"
    assert "only the platform writes" in caplog.text


@pytest.mark.parametrize("module", [PLATFORM_NAMED, __name__])
def test_a_plug_in_subclass_answering_a_platform_source_has_its_own_block(module: str) -> None:
    for _kind, base in _built_ins():
        for source in sorted(RESERVED_SOURCES):
            provider = _answering((base,), module, source)
            assert provider_source(provider) == "provider:answering_r4", base
