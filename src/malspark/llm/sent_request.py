"""What a built model sends with every request, read off the request its client would send.

The registry keeps one :class:`SentRequest` per model it builds for an agent
(``LLMProviderRegistry.sent_requests``), read by the run summary's environment
block (``analysis.run_environment``). Nothing here is what a setting says
should be sent. The sampling parameters and the thinking switches are read by
the provider adapter that built the model (``LLMProvider.sent_parameters``):
the adapter builds the request body its client library would send for a
one-line placeholder turn, with no network call, and reads them off that
body, after the client library made its own decisions (a model whose API
drops sampling parameters, or whose library leaves them out, is read as
sending none).

What is read is the body built once, when the model is built, with the
keyword arguments its bindings add; an argument a caller passes to one call
is not in it. Where the platform changes a request's thinking switches after
its client built the body (the Anthropic adapter asks, on the request after a
replayed history changed, that mismatched thinking blocks be dropped), the
record counts the requests it changed (:func:`note_thinking_changed`); the
switches themselves stay as built.

Only that hook may say that no sampling parameter is sent. A provider adapter
without the hook, a model object the hook cannot read, or a hook that fails is
recorded as not reported (``sampling`` and ``thinking`` ``None``), never as
sending none; a hook that fails is logged once per adapter. Effort is the
level the registry hands the provider and the setting it was read from
(``llm.effort.effort_in_force``). A configured model identifier shaped like a
file-system path is kept by its base name, as an answer's is
(``core.token_ledger.base_model_name``).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from malspark.core.logger import logger
from malspark.tools.capabilities import NOT_REPORTED

# The sampling parameters a chat request may carry, under the names the
# client libraries put them in the body by. A hook reads these names off the
# body it built; a body key outside this list is not reported as sampling.
SAMPLING_PARAMETERS: tuple[str, ...] = (
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "typical_p",
    "seed",
    "frequency_penalty",
    "presence_penalty",
    "repeat_penalty",
    "repetition_penalty",
    "repeat_last_n",
    "penalize_newline",
    "tfs_z",
    "mirostat",
    "mirostat_eta",
    "mirostat_tau",
    "dry_multiplier",
    "dry_base",
    "dry_allowed_length",
    "dry_penalty_last_n",
)

# What the record says where a hook built the request and found no sampling
# parameter in it.
NO_SAMPLING_SENT = "none sent; the provider's default applies"

# What the record says where nothing could be read off a request: no hook, a
# model object the hook cannot read, or a hook that failed. Built on the one
# phrase the environment record says an unread fact with.
NOT_REPORTED_BY_ADAPTER = f"{NOT_REPORTED}: no provider adapter read it"

# The one turn a hook builds the request for. Never sent.
PLACEHOLDER_TURN = "x"

# Where a built model keeps its record, in its own ``__dict__``.
_RECORD_ATTR = "_malspark_sent_request"

# The adapters whose failing hook was logged, by class: once each.
_WARNED: set[str] = set()
# Guards the counts a request adds to a record from several threads.
_COUNT_LOCK = threading.Lock()


@dataclass(frozen=True)
class SentParameters:
    """The sampling parameters and thinking switches one request body carries, by name.

    ``thinking`` holds each thinking switch the body carries, under its dotted
    path in the body (``chat_template_kwargs.enable_thinking``, ``think``).
    Both empty where the body carries none.
    """

    sampling: dict[str, Any] = field(default_factory=dict)
    thinking: dict[str, Any] = field(default_factory=dict)


def _value(value: Any) -> Any:
    """``value`` as a record keeps it: a number, a string or a flag; ``None`` for anything else."""
    if isinstance(value, bool | int | float | str):
        return value
    return None


def sampling_in(*bodies: Mapping[str, Any] | None) -> dict[str, Any]:
    """The sampling parameters the given body parts carry, a later part winning, in list order."""
    out: dict[str, Any] = {}
    for body in bodies:
        if not isinstance(body, Mapping):
            continue
        for name in SAMPLING_PARAMETERS:
            value = _value(body.get(name))
            if value is not None:
                out[name] = value
    return {name: out[name] for name in SAMPLING_PARAMETERS if name in out}


def _leaves(value: Any, path: str) -> Iterator[tuple[str, Any]]:
    if isinstance(value, Mapping):
        for key, held in value.items():
            yield from _leaves(held, f"{path}.{key}")
        return
    kept = _value(value)
    if kept is not None:
        yield path, kept


def switches_in(body: Mapping[str, Any] | None, paths: tuple[str, ...]) -> dict[str, Any]:
    """Each leaf the body carries under one of ``paths`` (dotted), by its dotted path."""
    out: dict[str, Any] = {}
    if not isinstance(body, Mapping):
        return out
    for path in paths:
        held: Any = body
        for part in path.split("."):
            held = held.get(part) if isinstance(held, Mapping) else None
        out.update(_leaves(held, path))
    return dict(sorted(out.items()))


def bound_of(llm: Any) -> tuple[Any, dict[str, Any]]:
    """The model under ``llm``'s bindings and the keyword arguments they add to every call.

    A binding (``llm.bind(...)``, ``bind_tools``) hands its keyword arguments
    to the model it wraps on every call, an outer binding's over an inner's;
    anything that is not a binding is returned as it is, with none.
    """
    kwargs: dict[str, Any] = {}
    seen = 0
    while seen < 16 and hasattr(llm, "bound") and isinstance(getattr(llm, "kwargs", None), dict):
        kwargs = {**llm.kwargs, **kwargs}
        llm = llm.bound
        seen += 1
    return llm, kwargs


def library_method(llm: Any, name: str) -> Any:
    """``name`` as the client library defines it for ``llm``'s class, or ``None``.

    The first definition in the class's order that is not this platform's own:
    the platform's subclasses rewrite the messages, the cache markers and the
    timeout of a request (and some keep a record of each request they build),
    never its sampling, so a hook reads the body as the library builds it and
    leaves the platform's records untouched. The one per-request change they
    make to a thinking switch is counted where it is made
    (:func:`note_thinking_changed`), not read here. Only this package's own
    modules are skipped; a plug-in package whose name merely starts the same
    is read.
    """
    for klass in type(llm).__mro__:
        module = str(klass.__module__)
        own = module == "malspark" or module.startswith("malspark.")
        if name in vars(klass) and not own:
            return vars(klass)[name]
    return None


def built_body(llm: Any, builder: str, kinds: tuple[str, ...]) -> Any:
    """The request body the client library's ``builder`` makes for ``llm``, or ``None``.

    For one placeholder turn, with the keyword arguments ``llm``'s bindings
    add (:func:`bound_of`), through the library's own builder
    (:func:`library_method`); no request is sent. ``None`` where the model
    under the bindings is not of one of ``kinds`` (its ``_llm_type``) or the
    library defines no such builder. A builder that fails raises.
    """
    from langchain_core.messages import HumanMessage

    model, kwargs = bound_of(llm)
    try:
        kind = str(model._llm_type)
    except Exception:  # noqa: BLE001 — a model that names no type is no adapter's
        return None
    build = library_method(model, builder) if kind in kinds else None
    if not callable(build):
        return None
    return build(model, [HumanMessage(content=PLACEHOLDER_TURN)], **kwargs)


def parameters_sent(provider: Any, llm: Any) -> SentParameters | None:
    """What ``llm`` sends, read by ``provider``'s hook; ``None`` where it reports nothing.

    ``provider`` is the adapter class (``facts_of``) or a provider's name.
    A hook that fails is logged as a warning once per adapter class, by the
    exception's type. Never raises.
    """
    if llm is None:
        return None
    try:
        if isinstance(provider, str):
            from malspark.llm.provider_base import facts_of

            provider = facts_of(provider)
        hook = getattr(provider, "sent_parameters", None)
        read = hook(llm) if callable(hook) else None
    except Exception as exc:  # noqa: BLE001 — a hook that fails reports nothing
        _warn_once(provider, exc)
        return None
    return read if isinstance(read, SentParameters) else None


def _warn_once(provider: Any, exc: BaseException) -> None:
    klass = provider if isinstance(provider, type) else type(provider)
    name = f"{klass.__module__}.{klass.__qualname__}"
    with _COUNT_LOCK:
        if name in _WARNED:
            return
        _WARNED.add(name)
    logger.warning(
        "What %s's models send could not be read (%s); recorded as %s.",
        name,
        type(exc).__name__,
        NOT_REPORTED_BY_ADAPTER,
    )


@dataclass
class SentRequest:
    """What one model of an agent's list sends: its sampling, thinking switches and effort."""

    agent: str
    # Its place in the agent's list: 0 the first model, 1 and on its fallbacks.
    position: int
    provider: str
    # The configured identifier, by its base name where it is shaped like a
    # file-system path (``model_reduced``).
    model: str
    model_reduced: bool = False
    # The sampling parameters sent, by name; empty where the request carries
    # none; ``None`` where the provider adapter reported nothing.
    sampling: dict[str, Any] | None = field(default_factory=dict)
    # The thinking switches sent, by their dotted path in the body; as
    # ``sampling`` for empty and ``None``.
    thinking: dict[str, Any] | None = field(default_factory=dict)
    # The effort level sent, or ``None`` where none is.
    effort: str | None = None
    # The setting ``effort`` was read from; empty where none is sent.
    effort_setting: str = ""
    # Where none is sent, why (``effort_in_force``'s phrase).
    effort_statement: str = ""
    # The requests whose thinking switches the platform changed after the
    # client built them (:func:`note_thinking_changed`).
    thinking_changed: int = 0

    def __post_init__(self) -> None:
        from malspark.core.token_ledger import base_model_name

        name, reduced = base_model_name(self.model)
        self.model, self.model_reduced = name, self.model_reduced or reduced

    def as_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "position": self.position,
            "provider": self.provider,
            "model": self.model,
            "sampling": None if self.sampling is None else dict(self.sampling),
            "thinking": None if self.thinking is None else dict(self.thinking),
        }
        if self.model_reduced:
            row["model_reduced"] = True
        if self.thinking_changed:
            row["thinking_changed_requests"] = self.thinking_changed
        if self.sampling is None:
            row["sampling_statement"] = NOT_REPORTED_BY_ADAPTER
        elif not self.sampling:
            row["sampling_statement"] = NO_SAMPLING_SENT
        if self.effort:
            row["effort"] = self.effort
            row["effort_setting"] = self.effort_setting
        else:
            row["effort"] = None
            row["effort_statement"] = self.effort_statement or "none sent"
        return row


def record_sent_request(llm: Any, record: SentRequest, provider: Any = None) -> Any:
    """Keep ``record`` on ``llm``, what it sends read by ``provider``'s hook; returns ``llm``.

    ``provider`` defaults to the record's own provider name. Never raises.
    """
    read = parameters_sent(provider if provider is not None else record.provider, llm)
    record.sampling = None if read is None else dict(read.sampling)
    record.thinking = None if read is None else dict(read.thinking)
    try:
        object.__setattr__(llm, _RECORD_ATTR, record)
    except Exception:  # noqa: BLE001 — a model that keeps no record still answers
        pass
    return llm


def sent_request_of(llm: Any) -> SentRequest | None:
    """The record kept on ``llm``, or ``None``."""
    held = getattr(llm, "__dict__", {}).get(_RECORD_ATTR) if llm is not None else None
    return held if isinstance(held, SentRequest) else None


def note_thinking_changed(llm: Any) -> None:
    """Count on ``llm``'s record one request whose thinking switches the platform changed.

    Called by an adapter where it changes a thinking switch of a body its
    client already built; the record's ``thinking`` stays as built. Never raises.
    """
    record = sent_request_of(llm)
    if record is None:
        return
    with _COUNT_LOCK:
        record.thinking_changed += 1


def carry_sent_request(replaced: Any, replacement: Any) -> None:
    """A rebuilt model's record: the replaced one's, what it sends read off ``replacement``.

    The same record object, so the registry's list says what the model now
    answering sends. Never raises.
    """
    record = sent_request_of(replaced)
    if record is not None:
        record_sent_request(replacement, record)


def sampling_said(sampling: Mapping[str, Any] | None) -> str:
    """The sampling parameters in words, for a log line."""
    if sampling is None:
        return NOT_REPORTED_BY_ADAPTER
    if not sampling:
        return NO_SAMPLING_SENT
    return ", ".join(f"{name}={value}" for name, value in sampling.items())
