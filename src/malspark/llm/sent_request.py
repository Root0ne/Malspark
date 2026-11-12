"""What a built model sends with every request, read off the model its provider built.

The registry keeps one :class:`SentRequest` per model it builds for an agent
(``LLMProviderRegistry.sent_requests``), read by the run summary's environment
block (``analysis.run_environment``). Nothing here is what a setting says
should be sent: the sampling parameters are read off the chat model object
the provider adapter handed back, after the adapter made its own decisions
(a model documented to refuse sampling parameters is built with none), from
the same fields the client library writes into the request body. A parameter
left unset is one the client leaves out of the request, so an empty
``sampling`` means no sampling parameter was sent and the provider's own
default applied.

The parameters are read by name from one fixed list of sampling parameter
names, never by provider: the model's own fields first, then its
``model_kwargs`` and ``extra_body``, the two channels a client passes into the
body as they are. Effort is the level the registry hands the provider and the
setting it was read from (``llm.effort.effort_in_force``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# The sampling parameters a chat request may carry, under the names the
# client libraries take them by. A name no client knows is never read.
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
    "tfs_z",
    "mirostat",
    "mirostat_eta",
    "mirostat_tau",
    "dry_multiplier",
    "dry_base",
    "dry_allowed_length",
    "dry_penalty_last_n",
)

# The channels a client passes into the request body as they are, after its
# own fields, in the order a later one wins.
_PASSED_THROUGH = ("model_kwargs", "extra_body")

# What the record says where no sampling parameter is sent.
NO_SAMPLING_SENT = "none sent; the provider's default applies"

# Where a built model keeps its record, in its own ``__dict__``.
_RECORD_ATTR = "_malspark_sent_request"


def _value(value: Any) -> Any:
    """``value`` as a record keeps it: a number, a string or a flag; ``None`` for anything else."""
    if isinstance(value, bool | int | float | str):
        return value
    return None


def sampling_sent(llm: Any) -> dict[str, Any]:
    """The sampling parameters ``llm`` puts in every request, by name. Never raises.

    Empty when it sends none: the provider's default applies.
    """
    out: dict[str, Any] = {}
    if llm is None:
        return out
    for name in SAMPLING_PARAMETERS:
        try:
            value = _value(getattr(llm, name, None))
        except Exception:  # noqa: BLE001 — a field that cannot be read is not sent by us
            value = None
        if value is not None:
            out[name] = value
    for channel in _PASSED_THROUGH:
        try:
            held = getattr(llm, channel, None)
        except Exception:  # noqa: BLE001
            held = None
        if not isinstance(held, Mapping):
            continue
        for name in SAMPLING_PARAMETERS:
            value = _value(held.get(name))
            if value is not None:
                out[name] = value
    return {name: out[name] for name in SAMPLING_PARAMETERS if name in out}


@dataclass
class SentRequest:
    """What one model of an agent's list sends: its sampling and its effort."""

    agent: str
    # Its place in the agent's list: 0 the first model, 1 and on its fallbacks.
    position: int
    provider: str
    model: str
    sampling: dict[str, Any] = field(default_factory=dict)
    # The effort level sent, or ``None`` where none is.
    effort: str | None = None
    # The setting ``effort`` was read from; empty where none is sent.
    effort_setting: str = ""
    # Where none is sent, why (``effort_in_force``'s phrase).
    effort_statement: str = ""

    def as_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "position": self.position,
            "provider": self.provider,
            "model": self.model,
            "sampling": dict(self.sampling),
        }
        if not self.sampling:
            row["sampling_statement"] = NO_SAMPLING_SENT
        if self.effort:
            row["effort"] = self.effort
            row["effort_setting"] = self.effort_setting
        else:
            row["effort"] = None
            row["effort_statement"] = self.effort_statement or "none sent"
        return row


def record_sent_request(llm: Any, record: SentRequest) -> Any:
    """Keep ``record`` on ``llm``, its sampling read off ``llm``; returns ``llm``. Never raises."""
    record.sampling = sampling_sent(llm)
    try:
        object.__setattr__(llm, _RECORD_ATTR, record)
    except Exception:  # noqa: BLE001 — a model that keeps no record still answers
        pass
    return llm


def sent_request_of(llm: Any) -> SentRequest | None:
    """The record kept on ``llm``, or ``None``."""
    held = getattr(llm, "__dict__", {}).get(_RECORD_ATTR) if llm is not None else None
    return held if isinstance(held, SentRequest) else None


def carry_sent_request(replaced: Any, replacement: Any) -> None:
    """A rebuilt model's record: the replaced one's, its sampling read off ``replacement``.

    The same record object, so the registry's list says what the model now
    answering sends. Never raises.
    """
    record = sent_request_of(replaced)
    if record is not None:
        record_sent_request(replacement, record)


def sampling_said(sampling: Mapping[str, Any]) -> str:
    """The sampling parameters in words, for a log line."""
    if not sampling:
        return NO_SAMPLING_SENT
    return ", ".join(f"{name}={value}" for name, value in sampling.items())
