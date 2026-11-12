"""What one sandbox submission asks of the sandbox beyond the sample, and its answer.

A job may carry launch arguments: one string, as the operator would type it
after the program's name (a locker's ``--password <value>``, an installer's
switch). The platform never reads them: it checks their length
and that they hold no control character, and hands them to the provider as
they were given. Each provider says whether it can pass them
(``SandboxCapabilities.can_pass_launch_arguments``) and, for one value, how
(``SandboxProvider.launch_arguments_answer``); a provider that cannot is never
handed them, and the run records that it asked and was not honoured. A
provider whose sandbox has no such field but runs a script picked from a
submitted archive may declare it honours them through a generated launcher
(``providers.launcher``).

``SandboxProvider.submit`` takes these options as a keyword, so a later
submission of the same sample with other options is the same call again.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The longest launch arguments a job may carry, in characters: well past any
# command line a sample needs, and short enough to state whole in the report.
LAUNCH_ARGUMENTS_MAX_CHARS = 1024
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def launch_arguments_problem(value: Any) -> str | None:
    """Why ``value`` cannot be a job's launch arguments, or ``None`` when it can.

    Text of at most :data:`LAUNCH_ARGUMENTS_MAX_CHARS` characters, holding
    something besides spaces and none of the Unicode categories Cc (control),
    Cf (format: bidi controls, zero-width characters), Zl and Zp (line and
    paragraph separators): a line break, a NUL or a character that reorders
    or hides what a reader sees cannot be part of one command line. Nothing
    else is judged: the words are the operator's and the sample's.
    """
    if not isinstance(value, str):
        return "must be text"
    if not value.strip():
        return "must hold some text"
    if len(value) > LAUNCH_ARGUMENTS_MAX_CHARS:
        return f"must be at most {LAUNCH_ARGUMENTS_MAX_CHARS} characters (got {len(value)})"
    if any(unicodedata.category(ch) in _REFUSED_CATEGORIES for ch in value):
        return (
            "must not hold a control character such as a line break or a tab, nor a format "
            "character (a bidi control, a zero-width character) or a line or paragraph separator"
        )
    return None


@dataclass(frozen=True)
class SubmissionOptions:
    """What one submission asks beyond the sample. Empty asks nothing."""

    launch_arguments: str = ""

    def __bool__(self) -> bool:
        return bool(self.launch_arguments)


@dataclass(frozen=True)
class LaunchArgumentsAnswer:
    """Whether a provider passes one value of launch arguments, and what the record says of it.

    ``note`` is the provider's sentence: why it cannot pass them, or, where it
    does, what else it changed to do so (a deployment setting the job's value
    replaced). Empty where there is nothing to add. ``via`` names the option
    or field the provider sends them in, where it does. ``launcher`` is the
    record of the generated launcher that carries them, where the provider
    honours them through one (``providers.launcher``); never set otherwise.
    """

    honoured: bool
    note: str = ""
    via: str = ""
    launcher: dict[str, Any] | None = None


def cannot_pass(provider: str) -> LaunchArgumentsAnswer:
    """The answer of a provider that cannot pass launch arguments at all."""
    return LaunchArgumentsAnswer(
        honoured=False,
        note=(
            f"the {provider} provider cannot pass launch arguments to its sandbox, "
            "so the sample was detonated without them"
        ),
    )


def answer_of(
    provider: Any, arguments: str, sample_path: str | Path | None = None
) -> LaunchArgumentsAnswer:
    """What ``provider`` makes of ``arguments``, asked before anything is sent.

    Its own answer (``SandboxProvider.launch_arguments_answer``); a provider
    that does not implement the contract's method answers by its capability
    flag, and one whose answer raises passes nothing, with the error's type.
    ``sample_path`` lets a provider whose launch path depends on the sample's
    format say so.
    """
    name = str(getattr(provider, "id", "") or "sandbox")
    ask = getattr(provider, "launch_arguments_answer", None)
    if not callable(ask):
        capabilities = getattr(provider, "capabilities", None)
        if getattr(capabilities, "can_pass_launch_arguments", False) is True:
            return LaunchArgumentsAnswer(honoured=True)
        return cannot_pass(name)
    try:
        answer = ask(arguments, sample_path=sample_path)
    except Exception as exc:  # noqa: BLE001 — a provider that cannot say passes nothing
        return LaunchArgumentsAnswer(
            honoured=False,
            note=(
                f"the {name} provider could not say whether it passes them "
                f"({type(exc).__name__}), so the sample was detonated without them"
            ),
        )
    if not isinstance(answer, LaunchArgumentsAnswer):
        return cannot_pass(name)
    return answer


def launch_record(provider: str, arguments: str, answer: LaunchArgumentsAnswer) -> dict[str, Any]:
    """The run's record of the launch arguments a job asked for: verbatim, and whether honoured."""
    record = {
        "provider": str(provider),
        "arguments": str(arguments),
        "honoured": bool(answer.honoured),
        "note": str(answer.note or ""),
    }
    if answer.via:
        record["via"] = str(answer.via)
    if answer.launcher:
        record["launcher"] = dict(answer.launcher)
    return record


def unmade_record(provider: str, arguments: str, why: str) -> dict[str, Any]:
    """The record of arguments a job asked for that no submission carried, and why."""
    return launch_record(
        provider,
        arguments[:LAUNCH_ARGUMENTS_MAX_CHARS],
        LaunchArgumentsAnswer(honoured=False, note=why),
    )


def not_honoured_reason(record: Any) -> str | None:
    """The run's limitation where the job's launch arguments were not passed; ``None`` otherwise."""
    if not isinstance(record, dict) or record.get("honoured") is not False:
        return None
    provider = str(record.get("provider") or "the sandbox")
    note = str(record.get("note") or "").strip()
    return f"launch arguments requested, not honoured by {provider}" + (f": {note}" if note else "")
