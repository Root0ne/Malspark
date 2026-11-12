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

import inspect
import json
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

# The longest launch arguments a job may carry, in characters: well past any
# command line a sample needs, and short enough to state whole in the report.
LAUNCH_ARGUMENTS_MAX_CHARS = 1024
_REFUSED_CATEGORIES = {
    "Cc": "control character",
    "Cf": "format character",
    "Zl": "line separator",
    "Zp": "paragraph separator",
}


def launch_arguments_problem(value: Any) -> str | None:
    """Why ``value`` cannot be a job's launch arguments, or ``None`` when it can.

    Text of at most :data:`LAUNCH_ARGUMENTS_MAX_CHARS` characters, holding
    something besides spaces and none of the Unicode categories Cc (control),
    Cf (format: bidi controls, zero-width characters), Zl and Zp (line and
    paragraph separators), the first named by code point and position: a line
    break, a NUL or a character that reorders
    or hides what a reader sees cannot be part of one command line. Nothing
    else is judged: the words are the operator's and the sample's.
    """
    if not isinstance(value, str):
        return "must be text"
    if not value.strip():
        return "must hold some text"
    if len(value) > LAUNCH_ARGUMENTS_MAX_CHARS:
        return f"must be at most {LAUNCH_ARGUMENTS_MAX_CHARS} characters (got {len(value)})"
    for position, ch in enumerate(value, start=1):
        kind = _REFUSED_CATEGORIES.get(unicodedata.category(ch))
        if kind:
            return (
                "must not hold a control character such as a line break or a tab, nor a format "
                "character (a bidi control, a zero-width character) or a line or paragraph "
                f"separator: the first is U+{ord(ch):04X} ({kind}) at position {position}"
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


def _takes_sample_path(ask: Any) -> bool:
    """Whether ``ask`` accepts the ``sample_path`` keyword (named, or through ``**kwargs``).

    Read from the signature, so a provider written to the one-argument form
    is called with the arguments alone, and a TypeError its own code raises is
    never taken for a mismatch. A callable whose signature cannot be read is
    given the keyword, as the contract says.
    """
    try:
        parameters = inspect.signature(ask).parameters
    except (TypeError, ValueError):
        return True
    return "sample_path" in parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()
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
        if _takes_sample_path(ask):
            answer = ask(arguments, sample_path=sample_path)
        else:
            answer = ask(arguments)
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
    """The record of arguments a job asked for that no submission carried, and why.

    A value longer than the limit is kept cut to it, and the note says so.
    """
    if len(arguments) > LAUNCH_ARGUMENTS_MAX_CHARS:
        why = (
            f"{why} (recorded cut to the first {LAUNCH_ARGUMENTS_MAX_CHARS} of "
            f"{len(arguments)} characters)"
        )
    return launch_record(
        provider,
        arguments[:LAUNCH_ARGUMENTS_MAX_CHARS],
        LaunchArgumentsAnswer(honoured=False, note=why),
    )


def unobserved_record(record: dict[str, Any], failure: str) -> dict[str, Any]:
    """``record`` of a submission that carried the arguments but ended without a report.

    The arguments were sent, so the record says so (``sent``), not that they
    were refused; ``note`` holds why no report came back, where known.
    """
    return {
        **record,
        "honoured": False,
        "sent": True,
        "note": str(failure or ""),
    }


def not_honoured_reason(record: Any) -> str | None:
    """The run's limitation where the job's launch arguments were not passed; ``None`` otherwise.

    A submission that sent them and produced no report is worded apart from
    one that refused them: they were sent, and nothing was observed.
    """
    if not isinstance(record, dict) or record.get("honoured") is not False:
        return None
    provider = str(record.get("provider") or "the sandbox")
    if record.get("sent") is True:
        failure = str(record.get("note") or "").strip()
        return (
            f"launch arguments sent to {provider}, but no sandbox report came back, so "
            "nothing was observed with them" + (f" ({failure})" if failure else "")
        )
    note = str(record.get("note") or "").strip()
    return f"launch arguments requested, not honoured by {provider}" + (f": {note}" if note else "")


_ARGUMENTS_MASK = "[the launch arguments, withheld]"
_LAUNCHER_MASK = "[the launcher text, withheld]"


def _spellings(value: str) -> list[str]:
    """The ways ``value`` can occur in a body that echoes it: as it is, and JSON-escaped."""
    found = [value]
    for ascii_only in (False, True):
        escaped = json.dumps(value, ensure_ascii=ascii_only)[1:-1]
        if escaped not in found:
            found.append(escaped)
    return found


def mask_submitted(text: str, arguments: str = "", launcher_text: str = "") -> str:
    """``text`` with the submitted launch arguments and launcher text withheld where they occur.

    Applied before any exception text or response body of a submission is
    logged or kept as a failure reason: a sandbox that echoes the form it
    received must not carry the operator's arguments into a log or a report.
    The launcher text is masked first, as it holds the arguments. Each value is
    matched as it was sent and as JSON writes it.
    """
    for value, mask in (
        (launcher_text, _LAUNCHER_MASK),
        (launcher_text.rstrip(), _LAUNCHER_MASK),
        (arguments, _ARGUMENTS_MASK),
    ):
        if not value:
            continue
        for spelling in sorted(_spellings(value), key=len, reverse=True):
            text = text.replace(spelling, mask)
    return text


def submitted_values(record: Any) -> tuple[str, str]:
    """The arguments and launcher text a run's launch record holds, to be masked."""
    if not isinstance(record, dict):
        return "", ""
    launcher = record.get("launcher")
    text = str(launcher.get("launcher_text") or "") if isinstance(launcher, dict) else ""
    return str(record.get("arguments") or ""), text


def reraise_masked(
    exc: BaseException, options: SubmissionOptions | None, launcher_text: str = ""
) -> NoReturn:
    """Raise ``exc``, or a ProviderError with its text masked where it holds a submitted value.

    For a provider's submit failure path: the original is dropped (not
    chained) when it carried the value, since its own text would carry it on.
    """
    from malspark.providers.errors import ProviderError

    arguments = options.launch_arguments if options is not None else ""
    message = str(exc)
    masked = mask_submitted(message, arguments, launcher_text)
    if masked == message:
        raise exc
    raise ProviderError(masked) from None
