"""A value a further detonation's launch text supplies is no observation of the sample.

An agent may ask for a further detonation with launch arguments
(``providers.detonation``: ``d2``, ``d3``…). What that launch text supplies —
a folder, a host, a password the agent typed — is the run's own input to the
detonation, not something the sample did: the same principle as a call's own
echo (``pipeline.validation.held_only_in_its_echo``). Two rules follow.

* **The launch echo holds nothing.** A read of a further detonation states its
  launch text (its ``launched_with`` field, and the end of the launched
  process's command line). On the publish route
  (``stated_host_values.scan_cited``) and the second-source route
  (``stix_renderer.second_source_reads``) that text is a second echo the
  shared pair-of-texts predicate reads a read without
  (``EntryTexts.with_launch_echoes``, :func:`launch_echoed`); the citation
  checks read the read as before.
* **A launch-supplied value is not published.** A value is refused where a
  further detonation's mark stands on it, it stands whole in that
  detonation's launch text in one of the forms a command line writes a value
  in (:func:`launch_values`), and no entry of the run outside the reads of
  the detonations launched with it holds it whole
  (:func:`launch_supplied_refusal`). The build records each such value and
  its holders once (:func:`launch_record`, ``MalwareReport.launch_values``);
  the publish rule reads that record, so every surface reads one answer.

The forms are read by the shape of the launch text, as a command line writes
a value: whole as one argument, the host of ``user@host``, the value of a
switch written against it (``-oX``, ``/D=X``, ``/path:X``, ``--x=X``), the
host of a URL or of ``host:port``, a part a path's separators, quotes or
key-value marks delimit (a leading folder among them), the end after an
environment variable (``%NAME%\\x``), compared on the path a read of the
detonation writes ending in it, and an address the detonation resolved for a
host the launch text holds. Never by a program's, a tool's or a sandbox's
name. A value the sample produced under a launch value (a file inside the
given folder, a subkey of the given key) is none of these and publishes as
before.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from functools import partial
from typing import Any, cast
from urllib.parse import urlsplit

from malspark.reporting.models import LaunchValue

# The marks after which a switch writes its value against it: ``/D=X``, ``/path:X``.
_SWITCH_MARKS = "=:"
# A one-letter switch with its value written right after it: ``-oC:\out``.
_GLUED_RE = re.compile(r"-[A-Za-z](?=\S)")
# A host with a port: ``host:8080``.
_HOST_PORT_RE = re.compile(r"([a-z0-9][a-z0-9.-]*):[0-9]{1,5}")
# A host name or an address as a command line writes one.
_HOST_RE = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+|[0-9a-f:]*:[0-9a-f:]+")
# An environment variable as a Windows command line writes one.
_VARIABLE_RE = re.compile(r"%[a-z_][a-z0-9_()]{0,40}%")
# The characters the publish route's delimited test may read a value's end at
# (``stated_host_values.delimited_in``): a path separator, a quote, a key-value
# mark, a call's or a list's bracket, a list mark and a line break.
_DELIMITERS = "\\\"'=:([)],;\n\r\t"
# What may stand before a path a read writes: its text's start, white space,
# a quote or a key-value mark.
_PATH_OPENS = " \t\n\r\"'=(,;"
# A path's start: a drive or a share.
_PATH_START_RE = re.compile(r"[a-z]:\\|\\\\")

# What a refusal says a launch-supplied value is.
LAUNCH_SUPPLIED = (
    "a value a further detonation's launch text supplies is no observation of the sample"
)
# How the launch text is compared, which the refusal states.
COMPARED = "read without case and with / as \\"


def launch_form(value: Any) -> str:
    """A value as the rule compares it with a launch text: lower case, ``/`` read as ``\\``,
    no trailing separator or dot."""
    text = str(value or "").strip().lower().replace("/", "\\")
    return text.rstrip("\\.") or text


def launch_values(launch: str) -> dict[str, str]:
    """Each value ``launch`` holds whole, folded (:func:`launch_form`), with the form: ``whole``.

    The launch text is split as Windows splits a command line
    (``stated_host_values.command_line_arguments``' reading); each argument
    writes a value as itself, as the value of a switch written against it,
    as the host of ``user@host``, of a URL or of ``host:port``
    (:func:`_written_values`); and each such text holds the parts the publish
    route's delimited test finds whole in it (:func:`_delimited_parts`).
    """
    from malspark.reporting.stated_host_values import _arguments

    out: dict[str, str] = {}
    for argument in _arguments(str(launch or "")):
        for text in _written_values(argument):
            for value in _delimited_parts(text):
                out.setdefault(value, "whole")
    return out


def launch_tails(launch: str) -> list[tuple[str, str]]:
    """``(variable, end)`` for each path ``launch`` writes after an environment variable.

    The end is folded (:func:`launch_form`) and begins at the separator after
    the variable; each leading part of it at a separator is an end too
    (``%TEMP%\\a\\b.txt``: ``\\a`` and ``\\a\\b.txt``).
    """
    from malspark.reporting.stated_host_values import _arguments

    out: list[tuple[str, str]] = []
    for argument in _arguments(str(launch or "")):
        for text in _written_values(argument):
            folded = str(text).strip().lower().replace("/", "\\")
            for found in _VARIABLE_RE.finditer(folded):
                tail = folded[found.end() :].rstrip("\\")
                if not tail.startswith("\\") or len(tail) < 2:
                    continue
                cuts = [at for at in range(1, len(tail)) if tail[at] == "\\"]
                for end in [*cuts, len(tail)]:
                    held = (found.group(0), tail[:end])
                    if held not in out:
                        out.append(held)
    return out


def _written_values(argument: str) -> list[str]:
    """The texts one argument writes a value as: itself, a switch's value, a host."""
    out = [argument]
    if argument[:1] in "-/" and len(argument) > 1:
        marks = [at for at in (argument.find(mark) for mark in _SWITCH_MARKS) if at > 1]
        if marks:
            out.append(argument[min(marks) + 1 :])
        if _GLUED_RE.match(argument) and not argument.startswith("--"):
            out.append(argument[2:])
    if "://" in argument:
        try:
            host = urlsplit(argument).hostname or ""
        except ValueError:
            host = ""
        if host:
            out.append(host)
    elif "@" in argument:
        host = re.split(r"[:/\\]", argument.rsplit("@", 1)[1], maxsplit=1)[0]
        if host:
            out.append(host)
    port = _HOST_PORT_RE.fullmatch(argument.lower())
    if port is not None:
        out.append(port.group(1))
    return [text for text in out if text.strip()]


def _delimited_parts(text: str) -> Iterator[str]:
    """The text folded, and each part of it the publish route's delimited test finds whole in it.

    Every span between two places the test may read an end at (the text's
    ends and each of :data:`_DELIMITERS`) that ``delimited_in`` holds, path
    separators delimiting: a leading folder, a component, a file's name. A
    URL is read as itself and its host alone.
    """
    from malspark.reporting.stated_host_values import delimited_in

    folded = launch_form(text)
    if not folded:
        return
    yield folded
    if "://" in text:
        return
    whole = str(text).strip().lower().replace("/", "\\")
    starts = [0, *(at + 1 for at, char in enumerate(whole) if char in _DELIMITERS)]
    ends = [len(whole), *(at for at, char in enumerate(whole) if char in _DELIMITERS)]
    seen = {folded}
    for start in starts:
        for end in ends:
            part = whole[start:end]
            if end <= start or not part.strip() or part in seen:
                continue
            seen.add(part)
            if delimited_in(part, whole):
                held = launch_form(part)
                if held:
                    yield held


def _leaves(value: Any) -> Iterator[str]:
    """Every string a JSON value holds, at any depth."""
    stack = [value]
    while stack:
        held = stack.pop()
        if isinstance(held, Mapping):
            stack.extend(held.values())
        elif isinstance(held, list | tuple):
            stack.extend(held)
        elif isinstance(held, str):
            yield held


def _texts_of(entries: Any, entry_id: str) -> list[str]:
    """The strings one entry's texts write, read through their JSON where they are JSON."""
    out: list[str] = []
    for part in entries.parts_of(entry_id):
        try:
            out.extend(_leaves(json.loads(part)))
        except (ValueError, RecursionError):
            out.append(part)
    return out


def _expanded(tail: str, texts: Iterable[str]) -> list[str]:
    """Each path ``texts`` write that ends with ``tail``, folded: where a variable expanded to.

    A place of the end counts where no letter, digit, ``.``, ``_`` or ``-``
    runs on after it; the path runs back to the nearest drive or share that
    opens a value before it.
    """
    out: list[str] = []
    for text in texts:
        folded = str(text).lower().replace("/", "\\")
        at = folded.find(tail)
        while at != -1:
            end = at + len(tail)
            after = folded[end : end + 1]
            if not (after.isalnum() or after in "._-"):
                starts = [
                    found.start()
                    for found in _PATH_START_RE.finditer(folded, 0, at)
                    if found.start() == 0 or folded[found.start() - 1] in _PATH_OPENS
                ]
                if starts:
                    path = launch_form(folded[starts[-1] : end])
                    if path and path not in out:
                        out.append(path)
            at = folded.find(tail, at + 1)
    return out


def launch_record(report: Any, ledger: Iterable[Any], corpus: Any = None) -> list[LaunchValue]:
    """Each value a further detonation's launch text supplies, and who else in the run holds it.

    For each detonation the ledger holds a read of that states a launch text
    (``detonation_reads.later_detonation_name``): every value of
    :func:`launch_values`; each path a read of it writes that ends with the
    end of a path after an environment variable (:func:`launch_tails`); and
    each address the report's network block says a domain row that
    detonation observed resolved to, for a host among those values. For each
    value: whether a read of a detonation supplying it holds it whole
    (``observed``), and each entry of the run that holds it whole
    (``EntryTexts.holds``, in either separator) outside the reads of the
    detonations supplying it, outside what its own call asked for
    (``validation.held_only_in_its_echo``) and with a call not given one of
    their launch texts (``held_by``). ``[]`` where no further detonation
    states a launch: a run with one detonation records nothing.
    """
    from malspark.analysis.detonation_reads import later_detonation_name
    from malspark.pipeline.validation import EntryTexts

    entries_in = list(ledger or ())
    launches: dict[str, str] = {}
    reads: dict[str, list[str]] = {}
    for entry in entries_in:
        name = later_detonation_name(entry)
        data = getattr(entry, "structured", None)
        stated = str(data.get("launched_with") or "") if isinstance(data, Mapping) else ""
        if name and stated.strip():
            launches.setdefault(name, stated)
            reads.setdefault(name, []).append(str(getattr(entry, "id", "") or "").lower())
    if not launches:
        return []
    entries = EntryTexts.from_ledger(entries_in, corpus)
    found: dict[str, list[tuple[str, str, str]]] = {}

    def _add(value: str, name: str, form: str, through: str = "") -> None:
        held = found.setdefault(value, [])
        if all(known != name for known, _form, _through in held):
            held.append((name, form, through))

    for name, launch in launches.items():
        for value in launch_values(launch):
            _add(value, name, "whole")
        texts = [text for read in reads[name] for text in _texts_of(entries, read)]
        for variable, tail in launch_tails(launch):
            for value in _expanded(tail, texts):
                _add(value, name, "variable", variable)
    network = getattr(report, "network", None)
    for domain in getattr(network, "domains", None) or []:
        host = launch_form(domain.fqdn)
        for name, form, _through in found.get(host, []):
            if form != "whole" or not _HOST_RE.fullmatch(host):
                continue
            if not any(mark.detonation == name for mark in domain.observed_in or ()):
                continue
            for address in domain.resolved_ips:
                if launch_form(address):
                    _add(launch_form(address), name, "resolved", host)
    out: list[LaunchValue] = []
    for value, supplied in found.items():
        names = {name for name, _form, _through in supplied}
        given = [launches[name].strip().lower() for name in names]
        excluded = {read for name in names for read in reads[name]}
        held_by = _holders(entries, value, excluded, given)
        for name, form, through in supplied:
            out.append(
                LaunchValue(
                    detonation=name,
                    launched_with=launches[name],
                    value=value,
                    form=form,
                    through=through,
                    observed=any(_holds(entries, read, value) for read in reads[name]),
                    held_by=held_by,
                )
            )
    return out


def _spellings(value: str) -> list[str]:
    """A folded value in both separators: a text may write a path either way round."""
    return list(dict.fromkeys([value, value.replace("\\", "/")]))


def _holds(entries: Any, entry_id: str, value: str) -> bool:
    """Whether an entry's text holds ``value`` whole in either separator (``EntryTexts.holds``)."""
    return any(entries.holds(entry_id, spelled) for spelled in _spellings(value))


def _holders(entries: Any, value: str, excluded: set[str], given: list[str]) -> list[str]:
    """Each entry that holds ``value`` whole outside the reads ``excluded``, its call's echo and
    a call given one of the launch texts ``given``, in ledger order."""
    from malspark.pipeline.validation import (
        ECHO_FREE_HOLDS_IT,
        _string_leaves,
        _text_holds,
        held_only_in_its_echo,
        library_spellings,
    )
    from malspark.utils.written_forms import written_forms

    candidates: set[str] = set()
    for spelled in _spellings(value):
        candidates |= set(entries.may_hold(spelled))
    order = {entry_id: at for at, entry_id in enumerate(entries.texts)}
    out: list[str] = []
    for entry_id in sorted(candidates, key=lambda known: order.get(known, -1)):
        holder = entries.holder_of.get(entry_id) or entry_id
        if entry_id in excluded or holder in excluded:
            continue
        entry = entries.entries.get(holder)
        asked = " ".join(_string_leaves(getattr(entry, "args", None))).lower()
        if any(launch and launch in asked for launch in given):
            continue
        for spelled in _spellings(value):
            if not entries.holds(entry_id, spelled):
                continue
            forms = [
                form for spelling in library_spellings(spelled) for form in written_forms(spelling)
            ]
            echo = held_only_in_its_echo(
                entries,
                entry_id,
                partial(_text_holds, value=spelled),
                forms,
                launch=False,
            )
            if not echo or echo == ECHO_FREE_HOLDS_IT:
                out.append(entry_id)
                break
    return out


def launch_supplied_refusal(report: Any, kind: str, value: Any) -> str:
    """Why the rule refuses ``value`` as a further detonation's launch supplied it, or ``""``.

    Read off the build's record (``MalwareReport.launch_values``,
    :func:`launch_record`). The value is refused where all three hold:

    * a further detonation's mark stands on it: a row of the report's
      network or dynamic block of its kind and value names that detonation
      (``detonation_marks``), or a read of it holds the value whole;
    * it stands whole in that detonation's launch text in one of the forms
      of :func:`launch_values`, as the end after an environment variable of a
      path a read of it writes, or as an address it resolved for a host the
      launch text holds;
    * no entry of the run holds it whole outside the reads of the
      detonations supplying it, what an entry's own call asked for and the
      entries whose call was given one of their launch texts.

    A value any row of the job's own detonation holds (a row with no mark, or
    one naming the job's own detonation) is never refused here. The words
    say which launch text holds the value and how, and what the search read.
    """
    record = list(getattr(report, "launch_values", None) or ())
    if not record:
        return ""
    folded = launch_form(value)
    rows = [row for row in record if row.value == folded]
    if not rows or any(row.held_by for row in rows):
        return ""
    from malspark.reporting.ledger_projection import FIRST_DETONATION, value_key

    named = {mark.detonation for mark in _row_marks(report).get((kind, value_key(kind, value)), [])}
    if FIRST_DETONATION in named:
        return ""
    marked = [row for row in rows if row.observed or row.detonation in named]
    if not marked:
        return ""
    return _refusal_words(marked[0], [row.detonation for row in rows])


def _row_marks(report: Any) -> dict[tuple[str, str], list[Any]]:
    """The detonations each value of the report's rows was observed in, the job's own too, read
    once per reading (``detonation_marks._value_held``)."""
    from malspark.reporting.detonation_marks import _value_held
    from malspark.reporting.renderers.stix_renderer import _memo

    return cast(
        "dict[tuple[str, str], list[Any]]",
        _memo(report, "launch_row_marks", lambda: _value_held(report)),
    )


def _number(name: str) -> str:
    return name[1:] if name.startswith("d") else name


def _refusal_words(row: LaunchValue, detonations: Iterable[str]) -> str:
    """What the refusal says: the launch text that supplies the value and how, then what the
    run's search read and found."""
    from malspark.reporting.detonation_marks import launch_text

    shown = f"`{launch_text(row.launched_with)}`"
    number = _number(row.detonation)
    if row.form == "resolved":
        supplied = (
            f"detonation {number} resolved it for `{launch_text(row.through)}`, which its "
            f"launch text holds, {COMPARED} ({shown})"
        )
    elif row.form == "variable":
        supplied = (
            f"detonation {number}'s launch text holds its end after the environment variable "
            f"`{launch_text(row.through)}`, {COMPARED} ({shown})"
        )
    else:
        supplied = f"detonation {number}'s launch text holds it, {COMPARED} ({shown})"
    names = sorted(dict.fromkeys(detonations), key=lambda name: (len(name), name))
    numbers = [_number(name) for name in names]
    if len(numbers) == 1:
        listed, given = f"detonation {numbers[0]}", "that launch text"
    else:
        listed = f"detonations {', '.join(numbers[:-1])} and {numbers[-1]}"
        given = "one of their launch texts"
    searched = (
        f"the run's search found it whole in no entry but the reads of {listed}, entries whose "
        f"call was given {given} and entries holding it only where their answer repeats their "
        "own call"
    )
    return f"{LAUNCH_SUPPLIED}: {supplied}, and {searched}"


def launch_echoed(entry: Any, values: Iterable[str], held: Any, corpus: Any = None) -> list[str]:
    """Each of ``values`` a read of a further detonation holds whole only where it states its
    launch text, by the second-source route's own test ``held`` (asked of a value and a text).

    The read's texts (its answer, the corpus's copy where kept, and its
    structured answer) each as a pair written the same way, whole and without
    the launch echo (``validation._without_call_echoes`` with the launch);
    the shared predicate (``validation.held_only_in_its_echo``) decides,
    its decoded-run exception included. ``[]`` for an entry that reads no
    further detonation.
    """
    from malspark.analysis.detonation_reads import later_detonation_name
    from malspark.pipeline.validation import (
        ECHO_FREE_HOLDS_IT,
        _without_call_echoes,
        held_only_in_its_echo,
    )
    from malspark.reporting.stated_host_values import encodings

    data = getattr(entry, "structured", None)
    launch = str(data.get("launched_with") or "") if isinstance(data, Mapping) else ""
    if not later_detonation_name(entry) or not launch.strip():
        return []
    written: list[str] = []
    if corpus is not None:
        try:
            from malspark.agents.run_evidence_corpus import read_of_entry

            written.append(read_of_entry(corpus, str(entry.id)) or "")
        except Exception:  # noqa: BLE001 — the stored answer is read instead
            written = []
    if not any(written):
        written = [str(getattr(entry, "output", "") or "")]
    if data:
        written.append(json.dumps(data, default=str))
    pairs: list[tuple[str, str | None]] = []
    for part in written:
        try:
            pairs.append(
                (_without_call_echoes(part, None), _without_call_echoes(part, None, launch=launch))
            )
        except RecursionError:
            pairs.append((part, None))
    texts = _PairsOf(tuple(pairs))
    out: list[str] = []
    for value in values:
        found = held_only_in_its_echo(
            cast(Any, texts),
            str(entry.id),
            partial(held, value),
            encodings(value),
        )
        if found and found != ECHO_FREE_HOLDS_IT:
            out.append(value)
    return out


class _PairsOf:
    """One entry's texts as the shared predicate reads them, already paired."""

    def __init__(self, pairs: tuple[tuple[str, str | None], ...]) -> None:
        self._pairs = pairs

    def echo_free_parts(
        self, entry_id: str, *, launch: bool = True
    ) -> tuple[tuple[str, str | None], ...]:
        del entry_id, launch
        return self._pairs
