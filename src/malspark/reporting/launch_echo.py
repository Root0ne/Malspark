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
* **A launch-supplied value is not published.** Where the publish rule's own
  answer publishes a value, it is refused where a further detonation's mark
  stands on its row, it stands whole in that detonation's launch text in one
  of the forms a command line writes a value in (:func:`launch_values`), and
  no entry of the run outside the reads of the detonations launched with it
  holds it whole (:func:`launch_supplied_refusal`). A detonation whose launch
  the run records as not honoured supplies nothing here. The build records
  each detonation's launch text once, with each value it supplies and that
  value's holders (:func:`launch_record`, ``MalwareReport.launch_values``);
  the publish rule reads that record, so every surface reads one answer.

The forms are read by the shape of the launch text, as a command line writes
a value: whole as one argument, or as a span of arguments the text writes as
one value where a read of the detonation holds that span whole outside its
launch echo, the host of ``user@host``, the value of a switch written against
it (``-oX``, ``/D=X``, ``/path:X``, ``--x=X``), the host of a URL or of
``host:port``, a part a path's separators, quotes or key-value marks delimit
(a leading folder among them), a path of a read of the detonation that ends
in what the launch text writes after an environment variable (``%NAME%\\x``),
whole or cut after a folder of that ending, and an address
the detonation resolved for a host the launch text supplies. Never by a
program's, a tool's or a sandbox's name. A value the sample produced under a
launch value (a file inside the given folder, a subkey of the given key) is
none of these and publishes as before.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from functools import partial
from typing import Any, cast
from urllib.parse import urlsplit

from malspark.reporting.models import LaunchedDetonation, LaunchValue

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


def launch_values(launch: str, held: Callable[[str], bool] | None = None) -> dict[str, str]:
    """Each value ``launch`` holds whole, folded (:func:`launch_form`), with the form: ``whole``.

    The launch text is split as Windows splits a command line
    (``stated_host_values.command_line_arguments``' reading); each argument
    writes a value as itself, as the value of a switch written against it,
    as the host of ``user@host``, of a URL or of ``host:port``
    (:func:`_written_values`); and each such text holds the parts the publish
    route's delimited test finds whole in it (:func:`_delimited_parts`). The
    launch text is also read as written, whole (:func:`_spanning_values`): a
    value an unquoted text writes over several arguments is held where
    ``held`` (asked of the folded value) says a read holds it, and never
    without ``held`` — a run no read holds reaches no row.
    """
    from malspark.reporting.stated_host_values import _arguments

    out: dict[str, str] = {}
    for argument in _arguments(str(launch or "")):
        for text in _written_values(argument):
            for value in _delimited_parts(text):
                out.setdefault(value, "whole")
    if held is not None:
        for value in _spanning_values(str(launch or ""), held):
            out.setdefault(value, "whole")
    return out


def _spanning_values(launch: str, held: Callable[[str], bool]) -> Iterator[str]:
    """Each value the launch text as written holds whole across white space that ``held``
    holds, folded.

    A span that runs over white space from the text's start, a place after
    white space or after one of :data:`_DELIMITERS` to the text's end, a
    place before white space or before one of them, and that the publish
    route's whole-value test (``whole_value_in``) finds whole in the text as
    written: an unquoted path with a space (``--dir C:\\Program Files\\X``).
    """
    from malspark.agents._indicator_denylists import whole_value_in

    written = launch.strip().lower().replace("/", "\\")
    if not any(char.isspace() for char in written):
        return
    starts = sorted(
        {0} | {at + 1 for at, char in enumerate(written) if char.isspace() or char in _DELIMITERS}
    )
    ends = sorted(
        {len(written)}
        | {at for at, char in enumerate(written) if char.isspace() or char in _DELIMITERS}
    )
    seen: set[str] = set()
    for start in starts:
        for end in ends:
            part = written[start:end]
            if end <= start or part != part.strip() or part in seen:
                continue
            seen.add(part)
            if any(char.isspace() for char in part) and whole_value_in(part, written):
                value = launch_form(part)
                if value and held(value):
                    yield value


def launch_tails(launch: str) -> list[tuple[str, str]]:
    """``(variable, tail)`` for each path ``launch`` writes after an environment variable.

    The tail is folded (:func:`launch_form`), whole: from the separator after
    the variable to the path's end (``%TEMP%\\a\\b.txt``: ``\\a\\b.txt``). A
    leading part of it is read only beside the head a read shows the whole
    tail under (:func:`_expanded`), never on its own.
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
                held = (found.group(0), tail)
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
    """The paths of ``texts`` that end in a variable's whole ``tail``, folded: each head a path
    of ``texts`` writes the whole tail after, with each leading part of the tail and the whole.

    A place of the tail counts where the path ends after it: at the text's
    end or where no letter, digit, ``.``, ``_`` or ``-`` runs on; the tail
    opens with its separator. The head runs back to the nearest drive or
    share that opens a value before it. The head alone is no such path, and
    a leading part of the tail is read only beside a head the whole tail
    stands under.
    """
    cuts = [at for at in range(1, len(tail)) if tail[at] == "\\"]
    out: list[str] = []
    for text in texts:
        folded = str(text).lower().replace("/", "\\")
        at = folded.find(tail)
        while at != -1:
            end = at + len(tail)
            after = folded[end : end + 1]
            if not after or not (after.isalnum() or after in "._-"):
                starts = [
                    found.start()
                    for found in _PATH_START_RE.finditer(folded, 0, at)
                    if found.start() == 0 or folded[found.start() - 1] in _PATH_OPENS
                ]
                head = folded[starts[-1] : at] if starts else ""
                for cut in [*cuts, len(tail)] if head.strip() else ():
                    path = launch_form(head + tail[:cut])
                    if path and path not in out:
                        out.append(path)
            at = folded.find(tail, at + 1)
    return out


def launch_record(
    report: Any, ledger: Iterable[Any], corpus: Any = None
) -> list[LaunchedDetonation]:
    """Each further detonation's launch text, once, with each value it supplies and its holders.

    For each detonation the ledger holds a read of that states a launch text
    (``detonation_reads.later_detonation_name``) and whose launch the run
    records as honoured (:func:`honoured_launches`): every value of
    :func:`launch_values`, a span of arguments where a read of that detonation
    holds it whole outside its launch echo (:func:`_read_holds`); each path a
    read of it writes ending in what the launch text writes after an
    environment variable, whole or cut after a folder of that ending
    (:func:`launch_tails`, :func:`_expanded` over the reads of it); and, for a
    host among those values that no other entry holds, each address the
    report's network block says a domain row that detonation observed resolved
    to. For each value, each entry of the run that holds it whole
    (``EntryTexts.holds``, in either separator) outside the reads of the
    detonations supplying it, outside what its own call asked for
    (``validation.held_only_in_its_echo``) and with a call not given one of
    their launch texts (``held_by``). ``[]`` where no further detonation
    states an honoured launch: a run with one detonation records nothing.
    """
    from malspark.analysis.detonation_reads import later_detonation_name
    from malspark.pipeline.validation import EntryTexts

    entries_in = list(ledger or ())
    honoured = honoured_launches(report)
    launches: dict[str, str] = {}
    reads: dict[str, list[str]] = {}
    for entry in entries_in:
        name = later_detonation_name(entry)
        data = getattr(entry, "structured", None)
        stated = str(data.get("launched_with") or "") if isinstance(data, Mapping) else ""
        if name and name in honoured and stated.strip():
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

    echoes = entries.with_launch_echoes()
    for name, launch in launches.items():
        echo_free = [
            (rest, rest.lower())
            for read in reads[name]
            for _whole, rest in echoes.echo_free_parts(read)
            if rest is not None
        ]
        held = partial(_read_holds, echo_free, {})
        for value in launch_values(launch, held):
            _add(value, name, "whole")
        texts = [text for read in reads[name] for text in _texts_of(entries, read)]
        for variable, tail in launch_tails(launch):
            for value in _expanded(tail, texts):
                _add(value, name, "variable", variable)
    holders: dict[str, list[str]] = {}

    def _held_by(value: str) -> list[str]:
        if value not in holders:
            names = {name for name, _form, _through in found[value]}
            given = [launches[name].strip().lower() for name in names]
            excluded = {read for name in names for read in reads[name]}
            holders[value] = _holders(entries, value, excluded, given)
        return holders[value]

    # An address is the launch's only for a host the launch supplies: a host
    # another entry holds is the sample's, and so is what it resolved to.
    network = getattr(report, "network", None)
    for domain in getattr(network, "domains", None) or []:
        host = launch_form(domain.fqdn)
        for name, form, _through in list(found.get(host, [])):
            if form != "whole" or not _HOST_RE.fullmatch(host) or _held_by(host):
                continue
            if not any(mark.detonation == name for mark in domain.observed_in or ()):
                continue
            for address in domain.resolved_ips:
                if launch_form(address):
                    _add(launch_form(address), name, "resolved", host)
    out: dict[str, LaunchedDetonation] = {
        name: LaunchedDetonation(detonation=name, launched_with=launch)
        for name, launch in launches.items()
    }
    for value, supplied in found.items():
        held_by = _held_by(value)
        for name, form, through in supplied:
            out[name].values.append(
                LaunchValue(value=value, form=form, through=through, held_by=held_by)
            )
    return list(out.values())


def honoured_launches(report: Any) -> frozenset[str]:
    """The detonations whose launch the run's record states was honoured.

    Read from the run's record of its detonations
    (``run_environment.detonations_record``, ``arguments_honoured``) as every
    reader of the launch record reads its flag: honoured only where it says
    so; a record that does not say, or no record, is not.
    """
    summary = getattr(report, "run_summary", None)
    environment = summary.get("environment") if isinstance(summary, Mapping) else None
    rows = environment.get("detonations") if isinstance(environment, Mapping) else None
    return frozenset(
        str(row.get("detonation") or "")
        for row in (rows if isinstance(rows, list) else ())
        if isinstance(row, Mapping) and row.get("arguments_honoured") is True
    )


def _spellings(value: str) -> list[str]:
    """A folded value in both separators: a text may write a path either way round."""
    return list(dict.fromkeys([value, value.replace("\\", "/")]))


def _read_holds(texts: list[tuple[str, str]], known: dict[str, bool], value: str) -> bool:
    """Whether one of ``texts`` (a text and its lower case) holds ``value`` whole, in either
    separator, by the test an entry's text is read with (``validation._text_holds``).

    The texts are the reads of one detonation as tier 1 reads them, outside
    their launch echo (``EntryTexts.echo_free_parts`` on the index with the
    launch echoes, :meth:`EntryTexts.with_launch_echoes`). A spelling's forms
    are read once, and the whole-value test asked only of a text a form
    stands in. Read once per value.
    """
    from malspark.agents._indicator_denylists import whole_value_in
    from malspark.pipeline.validation import library_spellings
    from malspark.utils.written_forms import written_forms

    if value not in known:
        forms = [
            form
            for spelled in _spellings(value)
            for spelling in library_spellings(spelled)
            for form in written_forms(spelling)
        ]
        known[value] = any(
            form.lower() in lowered and whole_value_in(form, text)
            for text, lowered in texts
            for form in forms
        )
    return known[value]


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


def launch_supplied_refusal(
    report: Any, kind: str, value: Any, *, cited: Iterable[str] | None = None
) -> str:
    """Why the rule refuses ``value`` as a further detonation's launch supplied it, or ``""``.

    Asked of a value the publish rule's own answer publishes
    (``stix_renderer.publish_answer``), and read off the build's record
    (``MalwareReport.launch_values``, :func:`launch_record`). The value is
    refused where all three hold:

    * a further detonation's mark stands on its row: a row of the report's
      network or dynamic block of its kind and value names that detonation
      (``detonation_marks``), or one of ``cited`` — the entries the row cites
      that hold it whole outside their echoes, where the row states them — is
      a read of it (``detonation_marks.entry_marks``), a cited repeat read as
      the entry it repeats; what a read states as its launch text is no
      observation;
    * it stands whole in that detonation's launch text in one of the forms of
      :func:`launch_values`, as a path a read of it writes ending in what it
      writes after an environment variable (:func:`_expanded`), or as an
      address it resolved for a host the launch text supplies;
    * no entry of the run holds it whole outside the reads of the
      detonations supplying it, what an entry's own call asked for and the
      entries whose call was given one of their launch texts.

    A value a row of the job's own detonation holds, of any kind
    (:func:`_own_values`), is never refused here. The words say which launch
    text holds the value and how, and what the search left out.
    """
    record = list(getattr(report, "launch_values", None) or ())
    if not record:
        return ""
    folded = launch_form(value)
    supplied = [
        (launched, held) for launched in record for held in launched.values if held.value == folded
    ]
    if not supplied or any(held.held_by for _launched, held in supplied):
        return ""
    if folded in _own_values(report):
        return ""
    from malspark.reporting.detonation_marks import detonation_named, entry_marks
    from malspark.reporting.ledger_projection import value_key

    named = {mark.detonation for mark in _row_marks(report).get((kind, value_key(kind, value)), [])}
    index = {row.id: row for row in getattr(report, "evidence_index", None) or ()}
    answering = [_answering(ref, index) for ref in cited or ()]
    named |= {mark.detonation for mark in entry_marks(answering, report)}
    # A stored record's detonation is read only where it names one.
    marked = [
        (launched, held)
        for launched, held in supplied
        if detonation_named(launched.detonation) and launched.detonation in named
    ]
    if not marked:
        return ""
    launched, held = marked[0]
    return _refusal_words(launched, held, [known.detonation for known, _held in supplied])


def _answering(ref: Any, index: Mapping[str, Any]) -> str:
    """The entry whose answer a cited id is: a repeat read as the entry it repeats, along the
    evidence index's ``repeated_of``."""
    held = str(ref or "").strip()
    seen: set[str] = set()
    while held in index and held not in seen and getattr(index[held], "repeated_of", None):
        seen.add(held)
        held = str(index[held].repeated_of).strip()
    return held


def _row_marks(report: Any) -> dict[tuple[str, str], list[Any]]:
    """The detonations each value of the report's rows was observed in, the job's own too, read
    once per reading (``detonation_marks._value_held``)."""
    from malspark.reporting.detonation_marks import _value_held
    from malspark.reporting.renderers.stix_renderer import _memo

    return cast(
        "dict[tuple[str, str], list[Any]]",
        _memo(report, "launch_row_marks", lambda: _value_held(report)),
    )


def _own_values(report: Any) -> frozenset[str]:
    """Each value a row of the report's network or dynamic block that came from the job's own
    detonation holds, folded (:func:`launch_form`), read once per reading.

    Which detonation a row came from, by kind, as the build records it
    (``ledger_projection``): a domain, address or URL row of the sandbox's
    (``source`` ``sandbox``: only a detonation's view or the job's own capture
    writes one) with no mark or one naming the job's own detonation
    (``observed_in``); a file-operation row (a written file, a mutex) and a
    sandbox signature likewise; and every row of the process tree (a further
    detonation's processes are its own tree, ``detonation_trees``), of the
    registry modifications and of the notable API calls, and every user
    agent and TLS fingerprint, which the build reads from the job's own
    detonation only. Each field that holds a value counts, whole.
    """
    from malspark.reporting.ledger_projection import FIRST_DETONATION, marks_of
    from malspark.reporting.renderers.stix_renderer import _memo

    def _own(row: Any) -> bool:
        return any(mark.detonation == FIRST_DETONATION for mark in marks_of(row))

    def _build() -> frozenset[str]:
        held: list[Any] = []
        network = getattr(report, "network", None)
        if network is not None:
            for domain in network.domains:
                if domain.source == "sandbox" and _own(domain):
                    held.append(domain.fqdn)
            for ip in network.ips:
                if ip.source == "sandbox" and _own(ip):
                    held.append(ip.address)
            for url in network.urls:
                if url.source == "sandbox" and _own(url):
                    held.append(url.url)
            held += [*network.user_agents, *network.ja3_fingerprints, *network.ja3s_fingerprints]
        dynamic = getattr(report, "dynamic", None)
        if dynamic is not None:
            nodes = list(dynamic.process_tree)
            while nodes:
                node = nodes.pop()
                held += [node.name, node.command_line]
                nodes.extend(node.children)
            for mod in dynamic.registry_mods:
                held += [mod.key, mod.value_name, mod.new_value]
            for api in dynamic.notable_apis:
                held += list(api.values()) if isinstance(api, Mapping) else []
            for operation in dynamic.file_operations:
                if isinstance(operation, Mapping) and _own(operation):
                    held += [item for key, item in operation.items() if key != "observed_in"]
            for signature in dynamic.sandbox_signatures:
                if _own(signature):
                    held += [signature.name, signature.description, *signature.marks]
        return frozenset(
            launch_form(text) for text in held if isinstance(text, str) and text.strip()
        )

    return cast("frozenset[str]", _memo(report, "launch_own_values", _build))


def _number(name: str) -> str:
    return name[1:] if name.startswith("d") else name


def _refusal_words(
    launched: LaunchedDetonation, held: LaunchValue, detonations: Iterable[str]
) -> str:
    """What the refusal says: the launch text that supplies the value and how, then what the
    run's search left out and found."""
    from malspark.reporting.detonation_marks import launch_text

    shown = f"`{launch_text(launched.launched_with)}`"
    number = _number(launched.detonation)
    if held.form == "resolved":
        supplied = (
            f"detonation {number} resolved it for `{launch_text(held.through)}`, which its "
            f"launch text holds, {COMPARED} ({shown})"
        )
    elif held.form == "variable":
        supplied = (
            f"detonation {number}'s launch text holds its end after the environment variable "
            f"`{launch_text(held.through)}`, {COMPARED} ({shown})"
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
        f"outside the reads of {listed}, entries whose call was given {given} and entries "
        "holding it only where their answer repeats their own call, the run's search found it "
        "whole in no entry"
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
