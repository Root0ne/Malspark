"""List the platform's publishing functions, and check the record kept on each of them.

    python -m scripts.audit.publishing_functions list [--json] [--class a|b|c|d|e|f|g]
    python -m scripts.audit.publishing_functions trace <stored-run directory>... --out FILE
        [--update-record] [--timeout SECONDS]
    python -m scripts.audit.publishing_functions --check [--trace-file FILE] [--json FILE]

A publishing function is one whose own wording can reach what a reader is
shown. The list is computed from the source, by one rule (T-770):

* **Entry points**: the renderers and exports (:data:`ENTRY_POINTS`), every
  GET route of the reports router and the jobs router's call-map route, and
  the worker's writers of the sentences a kept, a stopped and a refused job
  carry. An entry point that no longer exists ends the command with status 2,
  so a rename never empties the list.
* **Reach**: the closure over a static graph whose edges are a call or a
  reference (a function named as a value: ``key=f``, a lambda, ``map(f, ...)``);
  names resolved through imports and re-exports; ``self.``, ``cls.`` and
  ``super()`` to the class and its resolvable bases; ``x.m`` where ``x`` is a
  parameter annotated with a known class or was assigned ``Class(...)``; a
  nested def is reached by the function that holds it; a class named reaches
  its dunders and its decorated methods (properties, validators, serializers).
  A name bound more than once (rebound, bound in two branches, imported
  twice, a nested def beside a module-level one, a parameter beside a
  module-level name) resolves to every thing it can refer to, so one more
  binding never takes a target away.
  An ``obj.attr`` no rule resolves is not followed. Every package indexed
  counts: no module is left out by its name.
* **Publishing text**: the function's own body (nested defs excluded) holds a
  string literal or f-string of :data:`MIN_WORDS` or more words (a wordy
  literal; a word is a whitespace token of at least two letters, punctuation
  allowed at its ends; an f-string's placeholders are not words, and its fixed
  parts belong to it) in a hand-out position: returned or
  yielded, a lambda's body, passed to ``append``, ``extend``, ``insert``,
  ``add``, ``write``, ``writelines``, ``join``, ``setdefault``, ``update``,
  ``appendleft``, ``+=``-ed; and, followed to a fixed point, bound to a name
  read in such a position, or through a subscript or attribute of such a name
  or of what the caller holds (a parameter, ``self``, ``cls``). So a local
  name, a table of sentences, ``str.format``, ``%``, a join and an f-string
  placeholder carry wording to a hand-out. Never counted: a docstring or bare
  string statement, a logging or ``warnings.warn`` argument (what a call
  inside it receives, other than a composition of text, falls where it
  stands), a ``re`` pattern, an ``assert`` message (the four positions that
  publish nothing),
  a ``raise`` message, an operand of a comparison or membership test, and a
  literal whose strongest use is one of these (:class:`Uses`).
* **Uses**: a literal, and every name it is bound to, takes the strongest of
  its uses, weakest first: unread, a quiet position, a raise, a comparison,
  passed to a call, stored or otherwise read (not placed), handed out. A
  walrus's value is also read where the walrus stands, and a name a class
  body binds is not placed. Uses only add, so a log line, a comparison or a
  pass-through added to a function never lowers a literal's class and never
  removes an entry.
* **Constants**: each module or class constant (a field default among them)
  whose value holds such a literal and that a reached function hands out,
  recorded once as a constant with the functions that hand it out; one a
  reached function only compares a value with is class h. A name
  bound at module or class level to a value naming such a constant (a table
  derived from it, a ``default_factory`` lambda) hands it on.

Each function and constant is listed as ``module:qualname`` with its file, its
line, the digest of what it hands out (:func:`text_digest` says exactly what it
covers) and the entry groups that reach it, with the count per package. The
output is sorted and byte-equal from run to run, whatever the interpreter's
hash seed and the working directory.

The partition (:class:`Partition`)
----------------------------------

Every wordy literal of every module indexed falls in exactly one class, and
the classes' sizes sum to the total; each class is printed with its count on
every run and listed by name with ``list --class``. A literal in no class is
an error (status 2), never a silent gap:

* **a**: handed out by a function an entry point reaches (listed; needs an entry);
* **b**: in a constant a reached function hands out (listed; needs an entry);
* **c**: wordy, in a reached function (a class statement inside it among it)
  or in a constant a reached function names (a field of a class it names
  among them), where the rule cannot place it as handed out (named; needs an
  entry);
* **d**: in a function, a constant or other module or class code no entry point
  reaches by a call or a name, in a module an entry point does reach (counted
  and named per module; build-time writers sit here);
* **e**: in a module no entry point reaches (counted per package);
* **f**: never published by its position: a docstring or bare string
  statement, a logging call, a ``re`` pattern or an ``assert`` message, or a
  literal whose strongest use is one of these or that nothing reads (counted
  per kind);
* **g**: a ``raise`` message, or a literal whose strongest use is a raise
  (counted; those a route sends as a response body are named: raised in a
  function a route handler reaches, of a class :meth:`Tree.sent_exceptions`
  finds a route sends the message of);
* **h**: compared in a reached function: an operand of a comparison or a
  membership test, or a literal whose strongest use is one, or in a constant
  the reached functions use only in comparisons (each such constant named;
  needs an entry, since the value it lets through may be printed). An entry
  may say ``not_published`` with ``compared_only`` where its basis states the
  compared value is not printed, and only while no function of the tree,
  reached or not, hands the constant out, passes or stores it: each function
  that does is named beside the constant, and ``--check`` refuses that reason
  for it. An operand written in a function is counted and named, with no
  entry.

A position class (f, g) is read first, the outermost position winning; the
others by where the literal stands. d to g are the stated limits
(:func:`limit_lines`), with text built at run time from no literal.

``trace`` renders stored runs with ``scripts/replay/render_surfaces.py``, one
run per process and each mode apart (serve: the stored report as the API
serves it; build: the report the replay rebuilds), under the standard
library's profiler, and writes to ``--out`` which listed functions ran and
which functions with publishing text ran but are not in the list. Those that
ran while a run was served join what must have a record; those seen only in
build mode are listed apart. A run directory that holds no stored report ends
the command with status 2 and one line, nothing written; a render that raises
or runs no listed function is a failed run, and a run that outlasts
``--timeout`` ends the command with status 2 and one line. The
output names runs, so it is written only to the path given, and a path inside
any checkout of the repository (the main checkout or a work tree) is refused.
Its scratch is a directory ``trace`` creates beside ``--out`` and removes; it
never empties or removes a directory it did not create.
``--update-record`` adds the served ones to ``traced.json`` (below), the one
file ``trace`` writes inside the repository.

The record (``scripts/audit/publishing_records/``)
--------------------------------------------------

One JSON file per module, named ``<module>.json``, so several writers never
edit one file: ``{"entries": [...]}``, each entry with ``function`` (or
``constant``) as ``module:qualname``, the ``condition`` under which it prints,
the ``basis`` (the fields its text rests on), the ``test`` node id that pins it
(``tests/<file>.py::<name>``, resolved in the file without running it) and the
``text_digest`` the list gives; a ``test`` may be a list, and an entry may say
``no_published_surface`` with the reason where its text reaches no reader.
An entry whose text reaches no published surface may instead be a
``not_published`` entry: the key, the ``text_digest`` and
``{"reason": ..., "basis": "<one sentence>"}``, the reason one of
:data:`NOT_PUBLISHED_REASONS` open to the entry's class
(:data:`NOT_PUBLISHED_REASONS_BY_CLASS`, stated in ``schema.json`` as
``reasons_by_class``: a function or a constant that hands out wording, or
that the rule cannot place, gives a reason that says why that wording reaches
no reader; ``compared_only`` is open to a compared constant only); it needs
no test, and ``--check`` prints how many there are on every run.
``schema.json`` is the schema every entry is validated against;
``status.json`` holds ``complete``: ``false`` while entries are still being
written. ``traced.json`` holds only the ``module:qualname`` keys of functions a
trace saw hand out wording while a stored run was served that the static list
misses; each needs an entry, with no trace file. The "ran on stored runs" marks
are never kept here: they name runs, and live beside the stored runs.

``--check`` recomputes the list and reports: a function or constant of class
a, b or c, or a constant of class h, with no entry (``missing``), an entry
whose function or constant left the list (``left``) or is now listed under
another module (``moved``), an entry for a function the static list does not
reach and no trace given confirms (``not_reached_statically``), a digest that
moved since the entry was written (``digest``), a test node id that does not
resolve (``test``), a test node id reading the file cannot decide
(``unverified``), an entry the schema refuses, a ``not_published`` reason not
open to the entry's class or ``compared_only`` for a constant a function
hands out (``invalid``) and a function or
constant with two entries (``duplicate``); a key of ``traced.json`` that is no
longer a function handing out wording is ``left``. A test node id resolves
only to a test function or method the runner would collect
(:func:`test_verdict`). ``--trace-file`` adds the functions a trace saw while
serving to what must have an entry. While ``status.json`` says incomplete it
reports only (status 0); once complete, any report is status 1. Status 2: a
usage or read error.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 — this script itself, an argument list only
import sys
import tempfile
import threading
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, FrameType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RECORDS = Path(__file__).with_name("publishing_records")
SCHEMA_FILE = "schema.json"
STATUS_FILE = "status.json"
TRACED_FILE = "traced.json"
# The packages indexed: (directory under the repository, package name).
PACKAGE_ROOTS: tuple[tuple[str, str], ...] = (("src", "malspark"), ("apps/api", "app"))
MIN_WORDS = 2

_R = "malspark.reporting"
_W = "app.worker.analysis_worker"
ENTRY_POINTS: dict[str, tuple[str, ...]] = {
    "md": (
        f"{_R}.renderers.markdown:MarkdownRenderer.render",
        f"{_R}.renderers.markdown:MarkdownRenderer.render_with_notes",
    ),
    "html": (f"{_R}.renderers.html:HtmlRenderer.render",),
    "stix": (f"{_R}.renderers.stix_renderer:ExtendedSTIXRenderer.render",),
    "misp": (f"{_R}.misp:build_misp_attributes", f"{_R}.misp:build_misp_event"),
    "analyst": (f"{_R}.renderers.analyst:analyst_sections",),
    "figures": (f"{_R}.figures:build_figures",),
    "bundle": (f"{_R}.renderers.bundle:render_products", f"{_R}.renderers.bundle:bundle_json"),
    "layer": (f"{_R}.navigator_layer:build_layer",),
    "callmap": (f"{_R}.call_map:call_map",),
    "api": ("app.api.v1.jobs:get_job_call_map",),
    # The judge's bundle and techniques the worker stores, and the sentences a
    # kept, a stopped and a refused job carry.
    "worker": (
        f"{_W}:judge_bundle_record",
        f"{_W}:judge_bundle_json",
        f"{_W}:_extract_mitre",
        f"{_W}:kept_report_note",
        f"{_W}:stored_after_note",
        f"{_W}:stop_note",
        f"{_W}:concurrent_analyses_refusal",
    ),
}
# Every GET route of these routers is an entry point of the group named.
ROUTE_ENTRIES: dict[str, tuple[str, ...]] = {"api": ("app.api.v1.reports",)}

_WORD = re.compile(r"[(\"'`\[]*[A-Za-z][A-Za-z'’-]*[A-Za-z][)\"'`.,;:!?\]]*")
_LOG_ATTRS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)
# The receivers a logging call is made on: these names, and any name a module
# assigns from ``getLogger(...)`` or ``get_logger(...)``.
_LOG_BASES = frozenset(
    {"logging", "warnings", "structlog", "logger", "log", "_log", "_logger", "LOGGER", "LOG"}
)
_LOGGER_FACTORIES = frozenset({"getLogger", "get_logger", "getChild"})
_RE_FUNCS = frozenset(
    {"compile", "search", "match", "fullmatch", "sub", "subn", "split", "findall", "finditer"}
)
_HAND_OUT_CALLS = frozenset(
    {
        "append",
        "extend",
        "insert",
        "add",
        "write",
        "writelines",
        "join",
        "setdefault",
        "update",
        "appendleft",
    }
)
_IMPLICIT = re.compile(
    r"property|validator|serializer|computed_field|cached_property|setter|model_post_init"
)
_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_TEST_ID = re.compile(r"^(tests/[^:\[\]]+\.py)::([A-Za-z_]\w*)(?:::([A-Za-z_]\w*))?(?:\[(.+)\])?$")
_KEY = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_][\w.<>]*$")

REPORT_KINDS: tuple[str, ...] = (
    "missing",
    "left",
    "moved",
    "not_reached_statically",
    "digest",
    "test",
    "unverified",
    "invalid",
    "duplicate",
)
# The partition's classes (module docstring); a, b, c and h's constants need entries.
PARTITION_CLASSES: tuple[str, ...] = ("a", "b", "c", "d", "e", "f", "g", "h")
# Why a ``not_published`` entry's text reaches no published surface.
NOT_PUBLISHED_REASONS: dict[str, str] = {
    "operator_text": "operator text in settings or a console form",
    "schema_text": "schema or API description text",
    "non_sentence": "a key, a format or other non-sentence",
    "model_text": "text a model reads only (a prompt, a tool answer, a pack line), never a "
    "served report, export or console page",
    "compared_only": "compared, never printed: a value is compared with it and the basis "
    "states the compared value is not printed",
}
# The reasons an entry of each class may give (``schema.json`` states the same).
# Wording a function or a constant hands out, or that the rule cannot place,
# needs a reason that says why that wording reaches no reader; "compared, never
# printed" is open only to a constant of class h, and only while no function of
# the tree, reached or not, hands it out (:attr:`Listing.compared_handed_out`).
NOT_PUBLISHED_REASONS_BY_CLASS: dict[str, tuple[str, ...]] = {
    "a": ("operator_text", "schema_text", "non_sentence", "model_text"),
    "b": ("operator_text", "schema_text", "non_sentence", "model_text"),
    "c": ("operator_text", "schema_text", "non_sentence", "model_text"),
    "h": ("operator_text", "schema_text", "non_sentence", "model_text", "compared_only"),
}


def words(text: str) -> int:
    """The words of ``text``: whitespace tokens of at least two letters."""
    return sum(1 for token in text.split() if _WORD.fullmatch(token))


def literal_text(node: ast.AST) -> str | None:
    """A string literal's text; an f-string's with each placeholder as ``{}``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append(" {} ")
        return "".join(parts)
    return None


def handed_text(node: ast.AST) -> str:
    """A literal as its digest reads it: an f-string's fixed parts and, in order, each
    placeholder as its expression's source with its conversion and format spec
    (``{value!r:>8}``)."""
    if isinstance(node, ast.Constant):
        return str(node.value)
    if not isinstance(node, ast.JoinedStr):
        return ""
    parts = []
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            conversion = f"!{chr(value.conversion)}" if value.conversion != -1 else ""
            spec = f":{handed_text(value.format_spec)}" if value.format_spec else ""
            parts.append("{" + ast.unparse(value.value) + conversion + spec + "}")
        else:
            parts.append(handed_text(value))
    return "".join(parts)


def _parents(nodes: Iterable[ast.AST]) -> dict[int, ast.AST]:
    """Each child's parent among ``nodes``, by the child's id."""
    return {id(child): node for node in nodes for child in ast.iter_child_nodes(node)}


def _composition(node: ast.AST, parents: Mapping[int, ast.AST], chain: bool = True) -> str:
    """What ``node`` is composed with (:func:`composed_text`), ``""`` for nothing; a ``+``
    chain only when ``chain``."""
    parent = parents.get(id(node))
    if (
        isinstance(parent, ast.Attribute)
        and parent.attr in ("format", "format_map")
        and isinstance(call := parents.get(id(parent)), ast.Call)
        and call.func is parent
    ):
        given = [ast.unparse(arg) for arg in call.args]
        given += [
            f"{k.arg}={ast.unparse(k.value)}" if k.arg else f"**{ast.unparse(k.value)}"
            for k in call.keywords
        ]
        return f" .{parent.attr}({', '.join(given)})"
    if isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Mod) and parent.left is node:
        return f" % {ast.unparse(parent.right)}"
    if chain and isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
        top = parent
        while isinstance(up := parents.get(id(top)), ast.BinOp) and isinstance(up.op, ast.Add):
            top = up
        return f" + {ast.unparse(top)}"
    return ""


def composed_text(
    node: ast.AST,
    parents: Mapping[int, ast.AST],
    reads: Mapping[str, Sequence[ast.Name]] | None = None,
) -> str:
    """A literal as its digest reads it (:func:`handed_text`) with the arguments it is
    composed with: of a ``.format(...)`` or ``.format_map(...)`` it is the
    receiver of, each argument's source in order (a keyword as ``name=source``);
    of a ``%`` it is the left operand of, the right operand's source; and of a
    ``+`` chain it stands in, the whole chain's source. A literal bound alone to
    a name (``template = "..."``, or ``:=``) also counts the ``.format`` and
    ``%`` arguments of each read of the name in ``reads``, in source order."""
    text = handed_text(node) + _composition(node, parents)
    parent = parents.get(id(node))
    target: ast.expr | None = None
    if isinstance(parent, ast.Assign) and parent.value is node and len(parent.targets) == 1:
        target = parent.targets[0]
    elif isinstance(parent, ast.AnnAssign | ast.NamedExpr) and parent.value is node:
        target = parent.target
    if reads is not None and isinstance(target, ast.Name):
        found = sorted(reads.get(target.id, ()), key=lambda r: (r.lineno, r.col_offset))
        text += "".join(_composition(read, parents, chain=False) for read in found)
    return text


def text_digest(texts: Iterable[str]) -> str:
    """The digest of what a function or a constant hands out, in source order.

    For a function it covers every string literal of its own body that stands
    in a hand-out position, of any length (one word, a separator, an empty
    string), and every wordy literal of its body the rule cannot place (class
    c); for a constant, every string literal of its value. An f-string counts
    as its fixed parts and, in order, each placeholder's expression as source
    text (``ast.unparse``) with its conversion and format spec. A literal
    formatted with ``.format(...)`` or ``%``, or standing in a ``+`` chain,
    counts with the source of those arguments or of that chain, and a
    function's template bound alone to a local name and formatted through it
    with ``.format`` or ``%`` in the same function counts with those arguments
    (:func:`composed_text`). So a changed word, a changed
    or swapped placeholder, a changed or swapped argument of a ``%``, a
    ``.format`` or a concatenation, and a reordering of the literals move it.
    It does not move for a literal in no such position, a change of formatting
    that leaves the parsed expressions equal, an argument passed through a
    name whose binding changes (``args = (y, x)``, then ``"..." % args``), a
    template held in a constant, a tuple or another object and formatted in
    another function or through another name, a ``+`` chain a name held text
    stands in, a ``str.format(text, ...)`` call
    or a join's other items, nor for the code around the literals.
    """
    body = json.dumps(list(texts), ensure_ascii=True)
    return hashlib.sha256(body.encode("ascii")).hexdigest()


def _strings(node: ast.AST) -> Iterator[ast.AST]:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant | ast.JoinedStr):
            yield sub
            if isinstance(sub, ast.JoinedStr):
                yield from sub.values


def loggers(nodes: Iterable[ast.AST]) -> frozenset[str]:
    """The names a module assigns from ``getLogger(...)`` or ``get_logger(...)``."""
    out = set()
    for node in nodes:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in _LOGGER_FACTORIES:
                out.update(_target_names(node.targets))
                out.update(t.attr for t in node.targets if isinstance(t, ast.Attribute))
    return frozenset(out)


def _target_names(targets: Iterable[ast.AST]) -> set[str]:
    return {sub.id for target in targets for sub in ast.walk(target) if isinstance(sub, ast.Name)}


def positions(
    nodes: Iterable[ast.AST], logging_names: frozenset[str] = frozenset()
) -> dict[int, str]:
    """The nodes among a module's ``nodes`` in a position that publishes nothing, by kind.

    ``raise`` (a ``raise`` statement's exception), ``assert`` (its message),
    ``docstring`` (a docstring or any bare string statement), ``log`` (an
    argument of a logging call, made on ``logging``, ``warnings``,
    ``structlog``, a receiver named as a logger is, or a name assigned from
    ``getLogger``) and ``pattern`` (a ``re`` pattern). Only ``raise`` is no
    quiet position (:data:`QUIET_POSITIONS`). A comparison operand and a string
    annotation are none of these: they fall where they stand. A logging call's
    argument is marked only where it carries its text into the line: what a
    call inside it receives (other than ``str``, ``repr``, ``.format``,
    ``.format_map`` or ``.join``) is that call's and falls where it stands.
    ``nodes`` are read outer first (``ast.walk``), so the outermost position
    wins.
    """
    out: dict[int, str] = {}
    loggers_here = _LOG_BASES | logging_names

    def mark(node: ast.AST | None, kind: str) -> None:
        if node is not None:
            for sub in ast.walk(node):
                out.setdefault(id(sub), kind)

    def mark_carried(node: ast.AST, kind: str) -> None:
        # What a call inside the argument receives is that call's to place:
        # only the parts that carry their text into the argument are marked.
        stack = [node]
        while stack:
            sub = stack.pop()
            out.setdefault(id(sub), kind)
            if isinstance(sub, ast.Call) and not _composes(sub):
                stack.append(sub.func)
            else:
                stack.extend(ast.iter_child_nodes(sub))

    for node in nodes:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant | ast.JoinedStr):
            mark(node.value, "docstring")
        elif isinstance(node, ast.Raise):
            mark(node.exc, "raise")
        elif isinstance(node, ast.Assert):
            mark(node.msg, "assert")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = node.func.value
            name = (
                base.id
                if isinstance(base, ast.Name)
                else base.attr
                if isinstance(base, ast.Attribute)
                else ""
            )
            attr = node.func.attr
            if attr in _LOG_ATTRS and name in loggers_here:
                for arg in (*node.args, *(keyword.value for keyword in node.keywords)):
                    mark_carried(arg, "log")
            if name == "re" and attr in _RE_FUNCS and node.args:
                mark(node.args[0], "pattern")
    return out


def excluded(nodes: Iterable[ast.AST], logging_names: frozenset[str] = frozenset()) -> set[int]:
    """The nodes among a module's ``nodes`` in a position that publishes nothing
    (:func:`positions`, whatever the kind)."""
    return set(positions(nodes, logging_names))


def canonical_literals(nodes: Iterable[ast.AST], min_words: int = MIN_WORDS) -> list[ast.AST]:
    """The wordy literals among ``nodes``: each string literal or f-string of
    ``min_words`` or more words, an f-string's fixed parts and format specs
    belonging to it rather than counted apart. An f-string nested in another's
    placeholder is a literal of its own."""
    nodes = list(nodes)
    parts: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.JoinedStr):
            parts.update(id(v) for v in node.values if isinstance(v, ast.Constant))
        elif isinstance(node, ast.FormattedValue) and node.format_spec is not None:
            parts.add(id(node.format_spec))
    out: list[ast.AST] = []
    for node in nodes:
        if id(node) in parts or not isinstance(node, ast.Constant | ast.JoinedStr):
            continue
        text = literal_text(node)
        if text is not None and words(text) >= min_words:
            out.append(node)
    return out


def _blocks(node: ast.AST) -> list[list[ast.stmt]]:
    """The statement lists a compound statement holds (a branch, a loop, a ``try``,
    a ``with``, a ``match``); none for any other node."""
    if isinstance(node, ast.Match):
        return [case.body for case in node.cases]
    if not isinstance(
        node, ast.If | ast.For | ast.AsyncFor | ast.While | ast.Try | ast.TryStar | ast.With
    ) and not isinstance(node, ast.AsyncWith):
        return []
    out = [getattr(node, part, None) or [] for part in ("body", "orelse", "finalbody")]
    out += [handler.body for handler in getattr(node, "handlers", None) or []]
    return out


def _bound_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    """The names an assignment binds: each name target, and each name of a tuple target."""
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    out: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            out.append(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            out += [e.id for e in target.elts if isinstance(e, ast.Name)]
    return out


def own_nodes(function: ast.AST) -> list[ast.AST]:
    """Every node of a function's own code: a nested def or class is not walked into."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(function))
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPES):
            continue
        out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def class_body_nodes(function: ast.AST) -> list[ast.AST]:
    """Every node of a class statement in a function's own code, a def inside it not
    walked into: code the function runs whose names belong to the class."""
    out: list[ast.AST] = []
    stack = [(node, False) for node in ast.iter_child_nodes(function)]
    while stack:
        node, inside = stack.pop()
        if isinstance(node, _FUNC):
            continue
        if isinstance(node, ast.ClassDef):
            inside = True
        elif inside:
            out.append(node)
        stack.extend((child, inside) for child in ast.iter_child_nodes(node))
    return out


def _bindings(nodes: Sequence[ast.AST]) -> list[tuple[list[ast.expr], ast.AST]]:
    """Each ``(targets, value)`` a function's own ``nodes`` bind: an assignment, an
    augmented or annotated one, a walrus, a ``for`` or a comprehension's target
    and what it iterates, a ``with`` item's name and its context."""
    out: list[tuple[list[ast.expr], ast.AST]] = []
    for node in nodes:
        if isinstance(node, ast.Assign):
            out.append((list(node.targets), node.value))
        elif isinstance(node, ast.AnnAssign | ast.AugAssign | ast.NamedExpr):
            if node.value is not None:
                out.append(([node.target], node.value))
        elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            out.append(([node.target], node.iter))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            out.append(([node.optional_vars], node.context_expr))
    return out


def _root_name(node: ast.AST) -> str | None:
    """The name a subscript or attribute chain starts from: ``row`` of ``row["a"].b``."""
    while isinstance(node, ast.Subscript | ast.Attribute | ast.Starred):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _binds_to(target: ast.AST, names: set[str], held: frozenset[str]) -> bool:
    """Whether binding ``target`` hands its value on: a name in ``names``, or a
    subscript or attribute of one, or of a name in ``held``."""
    if isinstance(target, ast.Tuple | ast.List):
        return any(_binds_to(part, names, held) for part in target.elts)
    if isinstance(target, ast.Starred):
        return _binds_to(target.value, names, held)
    if isinstance(target, ast.Name):
        return target.id in names
    root = _root_name(target)
    return root is not None and (root in names or root in held)


def _flows(
    nodes: Sequence[ast.AST],
    seeds: set[int],
    bindings: Sequence[tuple[Sequence[ast.expr], ast.AST]],
    held: frozenset[str] = frozenset(),
) -> set[int]:
    """``seeds`` closed over names, to a fixed point.

    A name read inside a node of the set makes the values bound to it join the
    set; so does a value bound through a subscript or an attribute of such a
    name, or of a name in ``held`` (what the caller also holds).
    """
    out = set(seeds)
    names_read = [
        node for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    ]
    pending = list(bindings)
    while pending:
        names = {node.id for node in names_read if id(node) in out}
        joined = [
            binding
            for binding in pending
            if any(_binds_to(target, names, held) for target in binding[0])
        ]
        if not joined:
            break
        for binding in joined:
            pending.remove(binding)
            out.update(id(sub) for sub in ast.walk(binding[1]))
    return out


def hand_out_ids(
    nodes: Sequence[ast.AST],
    held: frozenset[str] = frozenset(),
    bindings: Sequence[tuple[list[ast.expr], ast.AST]] | None = None,
) -> set[int]:
    """The nodes in a hand-out position among a function's own ``nodes``.

    Returned or yielded, a lambda's body, passed to a call that collects or
    writes text, ``+=``-ed; and, to a fixed point, what is bound to a name read
    in such a position, or through a subscript or attribute of it or of a name
    in ``held`` (the parameters, ``self`` and ``cls``: the caller holds them).
    So wording reaches a hand-out position through a local name, a table of
    sentences, ``str.format``, ``%``, a join or an f-string placeholder.
    """
    seeds: set[int] = set()
    for node in nodes:
        value: ast.AST | None = None
        if isinstance(node, ast.Return | ast.Yield | ast.YieldFrom):
            value = node.value
        elif isinstance(node, ast.Lambda):
            value = node.body
        elif isinstance(node, ast.AugAssign):
            value = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _HAND_OUT_CALLS
        ):
            for arg in (*node.args, *(keyword.value for keyword in node.keywords)):
                seeds.update(id(sub) for sub in ast.walk(arg))
        if value is not None:
            seeds.update(id(sub) for sub in ast.walk(value))
    return _flows(nodes, seeds, _bindings(nodes) if bindings is None else bindings, held)


def held_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """What a function's caller also holds: its parameters, ``self`` and ``cls``."""
    args = function.args
    names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    names |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
    return frozenset(names | {"self", "cls"})


def _binding_names(targets: Sequence[ast.expr]) -> set[str] | None:
    """The names a binding's targets bind, a subscript's or an attribute's root among
    them; ``None`` when a target is no name and starts from none."""
    out: set[str] = set()
    for target in targets:
        if isinstance(target, ast.Tuple | ast.List):
            inner = _binding_names(target.elts)
            if inner is None:
                return None
            out |= inner
            continue
        root = _root_name(target)
        if root is None:
            return None
        out.add(root)
    return out


_COMPOSING = frozenset({"format", "format_map", "join", "str", "repr"})


def _composes(call: ast.Call) -> bool:
    """Whether ``call`` only composes text from its arguments (``str``, ``repr``,
    ``.format``, ``.format_map``, ``.join``), handing nothing elsewhere."""
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name in _COMPOSING


# The four positions that publish nothing (:func:`positions`): a literal there,
# or bound to a name only they read, is class f.
QUIET_POSITIONS = frozenset({"docstring", "log", "pattern", "assert"})
# How code uses a value, weakest first. A literal's use is the strongest use of
# it and of every name it is bound to, so adding a use never lowers it.
USES: tuple[str, ...] = ("unread", "held", "raise", "compared", "unplaced", "handed")
_STRENGTH = {use: n for n, use in enumerate(USES)}
# Expressions whose value carries the text of the part being read.
_CARRY = (
    ast.BinOp,
    ast.BoolOp,
    ast.JoinedStr,
    ast.FormattedValue,
    ast.Tuple,
    ast.List,
    ast.Set,
    ast.Dict,
    ast.Starred,
    ast.Await,
    ast.UnaryOp,
)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
_BINDING_STATEMENTS = (
    ast.Assign,
    ast.AnnAssign,
    ast.NamedExpr,
    ast.For,
    ast.AsyncFor,
    ast.comprehension,
    ast.withitem,
)
Use = tuple[str | None, frozenset[ast.Raise]]


def _stronger(first: Use, second: Use) -> Use:
    """The stronger of two uses, with the raises of both."""
    kinds = [u[0] for u in (first, second) if u[0]]
    kind = max(kinds, key=_STRENGTH.__getitem__) if kinds else None
    return kind, first[1] | second[1]


class Uses:
    """How one function's code uses each of its nodes (:data:`USES`).

    A node's use is read up from it to the first expression that does not carry
    its text on (an operator, an f-string, a container, a subscript or
    attribute of it, a method called on it, ``str``, ``repr``, ``.format``,
    ``.format_map``, ``.join``, a comprehension's item): a position that
    publishes nothing (``held``), a raise (``raise``), a comparison or
    membership test (``compared``), a hand-out (``handed``: the hand-out rule's
    own reading, :func:`hand_out_ids`), or any other call, store or
    expression (``unplaced``). A value bound to a name takes the strongest use
    of any read of the name, anywhere in the function (a nested def's reads
    among them), to a fixed point; a name nothing reads is ``unread``, and one
    a ``global`` or ``nonlocal`` statement shares, or a class body binds, is
    ``unplaced``. A walrus's value also takes the use of the walrus where it
    stands. Uses only add: one more read never lowers a node's use.
    """

    def __init__(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        where: Mapping[int, str],
        raise_of: Mapping[int, ast.Raise],
        handed: set[int],
    ) -> None:
        self.where = where
        self.raise_of = raise_of
        self.handed = handed
        walked = list(ast.walk(function))
        self.parents = _parents(walked)
        self.reads: dict[str, list[ast.Name]] = defaultdict(list)
        # Names a ``global`` or ``nonlocal`` statement shares with other code:
        # what is bound to them is stored where this function cannot follow.
        self.shared: set[str] = set()
        for node in walked:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                self.reads[node.id].append(node)
            elif isinstance(node, ast.Global | ast.Nonlocal):
                self.shared.update(node.names)
        self.bindings = _bindings(walked)
        self.by_value = {id(value): n for n, (_, value) in enumerate(self.bindings)}
        # A name a class body binds is the class's attribute: what is bound to
        # it goes wherever the class goes, which this function cannot follow.
        in_class = {
            n
            for n, (_, value) in enumerate(self.bindings)
            if isinstance(statement := self.parents.get(id(value)), ast.stmt)
            and isinstance(self.parents.get(id(statement)), ast.ClassDef)
        }
        self.classes: list[Use] = [(None, frozenset())] * len(self.bindings)
        changed = True
        while changed:
            changed = False
            for n, (targets, _) in enumerate(self.bindings):
                found = self._binding(targets)
                if n in in_class:
                    found = _stronger(found, ("unplaced", frozenset()))
                if found != self.classes[n]:
                    self.classes[n] = found
                    changed = True

    def _binding(self, targets: Sequence[ast.expr]) -> Use:
        names = _binding_names(targets)
        if names is None or names & self.shared:
            return "unplaced", frozenset()
        known = [u for name in sorted(names) for r in self.reads[name] if (u := self.use(r))[0]]
        if not known:
            return None, frozenset()
        strongest = max((u[0] for u in known if u[0]), key=_STRENGTH.__getitem__)
        return strongest, frozenset().union(*(u[1] for u in known))

    def use(self, node: ast.AST) -> Use:
        """The strongest use of ``node`` and the raises it reaches."""
        kind = self.where.get(id(node))
        if kind in QUIET_POSITIONS:
            return "held", frozenset()
        if kind == "raise":
            return "raise", frozenset({self.raise_of[id(node)]})
        child, parent = node, self.parents.get(id(node))
        while parent is not None:
            if isinstance(parent, ast.keyword):
                child, parent = parent, self.parents.get(id(parent))
                continue
            carries = (
                isinstance(parent, _CARRY)
                or (isinstance(parent, ast.Attribute | ast.Subscript) and child is parent.value)
                or (isinstance(parent, ast.IfExp) and child is not parent.test)
                or (isinstance(parent, ast.Call) and (child is parent.func or _composes(parent)))
                or (
                    isinstance(parent, _COMPREHENSIONS) and not isinstance(child, ast.comprehension)
                )
            )
            if not carries:
                break
            child, parent = parent, self.parents.get(id(parent))
        if isinstance(parent, ast.Compare):
            return "compared", frozenset()
        if id(node) in self.handed:
            return "handed", frozenset()
        if isinstance(parent, _BINDING_STATEMENTS) and id(child) in self.by_value:
            bound = self.classes[self.by_value[id(child)]]
            if isinstance(parent, ast.NamedExpr):
                # ``(t := value)`` is also an expression: its value is read where
                # it stands as well as through the name.
                return _stronger(bound, self.use(parent))
            return bound
        return "unplaced", frozenset()

    def kind(self, node: ast.AST) -> str:
        """``node``'s use, ``unread`` for a value nothing reads."""
        return self.use(node)[0] or "unread"


def _literals(nodes: Iterable[ast.AST], keep: set[int]) -> list[ast.AST]:
    """The string literals among ``nodes`` whose id is in ``keep``, in source order; an
    f-string stands for its fixed parts and its format specs."""
    found = [
        node
        for node in nodes
        if id(node) in keep
        and (
            isinstance(node, ast.JoinedStr)
            or (isinstance(node, ast.Constant) and isinstance(node.value, str))
        )
    ]
    inner = set()
    for node in found:
        if isinstance(node, ast.JoinedStr):
            for sub in ast.walk(node):
                if sub is not node and isinstance(sub, ast.JoinedStr):
                    inner.add(id(sub))
            for sub in [node, *(n for n in ast.walk(node) if isinstance(n, ast.JoinedStr))]:
                inner.update(id(v) for v in sub.values if isinstance(v, ast.Constant))
    found = [node for node in found if id(node) not in inner]
    return sorted(found, key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))


def _wordy(nodes: Iterable[ast.AST], skip: set[int], min_words: int) -> list[ast.AST]:
    """The string nodes among ``nodes`` of ``min_words`` or more words, in source order."""
    found = []
    for node in nodes:
        if isinstance(node, ast.Constant | ast.JoinedStr) and id(node) not in skip:
            text = literal_text(node)
            if text is not None and words(text) >= min_words:
                found.append(node)
    inner = {id(v) for node in found if isinstance(node, ast.JoinedStr) for v in node.values}
    found = [node for node in found if id(node) not in inner]
    return sorted(found, key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))


@dataclass
class Function:
    key: str
    module: str
    qualname: str
    path: str
    line: int
    first_line: int
    node: ast.FunctionDef | ast.AsyncFunctionDef
    owner: str | None
    parent: str | None
    # Every literal handed out and every wordy literal not placed, as the
    # digest reads it, in source order.
    texts: list[str] = field(default_factory=list)
    # A literal of ``min_words`` or more words stands in its own body (outside
    # the positions that publish nothing) ...
    wordy: bool = False
    # ... and in a hand-out position.
    hands_out: bool = False
    # Each wordy literal of its own code outside a position class, by id:
    # its use (:data:`USES`): "handed", "unplaced", "compared", "raise",
    # "held" or "unread".
    placed: dict[int, str] = field(default_factory=dict)
    # The raises each literal reaches through a name only raises and quiet
    # positions read, by id.
    raises: dict[int, frozenset[ast.Raise]] = field(default_factory=dict)


@dataclass
class Constant:
    key: str
    module: str
    qualname: str
    path: str
    line: int
    texts: list[str]


@dataclass
class ClassDef:
    key: str
    module: str
    node: ast.ClassDef
    methods: dict[str, str] = field(default_factory=dict)
    constants: dict[str, str] = field(default_factory=dict)
    # Every name its body binds by assignment, wordy or not.
    holders: dict[str, str] = field(default_factory=dict)


class Tree:
    """The indexed source of the packages under ``repo``."""

    def __init__(
        self,
        repo: Path = ROOT,
        roots: Sequence[tuple[str, str]] = PACKAGE_ROOTS,
        *,
        min_words: int = MIN_WORDS,
    ) -> None:
        self.repo = repo.resolve()
        self.min_words = min_words
        self.modules: dict[str, ast.Module] = {}
        self.paths: dict[str, Path] = {}
        self.functions: dict[str, Function] = {}
        self.classes: dict[str, ClassDef] = {}
        self.constants: dict[str, Constant] = {}
        self.top: dict[str, dict[str, str]] = defaultdict(dict)
        self.module_constants: dict[str, dict[str, str]] = defaultdict(dict)
        self.excluded: dict[str, set[int]] = {}
        # Per module: each node in a position class, by kind; the ids of its
        # wordy literals (:func:`canonical_literals`).
        self.positions: dict[str, dict[int, str]] = {}
        self.canonical: dict[str, set[int]] = {}
        # The key of every def and class statement indexed, by node id; the
        # constant keys a module or class level assignment binds, by its id.
        self.def_keys: dict[int, str] = {}
        self.class_keys: dict[int, str] = {}
        self.constant_stmts: dict[int, list[str]] = defaultdict(list)
        # Every name bound by assignment at module or class level, wordy or
        # not: key -> (module, value, class key or None).
        self.holders: dict[str, tuple[str, ast.AST, str | None]] = {}
        self.module_holders: dict[str, dict[str, str]] = defaultdict(dict)
        # Names bound to no wordy literal of their own whose value names a
        # wordy constant (a derived table, a ``default_factory`` lambda).
        self.relays: set[str] = set()
        self._wordy_of: dict[str, frozenset[str]] = {}
        self._carried: dict[str, frozenset[str]] = {}
        self._imports: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
        # Every import of each name, of every scope: a name imported twice
        # refers to each of them (:meth:`lookup_all`).
        self._every_import: dict[str, tuple[dict[str, list[str]], dict[str, list[str]]]] = {}
        self._lookup_all: dict[tuple[str, str], frozenset[str]] = {}
        self._constant_all: dict[tuple[str, str], frozenset[str]] = {}
        self._methods: dict[str, dict[str, str]] = {}
        self._edges: dict[str, frozenset[str]] = {}
        self._implicit: dict[str, set[str]] = {}
        self._rel: dict[str, str] = {}
        for base, package in roots:
            root = self.repo / base
            for path in sorted((root / package).rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                module = ".".join(path.relative_to(root).with_suffix("").parts)
                module = module.removesuffix(".__init__")
                self.modules[module] = ast.parse(path.read_text(encoding="utf-8"))
                self.paths[module] = path
        self._resolved: dict[str, list[tuple[str, str, int]]] = {}
        self._own: dict[str, list[ast.AST]] = {}
        self._uses: dict[str, Uses] = {}
        walked = {module: list(ast.walk(tree)) for module, tree in self.modules.items()}
        for module, tree in self.modules.items():
            self.positions[module] = positions(walked[module], loggers(walked[module]))
            self.excluded[module] = set(self.positions[module])
            self.canonical[module] = {
                id(n) for n in canonical_literals(walked[module], self.min_words)
            }
            self._index(module, tree.body, "", None, None)
            self._constants(module, tree.body)
        # The ``raise`` statement each node of a raised expression stands in, by
        # id (the outermost); each exception handler a module registers, as
        # (module, exception class expression, handler expression).
        self.raise_of: dict[int, ast.Raise] = {}
        self.handlers: list[tuple[str, ast.expr, ast.expr]] = []
        for module in self.modules:
            every = self._read_imports(module, walked[module])
            self._every_import[module] = every
            # A single reading takes the last import of a name, as the module's
            # own namespace does when it runs top to bottom.
            self._imports[module] = (
                {name: found[-1] for name, found in every[0].items()},
                {name: found[-1] for name, found in every[1].items()},
            )
            for node in walked[module]:
                if isinstance(node, ast.Raise) and node.exc is not None:
                    for sub in ast.walk(node.exc):
                        self.raise_of.setdefault(id(sub), node)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "add_exception_handler" and len(node.args) >= 2:
                        self.handlers.append((module, node.args[0], node.args[1]))
                elif isinstance(node, _FUNC):
                    for d in node.decorator_list:
                        if (
                            isinstance(d, ast.Call)
                            and isinstance(d.func, ast.Attribute)
                            and d.func.attr == "exception_handler"
                            and d.args
                        ):
                            self.handlers.append((module, d.args[0], ast.Name(node.name)))
        self._lineage: dict[str, frozenset[str]] = {}
        self._link_holders()
        for function in self.functions.values():
            self._place(function)

    def own(self, key: str) -> list[ast.AST]:
        """A function's own nodes (:func:`own_nodes`), read once."""
        if key not in self._own:
            self._own[key] = own_nodes(self.functions[key].node)
        return self._own[key]

    def uses(self, key: str) -> Uses:
        """How function ``key`` uses its nodes (:class:`Uses`), read once."""
        if key not in self._uses:
            function = self.functions[key]
            own = self.own(key)
            handed = hand_out_ids(own, held_names(function.node), _bindings(own))
            self._uses[key] = Uses(
                function.node, self.positions[function.module], self.raise_of, handed
            )
        return self._uses[key]

    def _place(self, function: Function) -> None:
        module = function.module
        where = self.positions[module]
        canonical = self.canonical[module]
        own = self.own(function.key)
        mine = [n for n in own if id(n) in canonical and id(n) not in where]
        # A class statement inside the function: its body's wording goes
        # wherever the class goes, so the rule cannot place it.
        in_class = [
            n for n in class_body_nodes(function.node) if id(n) in canonical and id(n) not in where
        ]
        if not mine and not in_class:
            return  # placement only ever takes literals away
        uses = self.uses(function.key)
        for node in mine:
            kind, raises = uses.use(node)
            function.placed[id(node)] = kind or "unread"
            if raises:
                function.raises[id(node)] = raises
        for node in in_class:
            function.placed[id(node)] = "unplaced"
        kinds = set(function.placed.values())
        function.wordy = bool(kinds & {"handed", "unplaced"})
        function.hands_out = "handed" in kinds
        if function.wordy:
            unplaced = {i for i, kind in function.placed.items() if kind == "unplaced"}
            handed = {
                id(n)
                for n in own
                if id(n) in uses.handed
                and id(n) not in where
                and isinstance(n, ast.Constant | ast.JoinedStr)
                and uses.kind(n) == "handed"
            }
            # A handed f-string's parts go with it.
            handed |= {
                id(sub)
                for n in own
                if id(n) in handed and isinstance(n, ast.JoinedStr)
                for sub in ast.walk(n)
            }
            function.texts = [
                composed_text(n, uses.parents, uses.reads)
                for n in _literals([*own, *class_body_nodes(function.node)], handed | unplaced)
            ]

    # --- indexing ------------------------------------------------------------

    def rel(self, module: str) -> str:
        if module not in self._rel:
            self._rel[module] = self.paths[module].relative_to(self.repo).as_posix()
        return self._rel[module]

    def _index(
        self,
        module: str,
        body: Sequence[ast.stmt],
        prefix: str,
        owner: str | None,
        parent: str | None,
    ) -> None:
        for node in body:
            if isinstance(node, _FUNC):
                qualname = f"{prefix}{node.name}"
                key = f"{module}:{qualname}"
                first = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                self.functions[key] = Function(
                    key, module, qualname, self.rel(module), node.lineno, first, node, owner, parent
                )
                self.def_keys[id(node)] = key
                if not prefix:
                    self.top[module][node.name] = key
                if owner and parent is None:
                    self.classes[owner].methods[node.name] = key
                self._index(module, node.body, f"{qualname}.<locals>.", None, key)
            elif isinstance(node, ast.ClassDef):
                qualname = f"{prefix}{node.name}"
                key = f"{module}:{qualname}"
                self.classes[key] = ClassDef(key, module, node)
                self.class_keys[id(node)] = key
                if not prefix:
                    self.top[module][node.name] = key
                self._index(module, node.body, f"{qualname}.", key, parent)
                self._class_constants(self.classes[key], node.body)
            else:
                # A def or class inside a branch, a loop, a ``with`` or a
                # ``match`` keeps the qualified name of the scope around it.
                for block in _blocks(node):
                    self._index(module, block, prefix, owner, parent)

    def _constant(self, module: str, qualname: str, node: ast.Assign | ast.AnnAssign) -> str | None:
        if node.value is None:
            return None
        found = _wordy(ast.walk(node.value), self.excluded[module], self.min_words)
        if not found:
            return None
        key = f"{module}:{qualname}"
        every = {id(n) for n in ast.walk(node.value)}
        parents = _parents(ast.walk(node.value))
        texts = [composed_text(n, parents) for n in _literals(ast.walk(node.value), every)]
        self.constants[key] = Constant(key, module, qualname, self.rel(module), node.lineno, texts)
        self.constant_stmts[id(node)].append(key)
        return key

    def _constants(self, module: str, body: Sequence[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Assign | ast.AnnAssign):
                for name in _bound_names(node):
                    if node.value is not None:
                        key = f"{module}:{name}"
                        self.holders[key] = (module, node.value, None)
                        self.module_holders[module][name] = key
                    constant = self._constant(module, name, node)
                    if constant:
                        self.module_constants[module][name] = constant
            elif isinstance(node, ast.If | ast.Try | ast.With):
                for block in _blocks(node):
                    self._constants(module, block)

    def _class_constants(self, cls: ClassDef, body: Sequence[ast.stmt]) -> None:
        qualname = cls.key.split(":", 1)[1]
        for node in body:
            if isinstance(node, ast.Assign | ast.AnnAssign):
                for name in _bound_names(node):
                    if node.value is not None:
                        key = f"{cls.module}:{qualname}.{name}"
                        self.holders[key] = (cls.module, node.value, cls.key)
                        cls.holders[name] = key
                    constant = self._constant(cls.module, f"{qualname}.{name}", node)
                    if constant:
                        cls.constants[name] = constant
            elif isinstance(node, ast.If | ast.Try | ast.With):
                for block in _blocks(node):
                    self._class_constants(cls, block)

    # --- holders -------------------------------------------------------------

    def holder(self, module: str, name: str, depth: int = 0) -> str | None:
        """``module``'s module-level name ``name`` as a holder key, through re-exports."""
        if depth > 6:
            return None
        if name in self.module_holders.get(module, {}):
            return self.module_holders[module][name]
        names = self._imports.get(module, ({}, {}))[0]
        if name in names:
            source, attr = names[name].split(":", 1)
            return self.holder(source, attr, depth + 1)
        return None

    def class_holder(self, cls: str, name: str, seen: frozenset[str] = frozenset()) -> str | None:
        """A class's name ``name`` bound in its body, its own or a resolvable base's."""
        if cls in seen or cls not in self.classes:
            return None
        info = self.classes[cls]
        if name in info.holders:
            return info.holders[name]
        for base in info.node.bases:
            key = self._base_key(info.module, base)
            found = self.class_holder(key, name, seen | {cls}) if key else None
            if found:
                return found
        return None

    def fields(self, cls: str, seen: frozenset[str] = frozenset()) -> set[str]:
        """Every name a class and its resolvable bases bind in their bodies, as holder keys."""
        if cls in seen or cls not in self.classes:
            return set()
        info = self.classes[cls]
        out = set(info.holders.values())
        for base in info.node.bases:
            key = self._base_key(info.module, base)
            if key:
                out |= self.fields(key, seen | {cls})
        return out

    def _link_holders(self) -> None:
        """Which wordy constants each holder's value names, to a fixed point; a holder
        with none of its own that names one becomes a relay a name resolves to."""
        refs: dict[str, set[str]] = {}
        for key, (module, value, owner) in self.holders.items():
            modules = self._imports[module][1]
            found: set[str] = set()
            for node in ast.walk(value):
                target: str | None = None
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    own = self.classes[owner].holders.get(node.id) if owner else None
                    target = own or self.holder(module, node.id)
                elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    base = node.value.id
                    if base in modules:
                        target = self.holder(modules[base], node.attr)
                    else:
                        cls = self.lookup(module, base)
                        target = self.class_holder(cls, node.attr) if cls else None
                if target and target != key:
                    found.add(target)
            refs[key] = found
        for key in self.holders:
            seen = {key}
            stack = [key]
            while stack:
                for target in refs.get(stack.pop(), ()):
                    if target not in seen:
                        seen.add(target)
                        stack.append(target)
            self._wordy_of[key] = frozenset(k for k in seen if k in self.constants)
        for key in sorted(self.holders):
            if key in self.constants or not self._wordy_of[key]:
                continue
            self.relays.add(key)
            module, _, owner = self.holders[key]
            name = key.rsplit(".", 1)[-1] if owner else key.split(":", 1)[1]
            if owner:
                self.classes[owner].constants.setdefault(name, key)
            else:
                self.module_constants[module].setdefault(name, key)

    def wordy_of(self, key: str) -> frozenset[str]:
        """The wordy constants a constant or a relay stands for: itself when wordy, and
        those its value names, to a fixed point."""
        if key in self._wordy_of:
            return self._wordy_of[key]
        return frozenset({key}) if key in self.constants else frozenset()

    # --- names ---------------------------------------------------------------

    def _from(self, module: str, level: int, name: str | None) -> str:
        if level == 0:
            return name or ""
        parts = module.split(".")
        base = parts if self.paths[module].name == "__init__.py" else parts[:-1]
        if level > 1:
            base = base[: len(base) - (level - 1)]
        return ".".join(base + ([name] if name else []))

    def _read_imports(
        self, module: str, nodes: Iterable[ast.AST]
    ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """(name -> each ``module:attr`` a from-import binds it to, alias -> each module),
        from every scope, in the order ``nodes`` give them."""
        names: dict[str, list[str]] = defaultdict(list)
        modules: dict[str, list[str]] = defaultdict(list)
        for node in nodes:
            if isinstance(node, ast.ImportFrom):
                source = self._from(module, node.level, node.module)
                for alias in node.names:
                    target = f"{source}.{alias.name}"
                    if target in self.modules:
                        modules[alias.asname or alias.name].append(target)
                    else:
                        names[alias.asname or alias.name].append(f"{source}:{alias.name}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        modules[alias.asname].append(alias.name)
                    else:
                        top = alias.name.split(".")[0]
                        modules[top].append(top)
        return dict(names), dict(modules)

    def lookup(self, module: str, name: str, depth: int = 0) -> str | None:
        """``module``'s ``name`` as a function or class key, through re-exports."""
        if depth > 6:
            return None
        if name in self.top.get(module, {}):
            return self.top[module][name]
        names = self._imports.get(module, ({}, {}))[0]
        if name in names:
            source, attr = names[name].split(":", 1)
            return self.lookup(source, attr, depth + 1)
        return None

    def lookup_all(self, module: str, name: str, depth: int = 0) -> frozenset[str]:
        """Every function or class key ``module``'s ``name`` can refer to: its own def or
        class and each import of the name, through re-exports."""
        if depth > 6:
            return frozenset()
        cached = self._lookup_all.get((module, name))
        if cached is not None:
            return cached
        out: set[str] = set()
        if name in self.top.get(module, {}):
            out.add(self.top[module][name])
        for target in self._every_import.get(module, ({}, {}))[0].get(name, ()):
            source, attr = target.split(":", 1)
            out |= self.lookup_all(source, attr, depth + 1)
        self._lookup_all[(module, name)] = frozenset(out)
        return self._lookup_all[(module, name)]

    def constant_all(self, module: str, name: str, depth: int = 0) -> frozenset[str]:
        """Every wordy constant key ``module``'s ``name`` can refer to, through re-exports."""
        if depth > 6:
            return frozenset()
        cached = self._constant_all.get((module, name))
        if cached is not None:
            return cached
        out: set[str] = set()
        if name in self.module_constants.get(module, {}):
            out.add(self.module_constants[module][name])
        for target in self._every_import.get(module, ({}, {}))[0].get(name, ()):
            source, attr = target.split(":", 1)
            out |= self.constant_all(source, attr, depth + 1)
        self._constant_all[(module, name)] = frozenset(out)
        return self._constant_all[(module, name)]

    def module_aliases(self, module: str, name: str) -> list[str]:
        """Every module ``module``'s ``name`` is bound to by an import, of any scope."""
        return list(self._every_import.get(module, ({}, {}))[1].get(name, ()))

    def constant(self, module: str, name: str, depth: int = 0) -> str | None:
        """``module``'s ``name`` as a wordy constant's key, through re-exports."""
        if depth > 6:
            return None
        if name in self.module_constants.get(module, {}):
            return self.module_constants[module][name]
        names = self._imports.get(module, ({}, {}))[0]
        if name in names:
            source, attr = names[name].split(":", 1)
            return self.constant(source, attr, depth + 1)
        return None

    def _base_key(self, module: str, base: ast.expr) -> str | None:
        if isinstance(base, ast.Name):
            return self.lookup(module, base.id)
        if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
            modules = self._imports[module][1]
            if base.value.id in modules:
                return self.lookup(modules[base.value.id], base.attr)
        return None

    def methods(self, cls: str, seen: frozenset[str] = frozenset()) -> dict[str, str]:
        """A class's methods with those of its resolvable bases, its own winning."""
        if cls in self._methods:
            return self._methods[cls]
        if cls in seen or cls not in self.classes:
            return {}
        info = self.classes[cls]
        out: dict[str, str] = {}
        for base in info.node.bases:
            key = self._base_key(info.module, base)
            if key in self.classes:
                out.update(self.methods(key, seen | {cls}))
        out.update(info.methods)
        self._methods[cls] = out
        return out

    def class_constant(self, cls: str, name: str, seen: frozenset[str] = frozenset()) -> str | None:
        """A class's wordy constant ``name``, its own or a resolvable base's."""
        if cls in seen or cls not in self.classes:
            return None
        info = self.classes[cls]
        if name in info.constants:
            return info.constants[name]
        for base in info.node.bases:
            key = self._base_key(info.module, base)
            found = self.class_constant(key, name, seen | {cls}) if key else None
            if found:
                return found
        return None

    def implicit(self, cls: str) -> set[str]:
        """What naming a class runs without a call: its dunders and decorated methods."""
        if cls in self._implicit:
            return self._implicit[cls]
        out = set()
        for name, key in self.methods(cls).items():
            decorators = " ".join(ast.unparse(d) for d in self.functions[key].node.decorator_list)
            if (name.startswith("__") and name.endswith("__")) or _IMPLICIT.search(decorators):
                out.add(key)
        self._implicit[cls] = out
        return out

    def _annotated(self, module: str, annotation: ast.expr | None) -> str | None:
        if annotation is None:
            return None
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(annotation, ast.BinOp):
            return self._annotated(module, annotation.left) or self._annotated(
                module, annotation.right
            )
        key = None
        if isinstance(annotation, ast.Name | ast.Attribute):
            key = self._base_key(module, annotation)
        return key if key in self.classes else None

    def _own_class(self, function: Function) -> str | None:
        current: Function | None = function
        while current is not None:
            if current.owner:
                return current.owner
            current = self.functions.get(current.parent) if current.parent else None
        return None

    # --- edges ---------------------------------------------------------------

    def resolved(self, key: str) -> list[tuple[str, str, int]]:
        """Each name a function's own code resolves to: ``(kind, key, id of the node)``."""
        if key not in self._resolved:
            function = self.functions[key]
            self._resolved[key] = list(self._resolve(function, self.own(key)))
        return self._resolved[key]

    def _resolve(
        self, function: Function, nodes: Sequence[ast.AST]
    ) -> Iterator[tuple[str, str, int]]:
        """Each name ``nodes`` resolve to: ``("function"|"class"|"constant", key, node id)``.

        A name bound more than once (rebound, bound in two branches, imported twice,
        a nested def beside a module-level one) resolves to every thing it can
        refer to, so one more binding never takes a target away."""
        module = function.module
        own_class = self._own_class(function)
        args = function.node.args
        types: dict[str, set[str]] = defaultdict(set)
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            key = self._annotated(module, arg.annotation)
            if key:
                types[arg.arg].add(key)
        for node in nodes:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
            ):
                found = {
                    k for k in self.lookup_all(module, node.value.func.id) if k in self.classes
                }
                for assigned in node.targets:
                    if isinstance(assigned, ast.Name):
                        types[assigned.id] |= found
        local = {
            n.name: f"{module}:{function.qualname}.<locals>.{n.name}"
            for n in ast.walk(function.node)
            if isinstance(n, _FUNC) and n is not function.node
        }
        for node in nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                keys = set(self.lookup_all(module, node.id))
                if local.get(node.id) in self.functions:
                    keys.add(local[node.id])
                parent = function.parent
                while parent:
                    candidate = f"{module}:{self.functions[parent].qualname}.<locals>.{node.id}"
                    if candidate in self.functions:
                        keys.add(candidate)
                    parent = self.functions[parent].parent
                for key in sorted(keys):
                    if key in self.functions:
                        yield "function", key, id(node)
                    elif key in self.classes:
                        yield "class", key, id(node)
                for constant in sorted(self.constant_all(module, node.id)):
                    yield "constant", constant, id(node)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                base = node.value
                targets: set[str] = set()
                holders: set[str] = set()
                constants: set[str] = set()
                if isinstance(base, ast.Name):
                    if base.id in ("self", "cls") and own_class:
                        holders.add(own_class)
                    for aliased in self.module_aliases(module, base.id):
                        in_module = self.lookup_all(aliased, node.attr)
                        targets |= in_module
                        if not in_module:
                            constants |= self.constant_all(aliased, node.attr)
                    holders |= types.get(base.id, set())
                    holders |= {k for k in self.lookup_all(module, base.id) if k in self.classes}
                elif (
                    isinstance(base, ast.Call)
                    and isinstance(base.func, ast.Name)
                    and base.func.id == "super"
                    and own_class
                ):
                    for parent_class in self.classes[own_class].node.bases:
                        key = (
                            self.lookup(module, parent_class.id)
                            if isinstance(parent_class, ast.Name)
                            else None
                        )
                        if key in self.classes:
                            method = self.methods(key).get(node.attr)
                            if method:
                                targets.add(method)
                elif isinstance(base, ast.Call) and isinstance(base.func, ast.Name):
                    holders |= {
                        k for k in self.lookup_all(module, base.func.id) if k in self.classes
                    }
                for holder in sorted(holders):
                    method = self.methods(holder).get(node.attr)
                    if method:
                        targets.add(method)
                    elif held := self.class_constant(holder, node.attr):
                        constants.add(held)
                for constant in sorted(constants):
                    yield "constant", constant, id(node)
                for target in sorted(targets):
                    if target in self.functions:
                        yield "function", target, id(node)
                    elif target in self.classes:
                        yield "class", target, id(node)

    def edges(self, key: str) -> frozenset[str]:
        """The functions ``key`` calls or names, its nested defs and what classes it names run."""
        if key in self._edges:
            return self._edges[key]
        function = self.functions[key]
        out: set[str] = set()
        for node in ast.walk(function.node):
            if isinstance(node, _FUNC) and node is not function.node:
                nested = f"{function.module}:{function.qualname}.<locals>.{node.name}"
                if nested in self.functions and self.functions[nested].parent == key:
                    out.add(nested)
        for kind, target, _ in self.resolved(key):
            if kind == "function":
                out.add(target)
            elif kind == "class":
                out |= self.implicit(target)
        self._edges[key] = frozenset(out)
        return self._edges[key]

    def named_constants(self, key: str) -> tuple[set[str], set[str], set[str]]:
        """The wordy constants ``key`` names by their strongest use (:class:`Uses`): those
        it hands out, passes, stores or otherwise names; of them, those it hands
        out; and those it only compares a value with. A constant read only in a
        position that publishes nothing, or only raised, is in none."""
        resolved = [
            (target, node) for kind, target, node in self.resolved(key) if kind == "constant"
        ]
        if not resolved:
            return set(), set(), set()
        uses = self.uses(key)
        nodes = {id(n): n for n in self.own(key)}
        named: set[str] = set()
        handed: set[str] = set()
        compared: set[str] = set()
        for target, node in resolved:
            kind = uses.kind(nodes[node]) if node in nodes else "unplaced"
            if kind in ("handed", "unplaced"):
                named.add(target)
            if kind == "handed":
                handed.add(target)
            elif kind == "compared":
                compared.add(target)
        return named, handed, compared

    def named_classes(self, key: str) -> set[str]:
        """The classes ``key`` names (a call, an annotation, a reference) and its own class,
        with the classes their instances carry (:meth:`carried`)."""
        out = {target for kind, target, _ in self.resolved(key) if kind == "class"}
        own = self._own_class(self.functions[key])
        if own:
            out.add(own)
        return {carried for cls in out for carried in self.carried(cls)}

    def carried(self, cls: str) -> frozenset[str]:
        """``cls`` and, to a fixed point, each class an annotated field of it or of a
        resolvable base names (``front: FrontMatter | None``): its instances hold them."""
        if cls in self._carried:
            return self._carried[cls]
        seen = {cls}
        stack = [cls]
        while stack:
            current = stack.pop()
            for found in self._field_classes(current):
                if found not in seen:
                    seen.add(found)
                    stack.append(found)
        self._carried[cls] = frozenset(seen)
        return self._carried[cls]

    def _field_classes(self, cls: str, seen: frozenset[str] = frozenset()) -> set[str]:
        if cls in seen or cls not in self.classes:
            return set()
        info = self.classes[cls]
        out: set[str] = set()
        for node in info.node.body:
            if isinstance(node, ast.AnnAssign):
                for sub in ast.walk(node.annotation):
                    if isinstance(sub, ast.Name | ast.Attribute | ast.Constant):
                        key = self._annotated(info.module, sub)
                        if key:
                            out.add(key)
        for base in info.node.bases:
            key = self._base_key(info.module, base)
            if key:
                out |= self._field_classes(key, seen | {cls})
        return out

    def route_handlers(self, module: str) -> list[str]:
        """The functions of ``module`` a ``<router>.get(...)`` decorator registers."""
        out = []
        for node in self.modules.get(module, ast.Module(body=[], type_ignores=[])).body:
            if isinstance(node, _FUNC) and any(
                isinstance(d, ast.Call)
                and isinstance(d.func, ast.Attribute)
                and d.func.attr == "get"
                for d in node.decorator_list
            ):
                out.append(f"{module}:{node.name}")
        return out

    # --- raises a route sends ------------------------------------------------

    def class_identity(self, module: str, node: ast.AST | None) -> str | None:
        """An exception class named in ``module``: its key when the tree defines it,
        else ``name:<its name>``; ``None`` for anything but a name or an attribute."""
        if isinstance(node, ast.Call):
            node = node.func
        if not isinstance(node, ast.Name | ast.Attribute):
            return None
        key = self._base_key(module, node)
        if key in self.classes:
            return key
        return f"name:{node.id if isinstance(node, ast.Name) else node.attr}"

    def lineage(self, identity: str, seen: frozenset[str] = frozenset()) -> frozenset[str]:
        """``identity`` and every class it derives from, as identities and as names: a
        class of the tree through its resolvable bases, a built-in exception
        through its own order of bases."""
        if identity in self._lineage:
            return self._lineage[identity]
        out: set[str] = {identity}
        if identity in self.classes:
            info = self.classes[identity]
            out.add(f"name:{info.node.name}")
            for base in info.node.bases:
                found = self.class_identity(info.module, base)
                if found and found not in seen:
                    out |= self.lineage(found, seen | {identity})
        else:
            builtin = getattr(builtins, identity.removeprefix("name:"), None)
            if isinstance(builtin, type) and issubclass(builtin, BaseException):
                out |= {f"name:{c.__name__}" for c in builtin.__mro__ if c is not object}
        if not seen:
            self._lineage[identity] = frozenset(out)
        return frozenset(out)

    def _reads(self, node: ast.AST, name: str) -> bool:
        return any(isinstance(s, ast.Name) and s.id == name for s in ast.walk(node))

    def sent_exceptions(self, served: Iterable[str]) -> frozenset[str]:
        """The exception classes whose message a route sends as a response body.

        ``HTTPException`` (any class of that name, and what derives from it);
        a class the application registers an exception handler for
        (``add_exception_handler`` or ``@app.exception_handler``) whose handler
        reads the exception it is given; and, to a fixed point, a class a
        function in ``served`` (what a route handler reaches) catches as
        ``except E as exc`` and answers by raising one of these with ``exc``
        read in its arguments.
        """
        sent = {"name:HTTPException"}
        for module, cls, handler in self.handlers:
            identity = self.class_identity(module, cls)
            key = self._base_key(module, handler)
            if identity is None or key not in self.functions:
                continue
            args = self.functions[key].node.args
            given = [*args.posonlyargs, *args.args]
            if len(given) >= 2 and self._reads(self.functions[key].node, given[1].arg):
                sent.add(identity)
        catchers = sorted(served)
        while True:
            before = len(sent)
            for key in catchers:
                module = self.functions[key].module
                for node in self.own(key):
                    if not (isinstance(node, ast.ExceptHandler) and node.name and node.type):
                        continue
                    answered = any(
                        isinstance(sub, ast.Raise)
                        and sub.exc is not None
                        and self.sent(module, sub, sent)
                        and self._reads(sub.exc, node.name)
                        for statement in node.body
                        for sub in ast.walk(statement)
                    )
                    if answered:
                        types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
                        sent |= {i for t in types if (i := self.class_identity(module, t))}
            if len(sent) == before:
                return frozenset(sent)

    def sent(self, module: str, raised: ast.Raise, sent: Iterable[str]) -> bool:
        """Whether the class ``raised`` raises derives from one in ``sent``."""
        identity = self.class_identity(module, raised.exc)
        return identity is not None and bool(self.lineage(identity) & set(sent))

    def sent_raise(self, key: str, node: ast.AST, sent: frozenset[str]) -> bool:
        """Whether the literal ``node`` of function ``key`` is a message a route sends: it
        stands in a raise of a class in ``sent``, or is bound to a name whose strongest
        use is a raise (:class:`Uses`) and one such raise is of a class in ``sent``."""
        function = self.functions[key]
        raised = self.raise_of.get(id(node))
        if raised is not None:
            return self.sent(function.module, raised, sent)
        return any(self.sent(function.module, r, sent) for r in function.raises.get(id(node), ()))


@dataclass(frozen=True)
class Placed:
    """One wordy literal and the class of the partition it falls in."""

    path: str
    line: int
    col: int
    module: str
    # The function, constant or ``<module>``/``<class body>`` code it stands in.
    holder: str
    cls: str
    kind: str
    text: str
    # A ``raise`` message a route sends as a response body (:meth:`Tree.sent_raise`),
    # raised in a function a route handler reaches.
    route_served: bool = False

    def row(self) -> str:
        shown = self.text if len(self.text) <= 72 else self.text[:69] + "..."
        return (
            f"{self.cls}  {self.path}:{self.line}:{self.col}  {self.holder}  {self.kind}  {shown!r}"
        )


@dataclass
class Partition:
    """Every wordy literal of the tree, each in one class (module docstring)."""

    total: int
    literals: list[Placed]
    # A wordy literal the rule reads in no class: an error, never a silent gap.
    unassigned: list[Placed]
    # The modules an entry point reaches (class d stands in them, e outside).
    modules_reached: frozenset[str] = frozenset()

    def counts(self) -> dict[str, int]:
        found = Counter(p.cls for p in self.literals)
        return {cls: found[cls] for cls in PARTITION_CLASSES}

    def of(self, cls: str) -> list[Placed]:
        return [p for p in self.literals if p.cls == cls]

    def per_kind(self, cls: str) -> dict[str, int]:
        return dict(sorted(Counter(p.kind for p in self.of(cls)).items()))

    def per_module(self, cls: str) -> dict[str, int]:
        return dict(sorted(Counter(p.module for p in self.of(cls)).items()))

    def per_package(self, cls: str) -> dict[str, int]:
        return dict(sorted(Counter(_package(p.module + ":") for p in self.of(cls)).items()))

    def route_served(self) -> list[Placed]:
        return [p for p in self.of("g") if p.route_served]


@dataclass
class Listing:
    """The rule's list over one tree."""

    tree: Tree
    functions: dict[str, list[str]]
    constants: dict[str, list[str]]
    # Functions that hand out wording no entry point reaches (their literals
    # fall in class d or e).
    unreachable: list[str]
    # Class c by key: reached functions with a wordy literal the rule cannot
    # place, and wordy constants reached functions name but none hands out.
    not_placed: list[str] = field(default_factory=list)
    not_placed_constants: list[str] = field(default_factory=list)
    # Class h by key: wordy constants reached functions only compare a value with.
    compared_constants: list[str] = field(default_factory=list)
    # Of them, each one a function no entry point reaches hands out, passes or
    # stores, with those functions: it may not say "compared, never printed".
    compared_handed_out: dict[str, list[str]] = field(default_factory=dict)
    partition: Partition = field(default_factory=lambda: Partition(0, [], []))

    def needs_entry(self) -> dict[str, str]:
        """Every function and constant of classes a, b and c and every constant of class
        h, with its kind."""
        out = dict.fromkeys(sorted({*self.functions, *self.not_placed}), "function")
        constants = {*self.constants, *self.not_placed_constants, *self.compared_constants}
        out.update(dict.fromkeys(sorted(constants), "constant"))
        return out

    def entry_class(self, key: str) -> str:
        """The class whose entry ``key`` needs: ``a`` for a function that hands out
        wording (a traced one among them), ``b`` for a constant handed out, ``c``
        for one the rule cannot place, ``h`` for a compared constant."""
        if key in self.constants:
            return "b"
        if key in self.not_placed_constants or (
            key in self.not_placed and key not in self.functions
        ):
            return "c"
        if key in self.compared_constants:
            return "h"
        return "a"

    def texts(self, key: str) -> list[str]:
        """What a function's or a constant's digest covers (:func:`text_digest`)."""
        if key in self.tree.functions:
            return self.tree.functions[key].texts
        return self.tree.constants[key].texts

    def per_package(self) -> dict[str, tuple[int, int]]:
        """The listed functions and constants per package (the first under each root)."""
        per: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for key in self.functions:
            per[_package(key)][0] += 1
        for key in self.constants:
            per[_package(key)][1] += 1
        return {package: (f, c) for package, (f, c) in sorted(per.items())}

    def as_json(self) -> dict[str, Any]:
        tree = self.tree
        partition = self.partition
        return {
            "rule": {
                "min_words": tree.min_words,
                "entry_points": {g: list(k) for g, k in sorted(ENTRY_POINTS.items())},
                "route_entries": {g: list(m) for g, m in sorted(ROUTE_ENTRIES.items())},
            },
            "functions": [
                {
                    "function": key,
                    "path": tree.functions[key].path,
                    "line": tree.functions[key].line,
                    "text_digest": text_digest(tree.functions[key].texts),
                    "groups": groups,
                }
                for key, groups in sorted(self.functions.items())
            ],
            "constants": [
                {
                    "constant": key,
                    "path": tree.constants[key].path,
                    "line": tree.constants[key].line,
                    "text_digest": text_digest(tree.constants[key].texts),
                    "handed_out_by": handers,
                }
                for key, handers in sorted(self.constants.items())
            ],
            "per_package": {
                package: {"functions": f, "constants": c}
                for package, (f, c) in self.per_package().items()
            },
            "unreachable_wordy_functions": {
                "count": len(self.unreachable),
                "per_package": dict(sorted(Counter(_package(k) for k in self.unreachable).items())),
            },
            "wordy_not_placed": {
                "count": len(self.not_placed),
                "functions": list(self.not_placed),
                "constants": list(self.not_placed_constants),
                "text_digests": {
                    key: text_digest(self.texts(key))
                    for key in sorted({*self.not_placed, *self.not_placed_constants})
                },
            },
            "compared_constants": {
                key: text_digest(self.texts(key)) for key in self.compared_constants
            },
            "compared_constants_handed_out": dict(sorted(self.compared_handed_out.items())),
            "partition": {
                "total": partition.total,
                "classes": partition.counts(),
                "unassigned": [p.row() for p in partition.unassigned],
                "d_per_module": partition.per_module("d"),
                "e_per_package": partition.per_package("e"),
                "f_per_kind": partition.per_kind("f"),
                "h_per_kind": partition.per_kind("h"),
                "g_per_kind": partition.per_kind("g"),
                "g_route_served": [p.row() for p in partition.route_served()],
            },
        }

    def table(self) -> str:
        per: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for key in self.functions:
            per[_module(key)][0] += 1
        for key in self.constants:
            per[_module(key)][1] += 1
        packages = self.per_package()
        width = max([len("module"), *(len(m) for m in per), *(len(p) for p in packages)])
        lines = [f"{'module':<{width}}  functions  constants"]
        for module, (functions, constants) in sorted(per.items()):
            lines.append(f"{module:<{width}}  {functions:>9}  {constants:>9}")
        lines.append(f"{'package':<{width}}  functions  constants")
        for package, (functions, constants) in packages.items():
            lines.append(f"{package:<{width}}  {functions:>9}  {constants:>9}")
        lines.append(f"{'total':<{width}}  {len(self.functions):>9}  {len(self.constants):>9}")
        lines += partition_lines(self)
        lines += [
            f"class d in {module}: {n}" for module, n in self.partition.per_module("d").items()
        ]
        lines += [
            f"class e in {package}: {n}" for package, n in self.partition.per_package("e").items()
        ]
        lines += limit_lines(self)
        lines += [f"wordy, not placed: {key}" for key in self.not_placed]
        lines += [f"wordy, not placed (constant): {key}" for key in self.not_placed_constants]
        for key in self.compared_constants:
            handers = self.compared_handed_out.get(key)
            lines.append(
                f"compared in a reached function (constant): {key}"
                + (
                    f"; handed out by a function no entry point reaches: {', '.join(handers)}"
                    if handers
                    else ""
                )
            )
        lines += [f"raised, route-served: {p.row()}" for p in self.partition.route_served()]
        return "\n".join(lines)


def _module(key: str) -> str:
    return key.split(":", 1)[0]


def _package(key: str) -> str:
    return ".".join(_module(key).split(".")[:2])


def partition_lines(listing: Listing) -> list[str]:
    """The partition's total and each class's count, printed on every run."""
    partition = listing.partition
    counts = partition.counts()
    a_functions = {p.holder for p in partition.of("a")}
    b_constants = {p.holder for p in partition.of("b")}
    return [
        f"partition: {partition.total} wordy literal(s) = "
        + " + ".join(f"{cls} {counts[cls]}" for cls in PARTITION_CLASSES)
        + (f" + in no class {len(partition.unassigned)}" if partition.unassigned else ""),
        f"class a: {counts['a']} wordy literal(s) handed out by {len(a_functions)} listed "
        "function(s) an entry point reaches; each function needs an entry",
        f"class b: {counts['b']} wordy literal(s) in {len(b_constants)} constant(s) a reached "
        "function hands out, also through a name bound to a value naming it; each needs an entry",
        f"class c: {counts['c']} wordy literal(s) in {len(listing.not_placed)} reached "
        f"function(s) and {len(listing.not_placed_constants)} constant(s) the rule cannot place "
        "as handed out (a constant a reached function names, a field of a class it names); "
        "named below, each needs an entry",
        f"class h: {counts['h']} wordy literal(s) compared in a reached function: an operand "
        "of a comparison or a membership test, or in one of "
        f"{len(listing.compared_constants)} constant(s) the reached functions use only in "
        "comparisons, each constant named below and needing an entry (the value it lets "
        f"through may be printed); {len(listing.compared_handed_out)} of these constants a "
        "function no entry point reaches hands out, passes or stores, named beside each, and "
        "their entries may not say compared, never printed; an operand written in the function "
        "is counted and named with --class h and needs no entry, also where the value it lets "
        "through is printed",
        *(
            f"class {cls}: {counts[cls]} wordy literal(s), a stated limit (limit lines below)"
            for cls in ("d", "e", "f", "g")
        ),
    ]


def limit_lines(listing: Listing) -> list[str]:
    """What the list does not hold (classes d to g, and text no literal holds), counted on
    every run."""
    partition = listing.partition
    counts = partition.counts()
    kinds = ", ".join(f"{kind} {n}" for kind, n in partition.per_kind("f").items()) or "none"
    served = len(partition.route_served())
    writers = sum(1 for k in listing.unreachable if _module(k) in partition.modules_reached)
    return [
        f"limit: class d, {counts['d']} wordy literal(s) in {len(partition.per_module('d'))} "
        "module(s) an entry point reaches, standing in a function no entry point reaches, or in "
        "a constant or other module or class code no reached function hands out or names "
        "outside a position that publishes nothing; not listed, named per module with "
        f"--class d. {writers} function(s) among them hand out wording: build-time writers "
        "whose text the report stores, writers whose text another surface or a model receives, "
        "and functions reached only through an instance attribute's type, a return value, a "
        "property or a context variable, which a trace finds when a served stored run runs "
        "them; field defaults of a class reached only that way stand here too",
        f"limit: class e, {counts['e']} wordy literal(s) in module(s) no entry point reaches, "
        f"counted per package ({len(partition.per_package('e'))} package(s)); "
        f"{len(listing.unreachable) - writers} function(s) among them hand out wording",
        f"limit: class f, {counts['f']} wordy literal(s) never published by their position, "
        f"counted per kind: {kinds}",
        f"limit: class g, {counts['g']} raise message(s), not listed; {served} of them a route "
        "sends as a response body, named with --class g: raised in a function a route handler "
        "reaches, of an HTTPException, of a class whose registered exception handler reads the "
        "exception, or of a class a reached function catches and answers with such a raise "
        "that reads it. The others, a raise FastAPI answers with a bare 500 among them, are "
        "counted. A catch counts for every reached raise of its class, inside its try or not. "
        "Not seen: a body built by middleware, a catch that reads the message through another "
        "name, an exception object held in a name and raised later, and a raise reached only "
        "through a call the static graph does not follow. A literal inside a raise's "
        "expression is counted here even where a call in that expression stores or hands "
        "it out (raise E(note(sink, text)))",
        "limit: wording built at run time from no literal (read from data, a file or a model), "
        "and the web console's own text, are outside a reading of the Python source",
        "limit: besides text written at build time into the stored report, classes d and e are "
        "known to hold text other surfaces give a reader that no entry point names: the job "
        "package download, the lines the command line prints, the sentences of the job event "
        "feed, and job error messages written outside the worker's entry points",
    ]


def class_rows(listing: Listing, cls: str) -> list[str]:
    """Each wordy literal of class ``cls``, one row each, sorted by place."""
    return [p.row() for p in listing.partition.of(cls)]


def partition_errors(listing: Listing) -> list[str]:
    """The literals the rule reads in no class: each is an error."""
    return [f"in no class: {p.row()}" for p in listing.partition.unassigned]


def partition_status(listing: Listing) -> int:
    """2 when a wordy literal falls in no class, or the classes miss the total; else 0."""
    partition = listing.partition
    if partition.unassigned or sum(partition.counts().values()) != partition.total:
        return 2
    return 0


def entry_points(
    tree: Tree,
    fixed: Mapping[str, Sequence[str]] = ENTRY_POINTS,
    routes: Mapping[str, Sequence[str]] = ROUTE_ENTRIES,
) -> dict[str, list[str]]:
    """Each entry group's functions; ``LookupError`` naming any that does not exist."""
    out: dict[str, list[str]] = {group: list(keys) for group, keys in fixed.items()}
    for group, modules in routes.items():
        for module in modules:
            handlers = tree.route_handlers(module)
            if not handlers:
                raise LookupError(f"no GET route in {module}")
            out.setdefault(group, []).extend(handlers)
    absent = sorted(k for keys in out.values() for k in keys if k not in tree.functions)
    if absent:
        raise LookupError("entry point(s) not found: " + ", ".join(absent))
    return out


def reach(tree: Tree, entries: Mapping[str, Sequence[str]]) -> dict[str, list[str]]:
    """Every function reached from ``entries``, with the groups that reach it."""
    reached: dict[str, set[str]] = defaultdict(set)
    for group, keys in entries.items():
        seen: set[str] = set()
        stack = list(keys)
        while stack:
            key = stack.pop()
            if key in seen:
                continue
            seen.add(key)
            stack.extend(k for k in tree.edges(key) if k not in seen)
        for key in seen:
            reached[key].add(group)
    return {key: sorted(groups) for key, groups in reached.items()}


def compute(
    tree: Tree,
    entries: Mapping[str, Sequence[str]] | None = None,
    routes: Iterable[str] | None = None,
) -> Listing:
    """The rule's list: reached, with publishing text; the constants handed out; and the
    partition of every wordy literal. ``routes`` names the entry groups whose
    functions are route handlers (by default those of :data:`ROUTE_ENTRIES`)."""
    groups = entries if entries is not None else entry_points(tree)
    reached = reach(tree, groups)
    functions = {key: found for key, found in reached.items() if tree.functions[key].hands_out}
    handed_by: dict[str, set[str]] = defaultdict(set)
    named_by: dict[str, set[str]] = defaultdict(set)
    compared_by: dict[str, set[str]] = defaultdict(set)
    for key in sorted(reached):
        names, handed, compared = tree.named_constants(key)
        for held in handed:
            for constant in tree.wordy_of(held):
                handed_by[constant].add(key)
        for held in names - handed:
            for constant in tree.wordy_of(held):
                named_by[constant].add(key)
        for held in compared:
            for constant in tree.wordy_of(held):
                compared_by[constant].add(key)
        # A class named is a class whose fields its instances carry.
        for cls in tree.named_classes(key):
            for held in tree.fields(cls):
                for constant in tree.wordy_of(held):
                    named_by[constant].add(key)
    constants = {key: sorted(handers) for key, handers in sorted(handed_by.items())}
    not_placed_constants = sorted(set(named_by) - set(constants))
    compared_constants = sorted(set(compared_by) - set(constants) - set(named_by))
    compared_handed_out = _handed_out_elsewhere(tree, set(compared_constants), set(reached))
    unreachable = sorted(
        key for key, function in tree.functions.items() if function.hands_out and key not in reached
    )
    not_placed = sorted(key for key in reached if "unplaced" in tree.functions[key].placed.values())
    served_groups = set(ROUTE_ENTRIES) if routes is None else set(routes)
    served = reach(tree, {g: list(k) for g, k in groups.items() if g in served_groups})
    listing = Listing(
        tree,
        dict(sorted(functions.items())),
        constants,
        unreachable,
        not_placed,
        not_placed_constants,
        compared_constants,
        compared_handed_out,
    )
    listing.partition = _partition(
        tree,
        set(reached),
        set(constants),
        set(named_by),
        set(served),
        tree.sent_exceptions(served),
        set(compared_constants),
    )
    return listing


def _handed_out_elsewhere(
    tree: Tree, constants: set[str], reached: set[str]
) -> dict[str, list[str]]:
    """Each of ``constants`` a function outside ``reached`` hands out, passes, stores or
    otherwise reads where the rule cannot place it, with those functions."""
    out: dict[str, set[str]] = defaultdict(set)
    if not constants:
        return {}
    for key in sorted(tree.functions):
        if key in reached:
            continue
        resolved = [
            (target, node)
            for kind, target, node in tree.resolved(key)
            if kind == "constant" and tree.wordy_of(target) & constants
        ]
        if not resolved:
            continue
        uses = tree.uses(key)
        nodes = {id(n): n for n in tree.own(key)}
        for target, node in resolved:
            if (uses.kind(nodes[node]) if node in nodes else "unplaced") in ("handed", "unplaced"):
                for constant in tree.wordy_of(target) & constants:
                    out[constant].add(key)
    return {constant: sorted(keys) for constant, keys in sorted(out.items())}


def _containers(tree: Tree, module: str) -> list[tuple[ast.AST, str, tuple[str, ...]]]:
    """Each wordy literal of ``module`` with where it stands: in a function's own code,
    a class statement inside it among it (``function``), in a def shadowed by
    another of the same qualified name (``shadowed``), in a constant's assignment
    (``constant``), or in other class body (``class``) or module (``module``)
    code."""
    canonical = tree.canonical[module]
    out: list[tuple[ast.AST, str, tuple[str, ...]]] = []
    stack: list[tuple[ast.AST, str, tuple[str, ...]]] = [
        (node, "module", (f"{module}:<module>",)) for node in tree.modules[module].body
    ]
    while stack:
        node, kind, keys = stack.pop()
        if isinstance(node, _FUNC):
            key = tree.def_keys.get(id(node))
            if key is not None and tree.functions[key].node is node:
                kind, keys = "function", (key,)
            else:
                kind, keys = "shadowed", (key or f"{module}:<unindexed def>",)
        elif isinstance(node, ast.ClassDef) and kind not in ("function", "shadowed"):
            key = tree.class_keys.get(id(node), f"{module}:<unindexed class>")
            kind, keys = "class", (f"{key} <class body>",)
        elif id(node) in tree.constant_stmts and kind in ("class", "module"):
            kind, keys = "constant", tuple(tree.constant_stmts[id(node)])
        if id(node) in canonical:
            out.append((node, kind, keys))
        stack.extend((child, kind, keys) for child in ast.iter_child_nodes(node))
    return out


def _partition(
    tree: Tree,
    reached: set[str],
    handed: set[str],
    named: set[str],
    served: set[str],
    sent: frozenset[str] = frozenset(),
    compared: set[str] | frozenset[str] = frozenset(),
) -> Partition:
    """Every wordy literal of the tree in its class (module docstring); a raise
    message is named route-served where :meth:`Tree.sent_raise` finds a route sends it."""
    reached_modules = {_module(k) for k in reached | handed | named | compared}
    literals: list[Placed] = []
    unassigned: list[Placed] = []
    total = 0
    for module in sorted(tree.modules):
        where = tree.positions[module]
        total += len(tree.canonical[module])
        near = "d" if module in reached_modules else "e"
        for node, kind, keys in _containers(tree, module):
            holder = keys[0]
            position = where.get(id(node))
            cls: str | None
            route_served = False
            if position == "raise":
                cls, detail = "g", "raise"
                route_served = (
                    kind == "function" and holder in served and tree.sent_raise(holder, node, sent)
                )
            elif position is not None:
                cls, detail = "f", position
            elif kind == "function":
                placed = tree.functions[holder].placed.get(id(node))
                is_reached = holder in reached
                if placed is None:
                    cls, detail = None, "not read in its function's own code"
                elif placed == "raise":
                    cls, detail = "g", "held in a name, then raised"
                    route_served = holder in served and tree.sent_raise(holder, node, sent)
                elif placed in ("held", "unread"):
                    cls, detail = "f", placed
                elif placed == "compared":
                    cls, detail = (
                        ("h", "compared in a reached function")
                        if is_reached
                        else (near, "function")
                    )
                elif placed == "handed":
                    cls, detail = ("a", "handed out") if is_reached else (near, "function")
                else:
                    cls, detail = ("c", "not placed") if is_reached else (near, "function")
            elif kind == "shadowed":
                cls, detail = (
                    ("c", "def shadowed by one of the same name")
                    if holder in reached
                    else (near, "def shadowed by one of the same name")
                )
            elif kind == "constant":
                in_b = [k for k in keys if k in handed]
                in_c = [k for k in keys if k in named]
                in_h = [k for k in keys if k in compared]
                if in_b:
                    holder, cls, detail = in_b[0], "b", "constant handed out"
                elif in_c:
                    holder, cls, detail = in_c[0], "c", "constant named"
                elif in_h:
                    holder, cls, detail = in_h[0], "h", "constant compared"
                else:
                    cls, detail = near, "constant"
            else:
                cls, detail = near, "class body" if kind == "class" else "module code"
            placed_literal = Placed(
                tree.rel(module),
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0),
                module,
                holder,
                cls or "",
                detail,
                literal_text(node) or "",
                route_served,
            )
            (literals if cls else unassigned).append(placed_literal)
    return Partition(
        total,
        sorted(literals, key=_place_order),
        sorted(unassigned, key=_place_order),
        frozenset(reached_modules),
    )


def _place_order(placed: Placed) -> tuple[str, int, int, str]:
    return (placed.path, placed.line, placed.col, placed.holder)


# ---------------------------------------------------------------------------
# The record and its check
# ---------------------------------------------------------------------------


def _valid(value: Any, schema: Mapping[str, Any], where: str) -> list[str]:
    """What in ``value`` the schema refuses (the subset of JSON Schema it is written in)."""
    errors: list[str] = []
    kinds = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
    }
    expected = schema.get("type")
    if expected and not isinstance(value, kinds[expected]):
        return [f"{where}: not a {expected}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: not one of {', '.join(map(str, schema['enum']))}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{where}: shorter than {schema['minLength']}")
        if len(value) > schema.get("maxLength", len(value)):
            errors.append(f"{where}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{where}: does not match {schema['pattern']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{where}: fewer than {schema['minItems']} item(s)")
        for index, item in enumerate(value):
            errors += _valid(item, schema.get("items", {}), f"{where}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{where}: {name} is required")
        if schema.get("additionalProperties") is False:
            errors += [
                f"{where}: {name} is not allowed" for name in value if name not in properties
            ]
        for name, sub in properties.items():
            if name in value:
                errors += _valid(value[name], sub, f"{where}.{name}")
    if "oneOf" in schema:
        passing = sum(1 for option in schema["oneOf"] if not _valid(value, option, where))
        if passing != 1:
            errors.append(f"{where}: must match exactly one of {len(schema['oneOf'])} forms")
    return errors


@dataclass
class Record:
    complete: bool
    entries: list[dict[str, Any]]
    reports: list[dict[str, str]]
    traced: list[str] = field(default_factory=list)


def read_record(records: Path) -> Record:
    """The entries of every module file under ``records``, and what the schema refused."""
    schema = json.loads((records / SCHEMA_FILE).read_text(encoding="utf-8"))
    status = json.loads((records / STATUS_FILE).read_text(encoding="utf-8"))
    if not isinstance(status, dict) or not isinstance(status.get("complete"), bool):
        raise ValueError(f"{STATUS_FILE}: complete must be true or false")
    entries: list[dict[str, Any]] = []
    reports: list[dict[str, str]] = []
    for path in sorted(records.glob("*.json")):
        if path.name in (SCHEMA_FILE, STATUS_FILE, TRACED_FILE):
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        errors = _valid(document, schema, path.name)
        if errors:
            reports += [{"kind": "invalid", "item": path.name, "detail": e} for e in errors]
            continue
        module = path.name.removesuffix(".json")
        for entry in document["entries"]:
            key = entry.get("function") or entry.get("constant")
            if _module(key) != module:
                reports.append(
                    {
                        "kind": "invalid",
                        "item": key,
                        "detail": f"its module's file is not {path.name}",
                    }
                )
                continue
            entries.append(entry)
    traced: list[str] = []
    try:
        traced = read_traced(records)
    except ValueError as exc:
        reports.append({"kind": "invalid", "item": TRACED_FILE, "detail": str(exc)})
    return Record(status["complete"], entries, reports, traced)


def _collected_file(repo: Path, relative: str) -> Path | None:
    """The file ``relative`` names when the test runner would collect it: under
    ``tests/`` once resolved, no ``..``, named ``test_*.py`` or ``*_test.py``."""
    parts = Path(relative).parts
    if ".." in parts or parts[:1] != ("tests",):
        return None
    tests = (repo / "tests").resolve()
    path = (repo / relative).resolve()
    if tests not in path.parents or not path.is_file():
        return None
    if not (path.name.startswith("test_") or path.name.endswith("_test.py")):
        return None
    return path


def _last_binding(body: Sequence[ast.stmt], name: str) -> ast.AST | None:
    """The statement of ``body`` that binds ``name`` last: a def, a class, an
    assignment, an import or a ``del`` (the runner sees only what that leaves)."""
    found: ast.AST | None = None
    for node in body:
        if isinstance(node, (*_FUNC, ast.ClassDef)) and node.name == name:
            found = node
        elif isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if name in _target_names(targets):
                found = node
        elif isinstance(node, ast.Import | ast.ImportFrom):
            if any((a.asname or a.name.split(".")[0]) == name for a in node.names):
                found = node
        elif isinstance(node, ast.Delete) and name in _target_names(node.targets):
            found = node
    return found


def _bound_in_a_branch(body: Sequence[ast.stmt], name: str) -> bool:
    """Whether a branch, a loop, a ``try``, a ``with`` or a ``match`` of ``body`` binds
    or deletes ``name``: whether it holds then is known only by running it."""
    for node in body:
        for block in _blocks(node):
            if _last_binding(block, name) is not None or _bound_in_a_branch(block, name):
                return True
    return False


def _fixture_names(body: Sequence[ast.stmt]) -> tuple[set[str], set[str]]:
    """(names bound to pytest's fixture decorator, by an import or an assignment;
    names the file cannot show are no fixture: bound by a module assignment to
    anything else, or imported from a module outside pytest and the standard
    library, either of which a decorator may be)."""
    fixtures: set[str] = set()
    other: set[str] = set()
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module in ("pytest", "_pytest.fixtures"):
            fixtures |= {
                a.asname or a.name for a in node.names if a.name in ("fixture", "yield_fixture")
            }
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if node.level or top not in sys.stdlib_module_names:
                other |= {a.asname or a.name for a in node.names}
        elif isinstance(node, ast.Assign):
            names = _target_names(node.targets)
            if _is_fixture(node.value):
                fixtures |= names
            else:
                other |= names
    return fixtures, other - fixtures


def _is_fixture(decorator: ast.expr, aliases: Iterable[str] = ()) -> bool:
    func = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name in ("fixture", "yield_fixture") or (
        isinstance(func, ast.Name) and func.id in set(aliases)
    )


def _test_flag(body: Sequence[ast.stmt]) -> str:
    """What ``__test__`` bound last in ``body`` says: "yes", "no" (a false constant)
    or "unverified" (any other value, or bound in a branch)."""
    if _bound_in_a_branch(body, "__test__"):
        return "unverified"
    found = _last_binding(body, "__test__")
    if found is None:
        return "yes"
    if isinstance(found, ast.Assign) and isinstance(found.value, ast.Constant):
        return "yes" if found.value.value else "no"
    return "unverified"


def _is_parametrize(decorator: ast.expr) -> bool:
    func = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(func, ast.Attribute) and func.attr == "parametrize"


def _scalar_id(node: ast.expr) -> str | None:
    """The id the runner gives a literal parameter value, where it can be read here."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _scalar_id(node.operand)
        return f"-{inner}" if inner is not None and isinstance(node.operand, ast.Constant) else None
    if not isinstance(node, ast.Constant):
        return None
    value = node.value
    if isinstance(value, str):
        return value if value and value.isascii() and value.isprintable() else None
    if value is None or isinstance(value, bool | int | float | complex):
        return str(value)
    return None


def parameter_ids(decorators: Sequence[ast.expr]) -> list[str] | None:
    """The parameter ids of a test with one ``parametrize`` of literal values, as the
    runner names them; ``None`` where they cannot be read without running it."""
    marks = [d for d in decorators if _is_parametrize(d)]
    if len(marks) != 1 or not isinstance(marks[0], ast.Call):
        return None
    call = marks[0]
    keywords = {k.arg: k.value for k in call.keywords if k.arg}
    names_node = call.args[0] if call.args else keywords.get("argnames")
    values_node = call.args[1] if len(call.args) > 1 else keywords.get("argvalues")
    if isinstance(names_node, ast.Constant) and isinstance(names_node.value, str):
        names = [n.strip() for n in names_node.value.split(",") if n.strip()]
    elif isinstance(names_node, ast.Tuple | ast.List) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in names_node.elts
    ):
        names = [str(e.value) for e in names_node.elts if isinstance(e, ast.Constant)]
    else:
        return None
    if not names or not isinstance(values_node, ast.Tuple | ast.List):
        return None
    given: list[ast.expr] | None = None
    if "ids" in keywords:
        ids_node = keywords["ids"]
        if not isinstance(ids_node, ast.Tuple | ast.List):
            return None
        given = list(ids_node.elts)
        if len(given) != len(values_node.elts):
            return None
    out: list[str] = []
    for index, item in enumerate(values_node.elts):
        explicit: str | None = None
        chosen = given[index] if given is not None else None
        if chosen is not None and not (isinstance(chosen, ast.Constant) and chosen.value is None):
            explicit = _scalar_id(chosen)
            if explicit is None:
                return None
        values: list[ast.expr]
        if (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Attribute | ast.Name)
            and (getattr(item.func, "attr", None) or getattr(item.func, "id", None)) == "param"
        ):
            values = list(item.args)
            for keyword in item.keywords:
                if keyword.arg == "id":
                    explicit = _scalar_id(keyword.value)
                    if explicit is None:
                        return None
        elif len(names) > 1:
            if not isinstance(item, ast.Tuple | ast.List):
                return None
            values = list(item.elts)
        else:
            values = [item]
        if explicit is not None:
            out.append(explicit)
            continue
        if len(values) != len(names):
            return None
        parts = []
        for name, value in zip(names, values, strict=True):
            part = _scalar_id(value)
            if part is None and isinstance(value, ast.List | ast.Dict | ast.Set | ast.Tuple):
                part = f"{name}{index}"
            if part is None:
                return None
            parts.append(part)
        out.append("-".join(parts))
    return out if len(out) == len(set(out)) else None


def test_verdict(repo: Path, node_id: str | Sequence[str]) -> str:
    """Whether ``node_id`` (or each of a list) names a test the runner would collect:
    "yes", "no", or "unverified" where reading the file cannot decide it.

    Read without running it: a file under ``tests/`` the runner collects, a
    test function or method: a def whose name starts with ``test``, the last
    binding of its name in its scope (a ``del`` or a later assignment leaves
    none), with no fixture decorator, also under an alias an import or an
    assignment gives it (in a class whose name starts with ``Test`` and has no
    ``__init__``), and no false ``__test__`` in its module or class; and a
    parameter id only where the test has one ``parametrize`` of literal values
    that holds it; any other parametrised test must be named bare. Unverified:
    the name bound or deleted in a branch, a ``try`` or a loop of its scope, a
    test name imported into the file, a ``__test__`` that is no constant or is
    bound in one, and a decorator that is a name a module assignment binds to
    anything but the fixture decorator or that is imported from a module outside
    pytest and the standard library.
    """
    if not isinstance(node_id, str):
        verdicts = [test_verdict(repo, one) for one in node_id]
        if not verdicts or "no" in verdicts:
            return "no"
        return "unverified" if "unverified" in verdicts else "yes"
    match = _TEST_ID.match(node_id)
    if not match:
        return "no"
    path = _collected_file(repo, match.group(1))
    if path is None:
        return "no"
    body = ast.parse(path.read_text(encoding="utf-8")).body
    first, second, parameter = match.group(2), match.group(3), match.group(4)
    found: ast.AST | None = None
    owner: ast.ClassDef | None = None
    flags = [_test_flag(body)]
    branched = _bound_in_a_branch(body, first)
    if second is None:
        found = _last_binding(body, first)
    else:
        holder = _last_binding(body, first)
        if isinstance(holder, ast.ClassDef):
            owner = holder
            if any(isinstance(n, _FUNC) and n.name == "__init__" for n in holder.body):
                return "no"
            found = _last_binding(holder.body, second)
            flags.append(_test_flag(holder.body))
            branched = branched or _bound_in_a_branch(holder.body, second)
    if isinstance(found, ast.ImportFrom | ast.Import) and second is None:
        # A test function imported from elsewhere: whether it is one, and no
        # fixture, is in a file this reading does not open.
        return "unverified"
    if not isinstance(found, _FUNC) or not found.name.startswith("test"):
        return "unverified" if branched else "no"
    fixtures, assigned = _fixture_names(body)
    if any(_is_fixture(d, fixtures) for d in found.decorator_list):
        return "no"
    if owner is not None and not owner.name.startswith("Test"):
        return "no"
    if "no" in flags:
        return "no"
    if parameter is not None:
        if owner is not None and (
            any(_is_parametrize(d) for d in owner.decorator_list)
            or any(
                isinstance(n, ast.Assign) and _target_names(n.targets) & {"pytestmark"}
                for n in owner.body
            )
        ):
            return "no"
        ids = parameter_ids(found.decorator_list)
        if ids is None or parameter not in ids:
            return "no"
    undecided = branched or "unverified" in flags
    undecided = undecided or any(
        isinstance(func := (d.func if isinstance(d, ast.Call) else d), ast.Name)
        and func.id in assigned
        for d in found.decorator_list
    )
    return "unverified" if undecided else "yes"


def test_exists(repo: Path, node_id: str | Sequence[str]) -> bool:
    """Whether :func:`test_verdict` finds ``node_id`` names a collected test."""
    return test_verdict(repo, node_id) == "yes"


def read_trace(path: Path) -> list[str]:
    """The functions a trace output saw hand out text while serving, not in the static list."""
    document = json.loads(path.read_text(encoding="utf-8"))
    return sorted(document["summary"]["serve"]["traced_only"])


def read_traced(records: Path) -> list[str]:
    """The keys of the traced record: functions a trace saw hand out text while a
    stored run was served that the static list misses. ``ValueError`` when it
    holds anything but sorted, distinct ``module:qualname`` keys."""
    path = records / TRACED_FILE
    if not path.is_file():
        return []
    keys = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(keys, list)
        or not all(isinstance(k, str) and _KEY.match(k) for k in keys)
        or keys != sorted(set(keys))
    ):
        raise ValueError(f"{TRACED_FILE}: only a sorted list of distinct module:qualname keys")
    return keys


def write_traced(records: Path, keys: Iterable[object], tree: Tree) -> Path:
    """Write the traced record: ``module:qualname`` keys of functions that hand out
    wording, sorted, and nothing else. Anything else is refused, unwritten."""
    chosen = list(keys)
    for key in chosen:
        if not isinstance(key, str) or not _KEY.match(key):
            raise ValueError(f"not a module:qualname key: {key!r}")
        if key not in tree.functions or not tree.functions[key].hands_out:
            raise ValueError(f"not a function that hands out wording: {key}")
    path = records / TRACED_FILE
    path.write_text(json.dumps(sorted(set(chosen)), indent=1) + "\n", encoding="utf-8")
    return path


def check(
    listing: Listing, record: Record, repo: Path = ROOT, traced: Iterable[str] = ()
) -> list[dict[str, str]]:
    """Every gap between the list and the record, sorted by kind and item."""
    tree = listing.tree
    reports = list(record.reports)
    must = listing.needs_entry()
    for key in record.traced:
        if key not in tree.functions or not tree.functions[key].hands_out:
            reports.append(
                {
                    "kind": "left",
                    "item": key,
                    "detail": f"in {TRACED_FILE}, no longer a function that hands out wording",
                }
            )
    confirmed = {
        key
        for key in (*traced, *record.traced)
        if key in tree.functions and tree.functions[key].hands_out
    }
    for key in sorted(confirmed - set(must)):
        must[key] = "function"
    by_name: dict[str, list[str]] = defaultdict(list)
    for key in must:
        by_name[key.split(":", 1)[1]].append(key)
    seen: Counter[str] = Counter()
    for entry in record.entries:
        kind = "function" if "function" in entry else "constant"
        key = entry[kind]
        seen[key] += 1
        if seen[key] == 2:
            reports.append({"kind": "duplicate", "item": key, "detail": "two entries"})
        if key not in must or must[key] != kind:
            elsewhere = [k for k in by_name.get(key.split(":", 1)[1], []) if k != key]
            if elsewhere:
                reports.append({"kind": "moved", "item": key, "detail": "now " + elsewhere[0]})
            elif kind == "function" and key in tree.functions and tree.functions[key].hands_out:
                reports.append(
                    {
                        "kind": "not_reached_statically",
                        "item": key,
                        "detail": f"not in the static list; add it to {TRACED_FILE} with "
                        "trace --update-record, or give --trace-file with a trace that saw it "
                        "served",
                    }
                )
            else:
                reports.append(
                    {"kind": "left", "item": key, "detail": f"no longer a listed {kind}"}
                )
            continue
        texts = tree.functions[key].texts if kind == "function" else tree.constants[key].texts
        if entry["text_digest"] != text_digest(texts):
            reports.append(
                {"kind": "digest", "item": key, "detail": "the wording changed since the entry"}
            )
        if "not_published" in entry:
            reason = entry["not_published"]["reason"]
            cls = listing.entry_class(key)
            if reason not in NOT_PUBLISHED_REASONS_BY_CLASS[cls]:
                reports.append(
                    {
                        "kind": "invalid",
                        "item": key,
                        "detail": f"not_published reason {reason} is not open to class {cls}",
                    }
                )
            elif reason == "compared_only" and key in listing.compared_handed_out:
                reports.append(
                    {
                        "kind": "invalid",
                        "item": key,
                        "detail": "not_published reason compared_only, but handed out by a "
                        "function no entry point reaches: "
                        + ", ".join(listing.compared_handed_out[key]),
                    }
                )
            continue  # it pins no test: its text reaches no published surface
        verdict = test_verdict(repo, entry["test"])
        if verdict == "no":
            reports.append({"kind": "test", "item": key, "detail": f"no test {entry['test']}"})
        elif verdict == "unverified":
            reports.append(
                {
                    "kind": "unverified",
                    "item": key,
                    "detail": f"{entry['test']} cannot be decided without running it",
                }
            )
    for key, kind in must.items():
        if key not in seen:
            reports.append({"kind": "missing", "item": key, "detail": f"a listed {kind}"})
    order = {kind: n for n, kind in enumerate(REPORT_KINDS)}
    return sorted(reports, key=lambda r: (order[r["kind"]], r["item"], r["detail"]))


def not_published_count(record: Record) -> int:
    """How many entries say their text reaches no published surface (``not_published``)."""
    return sum(1 for entry in record.entries if "not_published" in entry)


def check_status(record: Record, reports: Sequence[Mapping[str, str]]) -> int:
    return 1 if record.complete and reports else 0


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> str | None:
    try:
        done = subprocess.run(  # nosec B603 B607 — git, an argument list
            ["git", "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _common_dir(path: Path) -> Path | None:
    """The git common directory of the checkout holding ``path``'s nearest existing parent."""
    existing = path
    while not existing.is_dir() and existing != existing.parent:
        existing = existing.parent
    found = _git(existing, "rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(found.strip()).resolve() if found else None


def checkouts(repo: Path = ROOT) -> list[Path]:
    """Every checkout of the repository: ``repo`` and each work tree of its git common
    directory, the main checkout among them."""
    found = {repo.resolve()}
    listed = _git(repo, "worktree", "list", "--porcelain") or ""
    for line in listed.splitlines():
        if line.startswith("worktree "):
            found.add(Path(line.removeprefix("worktree ")).resolve())
    return sorted(found)


def inside_a_checkout(path: Path, repo: Path = ROOT) -> bool:
    """Whether ``path`` lies in any checkout of the repository (the main checkout or a
    work tree), resolved first, so ``..``, a symlink and a relative path count."""
    target = Path(os.path.abspath(path)).resolve()
    for root in checkouts(repo):
        if target == root or root in target.parents:
            return True
    ours = _common_dir(repo)
    return ours is not None and _common_dir(target) == ours


def _trace_one(run: Path, out: Path) -> None:
    """Render ``run`` in each mode under the profiler; write each mode's code objects to ``out``."""
    from scripts.replay import render_surfaces

    os.environ.update(render_surfaces.CLOSED_STORES)
    render_surfaces._prepare_path()
    roots = tuple(str(ROOT / base) + os.sep for base, _ in PACKAGE_ROOTS)
    result: dict[str, Any] = {}
    work = out.parent / (out.name + ".work")
    for mode in render_surfaces.MODES:
        called: set[CodeType] = set()

        def profile(frame: FrameType, event: str, arg: Any, called: set[CodeType] = called) -> None:
            if event == "call":
                called.add(frame.f_code)

        error = None
        threading.setprofile_all_threads(profile)
        sys.setprofile(profile)
        try:
            render_surfaces.render_run(run, modes=(mode,), work=work)
        except Exception as exc:  # noqa: BLE001 — said in the output, and the trace marks it
            error = f"{type(exc).__name__}: {exc}"
        finally:
            sys.setprofile(None)
            threading.setprofile_all_threads(None)
        codes = sorted(
            {
                (Path(c.co_filename).relative_to(ROOT).as_posix(), c.co_firstlineno)
                for c in called
                if c.co_filename.startswith(roots)
            }
        )
        result[mode] = {"error": error, "called": [list(c) for c in codes]}
    out.write_text(json.dumps(result), encoding="utf-8")


class TraceTimeout(Exception):
    """A run's render outlasted ``--timeout``."""


def trace(
    runs: Sequence[Path],
    out: Path,
    timeout: float | None = None,
    listing: Listing | None = None,
) -> dict[str, Any]:
    """Each run rendered in its own process; which listed functions ran, and which joined.

    The scratch is a directory made here, beside ``out``, and removed whatever
    happens; nothing else is emptied or removed. :class:`TraceTimeout` when a
    run outlasts ``timeout``.
    """
    listing = listing if listing is not None else compute(Tree())
    tree = listing.tree
    at = {(f.path, f.first_line): key for key, f in tree.functions.items()}
    out.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"{out.name}.work-", dir=out.parent))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "src"), str(ROOT / "apps" / "api"), str(ROOT)]
    )
    per_run = []
    union: dict[str, dict[str, set[str]]] = {
        mode: {"listed_ran": set(), "traced_only": set()} for mode in ("serve", "build")
    }
    try:
        for index, run in enumerate(runs):
            part = work / f"{index:02d}.json"
            try:
                done = subprocess.run(  # nosec B603 — this script, an argument list
                    [sys.executable, "-m", "scripts.audit.publishing_functions", "_trace-one"]
                    + [str(run.resolve()), str(part)],
                    cwd=ROOT,
                    env=environment,
                    timeout=timeout,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise TraceTimeout(f"{run} took longer than {timeout:g} s") from None
            row: dict[str, Any] = {"run": str(run), "status": done.returncode, "modes": {}}
            if done.returncode != 0 or not part.is_file():
                row["error"] = done.stderr.strip()[-2000:]
                per_run.append(row)
                continue
            modes = json.loads(part.read_text(encoding="utf-8"))
            for mode, got in modes.items():
                ran = {at[(p, line)] for p, line in got["called"] if (p, line) in at}
                listed = sorted(k for k in ran if k in listing.functions)
                extra = sorted(
                    k for k in ran if k not in listing.functions and tree.functions[k].hands_out
                )
                row["modes"][mode] = {
                    "error": got["error"],
                    "listed_ran": listed,
                    "traced_only": extra,
                }
                union[mode]["listed_ran"].update(listed)
                union[mode]["traced_only"].update(extra)
            if not any(got["listed_ran"] for got in row["modes"].values()):
                row["error"] = "the render ran no listed function"
            per_run.append(row)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    summary: dict[str, dict[str, Any]] = {
        mode: {name: sorted(keys) for name, keys in got.items()} for mode, got in union.items()
    }
    summary["build_only"] = {
        "traced_only": sorted(union["build"]["traced_only"] - union["serve"]["traced_only"])
    }
    summary["listed"] = {"functions": len(listing.functions)}
    return {"runs": per_run, "summary": summary}


def failed_runs(result: Mapping[str, Any]) -> tuple[int, int]:
    """(runs that failed, of them the ones whose render raised in some mode). A run
    whose process failed, or whose render ran no listed function, failed."""
    failed = errors = 0
    for row in result["runs"]:
        raised = any(mode.get("error") for mode in row.get("modes", {}).values())
        errors += raised
        failed += raised or row["status"] != 0 or bool(row.get("error"))
    return failed, errors


def holds_report(run: Path) -> bool:
    """Whether ``run`` holds a stored report, read as the replay reads one."""
    from scripts.replay import render_surfaces

    return render_surfaces._Stored(run).report is not None


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.audit.publishing_functions",
        description="List the platform's publishing functions, trace them over stored runs, "
        "and check the record kept on each.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listed = commands.add_parser("list", help="the list, as a table or as JSON")
    listed.add_argument("--json", action="store_true", help="print the whole list as JSON")
    listed.add_argument(
        "--class",
        dest="cls",
        choices=PARTITION_CLASSES,
        help="list every wordy literal of one class of the partition",
    )
    traced = commands.add_parser("trace", help="which functions ran when stored runs rendered")
    traced.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    traced.add_argument(
        "--out",
        type=Path,
        required=True,
        help="the trace output (never inside a checkout of the repository)",
    )
    traced.add_argument(
        "--update-record",
        action="store_true",
        help=f"add the served functions the static list misses to {TRACED_FILE}",
    )
    traced.add_argument("--timeout", type=float, help="seconds each run may take")
    checked = commands.add_parser("check", help="compare the list with the record")
    checked.add_argument("--records", type=Path, default=RECORDS, help=argparse.SUPPRESS)
    checked.add_argument(
        "--trace-file", type=Path, help="a trace output: its served-only functions need entries"
    )
    checked.add_argument("--json", type=Path, help="write every report here as JSON")
    one = commands.add_parser("_trace-one", help=argparse.SUPPRESS)
    one.add_argument("run", type=Path)
    one.add_argument("out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    given = list(sys.argv[1:] if argv is None else argv)
    if given[:1] == ["--check"]:
        given[0] = "check"
    args = _parser().parse_args(given)
    if args.command == "_trace-one":
        _trace_one(args.run, args.out)
        return 0
    if args.command == "trace":
        if inside_a_checkout(args.out):
            print(
                f"refused: {args.out} is inside a checkout of the repository; "
                "name a path outside every checkout",
                file=sys.stderr,
            )
            return 2
        for run in args.runs:
            if not run.is_dir():
                print(f"no stored run at {run}", file=sys.stderr)
                return 2
            if not holds_report(run):
                print(
                    f"no stored run at {run}: it holds no report (report.json or "
                    "report-byjob.json); nothing written",
                    file=sys.stderr,
                )
                return 2
        try:
            result = trace(args.runs, args.out, args.timeout)
        except (LookupError, TraceTimeout) as exc:
            print(f"publishing_functions: {exc}; nothing written", file=sys.stderr)
            return 2
        args.out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        summary = result["summary"]
        failed, errors = failed_runs(result)
        print(
            f"runs {len(result['runs'])} (failed {failed}, of them render errors {errors}); "
            f"listed functions ran: serve {len(summary['serve']['listed_ran'])}, build "
            f"{len(summary['build']['listed_ran'])}; traced only: serve "
            f"{len(summary['serve']['traced_only'])}, build only "
            f"{len(summary['build_only']['traced_only'])}"
        )
        if failed:
            return 2
        if args.update_record:
            tree = Tree()
            try:
                before = read_traced(RECORDS)
            except ValueError as exc:
                print(f"refused: {exc}", file=sys.stderr)
                return 2
            kept = [k for k in before if k in tree.functions and tree.functions[k].hands_out]
            for key in sorted(set(before) - set(kept)):
                print(f"{TRACED_FILE}: {key} left (no longer a function that hands out wording)")
            path = write_traced(RECORDS, [*kept, *summary["serve"]["traced_only"]], tree)
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    try:
        listing = compute(Tree())
    except LookupError as exc:
        print(f"publishing_functions: {exc}", file=sys.stderr)
        return 2
    gaps = partition_errors(listing)
    if args.command == "list":
        if args.cls:
            print("\n".join(class_rows(listing, args.cls)))
            print("\n".join(partition_lines(listing)[:1]), file=sys.stderr)
        elif args.json:
            print(json.dumps(listing.as_json(), indent=1, sort_keys=True))
            print("\n".join([*partition_lines(listing), *limit_lines(listing)]), file=sys.stderr)
        else:
            print(listing.table())
        if gaps:
            print("\n".join(gaps), file=sys.stderr)
        return partition_status(listing)
    try:
        record = read_record(args.records)
        traced = read_trace(args.trace_file) if args.trace_file else []
    except (OSError, ValueError, KeyError) as exc:
        print(f"could not read the record: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    reports = check(listing, record, ROOT, traced)
    if args.json:
        args.json.write_text(json.dumps(reports, indent=1) + "\n", encoding="utf-8")
    counts = Counter(r["kind"] for r in reports)
    missing = Counter(_module(r["item"]) for r in reports if r["kind"] == "missing")
    for module, count in sorted(missing.items()):
        print(f"missing  {count:>4}  {module}")
    for report in reports:
        if report["kind"] != "missing":
            print(f"{report['kind']}  {report['item']}  {report['detail']}")
    print(
        "record "
        + ("complete" if record.complete else "incomplete (reports only)")
        + f": {len(record.entries)} entr(ies), not_published {not_published_count(record)}; "
        + (", ".join(f"{kind} {counts[kind]}" for kind in REPORT_KINDS if counts[kind]) or "clean")
    )
    print("\n".join([*partition_lines(listing), *limit_lines(listing)]))
    if gaps:
        print("\n".join(gaps), file=sys.stderr)
        return 2
    return check_status(record, reports)


if __name__ == "__main__":
    sys.exit(main())
