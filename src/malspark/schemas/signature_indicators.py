"""A sandbox signature's indicators, in one neutral form, read where each format states them.

A signature a sandbox matched carries indicators: which process did what to
which, with the API or event, a description, and the addresses and values the
sandbox recorded. Each format states them under fields of its own, and its
reader declares where (:class:`IndicatorFields`, given as
``schemas.sandbox_report.Reading.signature_indicators``); a mapped format
declares them through its mapping's ``field_names``, and its reader writes them
on the signature's row in the neutral form under :data:`SIGNATURE_INDICATORS_KEY`.
This module reads an indicator by that declaration alone, never by a format's
own field name, into the neutral form (:func:`neutral_indicator`):

* ``process`` and ``target``: the id the report's process list gives the
  process that acted and the process acted on, in one text form
  (``schemas.sandbox_document.pid_of``); a field holding a value that cannot
  be an id states none, and the value stays among the indicator's values;
* ``event`` and ``description``: the API or event, and the sandbox's words;
* ``values``: every other field the indicator states, under the report's own
  name, as its text (a nested value as its compact JSON).

Every text is cut to :data:`INDICATOR_TEXT_CHARS` characters and every name to
:data:`INDICATOR_NAME_CHARS`, and at most :data:`INDICATOR_VALUES_SHOWN`
values are kept: what was cut is counted on the indicator itself
(``chars_left_out``, ``values_left_out``), never left out silently. Texts are
the report's, untrusted, and are written out by whoever shows them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from malspark.schemas.sandbox_document import pid_of

# On a signature's row: its indicators in the neutral form, where a reader that
# reads a mapping writes them (a format whose fields are declared by the
# operator). A built-in reader declares its format's own fields instead.
SIGNATURE_INDICATORS_KEY = "platform_indicators"

# The keys of one indicator in the neutral form.
PROCESS = "process"
TARGET = "target"
EVENT = "event"
DESCRIPTION = "description"
VALUES = "values"
CHARS_LEFT_OUT = "chars_left_out"
VALUES_LEFT_OUT = "values_left_out"

# The whole signature view's answer, its rows and the indicators listed after
# them (``providers.sandbox_tools.sandbox_signatures``): indicators are listed
# only while the answer stays within it, and never past what the model's copy
# of the answer holds. The rows are the view's whatever their size.
SIGNATURE_ANSWER_CHARS = 24_000
# How many indicators one call naming a signature, a process or a text lists,
# from its offset (within the same whole-answer bound).
SIGNATURE_INDICATORS_PAGE = 20
# The most indicators the item reader's signature item lists, the head of the
# signature's order, with where the rest are read.
SIGNATURE_INDICATORS_SHOWN = 16
# How long a text and a value's name an indicator keeps, and how many values:
# a hostile report's long strings and wide indicators cost their bound, and
# what was cut is counted beside it.
INDICATOR_TEXT_CHARS = 256
INDICATOR_NAME_CHARS = 64
INDICATOR_VALUES_SHOWN = 8


@dataclass(frozen=True)
class IndicatorFields:
    """Where a format's signature rows state their indicators, as its reader declares them.

    ``lists`` are the fields of a signature row (as the document holds it)
    that hold its indicators; ``process`` and ``target`` the fields of an
    indicator naming the process that acted and the one acted on, by the id
    the report's process list gives it, the first that holds an id read;
    ``event`` the dotted paths of the API or event and ``description`` the
    fields of the sandbox's words, the first that states one read. A format
    whose report lists its signatures again per task, each row naming its
    processes by that task's ids, names the channel holding those rows
    (``task_channel``), the field naming a row's signature (``task_name``) and
    the fields holding a row's indicators (``task_lists``): a signature's
    indicators then also take those of every task row of its name, each read
    in its row's task. ``neutral`` says the rows hold their indicators in the
    neutral form under :data:`SIGNATURE_INDICATORS_KEY` (a mapped format).
    ``guest_pid`` names the dotted paths of a process row (as the document
    holds it) that hold the guest's pid, where the report's own process id is
    another number: a resolved process then states both.
    """

    lists: tuple[str, ...] = ()
    process: tuple[str, ...] = ()
    target: tuple[str, ...] = ()
    event: tuple[str, ...] = ()
    description: tuple[str, ...] = ()
    task_channel: str = ""
    task_name: str = ""
    task_lists: tuple[str, ...] = ()
    neutral: bool = False
    guest_pid: tuple[str, ...] = ()


# A mapped format's rows: the neutral form, under the platform's own key.
NEUTRAL_FIELDS = IndicatorFields(lists=(SIGNATURE_INDICATORS_KEY,), neutral=True)


def _text(value: Any) -> str:
    """A value the report states, as its text: a string as written, anything else as JSON."""
    if isinstance(value, str):
        return value
    from malspark.core.safe_json import dumps

    return dumps(value, separators=(",", ":"), default=str, ensure_ascii=False)


def _cut(text: str, limit: int) -> tuple[str, int]:
    """``text`` cut to ``limit`` characters, ``…`` where it was cut; and how many were left out."""
    if len(text) <= limit:
        return text, 0
    return text[:limit] + "…", len(text) - limit


def held_at(row: Any, path: str) -> Any:
    """What ``row`` holds at the dotted ``path``, or ``None``."""
    node: Any = row
    for key in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def _stated(value: Any) -> bool:
    return value not in (None, "", [], {})


def neutral_indicator(indicator: Any, fields: IndicatorFields) -> dict[str, Any]:
    """One indicator a report states, in the neutral form, read by ``fields``.

    An indicator that is not a mapping is one value (``value``). Linear in the
    indicator; only the kept values are written as text.
    """
    if not isinstance(indicator, Mapping):
        indicator = {"value": indicator} if _stated(indicator) else {}
    out: dict[str, Any] = {}
    cut: dict[str, int] = {}
    used: set[str] = set()
    for key, names in ((PROCESS, fields.process), (TARGET, fields.target)):
        for name in names:
            procid = pid_of(indicator.get(name))
            if procid:
                out[key] = procid
                used.add(name)
                break
    for key, paths in ((EVENT, fields.event), (DESCRIPTION, fields.description)):
        for path in paths:
            value = held_at(indicator, path)
            if _stated(value):
                out[key], left = _cut(_text(value), INDICATOR_TEXT_CHARS)
                if left:
                    cut[key] = left
                if "." not in path:
                    used.add(path)
                break
    values: dict[str, str] = {}
    left_out = 0
    for name, value in indicator.items():
        if name in used or not _stated(value):
            continue
        key, _ = _cut(str(name), INDICATOR_NAME_CHARS)
        if len(values) >= INDICATOR_VALUES_SHOWN or key in values:
            left_out += 1
            continue
        values[key], left = _cut(_text(value), INDICATOR_TEXT_CHARS)
        if left:
            cut[f"{VALUES}.{key}"] = left
    if values:
        out[VALUES] = values
    if left_out:
        out[VALUES_LEFT_OUT] = left_out
    if cut:
        out[CHARS_LEFT_OUT] = cut
    return out


def held_neutral(indicator: Any) -> dict[str, Any]:
    """An indicator a reader wrote in the neutral form, as that form: anything else read as nothing.

    A row's own indicators are the report's, and a stored row may hold any
    value under the key: each part is read only in the form it takes.
    """
    if not isinstance(indicator, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key in (PROCESS, TARGET):
        procid = pid_of(indicator.get(key))
        if procid:
            out[key] = procid
    for key in (EVENT, DESCRIPTION):
        value = indicator.get(key)
        if isinstance(value, str) and value:
            out[key], _ = _cut(value, INDICATOR_TEXT_CHARS + 1)
    values = indicator.get(VALUES)
    if isinstance(values, Mapping):
        kept = {
            _cut(str(name), INDICATOR_NAME_CHARS + 1)[0]: _cut(text, INDICATOR_TEXT_CHARS + 1)[0]
            for name, text in list(values.items())[:INDICATOR_VALUES_SHOWN]
            if isinstance(text, str) and text
        }
        if kept:
            out[VALUES] = kept
    for key in (VALUES_LEFT_OUT,):
        count = indicator.get(key)
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            out[key] = count
    cut = indicator.get(CHARS_LEFT_OUT)
    if isinstance(cut, Mapping):
        counts = {
            str(name): count
            for name, count in list(cut.items())[: INDICATOR_VALUES_SHOWN + 2]
            if isinstance(count, int) and not isinstance(count, bool) and count > 0
        }
        if counts:
            out[CHARS_LEFT_OUT] = counts
    return out


def indicators_of(row: Any, lists: tuple[str, ...]) -> list[Any]:
    """The indicators a row holds under the first of ``lists`` holding a list; ``[]`` for none."""
    if not isinstance(row, Mapping):
        return []
    for name in lists:
        held = row.get(name)
        if isinstance(held, list) and held:
            return held
    return []


def indicator_rank(indicator: Mapping[str, Any]) -> int:
    """Where an indicator stands in its signature's order: a process pairing, one process, none.

    ``0`` where it names the process that acted and the one acted on, ``1``
    where it names one of them, ``2`` where it names none.
    """
    return 2 - bool(indicator.get(PROCESS)) - bool(indicator.get(TARGET))


def indicator_key(indicator: Mapping[str, Any], task: str) -> str:
    """One text per distinct indicator of a task, which two equal indicators share."""
    return json.dumps([task, indicator], sort_keys=True, default=str)
