"""What a row of the IOC table read from the file's strings is: its kind, or only its form.

The string sweep types a token by its form: a name@domain text is typed an
e-mail, a dotted name a domain. The form is all the sweep proves. A row of
source ``strings`` is a *form row* when nothing in the run reads it as its
kind: it is not published; no row of another source holds the same kind and
value; no judge indicator names it under that kind; and, for a domain, no URL
row of the run has it as the host the platform reads from a URL
(``network_extractor.url_host``, as the publish rule and the export read it)
and no recovering tool recovered it with a
spelling that reads as a host (``stix_renderer.reads_as_a_host_in_the_bytes``).
A recovered e-mail is read as one by the tool that recovered it.

A path or registry key row of source ``strings`` the extractor recorded taking
out of a longer string of the file (``StringIOC.cut_from``) prints that it is
text of that shape in a longer string. It says where the text stands, not that
it is incomplete; a row with no such record keeps its kind, and so does one
the run publishes, another source holds or a judge indicator names.

A form row keeps its kind: the kind stays the key of every lookup and match
(the publish answers, the judge's match, the defang). Only the edges that
print the kind print the form instead (:func:`string_row_forms`), and an
export carries the form as the row's kind (:func:`exported_form`); the kind
the row is keyed on is not exported. A form row's value is the text its
entries hold, never a host's folded case (:func:`written_texts`). Nothing
here reads a list of names, suffixes or tools: only the row's source, its
kind, its form and the run's other readers of the same value.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# The printed type of a form row, by what its form is.
NAME_AT_DOMAIN_TEXT = "Name@domain text"
DOTTED_NAME = "Dotted name"
# Any other form the form reader returns holds what no plain host name holds,
# whatever it names.
NOT_A_PLAIN_HOST_BY_FORM = "Text, not a plain host name by its form"
# A path or registry key row the extractor recorded taking out of a longer
# string: true of a fragment and of a whole path standing in ``NAME=…`` alike.
PATH_IN_A_LONGER_STRING = "Path-shaped text in a longer string"
REGISTRY_KEY_IN_A_LONGER_STRING = "Registry-key-shaped text in a longer string"

# The kind an export (``/iocs``, the console's table) carries a form row under,
# by its printed type: the form, never the kind the row is keyed on inside the
# report, which is not exported.
EXPORTED_FORM_KINDS = {
    NAME_AT_DOMAIN_TEXT: "name_at_domain_text",
    DOTTED_NAME: "dotted_name",
    NOT_A_PLAIN_HOST_BY_FORM: "text_not_a_plain_host_name",
    PATH_IN_A_LONGER_STRING: "path_shaped_text",
    REGISTRY_KEY_IN_A_LONGER_STRING: "registry_key_shaped_text",
}

_STRINGS = "strings"
# The kinds the extractor records taking out of a longer string, and what such a row prints.
_IN_A_LONGER_STRING = {
    "path": PATH_IN_A_LONGER_STRING,
    "registry": REGISTRY_KEY_IN_A_LONGER_STRING,
}


def _same_value(kind: str, value: Any) -> str:
    """One value in the spelling two writers of it share: a host by its host form."""
    from malspark.extractors.network_extractor import host_form
    from malspark.reporting.ledger_projection import value_key

    return host_form(value) if kind == "domain" else value_key(kind, value)


@dataclass(frozen=True)
class _Readers:
    """The run's readers of a value as its kind, read once for the whole table."""

    report: Any
    held: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    judged: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    url_hosts: frozenset[str] = field(default_factory=frozenset)
    cut: frozenset[tuple[str, str]] = field(default_factory=frozenset)


def _readers(report: Any, rows: Iterable[Any]) -> _Readers:
    from malspark.extractors.network_extractor import host_form, url_host
    from malspark.reporting.ledger_projection import value_key

    rows = list(rows)
    held = {
        (str(row.kind), _same_value(str(row.kind), row.value))
        for row in rows
        if row.kind and str(row.source or "") != _STRINGS
    }
    judged = {
        (str(item.kind or ""), _same_value(str(item.kind or ""), item.value))
        for item in getattr(report, "judge_indicators", None) or []
    }
    hosts = {host_form(url_host(row.value)) for row in rows if row.kind == "url"} - {""}
    static = getattr(report, "static", None)
    cut = {
        (str(row.kind), value_key(str(row.kind), row.value))
        for row in getattr(static, "interesting_strings", None) or []
        if row.kind in _IN_A_LONGER_STRING and getattr(row, "cut_from", None)
    }
    return _Readers(report, frozenset(held), frozenset(judged), frozenset(hosts), frozenset(cut))


def _spelled(report: Any, value: Any) -> str:
    """A recovered name as the recovering tool spelled it, or the value where no spelling is held.

    Read from the run's emulation record as the publish rule reads it: a name
    the strings entry holds too has no recovered spelling.
    """
    from malspark.reporting.renderers.stix_renderer import emulation_record

    found = emulation_record(report)
    key = str(value or "").strip().lower().rstrip(".")
    if key in found.plain or not found.values.get(key):
        return str(value or "")
    return found.spelled.get(key, "") or str(value or "")


def string_row_form(row: Any, readers: _Readers) -> str | None:
    """The printed type of one IOC table row that is a form row, ``None`` for any other row."""
    from malspark.reporting.ledger_projection import FORM_OTHER, path_or_host_form, value_key
    from malspark.reporting.renderers.stix_renderer import (
        publishes,
        reads_as_a_host_in_the_bytes,
    )

    kind = str(row.kind or "")
    if str(row.source or "") != _STRINGS:
        return None
    if kind not in ("email", "domain") and kind not in _IN_A_LONGER_STRING:
        return None
    # A row the run publishes, another source holds or the judge names is read
    # as its kind, whatever its form or its cut.
    if publishes(row.published):
        return None
    key = (kind, _same_value(kind, row.value))
    if key in readers.held or key in readers.judged:
        return None
    if kind in _IN_A_LONGER_STRING:
        cut = (kind, value_key(kind, row.value)) in readers.cut
        return _IN_A_LONGER_STRING[kind] if cut else None
    if kind == "email":
        return None if row.recovered_by else NAME_AT_DOMAIN_TEXT
    if key[1] in readers.url_hosts:
        return None
    if row.recovered_by and reads_as_a_host_in_the_bytes(_spelled(readers.report, row.value)):
        return None
    # Only the plain form is a dotted name; any other form is said to be no
    # plain host name, and nothing is said of whether it names a host.
    form = path_or_host_form(str(row.value or "").strip()).form
    return DOTTED_NAME if form == FORM_OTHER else NOT_A_PLAIN_HOST_BY_FORM


def string_row_forms(report: Any, rows: Iterable[Any]) -> dict[tuple[str, str], str]:
    """``(kind, value_key)`` of each form row of the IOC table ``rows``, with its printed type.

    Keyed as every lookup of the table keys a row
    (``ledger_projection.value_key``), so an edge holding a value of the
    run's strings or its network block finds the row's form by its kind and
    value. Read under one reading of the report's lookups.
    """
    from malspark.reporting.ledger_projection import value_key
    from malspark.reporting.renderers.stix_renderer import one_reading

    rows = list(rows)
    out: dict[tuple[str, str], str] = {}
    with one_reading(report):
        readers = _readers(report, rows)
        for row in rows:
            form = string_row_form(row, readers)
            if form is not None:
                out.setdefault((str(row.kind), value_key(str(row.kind), row.value)), form)
    return out


def written_texts(report: Any, row: Any) -> list[str]:
    """The texts a form row is exported as: each text its entries hold it as, once, in order.

    A form row is no host name, so its case is not folded: the network block
    reads a dotted name as a host and lower-cases it, and the row's own reason
    names the entries that hold it. Read from the rows of the file's strings
    (``static.interesting_strings``) of the row's kind whose value is the
    row's but for letter case, so one name the strings hold in two cases
    gives both texts; where no such row holds it, the spelling the recovering
    tool gave (:func:`_spelled`); else the row's own value.
    """
    kind = str(getattr(row, "kind", None) or "")
    folded = str(row.value or "").strip().lower()
    static = getattr(report, "static", None)
    texts = list(
        dict.fromkeys(
            text
            for held in getattr(static, "interesting_strings", None) or []
            if str(held.kind or "") == kind
            and (text := str(held.value or "").strip())
            and text.lower() == folded
        )
    )
    if texts:
        return texts
    if getattr(row, "recovered_by", None):
        return [_spelled(report, row.value).strip() or str(row.value)]
    return [str(row.value)]


def exported_form(row: Any, forms: dict[tuple[str, str], str]) -> tuple[str, str] | None:
    """The kind and type an export carries a form row under; ``None`` for any other row.

    ``forms`` is :func:`string_row_forms` of the table ``row`` belongs to;
    only a row of the file's strings is read in it, so a row of another
    source holding the same kind and value keeps its own.
    """
    from malspark.reporting.ledger_projection import value_key

    if str(getattr(row, "source", None) or "") != _STRINGS:
        return None
    kind = str(getattr(row, "kind", None) or "")
    label = forms.get((kind, value_key(kind, row.value)))
    return (EXPORTED_FORM_KINDS[label], label) if label else None
