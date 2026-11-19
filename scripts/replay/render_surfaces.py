"""Render every published surface of a stored run, and compare the surfaces of two git refs.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/render_surfaces.py runs/<family>/1 --out DIR

renders what a reader of the run is shown, at zero cost, and writes a surface
record (``DIR/surfaces.json``) beside the rendered files (``DIR/<run>/<mode>/``:
``report.md``, ``report.html``, ``evidence-bundle.json``,
``evidence-bundle.html``, ``iocs.json``, ``iocs-default.json``,
``stix-bundle.json``, ``stix-judge.json``, ``stix-note.txt``, ``mitre.json``,
``misp-event.json``, ``attack-layer.json``, ``call-map.json``,
``signatures.json`` and one rule download per kind). Nothing is written into a
run's directory: every file of it is digested before and after, and the
command fails when a digest changed.

The record is a list of units, each with its ``surface``, the ``mode`` that
produced it, a ``group`` (a section path, a figure id, a rule kind), a stable
``key`` and its ``text``, and the digest of each rendered file. The rule is
that everything a surface holds is compared, and what is not is named: no
value is left out unless it is shown to vary without a code change (the same
ref rendered twice, and once more with the clock moved), and each such
exclusion is listed with its proof in :data:`EXCLUDED`, in the record and in
the comparison's output. None is listed: rendered twice and with the clock
moved five years on, every unit and every file of a run is byte-equal. What
each surface compares:

=====================  ==========================================================
surface                compared
=====================  ==========================================================
``report.md``          every line as printed, blank and fenced ones too, under
                       its section path, in the layout the API serves (the
                       run's ``reporting.full_report_in_one_file``)
``banner``             every line of the title block, before the first section
``html.*``             ``report.html``: the cover's fields (``.header``); each
                       figure's caption, legend, SVG ``<text>`` labels,
                       ``<title>`` tooltips and any other text in it
                       (``.figure``); note paragraphs (``.notes``); every other
                       text node as a block, a table row's cells joined, each
                       line of a style or a script (``.body``); every
                       ``title``, ``aria-label`` and ``alt`` attribute
                       (``.attrs``)
``bundle.html.*``      the same, over ``/evidence-bundle.html``
``bundle.lines``       every line of every section of ``/evidence-bundle.json``,
                       blank and fenced ones too
``bundle.notes``       each numbered note, every field, as canonical JSON
``bundle.index``       each section's other fields, the header, the format, each
                       evidence entry and every other field of the document, as
                       canonical JSON
``iocs.default``,      each row ``/iocs`` serves (by default; with
``iocs.all``           ``include=all`` and the filter-only kinds), keyed by kind
                       and value, every other field as canonical JSON
``stix``,              the bundle ``/stix`` serves (export; ``source=judge``):
``stix.judge``         its envelope, the bundle's own properties, and per object
                       its ``id`` and every other property, timestamps included,
                       as canonical JSON, each ref said as its target's key;
                       keyed by type and identity, a relationship by its
                       source, its type and its target
``stix.notice``,       the notice an unpublished bundle is served with, the
``stix.judge.notice``  judge view's envelope, the STIX note the report detail
``stix.note``          serves
``mitre``              each ``/mitre`` row keyed by technique, every other field
``misp``               the event without its lists, each attribute, each object
                       without its attributes and each object attribute, every
                       field as canonical JSON
``navigator``          the layer's own fields, each legend item and each
                       technique, every field as canonical JSON
``call_map``           the map's own fields and each function, every field
``rules``              each drafted rule's every field but its body, as
                       canonical JSON; ``rules.body``: every line of its body;
                       ``rules.download``: every line of each kind's download
``file``               each rendered file by digest: one that differs (or is on
                       one side only) where no unit read from it does is a
                       change, shown at its first differing line, so what the
                       units do not hold (any other attribute, the whitespace,
                       the order of rows and keys) is compared all the same
=====================  ==========================================================

The API's routes and writers are the tree's own: the ``/stix`` route is called
with the tree's service reading a row of the stored (or rebuilt) columns.

Two modes produce the units, and each unit says which:

* **serve**: the stored report (``report-byjob.json``'s ``malware_report``, else
  ``report.json``) typed under the tree's own models and passed to its
  renderers and the API's writers, as the API does for a stored job. The STIX
  bundle and ``/mitre`` are the stored report row's columns, and the judge
  column is read back from the served view (``stix-judge.json``).
* **build**: the report rebuilt by the replay (``scripts/replay/rules.py``: the
  deterministic build, the stored composed sections put back, the export, the
  IOC table, the MISP attributes and the detection drafts), its figures drawn
  as the report node draws them, then rendered and exported the same way. Its
  clock is the stored report's: ``generated_at`` and every value the builder
  dates from the current time (the cover's date, the date inside the report
  number, the copyright year, the revision history's date) are set to the
  stored report's before the export and the drafts read them.

A surface a tree cannot produce (a function its tree does not have, a stored
file the run lacks, a report the replay could not rebuild) is listed under
``not_produced`` with the reason; it is never skipped and never compared as
equal. One that raised is listed there too, marked as an error.

``--compare REF_A REF_B`` writes both refs out of the object store
(``scripts.replay.compare.materialise``) and runs *this* driver against each
tree in a process of its own, with that tree first on the import path: the
driver resolves the tree's entry points by name at run time, so a ref from
before this tool is rendered too, and an entry point it lacks is a surface not
produced. The record says where the platform, the API and the replay scripts
were imported from, and a package imported from outside the tree fails the
comparison (the plain ``--out`` render is checked the same way, against this
checkout). It prints, per run and grouped by surface, every unit changed,
added or removed with both texts; then the count of units compared, of
differences and of surfaces not compared, the units compared per mode and
surface beside their differences, and what was excluded. Every unit is compared,
those marked ``dynamic`` too (see the limits). A surface produced by neither
ref is listed NOT COMPARED with both reasons. ``--expect FILE`` (JSON: a list
of ``{"surface", "mode"?, "key"?, "old"?, "new"?, "reason"}``, each pattern a
regular expression searched in the key or the text) names the changes
expected: a difference no expectation matches is UNEXPECTED, and an
expectation no difference matches is UNEXERCISED. The exit status is the first
that applies of: 2 when a surface raised in either tree, a tree could not be
written out or rendered, or on an error; 1 when a difference was not expected;
3 when a surface was produced by neither ref (unless ``--accept-not-compared``);
4 when an expectation was not exercised; 0 otherwise.

Limits:

* serve mode cannot change platform text that was written before rendering
  and stored: clauses appended to section bodies, degradation reasons, the
  indicators' reasons, the figures a stored report holds and the stored STIX
  bundle (its export reasons among them) are read as stored;
* build mode rebuilds without the sandbox report, so the units that only it
  fills (the process tree and network figures, the sandbox's IOC rows, the
  export's process, observed-data and network objects) are drawn from no
  sandbox data. Both refs draw them alike, so they are compared, but they are
  marked ``dynamic``: read against the stored report, they differ;
* build mode's judge view carries the stored record's label map: the replay
  keeps none of its own;
* the report detail is read for its STIX note only (``with_current_iocs``):
  its other fields (the transcript, the findings, the verdict reading, the
  section tabs) are not rendered; nor are the PDF (the HTML through WeasyPrint),
  the job package and the console, which draws the API's JSON;
* fields an older build lacked default to empty when typed under a newer
  model, so a re-render shows the differences between two refs only, and is
  not what a new run would print;
* the findings the run's checks left unresolved are read as the run summary
  stored them in serve mode, and build mode prints none of the narrative
  findings: a finding's message changed in the code is reported by neither
  mode. The replay comparison (``scripts/replay/run.py --compare``) does not
  report it either: it keys a finding by its producer, answer, claim, path and
  code, not by its words, so no tool here compares a finding's message.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 — this driver under another tree, an argument list only
import sys
import tempfile
import traceback
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from fnmatch import fnmatch
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, NoReturn

_ROOT = Path(__file__).resolve().parents[2]
# Set to the tree a run of this driver renders under: that tree's import path is
# the process's own, and nothing of this checkout is put on it.
TREE_VARIABLE = "MALSPARK_SURFACES_TREE"
# The package names the tree's platform may be imported under, current first.
PACKAGES_VARIABLE = "MALSPARK_SURFACES_PACKAGES"
# The ATT&CK loader's cache directory, read at import (``scripts.replay.guard``).
ATTCK_CACHE_VARIABLE = "MALSPARK_ATTCK_CACHE"
SCHEMA = 1
MODES: tuple[str, ...] = ("serve", "build")
RECORD_FILE = "surfaces.json"
# The exit statuses of a comparison, the first that applies.
EXIT_ERROR = 2
EXIT_UNEXPECTED = 1
EXIT_NOT_COMPARED = 3
EXIT_UNEXERCISED = 4
EXIT_STATUSES: tuple[tuple[int, str], ...] = (
    (EXIT_ERROR, "a surface raised in either tree, a tree could not be written out or rendered"),
    (EXIT_UNEXPECTED, "a difference no expectation names"),
    (EXIT_NOT_COMPARED, "a surface neither ref produced, unless --accept-not-compared"),
    (EXIT_UNEXERCISED, "an expectation no difference matched"),
    (0, "the refs render the same, or every difference was expected"),
)

LIMITS: tuple[str, ...] = (
    "serve mode cannot change platform text that was written before rendering and stored: "
    "clauses appended to section bodies, degradation reasons, the indicators' reasons and the "
    "stored figures and the stored STIX bundle are read as stored",
    "build mode rebuilds without the sandbox report, so the units only it fills are drawn from "
    "no sandbox data: both refs draw them alike and they are compared, but they are marked "
    "dynamic, as read against the stored report they differ",
    "build mode's judge view carries the stored record's label map",
    "the report detail is read for its STIX note only; its other fields, the PDF, the job "
    "package and the console are not rendered",
    "fields an older build lacked default to empty, so a re-render shows the differences "
    "between two refs only and is not what a new run would print",
    "the run's unresolved findings are read as the run summary stored them in serve mode and "
    "build mode prints none of the narrative findings, so a finding's message changed in the "
    "code is reported by neither mode; the replay comparison (scripts/replay/run.py --compare) "
    "keys a finding by its producer, answer, claim, path and code, not by its words, so no tool "
    "here compares a finding's message",
)

# The surfaces of each mode, in the order they are rendered.
SURFACES: tuple[str, ...] = (
    "report.md",
    "banner",
    "html.header",
    "html.figure",
    "html.notes",
    "html.body",
    "html.attrs",
    "iocs.default",
    "iocs.all",
    "stix",
    "stix.notice",
    "stix.note",
    "stix.judge",
    "stix.judge.notice",
    "mitre",
    "misp",
    "navigator",
    "call_map",
    "rules",
    "rules.body",
    "rules.download",
    "bundle.notes",
    "bundle.lines",
    "bundle.index",
    "bundle.html.header",
    "bundle.html.figure",
    "bundle.html.notes",
    "bundle.html.body",
    "bundle.html.attrs",
)
# The surfaces whose units are lines in order: compared by aligning each
# group's texts, so a line put in does not move every key after it.
ORDERED: frozenset[str] = frozenset(
    {
        "report.md",
        "banner",
        "html.header",
        "html.notes",
        "html.body",
        "html.attrs",
        "rules.body",
        "rules.download",
        "bundle.lines",
        "bundle.html.header",
        "bundle.html.notes",
        "bundle.html.body",
        "bundle.html.attrs",
    }
)
# The rendered file each surface is read from (shell patterns). A file that
# differs between the refs while no unit of its surfaces does is a change all
# the same (surface ``file``): what the units do not hold (an attribute, the
# whitespace, the order of rows) is compared through the file.
SURFACE_FILES: dict[str, tuple[str, ...]] = {
    "report.md": ("report.md",),
    "banner": ("report.md",),
    "html.header": ("report.html",),
    "html.figure": ("report.html",),
    "html.notes": ("report.html",),
    "html.body": ("report.html",),
    "html.attrs": ("report.html",),
    "iocs.default": ("iocs-default.json",),
    "iocs.all": ("iocs.json",),
    "stix": ("stix-bundle.json",),
    "stix.notice": ("stix-bundle.json",),
    "stix.note": ("stix-note.txt",),
    "stix.judge": ("stix-judge.json",),
    "stix.judge.notice": ("stix-judge.json",),
    "mitre": ("mitre.json",),
    "misp": ("misp-event.json",),
    "navigator": ("attack-layer.json",),
    "call_map": ("call-map.json",),
    "rules": ("signatures.json",),
    "rules.body": ("signatures.json",),
    "rules.download": ("signatures-*.txt",),
    "bundle.notes": ("evidence-bundle.json",),
    "bundle.lines": ("evidence-bundle.json",),
    "bundle.index": ("evidence-bundle.json",),
    "bundle.html.header": ("evidence-bundle.html",),
    "bundle.html.figure": ("evidence-bundle.html",),
    "bundle.html.notes": ("evidence-bundle.html",),
    "bundle.html.body": ("evidence-bundle.html",),
    "bundle.html.attrs": ("evidence-bundle.html",),
}
# The surface a rendered file's own change is reported on.
FILE_SURFACE = "file"
# What is left out of the comparison, each with the proof that it varies
# without a code change (the same ref rendered twice, and once more with the
# clock moved): (surface, what, proof). Every other value is compared.
EXCLUDED: tuple[tuple[str, str, str], ...] = ()
# What only the sandbox report fills, which build mode rebuilds without: the
# figures drawn from its process tree and its network block, the IOC rows it
# is the source of, and the export's objects made from its process tree and
# network block (``scripts.replay.rules``).
DYNAMIC_FIGURES: frozenset[str] = frozenset({"fig-process-tree", "fig-network"})
DYNAMIC_IOC_SOURCES: frozenset[str] = frozenset({"sandbox"})
DYNAMIC_STIX_TYPES: frozenset[str] = frozenset(
    {
        "process",
        "observed-data",
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "network-traffic",
    }
)
# The IOC kinds ``/iocs`` serves only to a ``kind`` filter that names them.
_FILTERED_IOC_KINDS: tuple[str, ...] = ("secret", "crypto_wallet")
# The rule kinds the API serves a download of.
RULE_KINDS: tuple[str, ...] = ("yara", "sigma", "suricata", "snort")
# A STIX identifier: what a ``*_ref`` names.
_STIX_ID = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-fA-F-]{36}$")


class Absent(LookupError):
    """An entry point the tree does not have, or an input the stored run does not hold."""


# ---------------------------------------------------------------------------
# The tree's entry points, resolved by name
# ---------------------------------------------------------------------------


def _packages() -> tuple[str, ...]:
    named = [p for p in os.environ.get(PACKAGES_VARIABLE, "").split(",") if p.strip()]
    if named:
        return tuple(p.strip() for p in named)
    try:
        from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME
    except Exception:  # noqa: BLE001 — a tree with one name
        return ("malspark",)
    return (CURRENT_NAME, PREVIOUS_NAME)


def entry(module: str, name: str) -> Any:
    """``module.name`` of the tree this process imports, or :class:`Absent` saying which.

    A module of the platform is written ``platform.<path>`` and tried under each
    of the tree's package names; ``app.*`` and ``scripts.*`` are the tree's API
    and scripts as they are.
    """
    if module.startswith("platform."):
        candidates = [f"{p}.{module.removeprefix('platform.')}" for p in _packages()]
    else:
        candidates = [module]
    for candidate in candidates:
        try:
            found = importlib.import_module(candidate)
        except ModuleNotFoundError as exc:
            # The module itself or a package above it is not there; a module it
            # imports that is not there is a broken tree, and raises.
            missing = str(exc.name or "")
            if candidate != missing and not candidate.startswith(f"{missing}."):
                raise
            continue
        if hasattr(found, name):
            return getattr(found, name)
        raise Absent(f"this tree's {candidate} has no {name}")
    raise Absent(f"this tree has no module {candidates[0]}")


def _where(exc: BaseException) -> str:
    """An exception's class and where it was raised: never its message."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return type(exc).__name__
    last = frames[-1]
    return f"{type(exc).__name__} at {Path(last.filename).name}:{last.lineno} ({last.name})"


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


def _space(text: Any) -> str:
    return " ".join(str(text or "").split())


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class _Units:
    """The units of one mode, each key unique within its surface."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.rows: list[dict[str, Any]] = []
        self._seen: dict[tuple[str, str], int] = {}

    def add(
        self, surface: str, key: str, text: Any, *, group: str = "", dynamic: bool = False
    ) -> None:
        said = str(text if text is not None else "")
        base = f"{group} | {key}" if group and surface in ORDERED else key
        count = self._seen.get((surface, base), 0) + 1
        self._seen[(surface, base)] = count
        row: dict[str, Any] = {
            "mode": self.mode,
            "surface": surface,
            "group": group,
            "key": base if count == 1 else f"{base} ({count})",
            "text": said,
        }
        if dynamic:
            row["dynamic"] = True
        self.rows.append(row)


_HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


def markdown_units(markdown: str, units: _Units) -> None:
    """Every line of the Markdown as it is, blank and fenced ones too, under its section path.

    ``banner``: every line of the title block, before the first section.
    """
    path: list[str] = []
    fenced = False
    before_body = True
    for text in markdown.splitlines():
        if _FENCE.match(text):
            fenced = not fenced
        heading = None if fenced else _HEADING.match(text)
        if heading is not None:
            level = len(heading.group(1))
            path = [*path[: level - 1], heading.group(2)]
            path += [""] * (level - len(path))
            if level == 2:
                before_body = False
        group = " > ".join(p for p in path if p)
        units.add("report.md", "line", text, group=group)
        if before_body:
            units.add("banner", "line", text, group="title block")


# The attributes whose value a reader is shown: a tooltip, a name read aloud, an
# image's text. Each is a unit (``html.attrs``) wherever it stands.
_SHOWN_ATTRIBUTES: tuple[str, ...] = ("title", "aria-label", "alt")


class _HtmlReader(HTMLParser):
    """The cover's fields, each figure's text, note paragraphs, and every shown attribute.

    A figure's parts: its caption, its legend, each SVG ``<text>`` label, each
    ``<title>`` (a tooltip) and any other text inside it.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.header: list[str] = []
        self.figures: list[tuple[str, str, str]] = []  # (figure id, part, text)
        self.notes: list[tuple[str, str]] = []  # (section, text)
        self.attributes: list[tuple[str, str, str]] = []  # (where, "tag attribute", value)
        self._in_header = 0
        self._chunk: list[str] = []
        self._section: list[str] = ["", ""]
        self._heading: list[str] | None = None
        self._heading_level = 0
        self._figure: str | None = None
        self._figures_seen = 0
        self._svg_text: list[str] | None = None
        self._title: list[str] | None = None
        self._caption: list[str] | None = None
        self._legend: list[str] | None = None
        self._paragraph: dict[str, Any] | None = None
        self._notes_list = False
        self._note_item: list[str] | None = None

    def _flush_header(self) -> None:
        said = _space("".join(self._chunk))
        if said:
            self.header.append(said)
        self._chunk = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        named = dict(attrs)
        classes = set(str(named.get("class") or "").split())
        if tag == "figure":
            self._figures_seen += 1
            self._figure = str(named.get("id") or f"figure {self._figures_seen}")
        where = self._figure or ("cover" if self._in_header or tag == "header" else self.section)
        for name in _SHOWN_ATTRIBUTES:
            if named.get(name) is not None:
                self.attributes.append((where, f"{tag} {name}", str(named[name])))
        if tag == "header":
            self._in_header += 1
            self._chunk = []
            return
        if self._in_header:
            if tag in {"br", "span", "p", "h1"}:
                self._flush_header()
            return
        if tag in {"h2", "h3"}:
            self._heading = []
            self._heading_level = int(tag[1])
        elif tag == "figure":
            pass
        elif self._figure is not None and tag == "text":
            self._svg_text = []
        elif self._figure is not None and tag == "title":
            self._title = []
        elif self._figure is not None and tag == "figcaption":
            self._caption = []
        elif self._caption is not None and tag == "span" and "fig-legend" in classes:
            self._legend = []
        elif tag == "p" and self._figure is None:
            self._paragraph = {"em": 0, "notes": [], "current": None, "outside": []}
        elif tag == "em" and self._paragraph is not None:
            self._paragraph["em"] += 1
            if self._paragraph["em"] == 1:
                self._paragraph["current"] = []
        elif tag == "ol" and "notes" in classes:
            self._notes_list = True
        elif tag == "li" and self._notes_list:
            self._note_item = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "header" and self._in_header:
            self._flush_header()
            self._in_header -= 1
            return
        if self._in_header:
            if tag in {"span", "p", "h1"}:
                self._flush_header()
            return
        if tag in {"h2", "h3"} and self._heading is not None:
            title = _space("".join(self._heading))
            if self._heading_level == 2:
                self._section = [title, ""]
            else:
                self._section = [self._section[0], title]
            self._heading = None
        elif tag == "text" and self._svg_text is not None and self._figure is not None:
            self.figures.append((self._figure, "label", _space("".join(self._svg_text))))
            self._svg_text = None
        elif tag == "title" and self._title is not None and self._figure is not None:
            self.figures.append((self._figure, "title", _space("".join(self._title))))
            self._title = None
        elif tag == "span" and self._legend is not None and self._figure is not None:
            self.figures.append((self._figure, "legend", _space("".join(self._legend))))
            self._legend = None
        elif tag == "figcaption" and self._caption is not None and self._figure is not None:
            self.figures.append((self._figure, "caption", _space("".join(self._caption))))
            self._caption = None
        elif tag == "figure":
            self._figure = None
        elif tag == "em" and self._paragraph is not None and self._paragraph["em"]:
            self._paragraph["em"] -= 1
            if self._paragraph["em"] == 0:
                said = _space("".join(self._paragraph["current"] or []))
                if said:
                    self._paragraph["notes"].append(said)
                self._paragraph["current"] = None
        elif tag == "p" and self._paragraph is not None:
            paragraph, self._paragraph = self._paragraph, None
            if paragraph["notes"] and not _space("".join(paragraph["outside"])):
                for said in paragraph["notes"]:
                    self.notes.append((self.section, said))
        elif tag == "li" and self._note_item is not None:
            said = _space("".join(self._note_item))
            if said:
                self.notes.append((self.section, said))
            self._note_item = None
        elif tag == "ol" and self._notes_list:
            self._notes_list = False

    @property
    def section(self) -> str:
        return " > ".join(p for p in self._section if p)

    def handle_data(self, data: str) -> None:
        if self._in_header:
            self._chunk.append(data)
            return
        if self._heading is not None:
            self._heading.append(data)
        if self._svg_text is not None:
            self._svg_text.append(data)
        elif self._title is not None:
            self._title.append(data)
        elif self._legend is not None:
            self._legend.append(data)
        elif self._caption is not None:
            self._caption.append(data)
        elif self._figure is not None and _space(data):
            # Any other text inside a figure: a description, a styled block.
            self.figures.append((self._figure, "text", _space(data)))
        if self._paragraph is not None:
            if self._paragraph["current"] is not None:
                self._paragraph["current"].append(data)
            else:
                self._paragraph["outside"].append(data)
        if self._note_item is not None:
            self._note_item.append(data)


class _HtmlBody(HTMLParser):
    """The text of every block of the body outside the cover and the figures, in order.

    A block (a paragraph, a list item, a heading, a preformatted block, a table
    row, a quote, a definition, the document's title, an SVG outside a figure)
    is one text; the cells of a row are joined with `` | ``. Each line of a
    style or a script is a block of its own, grouped under ``<style>`` or
    ``<script>``. The cover and the figures are :class:`_HtmlReader`'s.
    """

    _BLOCKS = frozenset(
        {
            "p",
            "li",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "pre",
            "blockquote",
            "dt",
            "dd",
            "tr",
            "caption",
            "summary",
            "div",
            "section",
            "article",
            "aside",
            "nav",
            "footer",
            "main",
            "details",
            "table",
            "ul",
            "ol",
            "dl",
            "title",
            "br",
            "hr",
        }
    )
    _CELLS = frozenset({"td", "th"})
    _SKIPPED = frozenset({"header", "figure"})
    _RAW = frozenset({"style", "script"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[tuple[str, str]] = []  # (section, text)
        self._chunk: list[str] = []
        self._skipping: list[str] = []
        self._raw: str | None = None
        self._section: list[str] = ["", ""]
        self._heading: list[str] | None = None
        self._heading_level = 0

    @property
    def section(self) -> str:
        return " > ".join(p for p in self._section if p)

    def _flush(self) -> None:
        # A row whose first cells are empty starts with a separator: dropped.
        said = _space("".join(self._chunk)).strip(" |")
        if said:
            self.blocks.append((self.section, said))
        self._chunk = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._skipping:
            if tag in self._SKIPPED:
                self._skipping.append(tag)
            return
        if tag in self._SKIPPED:
            self._flush()
            self._skipping.append(tag)
        elif tag in self._RAW:
            self._flush()
            self._raw = tag
        elif tag in self._CELLS:
            if _space("".join(self._chunk)):
                self._chunk.append(" | ")
        elif tag in self._BLOCKS:
            self._flush()
            if tag in {"h2", "h3"}:
                self._heading = []
                self._heading_level = int(tag[1])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self._skipping and tag in self._BLOCKS:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if self._skipping:
            if tag == self._skipping[-1]:
                self._skipping.pop()
            return
        if tag == self._raw:
            self._raw = None
            return
        if tag in self._BLOCKS:
            if tag in {"h2", "h3"} and self._heading is not None:
                title = _space("".join(self._heading))
                self._heading = None
                # The heading is a block of the section it opens.
                if self._heading_level == 2:
                    self._section = [title, ""]
                else:
                    self._section = [self._section[0], title]
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skipping:
            return
        if self._raw is not None:
            for line in data.splitlines():
                if line.strip():
                    self.blocks.append((f"<{self._raw}>", line.strip()))
            return
        self._chunk.append(data)
        if self._heading is not None:
            self._heading.append(data)

    def close(self) -> None:
        super().close()
        self._flush()


def html_units(
    document: str,
    units: _Units,
    *,
    dynamic_figures: Iterable[str] = (),
    prefix: str = "html",
) -> None:
    """Every text of the HTML and every shown attribute, under the surfaces ``prefix.*``.

    The cover's fields (``.header``), each figure's caption, legend, SVG
    labels, tooltips and other text (``.figure``), the note paragraphs
    (``.notes``), every other block (``.body``) and each ``title``,
    ``aria-label`` and ``alt`` attribute (``.attrs``).
    """
    reader = _HtmlReader()
    reader.feed(document)
    reader.close()
    body = _HtmlBody()
    body.feed(document)
    body.close()
    for section, said in body.blocks:
        units.add(f"{prefix}.body", "block", said, group=section)
    marked = set(dynamic_figures)
    for said in reader.header:
        units.add(f"{prefix}.header", "field", said, group="cover")
    for figure, part, said in reader.figures:
        units.add(
            f"{prefix}.figure", f"{figure} {part}", said, group=figure, dynamic=figure in marked
        )
    for section, said in reader.notes:
        units.add(f"{prefix}.notes", "note", said, group=section)
    for where, name, said in reader.attributes:
        units.add(f"{prefix}.attrs", name, said, group=where, dynamic=where in marked)


def canonical(value: Any) -> str:
    """``value`` as canonical JSON: sorted keys, one line, the text as it is."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(", ", ": "), default=str
    )


def _without(row: Mapping[str, Any], *names: str) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in names}


def _ioc_units(rows: Sequence[Mapping[str, Any]], units: _Units, *, dynamic: bool) -> None:
    """Each row as served, keyed by its kind and value, every other field its text."""
    for surface, wanted in (("iocs.default", True), ("iocs.all", None)):
        for row in rows:
            if wanted is not None and row.get("published") is not wanted:
                continue
            key = f"{row.get('kind') or ''} {row.get('value') or ''}"
            text = canonical(_without(row, "kind", "value"))
            units.add(
                surface,
                key,
                text,
                group=str(row.get("kind") or ""),
                dynamic=dynamic and str(row.get("source") or "") in DYNAMIC_IOC_SOURCES,
            )


def _stix_ident(obj: Mapping[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, Mapping) and ref.get("external_id"):
            return str(ref["external_id"])
    for name in ("name", "pattern", "value", "abstract", "content", "path", "key"):
        if obj.get(name):
            return _space(obj[name])[:200]
    return ""


def stix_keys(objects: Sequence[Mapping[str, Any]]) -> tuple[list[str], dict[str, str]]:
    """Each object's key, in order, and the map from an object's id to its key.

    An object is keyed by its type and identity (:func:`_stix_ident`), numbered
    on a repeat; a relationship by its source's key, its type and its target's
    key, so one pointed elsewhere is another unit. A ref to an object the
    bundle does not hold stays the id it is.
    """
    seen: dict[str, int] = {}
    by_id: dict[str, str] = {}
    keys: list[str] = [""] * len(objects)

    def _numbered(base: str) -> str:
        count = seen.get(base, 0) + 1
        seen[base] = count
        return base if count == 1 else f"{base} ({count})"

    relationships = [i for i, o in enumerate(objects) if o.get("type") == "relationship"]
    for index, obj in enumerate(objects):
        if index in relationships:
            continue
        keys[index] = _numbered(f"{obj.get('type') or ''} {_stix_ident(obj)}".strip())
        if obj.get("id"):
            by_id[str(obj["id"])] = keys[index]
    for index in relationships:
        obj = objects[index]
        source = str(obj.get("source_ref") or "")
        target = str(obj.get("target_ref") or "")
        keys[index] = _numbered(
            f"relationship {by_id.get(source, source)} {obj.get('relationship_type') or ''} "
            f"{by_id.get(target, target)}"
        )
        if obj.get("id"):
            by_id[str(obj["id"])] = keys[index]
    return keys, by_id


def _stix_value(value: Any, by_id: Mapping[str, str], *, top: bool = False) -> Any:
    """``value`` with each id of the bundle a ref names said as its object's key.

    ``top``: the object itself, whose ``id`` is a unit of its own.
    """
    if isinstance(value, Mapping):
        return {str(k): _stix_value(v, by_id) for k, v in value.items() if not (top and k == "id")}
    if isinstance(value, list):
        return [_stix_value(v, by_id) for v in value]
    if isinstance(value, str) and _STIX_ID.match(value) and value in by_id:
        return f"-> {by_id[value]}"
    return value


def _stix_text(obj: Mapping[str, Any], by_id: Mapping[str, str] | None = None) -> str:
    """Every property of the object but its id (a unit of its own), timestamps too, as JSON."""
    return canonical(_stix_value(obj, by_id or {}, top=True))


def _stix_units(
    served: Mapping[str, Any],
    units: _Units,
    *,
    dynamic: bool,
    surface: str = "stix",
    notice_surface: str = "stix.notice",
) -> None:
    """The bundle as served: its envelope, its own properties, and each object and its id.

    Each object is two units: its ``id``, and every other property as
    canonical JSON, each ref said as its target's key. The bundle's own
    properties (its id, its flags) are the unit ``bundle``; the envelope an
    unpublished bundle is served in, the unit ``envelope``.
    """
    found = served.get("bundle")
    bundle: Mapping[str, Any] = found if isinstance(found, Mapping) else served
    notice = served.get("notice") or bundle.get("x_malspark_notice")
    units.add(notice_surface, "notice", notice or "(none)")
    if isinstance(found, Mapping):
        units.add(surface, "envelope", canonical(_without(served, "bundle")))
    units.add(surface, "bundle", canonical(_without(bundle, "objects")))
    objects = [o for o in bundle.get("objects") or [] if isinstance(o, Mapping)]
    keys, by_id = stix_keys(objects)
    for obj, key in zip(objects, keys, strict=True):
        kind = str(obj.get("type") or "")
        moving = dynamic and kind in DYNAMIC_STIX_TYPES
        units.add(surface, key, _stix_text(obj, by_id), group=kind, dynamic=moving)
        units.add(surface, f"{key} id", str(obj.get("id") or ""), group=kind, dynamic=moving)


def _judge_view_units(view: Mapping[str, Any], units: _Units) -> None:
    """The judge-source view: its envelope (kept, reason, labels, notice) and its objects."""
    units.add("stix.judge.notice", "envelope", canonical(_without(view, "bundle")))
    found = view.get("bundle")
    if isinstance(found, Mapping):
        _stix_units(
            {"bundle": found, "notice": view.get("notice")},
            units,
            dynamic=False,
            surface="stix.judge",
            notice_surface="stix.judge.notice",
        )


def _mitre_units(rows: Sequence[Mapping[str, Any]] | None, units: _Units) -> None:
    if not rows:
        units.add("mitre", "techniques", "(none)")
        return
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        units.add(
            "mitre", str(row.get("technique_id") or ""), canonical(_without(row, "technique_id"))
        )


def _misp_units(event: Mapping[str, Any], units: _Units) -> None:
    """The event without its lists, each attribute, each object and each object attribute.

    Each as canonical JSON with every field it has: the event keyed ``event``,
    an attribute by its type and value, an object by its name, an object's
    attribute by its object's name and its relation.
    """
    found = event.get("Event")
    body: Mapping[str, Any] = found if isinstance(found, Mapping) else event
    if isinstance(found, Mapping) and len(event) > 1:
        units.add("misp", "envelope", canonical(_without(event, "Event")))
    units.add("misp", "event", canonical(_without(body, "Attribute", "Object")))
    for attribute in body.get("Attribute") or []:
        if not isinstance(attribute, Mapping):
            continue
        key = f"attribute {attribute.get('type') or ''} {attribute.get('value') or ''}"
        units.add("misp", key, canonical(attribute), group=str(attribute.get("type") or ""))
    for obj in body.get("Object") or []:
        if not isinstance(obj, Mapping):
            continue
        name = str(obj.get("name") or "")
        units.add("misp", f"object {name}", canonical(_without(obj, "Attribute")), group="object")
        for attribute in obj.get("Attribute") or []:
            if isinstance(attribute, Mapping):
                key = f"object {name} {attribute.get('object_relation') or ''}"
                units.add("misp", key, canonical(attribute), group="object")


def _layer_units(layer: Mapping[str, Any], units: _Units) -> None:
    """The layer's own fields, each legend item, and each technique with every field it has."""
    units.add("navigator", "description", layer.get("description") or "")
    units.add("navigator", "layer", canonical(_without(layer, "techniques", "legendItems")))
    for item in layer.get("legendItems") or []:
        if isinstance(item, Mapping):
            units.add("navigator", f"legend {item.get('label') or ''}", canonical(item))
    for row in layer.get("techniques") or []:
        if not isinstance(row, Mapping):
            continue
        units.add(
            "navigator",
            f"technique {row.get('techniqueID') or ''}",
            canonical(_without(row, "techniqueID")),
        )


def _call_map_units(found: Mapping[str, Any], units: _Units) -> None:
    """The map without its functions, and each function with every field it has."""
    units.add("call_map", "map", canonical(_without(found, "functions")))
    for function in found.get("functions") or []:
        if not isinstance(function, Mapping):
            continue
        key = str(function.get("address") or ", ".join(function.get("names") or []) or "?")
        units.add("call_map", f"function {key}", canonical(_without(function, "address")))


def _rule_units(
    signatures: Sequence[Mapping[str, Any]],
    downloads: Mapping[str, str],
    units: _Units,
) -> None:
    """Each drafted rule's every field, every line of its body, and every line of each download."""
    for rule in signatures:
        if not isinstance(rule, Mapping):
            continue
        name = f"{rule.get('kind') or ''} {rule.get('name') or ''}"
        units.add("rules", name, canonical(_without(rule, "body")))
        for line in str(rule.get("body") or "").splitlines():
            units.add("rules.body", "line", line, group=name)
    if not signatures:
        units.add("rules", "drafts", "(none)")
    for kind, download in downloads.items():
        for line in download.splitlines():
            units.add("rules.download", "line", line, group=kind)


def _bundle_units(document: Mapping[str, Any], units: _Units) -> None:
    """The bundle's numbered notes, every line of its sections, and the rest of the document.

    A line is a unit whether the model or the platform wrote it, blank and
    fenced ones too: a heading with its tag, a note in italics, a quote, a
    table row, a list item, a line of a code block. Each section's other
    fields, the header, each evidence entry and every other field of the
    document are units of ``bundle.index``.
    """
    for note in document.get("notes") or []:
        if isinstance(note, Mapping):
            units.add(
                "bundle.notes",
                f"note {note.get('number')}",
                canonical(_without(note, "number")),
                group="notes",
            )
    for section in document.get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        group = str(section.get("title") or section.get("anchor") or "")
        units.add("bundle.index", f"section {group}", canonical(_without(section, "markdown")))
        for line in str(section.get("markdown") or "").splitlines():
            units.add("bundle.lines", "line", line, group=group)
    header = document.get("report")
    if isinstance(header, Mapping):
        units.add("bundle.index", "report", canonical(header))
    units.add("bundle.index", "format", str(document.get("format") or ""))
    rest = _without(document, "notes", "sections", "report", "format", "evidence_index")
    units.add("bundle.index", "document", canonical(rest))
    for row in document.get("evidence_index") or []:
        if isinstance(row, Mapping):
            units.add("bundle.index", f"entry {row.get('id')}", canonical(_without(row, "id")))


# ---------------------------------------------------------------------------
# One run under the tree this process imports
# ---------------------------------------------------------------------------


def _digests(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(p for p in Path(root).rglob("*") if p.is_file()):
        found = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                found.update(block)
        out[path.relative_to(root).as_posix()] = found.hexdigest()
    return out


def _read(root: Path, name: str) -> Any:
    path = root / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None


def _evidence_rows(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, dict):
        found = document.get("items") or document.get("entries")
    else:
        found = document
    return [row for row in found if isinstance(row, dict)] if isinstance(found, list) else []


class _Stored:
    """What a stored run holds that the surfaces read, read once and never written."""

    def __init__(self, root: Path) -> None:
        self.root = root
        byjob = _read(root, "report-byjob.json")
        self.byjob: dict[str, Any] = byjob if isinstance(byjob, dict) else {}
        report = self.byjob.get("malware_report")
        self.report_source = "report-byjob.json"
        if not isinstance(report, dict):
            report = _read(root, "report.json")
            self.report_source = "report.json"
        self.report: dict[str, Any] | None = report if isinstance(report, dict) else None
        job = _read(root, "job.json")
        self.job: dict[str, Any] = job if isinstance(job, dict) else {}
        self.evidence = _evidence_rows(_read(root, "evidence.json"))
        summary = _read(root, "run-summary.json")
        if not isinstance(summary, dict):
            summary = self.byjob.get("run_summary")
        self.run_summary: dict[str, Any] = summary if isinstance(summary, dict) else {}
        # The judge-source view as the run served it: the row's judge column is
        # what it holds besides the envelope the route adds.
        judge = _read(root, "stix-judge.json")
        self.judge_view: dict[str, Any] | None = judge if isinstance(judge, dict) else None

    @property
    def judge_column(self) -> dict[str, Any] | None:
        """The report row's ``judge_stix_bundle`` column, read back from the served view."""
        view = self.judge_view
        if view is None:
            raise Absent("the stored run holds no judge-source view (stix-judge.json)")
        if view.get("kept") is False:
            return None
        return {k: v for k, v in view.items() if k in {"bundle", "labels", "as_written"}}

    @property
    def report_id(self) -> str:
        return str(self.byjob.get("id") or "")

    @property
    def job_id(self) -> str | None:
        return str(self.byjob.get("job_id") or self.job.get("id") or "") or None

    @property
    def settings(self) -> dict[str, Any]:
        snapshot = self.run_summary.get("settings_snapshot")
        return snapshot if isinstance(snapshot, dict) else {}


class _Mode:
    """The units, the reasons and the rendered files of one mode over one run."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.units = _Units(mode)
        self.not_produced: list[dict[str, Any]] = []
        self.files: dict[str, str] = {}

    def lack(self, surfaces: Iterable[str], why: str, *, error: bool = False) -> None:
        for surface in surfaces:
            row: dict[str, Any] = {"mode": self.mode, "surface": surface, "reason": why}
            if error:
                row["error"] = True
            self.not_produced.append(row)

    def produce(self, surfaces: Sequence[str], make: Callable[[], None]) -> None:
        """Run ``make``; the surfaces it fills are not produced, with why, when it cannot."""
        before = len(self.units.rows)
        written = set(self.files)
        try:
            make()
            # A surface rendered with nothing on it is said as one unit, so its
            # appearing on the other side is a change, never a silence.
            held = {row["surface"] for row in self.units.rows[before:]}
            for surface in surfaces:
                if surface not in held:
                    self.units.add(surface, "(empty)", "(nothing printed)")
        except Absent as exc:
            self._drop(before, written)
            self.lack(surfaces, str(exc))
        except Exception as exc:  # noqa: BLE001 — named as an error, the other surfaces stand
            self._drop(before, written)
            self.lack(surfaces, f"raised: {_where(exc)}", error=True)

    def _drop(self, before: int, written: set[str]) -> None:
        """The units and the files a surface that could not be produced left behind."""
        del self.units.rows[before:]
        for name in set(self.files) - written:
            del self.files[name]


def _environment(stored: _Stored) -> Any:
    """The tree's replay guard over the run's settings, or a block that changes nothing."""
    try:
        guard = entry("scripts.replay.guard", "replay_environment")
    except Absent:
        from contextlib import nullcontext

        return nullcontext()
    return guard(stored.settings)


def _typed(report: Mapping[str, Any]) -> Any:
    """The stored report as the tree's model, read in sorted key order as the API reads it."""
    model = entry("platform.reporting.models", "MalwareReport")
    try:
        ordered = entry("platform.reporting.models", "key_ordered")(report)
    except Absent:
        ordered = report
    return model.model_validate(ordered)


def _served_stix(bundle: Any) -> dict[str, Any]:
    """The bundle as ``/reports/{id}/stix`` serves it: renamed properties, a draft enveloped."""
    if not isinstance(bundle, dict) or not bundle:
        raise Absent("no STIX bundle is stored on the report row")
    try:
        served: dict[str, Any] = dict(
            entry("platform.schemas.stix_models", "with_current_property_names")(bundle)
        )
    except Absent:
        served = dict(bundle)
    if served.get("x_malspark_published") is False:
        try:
            notice = entry("platform.schemas.stix_models", "UNPUBLISHED_NOTICE")
        except Absent:
            # A tree from before the notice served the bundle as it was stored.
            return served
        return {"published": False, "notice": notice, "bundle": served}
    return served


def _routed_stix(export: Any, judge: Any, source: str, report_id: str) -> dict[str, Any]:
    """What the tree's ``/reports/{id}/stix`` route answers for a row holding these columns.

    The route itself is called, its service the tree's own ``ReportService``
    reading a row of the two columns, so the envelope, the notice and the
    renamed properties are the tree's. A tree without the route serves the
    export as :func:`_served_stix` does; the judge source, which only the route
    serves, is then not produced.
    """
    import asyncio
    import inspect
    import uuid
    from types import SimpleNamespace

    try:
        route = entry("app.api.v1.reports", "get_stix_bundle")
        service = entry("app.services.report_service", "ReportService")
    except Absent:
        if source == "judge":
            raise
        return _served_stix(export)
    parameters = inspect.signature(route).parameters
    if source == "judge" and "source" not in parameters:
        raise Absent("this tree's /stix route serves no judge source")
    row = SimpleNamespace(
        id=report_id or None, stix_bundle=export, judge_stix_bundle=judge, malware_report=None
    )

    class _Row(service):  # type: ignore[misc, valid-type]
        async def get_report(self, *_args: Any, **_kwargs: Any) -> Any:
            return row

    named: dict[str, Any] = {
        "report_id": uuid.UUID(int=0),
        "user": None,
        "svc": _Row(None),
    }
    if "source" in parameters:
        named["source"] = source
    try:
        answer = asyncio.run(route(**named))
    except Exception as exc:
        # The route's 404, with what it says: no surface, never an empty one.
        status = getattr(exc, "status_code", None)
        if status is None:
            raise
        raise Absent(f"the route answers {status}: {getattr(exc, 'detail', '')}") from exc
    return dict(answer)


def _render(
    mode: _Mode,
    stored: _Stored,
    report: Any,
    mr: dict[str, Any],
    *,
    untyped: str = "",
    **parts: Any,
) -> None:
    """Every surface of one report: the renderers' and the API writers' own output.

    ``report`` is the typed report, ``None`` when it does not read as the tree's
    model (``untyped`` says why): the surfaces the API builds from the stored
    document alone are produced all the same, as the API serves them.
    """
    dynamic = mode.mode == "build"
    # The layout the API serves the report in, by the run's settings
    # (``reporting.full_report_in_one_file``, read under the replay guard);
    # a tree without layouts prints its one.
    try:
        layout: str | None = str(entry("platform.reporting.renderers.layout", "report_layout")())
    except Absent:
        layout = None

    def _need() -> Any:
        if report is None:
            raise Absent(untyped)
        return report

    def _laid_out(module: str, name: str) -> Any:
        renderer = entry(module, name)
        if layout is None:
            return renderer()
        try:
            return renderer(layout=layout)
        except TypeError as exc:
            raise Absent(f"this tree's {name} prints no {layout} layout") from exc

    def _markdown() -> None:
        renderer = _laid_out("platform.reporting.renderers.markdown", "MarkdownRenderer")
        text = str(renderer.render(_need()))
        mode.files["report.md"] = text
        markdown_units(text, mode.units)

    def _html() -> None:
        renderer = _laid_out("platform.reporting.renderers.html", "HtmlRenderer")
        text = str(renderer.render(_need()))
        mode.files["report.html"] = text
        html_units(text, mode.units, dynamic_figures=DYNAMIC_FIGURES if dynamic else ())

    def _iocs() -> None:
        feed = entry("app.services.report_service", "ioc_feed_rows")
        rows = list(feed(mr))
        # The kinds served only to a filter that names them, after the rest.
        held = {(row.get("kind"), row.get("value")) for row in rows}
        for kind in _FILTERED_IOC_KINDS:
            try:
                only = feed(mr, kind)
            except TypeError:
                break  # a feed without the filter serves every kind unfiltered
            rows += [r for r in only if (r.get("kind"), r.get("value")) not in held]
        mode.files["iocs.json"] = _json({"items": rows, "total": len(rows)})
        default = [row for row in rows if row.get("published") is True]
        mode.files["iocs-default.json"] = _json({"items": default, "total": len(default)})
        _ioc_units(rows, mode.units, dynamic=dynamic)

    def _stix() -> None:
        served = parts["stix"]()
        mode.files["stix-bundle.json"] = _json(served)
        _stix_units(served, mode.units, dynamic=dynamic)

    def _stix_note() -> None:
        # The note the detail endpoint serves beside the report (``with_current_iocs``).
        with_current_iocs = entry("app.services.report_service", "with_current_iocs")
        _served, note = with_current_iocs(dict(mr), stored.report_id)
        mode.files["stix-note.txt"] = f"{note or '(none)'}\n"
        mode.units.add("stix.note", "note", note or "(none)")

    def _judge_view() -> None:
        view = parts["judge"]()
        mode.files["stix-judge.json"] = _json(view)
        _judge_view_units(view, mode.units)

    def _mitre() -> None:
        rows = parts["mitre"]()
        mode.files["mitre.json"] = _json({"techniques": rows or []})
        _mitre_units(rows, mode.units)

    def _misp() -> None:
        event = parts["misp"](_need())
        mode.files["misp-event.json"] = _json(event)
        _misp_units(event, mode.units)

    def _layer() -> None:
        build_layer = entry("platform.reporting.navigator_layer", "build_layer")
        layer = build_layer(mr, name=f"Malspark report {stored.report_id}")
        mode.files["attack-layer.json"] = _json(layer)
        _layer_units(layer, mode.units)

    def _call_map() -> None:
        call_map = entry("platform.reporting.call_map", "call_map")
        stored_ledger = entry("platform.reporting.follow_up", "stored_ledger")
        if not stored.evidence:
            raise Absent("the stored run holds no evidence ledger")
        found = call_map(stored_ledger(stored.evidence)[0])
        mode.files["call-map.json"] = _json(found)
        _call_map_units(found, mode.units)

    def _rules() -> None:
        signatures = [r for r in mr.get("detection_signatures") or [] if isinstance(r, dict)]
        download = entry("app.services.report_service", "signature_download")
        downloads: dict[str, str] = {}
        mode.files["signatures.json"] = _json(signatures)
        for kind in RULE_KINDS:
            downloads[kind] = str(download(signatures, kind, "all"))
            if downloads[kind]:
                mode.files[f"signatures-{kind}.txt"] = downloads[kind]
        _rule_units(signatures, downloads, mode.units)

    def _bundle() -> None:
        text = str(entry("platform.reporting.renderers.bundle", "bundle_json")(_need()))
        mode.files["evidence-bundle.json"] = text
        _bundle_units(json.loads(text), mode.units)

    def _bundle_html() -> None:
        # ``/reports/{id}/evidence-bundle.html``: the bundle layout, whatever the run's.
        layout_name = entry("platform.reporting.renderers.layout", "BUNDLE")
        renderer = entry("platform.reporting.renderers.html", "HtmlRenderer")(layout=layout_name)
        text = str(renderer.render(_need()))
        mode.files["evidence-bundle.html"] = text
        html_units(
            text,
            mode.units,
            dynamic_figures=DYNAMIC_FIGURES if dynamic else (),
            prefix="bundle.html",
        )

    mode.produce(("report.md", "banner"), _markdown)
    mode.produce(("html.header", "html.figure", "html.notes", "html.body", "html.attrs"), _html)
    mode.produce(("iocs.default", "iocs.all"), _iocs)
    mode.produce(("stix", "stix.notice"), _stix)
    mode.produce(("stix.note",), _stix_note)
    mode.produce(("stix.judge", "stix.judge.notice"), _judge_view)
    mode.produce(("mitre",), _mitre)
    mode.produce(("misp",), _misp)
    mode.produce(("navigator",), _layer)
    mode.produce(("call_map",), _call_map)
    mode.produce(("rules", "rules.body", "rules.download"), _rules)
    mode.produce(("bundle.notes", "bundle.lines", "bundle.index"), _bundle)
    mode.produce(
        (
            "bundle.html.header",
            "bundle.html.figure",
            "bundle.html.notes",
            "bundle.html.body",
            "bundle.html.attrs",
        ),
        _bundle_html,
    )


def _json(value: Any) -> str:
    return json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False, default=str) + "\n"


def _misp_event(report: Any, mr: Mapping[str, Any], owner_id: str | None, report_id: str) -> Any:
    """The MISP event as ``/reports/{id}/misp-event`` builds it."""
    build_misp_event = entry("platform.reporting.misp", "build_misp_event")
    misp_owner = entry("platform.reporting.misp", "misp_owner")
    with_current_iocs = entry("app.services.report_service", "with_current_iocs")
    built = mr.get("misp_attributes") is not None
    owner = misp_owner(report, owner_id) if built else report_id
    served, _note = with_current_iocs(dict(mr), owner)
    return build_misp_event(report, served.get("misp_attributes") or [], owner=owner)


def _serve(stored: _Stored) -> _Mode:
    mode = _Mode("serve")
    if stored.report is None:
        mode.lack(
            SURFACES,
            "the stored run holds no report document (report-byjob.json's malware_report or "
            "report.json)",
        )
        return mode
    mr = stored.report
    with _environment(stored):
        report: Any = None
        untyped = ""
        try:
            report = _typed(mr)
        except Absent as exc:
            untyped = str(exc)
        except Exception as exc:  # noqa: BLE001 — the API answers 404 for these surfaces
            untyped = f"the stored report does not read as this tree's report model: {_where(exc)}"

        def _stix() -> Any:
            if "stix_bundle" not in stored.byjob:
                raise Absent("report-byjob.json holds no stix_bundle column")
            judge = stored.judge_column if stored.judge_view is not None else None
            return _routed_stix(stored.byjob.get("stix_bundle"), judge, "export", stored.report_id)

        def _judge() -> Any:
            return _routed_stix(
                stored.byjob.get("stix_bundle"), stored.judge_column, "judge", stored.report_id
            )

        def _mitre() -> Any:
            if "mitre_techniques" not in stored.byjob:
                raise Absent("report-byjob.json holds no mitre_techniques column")
            return stored.byjob.get("mitre_techniques")

        def _misp(typed: Any) -> Any:
            return _misp_event(typed, mr, stored.job_id, stored.report_id)

        _render(
            mode,
            stored,
            report,
            mr,
            untyped=untyped,
            stix=_stix,
            judge=_judge,
            mitre=_mitre,
            misp=_misp,
        )
    return mode


def _clock(stored: _Stored) -> datetime:
    """When the stored report was built, else when its job was made; the epoch with neither."""
    for said in (
        (stored.report or {}).get("generated_at"),
        stored.job.get("completed_at"),
        stored.job.get("created_at"),
    ):
        if said:
            try:
                return datetime.fromisoformat(str(said).replace("Z", "+00:00"))
            except ValueError:
                continue
    return datetime(1970, 1, 1, tzinfo=UTC)


def pin_clock(report: Any, stored: Mapping[str, Any] | None, clock: datetime) -> None:
    """Every value the build derived from the current time, set to the stored report's.

    The builder dates the cover from the clock it reads (``_build_front_matter``):
    the report date, the date inside the report number, the copyright year and
    the revision history's date. Each is set to the stored report's date
    (its ``front_matter.report_date``, else ``clock``'s), and ``generated_at``,
    which the export, the MISP event and the drafted rules read, to ``clock``.
    Only the date in each value is replaced, so a prefix, a digest or a wording
    the tree changed still shows.
    """
    report.generated_at = clock
    front = getattr(report, "front_matter", None)
    built = str(getattr(front, "report_date", "") or "")
    if front is None or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", built):
        return
    stored_front = (stored or {}).get("front_matter")
    stored_front = stored_front if isinstance(stored_front, Mapping) else {}
    pinned = str(stored_front.get("report_date") or "")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", pinned):
        pinned = f"{clock:%Y-%m-%d}"
    if front.report_number:
        front.report_number = str(front.report_number).replace(
            built.replace("-", ""), pinned.replace("-", "")
        )
    if getattr(front, "copyright", None):
        front.copyright = re.sub(rf"\b{built[:4]}\b", pinned[:4], str(front.copyright))
    front.report_date = pinned
    for row in getattr(report, "version_history", None) or []:
        if getattr(row, "date", None) == built:
            row.date = pinned


def _build(run_dir: Path, stored: _Stored) -> _Mode:
    """The report the replay rebuilds, captured where the export decided its values."""
    mode = _Mode("build")
    try:
        rules: Any = importlib.import_module("scripts.replay.rules")
        read_run = entry("scripts.replay.stored", "read_run")
        built_by = rules._build
        original = rules._report_values
    except (ImportError, AttributeError, Absent) as exc:
        mode.lack(SURFACES, f"this tree has no replay build to rebuild the report with ({exc})")
        return mode
    captured: dict[str, Any] = {}
    clock = _clock(stored)

    def _clocked(*args: Any, **kwargs: Any) -> Any:
        # The build's clock is the stored report's, set before the export and
        # the drafts read it: their object ids and dates derive from it, and
        # the cover's dates and report number are the stored report's.
        values = built_by(*args, **kwargs)
        built: Any = args[2] if len(args) > 2 else kwargs.get("built")
        if getattr(built, "report", None) is not None:
            pin_clock(built.report, stored.report, clock)
        return values

    def _capturing(*args: Any, **kwargs: Any) -> Any:
        values = original(*args, **kwargs)
        built: Any = args[1] if len(args) > 1 else kwargs.get("built")
        captured["report"] = built.report.model_copy(deep=True)
        captured["judged"] = args[2] if len(args) > 2 else kwargs.get("judged")
        return values

    rules._build, rules._report_values = _clocked, _capturing
    try:
        record = rules.replay_run(read_run(run_dir))
    except Exception as exc:  # noqa: BLE001 — the build raised: nothing to render
        mode.lack(SURFACES, f"the replay's build raised: {_where(exc)}", error=True)
        return mode
    finally:
        rules._build, rules._report_values = built_by, original
    report = captured.get("report")
    if report is None:
        why = "; ".join(
            f"{row.get('part')}: {row.get('why')}"
            for row in record.get("not_replayed") or []
            if row.get("error")
        )
        mode.lack(SURFACES, f"the replay did not rebuild the report ({why or 'no reason given'})")
        return mode
    with _environment(stored):
        if not report.figures:
            try:
                report.figures = entry("platform.reporting.figures", "build_figures")(report)
            except Absent as exc:
                mode.lack(
                    ("html.figure",),
                    f"the report node's figures are not drawn ({exc}); only the ones the "
                    "renderer draws itself are",
                )
        mr = report.model_dump(mode="json")

        def _judge_column() -> Any:
            # The column the worker stores (``judge_bundle_record``): the judge's
            # answer as written when the run kept it, else the rebuilt parse. The
            # label map is the stored record's: the replay keeps none of its own.
            judge = getattr(captured.get("judged"), "bundle", None)
            record = stored.judge_column if stored.judge_view is not None else None
            if judge is None:
                return None
            written = (record or {}).get("bundle") if (record or {}).get("as_written") else None
            build_record = entry("app.worker.analysis_worker", "judge_bundle_record")
            return build_record(
                {
                    "stix_output": judge.model_dump(),
                    "stix_labels": (record or {}).get("labels") or {},
                    "stix_written": written,
                }
            )

        def _export_column() -> Any:
            bundle = report.stix_bundle_extended
            if bundle:
                return bundle
            judge = getattr(captured.get("judged"), "bundle", None)
            if judge is None:
                raise Absent("the rebuilt report holds no export and the judge's bundle is absent")
            # The worker stores the judge's draft, marked unpublished, when no export exists.
            as_json = entry("app.worker.analysis_worker", "judge_bundle_json")(judge.model_dump())
            only = entry("platform.schemas.stix_models", "JUDGE_ONLY_PROPERTIES")
            flag = entry("platform.schemas.stix_models", "UNPUBLISHED_PROPERTY")
            notice = entry("platform.schemas.stix_models", "UNPUBLISHED_NOTICE")
            draft = {k: v for k, v in as_json.items() if k not in only}
            return {**draft, flag: False, "x_malspark_notice": notice}

        def _stix() -> Any:
            return _routed_stix(_export_column(), None, "export", stored.report_id)

        def _judge() -> Any:
            return _routed_stix(None, _judge_column(), "judge", stored.report_id)

        def _mitre() -> Any:
            extract = entry("app.worker.analysis_worker", "_extract_mitre")
            return extract({"malware_report": mr, "stix_bundle_extended": mr.get("stix_bundle")})

        def _misp(typed: Any) -> Any:
            return _misp_event(typed, mr, stored.job_id, stored.report_id)

        _render(mode, stored, report, mr, stix=_stix, judge=_judge, mitre=_mitre, misp=_misp)
    return mode


def platform_tree() -> str:
    """Where the platform this process renders with was imported from."""
    for package in _packages():
        try:
            found = importlib.import_module(package)
        except ModuleNotFoundError:
            continue
        return str(Path(str(found.__file__)).resolve().parents[2])
    return ""


def imported_from() -> dict[str, str | None]:
    """The directory each package the render reads was imported from, by name.

    The API (``app``) and the replay scripts (``scripts.replay``); ``None`` for
    one this tree does not hold. The platform's is the record's ``tree``.
    """
    out: dict[str, str | None] = {}
    for name in ("app", "scripts.replay"):
        try:
            found = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            missing = str(exc.name or "")
            if name != missing and not name.startswith(f"{missing}."):
                raise  # a module the package imports is missing: a broken tree
            out[name] = None
            continue
        at = getattr(found, "__file__", None)
        if at:
            out[name] = str(Path(at).resolve().parent)
        else:
            # A namespace package: each of its directories is said.
            out[name] = os.pathsep.join(str(Path(p).resolve()) for p in found.__path__)
    return out


def render_run(
    run_dir: Path, *, modes: Sequence[str] = MODES
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """One stored run's surface record under the tree this process imports, and its files.

    Every file of ``run_dir`` is digested before and after; a run changed while
    it was rendered raises ``RuntimeError``. Nothing is written.
    """
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"no stored run at {run_dir}")
    before = _digests(run_dir)
    stored = _Stored(run_dir)
    done: list[_Mode] = []
    # A cache of the render's own, as the replay keeps one: the machine's ATT&CK
    # cache is neither read nor written.
    cache = tempfile.mkdtemp(prefix="malspark-surfaces-attck-")
    previous = os.environ.get(ATTCK_CACHE_VARIABLE)
    if not os.environ.get(TREE_VARIABLE):
        os.environ[ATTCK_CACHE_VARIABLE] = cache
    try:
        for name in modes:
            done.append(_serve(stored) if name == "serve" else _build(run_dir, stored))
    finally:
        if previous is None:
            os.environ.pop(ATTCK_CACHE_VARIABLE, None)
        else:
            os.environ[ATTCK_CACHE_VARIABLE] = previous
        shutil.rmtree(cache, ignore_errors=True)
    if _digests(run_dir) != before:
        raise RuntimeError(f"the stored run {run_dir} changed while it was rendered")
    record = {
        "schema": SCHEMA,
        # A repeat's directory is named by its number alone: the run is named with its parent.
        "run": f"{run_dir.parent.name}/{run_dir.name}" if run_dir.name.isdigit() else run_dir.name,
        "path": str(run_dir),
        "tree": platform_tree(),
        "imported_from": imported_from(),
        "modes": list(modes),
        "report_source": stored.report_source if stored.report is not None else None,
        "limits": list(LIMITS),
        "excluded": [list(row) for row in EXCLUDED],
        "units": [row for mode in done for row in mode.units.rows],
        # Each rendered file's digest: a file that differs where no unit does is a change.
        "file_digests": {
            mode.mode: {name: digest(text) for name, text in sorted(mode.files.items())}
            for mode in done
        },
        "not_produced": [row for mode in done for row in mode.not_produced],
    }
    return record, {mode.mode: mode.files for mode in done}


def counts(record: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    """Units per mode and surface."""
    out: dict[str, dict[str, int]] = {}
    for row in record.get("units") or []:
        per = out.setdefault(str(row["mode"]), {})
        per[row["surface"]] = per.get(row["surface"], 0) + 1
    return out


# ---------------------------------------------------------------------------
# Two records compared, and the expectations
# ---------------------------------------------------------------------------


def _change(row_a: Mapping[str, Any] | None, row_b: Mapping[str, Any] | None) -> dict[str, Any]:
    row = row_a or row_b or {}
    kind = "changed" if row_a and row_b else "removed" if row_a else "added"
    return {
        "change": kind,
        "mode": row.get("mode"),
        "surface": row.get("surface"),
        "group": row.get("group") or "",
        "key": (row_b or row_a or {}).get("key"),
        "old": row_a.get("text") if row_a else None,
        "new": row_b.get("text") if row_b else None,
    }


def compare_records(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    """Every unit changed, added or removed between two records of one run.

    Every unit is compared, those marked dynamic too: both refs rebuild them
    from the same stored ledger without the sandbox report, so a difference
    between them is the trees'. A surface neither side produced is listed
    under ``not_compared`` with both reasons and counted in ``neither``.
    """
    changes: list[dict[str, Any]] = []
    rows_a = list(a.get("units") or [])
    rows_b = list(b.get("units") or [])
    # Each unit marked dynamic on either side, counted once.
    dynamic = len(
        {(r["mode"], r["surface"], r["key"]) for r in [*rows_a, *rows_b] if r.get("dynamic")}
    )
    keyed_a = {
        (r["mode"], r["surface"], r["key"]): r for r in rows_a if r["surface"] not in ORDERED
    }
    keyed_b = {
        (r["mode"], r["surface"], r["key"]): r for r in rows_b if r["surface"] not in ORDERED
    }
    for key in sorted(keyed_a.keys() | keyed_b.keys()):
        row_a, row_b = keyed_a.get(key), keyed_b.get(key)
        if row_a is None or row_b is None or row_a["text"] != row_b["text"]:
            changes.append(_change(row_a, row_b))
    groups: dict[tuple[str, str, str], tuple[list[Any], list[Any]]] = {}
    for side, rows in ((0, rows_a), (1, rows_b)):
        for row in rows:
            if row["surface"] in ORDERED:
                groups.setdefault((row["mode"], row["surface"], row["group"]), ([], []))[
                    side
                ].append(row)
    for key in sorted(groups):
        seq_a, seq_b = groups[key]
        matcher = difflib.SequenceMatcher(
            None, [r["text"] for r in seq_a], [r["text"] for r in seq_b], autojunk=False
        )
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op == "equal":
                continue
            olds, news = seq_a[i1:i2], seq_b[j1:j2]
            for index in range(max(len(olds), len(news))):
                changes.append(
                    _change(
                        olds[index] if index < len(olds) else None,
                        news[index] if index < len(news) else None,
                    )
                )
    changes += _file_changes(a, b, changes)
    compared: dict[str, int] = {}
    for mode, surface, _key in {(r["mode"], r["surface"], r["key"]) for r in [*rows_a, *rows_b]}:
        compared[f"{mode} {surface}"] = compared.get(f"{mode} {surface}", 0) + 1
    files_a, files_b = a.get("file_digests") or {}, b.get("file_digests") or {}
    for mode in set(files_a) & set(files_b):
        compared[f"{mode} {FILE_SURFACE}"] = len(set(files_a[mode]) | set(files_b[mode]))
    reasons_a = {(r["mode"], r["surface"]): r for r in a.get("not_produced") or []}
    reasons_b = {(r["mode"], r["surface"]): r for r in b.get("not_produced") or []}
    not_compared = [
        {
            "mode": key[0],
            "surface": key[1],
            "a": (reasons_a.get(key) or {}).get("reason"),
            "b": (reasons_b.get(key) or {}).get("reason"),
            # Produced by neither side: nothing of it was compared at all.
            "neither": key in reasons_a and key in reasons_b,
        }
        for key in sorted(reasons_a.keys() | reasons_b.keys())
    ]
    errors = [
        {"side": side, **row}
        for side, rows in (("a", a.get("not_produced")), ("b", b.get("not_produced")))
        for row in rows or []
        if row.get("error")
    ]
    out: dict[str, Any] = {"run": a.get("run") or b.get("run"), "changes": changes}
    out["summary"] = _summary(changes)
    out["compared"] = dict(sorted(compared.items()))
    out["dynamic_compared"] = dynamic
    out["neither"] = sum(1 for row in not_compared if row["neither"])
    if not_compared:
        out["not_compared"] = not_compared
    if errors:
        out["errors"] = errors
    return out


def _file_surfaces(name: str) -> set[str]:
    return {s for s, patterns in SURFACE_FILES.items() if any(fnmatch(name, p) for p in patterns)}


def _file_changes(
    a: Mapping[str, Any], b: Mapping[str, Any], changes: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Each rendered file that differs, or is on one side only, while no unit read from it does.

    What the units leave to the file (an attribute, the whitespace, the order
    of rows) is compared this way, so nothing a file holds goes unseen.
    """
    out: list[dict[str, Any]] = []
    digests_a = a.get("file_digests") or {}
    digests_b = b.get("file_digests") or {}
    moved = {(c["mode"], c["surface"]) for c in changes}
    for mode in sorted(set(digests_a) & set(digests_b)):
        held_a, held_b = digests_a[mode], digests_b[mode]
        for name in sorted(set(held_a) | set(held_b)):
            old, new = held_a.get(name), held_b.get(name)
            if old == new or any((mode, s) in moved for s in _file_surfaces(name)):
                continue
            out.append(
                {
                    "change": "changed" if old and new else "removed" if old else "added",
                    "mode": mode,
                    "surface": FILE_SURFACE,
                    "group": "the file differs where no unit read from it does",
                    "key": name,
                    "old": f"sha256:{old}" if old else None,
                    "new": f"sha256:{new}" if new else None,
                }
            )
    return out


def first_difference(old: str, new: str) -> tuple[str, str]:
    """The first line at which two texts differ, each side said with its line number."""
    lines_a, lines_b = old.splitlines(), new.splitlines()
    for index in range(max(len(lines_a), len(lines_b))):
        line_a = lines_a[index] if index < len(lines_a) else None
        line_b = lines_b[index] if index < len(lines_b) else None
        if line_a != line_b:
            return (
                f"line {index + 1}: {line_a if line_a is not None else '(no line)'}",
                f"line {index + 1}: {line_b if line_b is not None else '(no line)'}",
            )
    return ("the same lines; the line ends differ", "the same lines; the line ends differ")


def _summary(changes: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for change in changes:
        per = out.setdefault(f"{change['mode']} {change['surface']}", {})
        per[change["change"]] = per.get(change["change"], 0) + 1
    return dict(sorted(out.items()))


def read_expectations(path: Path) -> list[dict[str, Any]]:
    """The expected changes in ``path``, each checked to name a surface, a pattern and a reason."""
    found = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(found, dict):
        found = found.get("expectations")
    if not isinstance(found, list):
        raise ValueError(f"{path} holds no list of expectations")
    out: list[dict[str, Any]] = []
    for index, row in enumerate(found):
        if not isinstance(row, dict) or not row.get("surface") or not row.get("reason"):
            raise ValueError(f"expectation {index} names no surface or no reason")
        if not any(row.get(name) for name in ("key", "old", "new")):
            raise ValueError(f"expectation {index} names no key, old or new pattern")
        for name in ("key", "old", "new"):
            if row.get(name):
                re.compile(str(row[name]))
        out.append({**row, "index": index})
    return out


def _matches(expectation: Mapping[str, Any], change: Mapping[str, Any]) -> bool:
    if expectation["surface"] != change["surface"]:
        return False
    if expectation.get("mode") and expectation["mode"] != change["mode"]:
        return False
    for name, said in (("key", change["key"]), ("old", change["old"]), ("new", change["new"])):
        pattern = expectation.get(name)
        if pattern and (said is None or re.search(str(pattern), str(said)) is None):
            return False
    return True


def judge_changes(
    diffs: Sequence[dict[str, Any]], expectations: Sequence[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], list[Mapping[str, Any]]]:
    """Mark each change expected or not; return the unexpected and the unexercised expectations."""
    used: set[int] = set()
    unexpected: list[dict[str, Any]] = []
    for diff in diffs:
        for change in diff["changes"]:
            hit = next((e for e in expectations if _matches(e, change)), None)
            if hit is None:
                change["expected"] = False
                unexpected.append({"run": diff["run"], **change})
            else:
                change["expected"] = True
                change["reason"] = hit["reason"]
                used.add(int(hit["index"]))
    unexercised = [e for e in expectations if int(e["index"]) not in used]
    return unexpected, unexercised


# ---------------------------------------------------------------------------
# The two refs
# ---------------------------------------------------------------------------


def render_under(
    tree: Path,
    runs: Sequence[Path],
    out: Path,
    *,
    modes: Sequence[str] = MODES,
    timeout: float | None = None,
) -> list[dict[str, Any]]:
    """This driver run against ``tree`` in a process of its own; the records it wrote.

    ``tree`` and its API come first on the import path and nothing of this
    checkout is put on it, so every entry point is the tree's own.
    """
    from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree / "apps" / "api"), str(tree)])
    env[TREE_VARIABLE] = str(tree.resolve())
    env[PACKAGES_VARIABLE] = f"{CURRENT_NAME},{PREVIOUS_NAME}"
    cache = out.with_name(f"{out.name}-attck")
    cache.mkdir(parents=True, exist_ok=True)
    env[ATTCK_CACHE_VARIABLE] = str(cache.resolve())
    previous = PREVIOUS_NAME.upper() + ATTCK_CACHE_VARIABLE.removeprefix(CURRENT_NAME.upper())
    env[previous] = str(cache.resolve())
    if out.exists():
        shutil.rmtree(out)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        *(str(Path(run).resolve()) for run in runs),
        "--out",
        str(out.resolve()),
        "--quiet",
        *(f"--mode={mode}" for mode in modes),
    ]
    try:
        done = subprocess.run(  # nosec B603 — this driver, an argument list
            command, env=env, cwd=tree, capture_output=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"the render under {tree} did not finish within {timeout:g} s and was stopped"
        ) from exc
    record_file = out / RECORD_FILE
    if done.returncode not in (0, 2) or not record_file.is_file():
        kept = out.with_name(f"{out.name}-stderr.txt")
        kept.write_bytes(done.stderr)
        raise RuntimeError(
            f"the render under {tree} wrote no record (exit status {done.returncode}; its error "
            f"output is kept in {kept})"
        )
    records = json.loads(record_file.read_text(encoding="utf-8"))
    for record in records:
        check_imports(record, tree)
    return list(records)


def check_imports(record: Mapping[str, Any], tree: Path) -> None:
    """Raise ``RuntimeError`` unless the record's packages were all imported from ``tree``.

    The platform, the API and the replay scripts; a package the tree does not
    hold passes as absent.
    """
    root = tree.resolve()
    if Path(str(record.get("tree") or "")).resolve() != root:
        raise RuntimeError(
            f"the render under {tree} imported its platform from {record.get('tree')}"
        )
    found = record.get("imported_from")
    if not isinstance(found, Mapping):
        raise RuntimeError(f"the render under {tree} did not say where it imported its API from")
    for name in ("app", "scripts.replay"):
        if name not in found:
            raise RuntimeError(f"the render under {tree} did not say where it imported {name} from")
        if found[name] is None:
            continue
        for at in str(found[name]).split(os.pathsep):
            where = Path(at).resolve()
            if where != root and root not in where.parents:
                raise RuntimeError(f"the render under {tree} imported {name} from {at}")


def _show_file_changes(diff: Mapping[str, Any], at_a: Path, at_b: Path) -> None:
    """Each changed file's first differing line beside its digests, read from the files written."""
    for change in diff["changes"]:
        if change["surface"] != FILE_SURFACE or change["change"] != "changed":
            continue
        try:
            old = (at_a / change["mode"] / change["key"]).read_text(encoding="utf-8")
            new = (at_b / change["mode"] / change["key"]).read_text(encoding="utf-8")
        except OSError:
            continue
        line_a, line_b = first_difference(old, new)
        change["old"] = f"{change['old']}; {line_a}"
        change["new"] = f"{change['new']}; {line_b}"


def _compare(
    runs: list[Path],
    refs: tuple[str, str],
    *,
    repo: Path,
    work: Path | None,
    timeout: float | None,
    modes: Sequence[str] = MODES,
) -> list[dict[str, Any]]:
    from scripts.replay import compare

    owned = work is None
    base = Path(tempfile.mkdtemp(prefix="malspark-surfaces-")) if work is None else work
    try:
        records: dict[str, list[dict[str, Any]]] = {}
        for side, ref in zip(("a", "b"), refs, strict=True):
            tree = compare.materialise(repo, ref, base / f"{side}-tree", harness=None)
            records[side] = render_under(
                tree, runs, base / f"{side}-out", modes=modes, timeout=timeout
            )
        diffs: list[dict[str, Any]] = []
        for a, b in zip(records["a"], records["b"], strict=True):
            diff = compare_records(a, b)
            _show_file_changes(
                diff, base / "a-out" / str(a.get("files")), base / "b-out" / str(b.get("files"))
            )
            diffs.append(diff)
        return diffs
    finally:
        if owned:
            shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def _safe(text: Any) -> str:
    try:
        from scripts.replay.output import terminal_safe
    except Exception:  # noqa: BLE001 — a tree without it: shown escaped all the same
        return str(text).encode("unicode_escape").decode("ascii")
    return terminal_safe(text)


def render_comparison(
    diffs: Sequence[Mapping[str, Any]],
    refs: tuple[str, str],
    unexercised: Sequence[Mapping[str, Any]],
) -> str:
    """The comparison as text: per run, the changes grouped by surface, then the counts."""
    ref_a, ref_b = refs
    lines: list[str] = []
    for diff in diffs:
        lines.append(f"run {_safe(diff['run'])}: {ref_a} -> {ref_b}")
        by_surface: dict[str, list[Mapping[str, Any]]] = {}
        for change in diff["changes"]:
            by_surface.setdefault(f"{change['mode']} {change['surface']}", []).append(change)
        for surface, changes in sorted(by_surface.items()):
            lines.append(f"  [{surface}]")
            for change in changes:
                mark = "expected" if change.get("expected") else "UNEXPECTED"
                where = f"{change['group']} | " if change["group"] else ""
                lines.append(f"    {change['change'].upper()} {mark}: {_safe(where)}")
                lines.append(f"      key: {_safe(change['key'])}")
                if change["old"] is not None:
                    lines.append(f"      - {_safe(change['old'])}")
                if change["new"] is not None:
                    lines.append(f"      + {_safe(change['new'])}")
                if change.get("reason"):
                    lines.append(f"      reason: {_safe(change['reason'])}")
        for row in diff.get("not_compared") or []:
            if row.get("neither"):
                lines.append(
                    f"  NOT COMPARED [{row['mode']} {row['surface']}]: produced by neither ref: "
                    f"A: {_safe(row['a'])}; B: {_safe(row['b'])}"
                )
            else:
                lines.append(
                    f"  PRODUCED BY ONE REF [{row['mode']} {row['surface']}]: A: "
                    f"{_safe(row['a'] or 'produced')}; B: {_safe(row['b'] or 'produced')}"
                )
        for row in diff.get("errors") or []:
            lines.append(
                f"  ERROR under {row['side'].upper()} [{row['mode']} {row['surface']}]: "
                f"{_safe(row['reason'])}"
            )
        if diff.get("dynamic_compared"):
            lines.append(
                f"  {diff['dynamic_compared']} unit(s) marked dynamic (drawn without the sandbox "
                "report) compared"
            )
        total = sum(sum(per.values()) for per in diff["summary"].values())
        unexpected = sum(1 for c in diff["changes"] if not c.get("expected"))
        neither = int(diff.get("neither") or 0)
        compared: Mapping[str, int] = diff.get("compared") or {}
        lines.append(
            f"  summary: {sum(compared.values())} unit(s) compared on {len(compared)} "
            f"surface(s), {total} difference(s), {unexpected} unexpected, "
            f"{neither} surface(s) not compared"
        )
        for surface in sorted(set(compared) | set(diff["summary"])):
            per = diff["summary"].get(surface) or {}
            said = ", ".join(f"{k} {v}" for k, v in sorted(per.items())) or "no difference"
            lines.append(f"    {surface}: {compared.get(surface, 0)} compared, {said}")
        if EXCLUDED:
            for surface, what, proof in EXCLUDED:
                lines.append(f"  excluded [{surface}] {what}: {proof}")
        else:
            lines.append("  excluded from the comparison: nothing")
        if not diff["changes"] and not neither:
            lines.append("  no difference: both refs render the same units")
        elif not diff["changes"]:
            lines.append(
                f"  no difference in the units compared; {neither} surface(s) produced by "
                "neither ref were not compared (listed above)"
            )
    for expectation in unexercised:
        lines.append(
            f"UNEXERCISED expectation {expectation['index']} [{_safe(expectation['surface'])}]: "
            f"{_safe(expectation['reason'])}: no difference matched it"
        )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/replay/render_surfaces.py",
        description=(
            "Render every published surface of stored runs, at zero cost, in two modes (serve: "
            "the stored report rendered as the API renders it; build: the report the replay "
            "rebuilds, rendered and exported), and compare two git refs unit by unit."
        ),
        epilog=(
            "Every value of every surface is compared, and a rendered file that differs where "
            "no unit does is a change of its own. Excluded from the comparison: "
            + ("; ".join(f"[{s}] {what}: {proof}" for s, what, proof in EXCLUDED) or "nothing")
            + ". Limits: "
            + " ".join(f"({n}) {limit}." for n, limit in enumerate(LIMITS, 1))
        ),
    )
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument(
        "--out", type=Path, help="write the surface record and the rendered files here"
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("REF_A", "REF_B"),
        help="render under two git refs and list every unit changed, added or removed",
    )
    parser.add_argument("--expect", type=Path, help="the expected changes (JSON), with --compare")
    parser.add_argument("--json", type=Path, help="write the comparison here, with --compare")
    parser.add_argument(
        "--work", type=Path, help="where --compare writes the trees (temporary by default)"
    )
    parser.add_argument(
        "--repo", type=Path, default=_ROOT, help="the repository the refs are read from"
    )
    parser.add_argument(
        "--timeout", type=float, metavar="SECONDS", help="how long each ref's render may take"
    )
    parser.add_argument(
        "--mode", choices=MODES, action="append", help="render one mode only (both by default)"
    )
    parser.add_argument(
        "--accept-not-compared",
        action="store_true",
        help=(
            "with --compare: a surface produced by neither ref (listed NOT COMPARED with both "
            f"reasons) does not end the comparison with status {EXIT_NOT_COMPARED}"
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="print nothing; write files only")
    return parser


def comparison_status(
    diffs: Sequence[Mapping[str, Any]],
    unexpected: Sequence[Any],
    unexercised: Sequence[Any],
    *,
    accept_not_compared: bool = False,
) -> int:
    """The comparison's exit status, the first that applies of :data:`EXIT_STATUSES`."""
    if any(diff.get("errors") for diff in diffs):
        return EXIT_ERROR
    if unexpected:
        return EXIT_UNEXPECTED
    if not accept_not_compared and any(diff.get("neither") for diff in diffs):
        return EXIT_NOT_COMPARED
    if unexercised:
        return EXIT_UNEXERCISED
    return 0


def _error(words: str) -> NoReturn:
    print(f"render_surfaces: {_safe(words)}", file=sys.stderr)
    raise SystemExit(2)


def _outside(path: Path, runs: Sequence[Path]) -> None:
    target = path.resolve()
    for run in runs:
        if target == run.resolve() or run.resolve() in target.parents:
            _error(f"refused: {path} is inside the stored run {run}")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8", "backslashreplace"))


def rendered_tree() -> Path:
    """The tree this process renders under: the one named to it, else this checkout."""
    named = os.environ.get(TREE_VARIABLE)
    return Path(named).resolve() if named else _ROOT


def write_out(out: Path, runs: Sequence[Path], modes: Sequence[str]) -> list[dict[str, Any]]:
    """Each run rendered into ``out``: the records in ``surfaces.json``, the files per run.

    The record is written, then each is checked to have imported the
    platform, the API and the replay scripts from the tree rendered under
    (:func:`check_imports`): ``RuntimeError`` when one came from elsewhere.
    """
    out.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    for index, run in enumerate(runs):
        record, files = render_run(run, modes=modes)
        name = f"{index:02d}-{re.sub(r'[^A-Za-z0-9._-]+', '-', record['run'])}"
        for mode, rendered in files.items():
            for file_name, text in rendered.items():
                _write_text(out / name / mode / file_name, text)
        record["files"] = name
        records.append(record)
    _write_text(out / RECORD_FILE, json.dumps(records, indent=1, ensure_ascii=True) + "\n")
    for record in records:
        check_imports(record, rendered_tree())
    return records


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    runs = [Path(run) for run in args.runs]
    for run in runs:
        if not run.is_dir():
            _error(f"no stored run at {run}")
    for written in (args.out, args.json, args.work):
        if written is not None:
            _outside(written, runs)
    modes = tuple(args.mode or MODES)
    if args.compare:
        expectations: list[dict[str, Any]] = []
        if args.expect is not None:
            try:
                expectations = read_expectations(args.expect)
            except (OSError, ValueError) as exc:
                _error(f"the expectations cannot be read: {exc}")
        try:
            diffs = _compare(
                runs,
                (args.compare[0], args.compare[1]),
                repo=args.repo,
                work=args.work,
                timeout=args.timeout,
                modes=modes,
            )
        except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
            _error(str(exc))
        unexpected, unexercised = judge_changes(diffs, expectations)
        if args.json is not None:
            _write_text(
                args.json,
                json.dumps({"runs": diffs, "unexercised": unexercised}, indent=1, ensure_ascii=True)
                + "\n",
            )
        if not args.quiet:
            print(render_comparison(diffs, (args.compare[0], args.compare[1]), unexercised))
        return comparison_status(
            diffs, unexpected, unexercised, accept_not_compared=args.accept_not_compared
        )
    if args.out is None:
        parser.error("name --out DIR, or --compare REF_A REF_B")
    try:
        records = write_out(args.out, runs, modes)
    except RuntimeError as exc:
        _error(f"refused: {exc}")
    raised = [row for record in records for row in record["not_produced"] if row.get("error")]
    if not args.quiet:
        for record in records:
            print(f"run {_safe(record['run'])}: {args.out / record['files']}")
            for mode, per in counts(record).items():
                print(f"  {mode}: " + ", ".join(f"{s} {n}" for s, n in sorted(per.items())))
            dynamic = sum(1 for row in record["units"] if row.get("dynamic"))
            if dynamic:
                print(
                    f"  note: {dynamic} unit(s) marked dynamic: the build drew them without the "
                    "sandbox report, so read against the stored report they differ"
                )
            for row in record["not_produced"]:
                mark = "ERROR " if row.get("error") else ""
                print(
                    f"  {mark}not produced [{row['mode']} {row['surface']}]: {_safe(row['reason'])}"
                )
    return 2 if raised else 0


def _prepare_path() -> None:
    """The tree rendered under first on the import path, and nothing outside it that competes.

    The tree is the one named in :data:`TREE_VARIABLE`, else this checkout:
    its root, its ``src`` and its API come before every other entry, so an
    editable install of another checkout is never what is imported, and every
    entry outside the tree that holds the platform, the API or the scripts is
    taken off, so a module the tree lacks is a module not found.
    """
    here = Path(__file__).resolve().parent
    root = rendered_tree()
    first = [str(root / "src"), str(root / "apps" / "api"), str(root)]
    sys.path[:] = first + [
        p for p in sys.path if p not in first and Path(p or ".").resolve() != here
    ]
    names = (*_packages(), "app", "scripts")

    def _foreign(entry: str) -> bool:
        at = Path(entry or ".").resolve()
        if at == root or root in at.parents or {"site-packages", "dist-packages"} & set(at.parts):
            return False
        return any((at / name).is_dir() for name in names)

    sys.path[:] = [p for p in sys.path if not _foreign(p)]


if __name__ == "__main__":
    _prepare_path()
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
        print(f"render_surfaces failed: {_where(exc)}", file=sys.stderr)
        sys.exit(2)
