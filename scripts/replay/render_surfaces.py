"""Render every published surface of a stored run, and compare the surfaces of two git refs.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/render_surfaces.py runs/plink-r4/1 --out DIR

renders what a reader of the run is shown, at zero cost, and writes a surface
record (``DIR/surfaces.json``) beside the rendered files (``DIR/<run>/<mode>/``:
``report.md``, ``report.html``, ``iocs.json``, ``iocs-default.json``,
``stix-bundle.json``, ``mitre.json``, ``misp-event.json``, ``attack-layer.json``,
``call-map.json``, ``evidence-bundle.json`` and one rule file per kind). Nothing
is written into a run's directory: every file of it is digested before and
after, and the command fails when a digest changed.

The record is a list of units, each with its ``surface``, the ``mode`` that
produced it, a ``group`` (a section path, a figure id, a rule kind), a stable
``key`` and its ``text``:

* ``report.md``: each line of the analyst-layout Markdown, under its section
  path; ``banner``: the title block's note and banner lines;
* ``html.header`` (the cover's fields), ``html.figure`` (each figure's caption,
  legend and every SVG ``<text>`` label), ``html.notes`` (a paragraph made of
  notes alone, the self-contained report's note list);
* ``iocs.default`` and ``iocs.all``: each row of ``/iocs`` (kind, value, publish
  answer, source, note), as served by default and with ``include=all``;
* ``stix``: each object's type, key and every text property;
  ``stix.notice``: the notice the API serves an unpublished bundle with;
* ``mitre``: each row of ``/mitre``; ``misp``: the event's info and each
  attribute; ``navigator``: the layer's description, legend and each
  technique's comment and metadata; ``call_map``: each function of the call
  map and its roots;
* ``rules``: each drafted detection rule as a digest of its body with its
  compile error, and ``rules.comments``: every comment line of each kind's
  download (``include=all``), the bodies' own comment lines among them;
* ``bundle.notes``: the evidence bundle's numbered notes and its platform note
  lines (each line of its sections written as a note: italic or quoted).

Two modes produce the units, and each unit says which:

* **serve**: the stored report (``report-byjob.json``'s ``malware_report``, else
  ``report.json``) typed under the tree's own models and passed to its
  renderers and the API's writers, as the API does for a stored job. The STIX
  bundle and ``/mitre`` are the stored report row's columns, served as the API
  serves them.
* **build**: the report rebuilt by the replay (``scripts/replay/rules.py``: the
  deterministic build, the stored composed sections put back, the export, the
  IOC table, the MISP attributes and the detection drafts), its figures drawn
  as the report node draws them and its clock set to the stored report's, then
  rendered and exported the same way.

A surface a tree cannot produce (a function its tree does not have, a stored
file the run lacks, a report the replay could not rebuild) is listed under
``not_produced`` with the reason; it is never skipped and never compared as
equal. One that raised is listed there too, marked as an error.

``--compare REF_A REF_B`` writes both refs out of the object store
(``scripts.replay.compare.materialise``) and runs *this* driver against each
tree in a process of its own, with that tree first on the import path: the
driver resolves the tree's entry points by name at run time, so a ref from
before this tool is rendered too, and an entry point it lacks is a surface not
produced. It prints, per run and grouped by surface, every unit changed, added
or removed with both texts, and a summary count. ``--expect FILE`` (JSON: a list
of ``{"surface", "mode"?, "key"?, "old"?, "new"?, "reason"}``, each pattern a
regular expression searched in the key or the text) names the changes
expected: a difference no expectation matches is UNEXPECTED, and an
expectation no difference matches is UNEXERCISED. The exit status is 0 when the
refs render the same or every difference was expected, 1 when a difference was
not expected, and 2 when a surface raised in either tree, a tree could not be
written out or rendered, or on an error.

Limits:

* serve mode cannot change platform text that was written before rendering
  and stored: clauses appended to section bodies, degradation reasons, the
  indicators' reasons, the figures a stored report holds are read as stored;
* build mode rebuilds without the sandbox report, so the units that only it
  fills (the process tree and network figures, the sandbox's IOC rows, the
  export's process, observed-data and network objects) are marked ``dynamic``
  and not compared;
* fields an older build lacked default to empty when typed under a newer
  model, so a re-render shows the differences between two refs only, and is
  not what a new run would print.
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

LIMITS: tuple[str, ...] = (
    "serve mode cannot change platform text that was written before rendering and stored: "
    "clauses appended to section bodies, degradation reasons, the indicators' reasons and the "
    "stored figures are read as stored",
    "build mode rebuilds without the sandbox report, so the units only it fills are marked "
    "dynamic and not compared",
    "fields an older build lacked default to empty, so a re-render shows the differences "
    "between two refs only and is not what a new run would print",
)

# The surfaces of each mode, in the order they are rendered.
SURFACES: tuple[str, ...] = (
    "report.md",
    "banner",
    "html.header",
    "html.figure",
    "html.notes",
    "iocs.default",
    "iocs.all",
    "stix",
    "stix.notice",
    "mitre",
    "misp",
    "navigator",
    "call_map",
    "rules",
    "rules.comments",
    "bundle.notes",
)
# The surfaces whose units are lines in order: compared by aligning each
# group's texts, so a line put in does not move every key after it.
ORDERED: frozenset[str] = frozenset(
    {"report.md", "banner", "html.header", "html.notes", "rules.comments", "bundle.notes"}
)
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
# The download comment of each rule kind, as the API writes it.
RULE_KINDS: tuple[str, ...] = ("yara", "sigma", "suricata", "snort")
_RULE_COMMENT = {"yara": "//", "sigma": "#", "suricata": "#", "snort": "#"}
# A STIX property that identifies or dates an object rather than says something.
_STIX_NOT_TEXT = frozenset(
    {
        "id",
        "type",
        "spec_version",
        "created",
        "modified",
        "valid_from",
        "valid_until",
        "first_seen",
        "last_seen",
        "first_observed",
        "last_observed",
        "published",
        "number_observed",
    }
)


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
    """Each non-blank line of the Markdown under its section path, and the title block's notes."""
    path: list[str] = []
    fenced = False
    before_body = True
    for line in markdown.splitlines():
        text = line.rstrip()
        if not text.strip():
            continue
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
        if before_body and heading is None and text.lstrip()[:1] in {">", "_"}:
            units.add("banner", "line", text.strip(), group="title block")


class _HtmlReader(HTMLParser):
    """The cover's fields, each figure's caption, legend and SVG labels, and note paragraphs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.header: list[str] = []
        self.figures: list[tuple[str, str, str]] = []  # (figure id, part, text)
        self.notes: list[tuple[str, str]] = []  # (section, text)
        self._in_header = 0
        self._chunk: list[str] = []
        self._section: list[str] = ["", ""]
        self._heading: list[str] | None = None
        self._heading_level = 0
        self._figure: str | None = None
        self._figures_seen = 0
        self._svg_text: list[str] | None = None
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
            self._figures_seen += 1
            self._figure = str(named.get("id") or f"figure {self._figures_seen}")
        elif self._figure is not None and tag == "text":
            self._svg_text = []
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
        if self._legend is not None:
            self._legend.append(data)
        elif self._caption is not None:
            self._caption.append(data)
        if self._paragraph is not None:
            if self._paragraph["current"] is not None:
                self._paragraph["current"].append(data)
            else:
                self._paragraph["outside"].append(data)
        if self._note_item is not None:
            self._note_item.append(data)


def html_units(document: str, units: _Units, *, dynamic_figures: Iterable[str] = ()) -> None:
    """The HTML's cover fields, figure texts (SVG ``<text>`` nodes) and note paragraphs."""
    reader = _HtmlReader()
    reader.feed(document)
    reader.close()
    marked = set(dynamic_figures)
    for said in reader.header:
        units.add("html.header", "field", said, group="cover")
    for figure, part, said in reader.figures:
        if part == "label":
            key = f"{figure} label"
        else:
            key = f"{figure} {part}"
        units.add("html.figure", key, said, group=figure, dynamic=figure in marked)
    for section, said in reader.notes:
        units.add("html.notes", "note", said, group=section)


def _ioc_units(rows: Sequence[Mapping[str, Any]], units: _Units, *, dynamic: bool) -> None:
    for surface, wanted in (("iocs.default", True), ("iocs.all", None)):
        for row in rows:
            if wanted is not None and row.get("published") is not wanted:
                continue
            key = f"{row.get('kind') or ''} {row.get('value') or ''}"
            text = " | ".join(
                f"{name}: {row.get(name) if row.get(name) is not None else ''}"
                for name in ("publish_answer", "source", "notes", "role", "indicator_type")
            )
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


def _stix_text(obj: Mapping[str, Any]) -> str:
    lines: list[str] = []
    for name in sorted(obj):
        if name in _STIX_NOT_TEXT or name.endswith(("_ref", "_refs")):
            continue
        value = obj[name]
        if isinstance(value, str):
            lines.append(f"{name}: {value}")
        elif isinstance(value, list) and value and all(isinstance(v, str) for v in value):
            lines.append(f"{name}: {', '.join(value)}")
        elif name == "kill_chain_phases" and isinstance(value, list):
            phases = [str(p.get("phase_name") or "") for p in value if isinstance(p, Mapping)]
            lines.append(f"{name}: {', '.join(phases)}")
    return "\n".join(lines)


def _stix_units(served: Mapping[str, Any], units: _Units, *, dynamic: bool) -> None:
    """Each object of the bundle as served, and the notice served with an unpublished one."""
    found = served.get("bundle")
    bundle: Mapping[str, Any] = found if isinstance(found, Mapping) else served
    notice = served.get("notice") or bundle.get("x_malspark_notice")
    units.add("stix.notice", "notice", notice or "(none)")
    for obj in bundle.get("objects") or []:
        if not isinstance(obj, Mapping):
            continue
        kind = str(obj.get("type") or "")
        units.add(
            "stix",
            f"{kind} {_stix_ident(obj)}".strip(),
            _stix_text(obj),
            group=kind,
            dynamic=dynamic and kind in DYNAMIC_STIX_TYPES,
        )


def _mitre_units(rows: Sequence[Mapping[str, Any]] | None, units: _Units) -> None:
    if not rows:
        units.add("mitre", "techniques", "(none)")
        return
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        text = " | ".join(
            f"{name}: {row.get(name) if row.get(name) is not None else ''}"
            for name in (
                "name",
                "description",
                "evidence_ids",
                "sandbox_items",
                "absence_sources",
            )
            if name in row
        )
        units.add("mitre", str(row.get("technique_id") or ""), text)


def _misp_units(event: Mapping[str, Any], units: _Units) -> None:
    found = event.get("Event")
    body: Mapping[str, Any] = found if isinstance(found, Mapping) else event
    units.add("misp", "info", body.get("info") or "")
    tags = ", ".join(str(t.get("name") or "") for t in body.get("Tag") or [] if isinstance(t, dict))
    units.add("misp", "tags", tags)
    for attribute in body.get("Attribute") or []:
        if not isinstance(attribute, Mapping):
            continue
        key = f"{attribute.get('type') or ''} {attribute.get('value') or ''}"
        text = " | ".join(
            f"{name}: {attribute.get(name) if attribute.get(name) is not None else ''}"
            for name in ("category", "comment", "to_ids")
        )
        units.add("misp", key, text, group=str(attribute.get("type") or ""))
    for obj in body.get("Object") or []:
        if not isinstance(obj, Mapping):
            continue
        for attribute in obj.get("Attribute") or []:
            if isinstance(attribute, Mapping):
                key = f"object {obj.get('name') or ''} {attribute.get('object_relation') or ''}"
                units.add("misp", key, attribute.get("value") or "", group="object")


def _layer_units(layer: Mapping[str, Any], units: _Units) -> None:
    units.add("navigator", "description", layer.get("description") or "")
    for item in layer.get("legendItems") or []:
        if isinstance(item, Mapping):
            units.add("navigator", f"legend {item.get('label') or ''}", item.get("color") or "")
    for row in layer.get("techniques") or []:
        if not isinstance(row, Mapping):
            continue
        metadata = "; ".join(
            f"{m.get('name')}: {m.get('value')}"
            for m in row.get("metadata") or []
            if isinstance(m, Mapping)
        )
        units.add(
            "navigator",
            f"technique {row.get('techniqueID') or ''}",
            f"comment: {row.get('comment') or ''} | {metadata}",
        )


def _call_map_units(found: Mapping[str, Any], units: _Units) -> None:
    roots = ", ".join(str(r) for r in found.get("roots") or [])
    units.add("call_map", "roots", roots)
    for function in found.get("functions") or []:
        if not isinstance(function, Mapping):
            continue
        key = str(function.get("address") or ", ".join(function.get("names") or []) or "?")
        text = " | ".join(
            f"{name}: {function.get(name)}"
            for name in ("names", "read", "listed_in", "read_by", "calls", "called_by")
            if name in function
        )
        units.add("call_map", f"function {key}", text)


def _rule_units(
    signatures: Sequence[Mapping[str, Any]],
    downloads: Mapping[str, str],
    units: _Units,
) -> None:
    for rule in signatures:
        if not isinstance(rule, Mapping):
            continue
        body = str(rule.get("body") or "")
        text = f"body sha256:{digest(body)} ({len(body.splitlines())} lines)"
        if rule.get("compile_error"):
            text += f" | compile error: {rule['compile_error']}"
        if rule.get("printed") is not None:
            text += f" | printed: {rule.get('printed')}"
        units.add("rules", f"{rule.get('kind') or ''} {rule.get('name') or ''}", text)
    if not signatures:
        units.add("rules", "drafts", "(none)")
    for kind, download in downloads.items():
        mark = _RULE_COMMENT[kind]
        for line in download.splitlines():
            if line.lstrip().startswith(mark):
                units.add("rules.comments", "line", line.strip(), group=kind)


def _bundle_units(document: Mapping[str, Any], units: _Units) -> None:
    for note in document.get("notes") or []:
        if isinstance(note, Mapping):
            ids = ", ".join(str(i) for i in note.get("evidence_ids") or [])
            units.add(
                "bundle.notes",
                f"note {note.get('number')}",
                f"{note.get('section') or ''}: {ids}",
                group="notes",
            )
    for section in document.get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        fenced = False
        for line in str(section.get("markdown") or "").splitlines():
            said = line.strip()
            if _FENCE.match(said):
                fenced = not fenced
                continue
            if fenced or len(said) < 3:
                continue
            note = (said.startswith("_") and said.endswith("_")) or said.startswith(">")
            if note:
                units.add("bundle.notes", "line", said, group=str(section.get("title") or ""))


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
        try:
            make()
            # A surface rendered with nothing on it is said as one unit, so its
            # appearing on the other side is a change, never a silence.
            held = {row["surface"] for row in self.units.rows[before:]}
            for surface in surfaces:
                if surface not in held:
                    self.units.add(surface, "(empty)", "(nothing printed)")
        except Absent as exc:
            del self.units.rows[before:]
            self.lack(surfaces, str(exc))
        except Exception as exc:  # noqa: BLE001 — named as an error, the other surfaces stand
            del self.units.rows[before:]
            self.lack(surfaces, f"raised: {_where(exc)}", error=True)


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
    layout = "analyst"

    def _need() -> Any:
        if report is None:
            raise Absent(untyped)
        return report

    def _laid_out(module: str, name: str) -> Any:
        renderer = entry(module, name)
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
        rows = entry("app.services.report_service", "ioc_feed_rows")(mr)
        mode.files["iocs.json"] = _json({"items": rows, "total": len(rows)})
        default = [row for row in rows if row.get("published") is True]
        mode.files["iocs-default.json"] = _json({"items": default, "total": len(default)})
        _ioc_units(rows, mode.units, dynamic=dynamic)

    def _stix() -> None:
        served = parts["stix"]()
        mode.files["stix-bundle.json"] = _json(served)
        _stix_units(served, mode.units, dynamic=dynamic)

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
        for kind in RULE_KINDS:
            downloads[kind] = str(download(signatures, kind, "all"))
            if downloads[kind]:
                mode.files[f"signatures-{kind}.txt"] = downloads[kind]
        _rule_units(signatures, downloads, mode.units)

    def _bundle() -> None:
        text = str(entry("platform.reporting.renderers.bundle", "bundle_json")(_need()))
        mode.files["evidence-bundle.json"] = text
        _bundle_units(json.loads(text), mode.units)

    mode.produce(("report.md", "banner"), _markdown)
    mode.produce(("html.header", "html.figure", "html.notes"), _html)
    mode.produce(("iocs.default", "iocs.all"), _iocs)
    mode.produce(("stix", "stix.notice"), _stix)
    mode.produce(("mitre",), _mitre)
    mode.produce(("misp",), _misp)
    mode.produce(("navigator",), _layer)
    mode.produce(("call_map",), _call_map)
    mode.produce(("rules", "rules.comments"), _rules)
    mode.produce(("bundle.notes",), _bundle)


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
            return _served_stix(stored.byjob.get("stix_bundle"))

        def _mitre() -> Any:
            if "mitre_techniques" not in stored.byjob:
                raise Absent("report-byjob.json holds no mitre_techniques column")
            return stored.byjob.get("mitre_techniques")

        def _misp(typed: Any) -> Any:
            return _misp_event(typed, mr, stored.job_id, stored.report_id)

        _render(mode, stored, report, mr, untyped=untyped, stix=_stix, mitre=_mitre, misp=_misp)
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
        # the drafts read it: their object ids and dates derive from it.
        values = built_by(*args, **kwargs)
        built: Any = args[2] if len(args) > 2 else kwargs.get("built")
        if getattr(built, "report", None) is not None:
            built.report.generated_at = clock
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

        def _stix() -> Any:
            bundle = report.stix_bundle_extended
            if bundle:
                return _served_stix(bundle)
            judge = getattr(captured.get("judged"), "bundle", None)
            if judge is None:
                raise Absent("the rebuilt report holds no export and the judge's bundle is absent")
            # The worker stores the judge's draft, marked unpublished, when no export exists.
            as_json = entry("app.worker.analysis_worker", "judge_bundle_json")(judge.model_dump())
            only = entry("platform.schemas.stix_models", "JUDGE_ONLY_PROPERTIES")
            flag = entry("platform.schemas.stix_models", "UNPUBLISHED_PROPERTY")
            notice = entry("platform.schemas.stix_models", "UNPUBLISHED_NOTICE")
            draft = {k: v for k, v in as_json.items() if k not in only}
            return _served_stix({**draft, flag: False, "x_malspark_notice": notice})

        def _mitre() -> Any:
            extract = entry("app.worker.analysis_worker", "_extract_mitre")
            return extract({"malware_report": mr, "stix_bundle_extended": mr.get("stix_bundle")})

        def _misp(typed: Any) -> Any:
            return _misp_event(typed, mr, stored.job_id, stored.report_id)

        _render(mode, stored, report, mr, stix=_stix, mitre=_mitre, misp=_misp)
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
        "modes": list(modes),
        "report_source": stored.report_source if stored.report is not None else None,
        "limits": list(LIMITS),
        "units": [row for mode in done for row in mode.units.rows],
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
    """Every unit changed, added or removed between two records of one run."""
    changes: list[dict[str, Any]] = []
    dynamic = 0
    rows_a = [r for r in a.get("units") or [] if not r.get("dynamic")]
    rows_b = [r for r in b.get("units") or [] if not r.get("dynamic")]
    dynamic = sum(1 for r in [*(a.get("units") or []), *(b.get("units") or [])] if r.get("dynamic"))
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
    reasons_a = {(r["mode"], r["surface"]): r for r in a.get("not_produced") or []}
    reasons_b = {(r["mode"], r["surface"]): r for r in b.get("not_produced") or []}
    not_compared = [
        {
            "mode": key[0],
            "surface": key[1],
            "a": (reasons_a.get(key) or {}).get("reason"),
            "b": (reasons_b.get(key) or {}).get("reason"),
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
    out["dynamic_not_compared"] = dynamic
    if not_compared:
        out["not_compared"] = not_compared
    if errors:
        out["errors"] = errors
    return out


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
        if Path(str(record.get("tree") or "")).resolve() != tree.resolve():
            raise RuntimeError(
                f"the render under {tree} imported its platform from {record.get('tree')}"
            )
    return list(records)


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
        return [compare_records(a, b) for a, b in zip(records["a"], records["b"], strict=True)]
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
            lines.append(
                f"  NOT COMPARED [{row['mode']} {row['surface']}]: A: "
                f"{_safe(row['a'] or 'produced')}; B: {_safe(row['b'] or 'produced')}"
            )
        for row in diff.get("errors") or []:
            lines.append(
                f"  ERROR under {row['side'].upper()} [{row['mode']} {row['surface']}]: "
                f"{_safe(row['reason'])}"
            )
        if diff.get("dynamic_not_compared"):
            lines.append(f"  {diff['dynamic_not_compared']} dynamic unit(s) not compared")
        total = sum(sum(per.values()) for per in diff["summary"].values())
        unexpected = sum(1 for c in diff["changes"] if not c.get("expected"))
        lines.append(f"  summary: {total} difference(s), {unexpected} unexpected")
        for surface, per in diff["summary"].items():
            lines.append(f"    {surface}: " + ", ".join(f"{k} {v}" for k, v in sorted(per.items())))
        if not diff["changes"]:
            lines.append("  no difference: both refs render the same units")
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
        epilog="Limits: " + " ".join(f"({n}) {limit}." for n, limit in enumerate(LIMITS, 1)),
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
    parser.add_argument("--quiet", action="store_true", help="print nothing; write files only")
    return parser


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


def write_out(out: Path, runs: Sequence[Path], modes: Sequence[str]) -> list[dict[str, Any]]:
    """Each run rendered into ``out``: the records in ``surfaces.json``, the files per run."""
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
        if any(diff.get("errors") for diff in diffs):
            return 2
        return 1 if unexpected else 0
    if args.out is None:
        parser.error("name --out DIR, or --compare REF_A REF_B")
    records = write_out(args.out, runs, modes)
    raised = [row for record in records for row in record["not_produced"] if row.get("error")]
    if not args.quiet:
        for record in records:
            print(f"run {_safe(record['run'])}: {args.out / record['files']}")
            for mode, per in counts(record).items():
                print(f"  {mode}: " + ", ".join(f"{s} {n}" for s, n in sorted(per.items())))
            for row in record["not_produced"]:
                mark = "ERROR " if row.get("error") else ""
                print(
                    f"  {mark}not produced [{row['mode']} {row['surface']}]: {_safe(row['reason'])}"
                )
    return 2 if raised else 0


def _prepare_path() -> None:
    """This checkout on the import path, unless the driver renders under another tree.

    Under another tree, every entry of the path outside it that holds the
    platform, the API or the scripts (an editable install's) is taken off, so
    a module the tree lacks is a module not found, never this checkout's.
    """
    here = str(Path(__file__).resolve().parent)
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != Path(here)]
    tree = os.environ.get(TREE_VARIABLE)
    if tree:
        root = Path(tree).resolve()
        names = (*_packages(), "app", "scripts")

        def _foreign(entry: str) -> bool:
            at = Path(entry or ".").resolve()
            if (
                at == root
                or root in at.parents
                or {"site-packages", "dist-packages"} & set(at.parts)
            ):
                return False
            return any((at / name).is_dir() for name in names)

        sys.path[:] = [p for p in sys.path if not _foreign(p)]
        return
    for path in (_ROOT, _ROOT / "src", _ROOT / "apps" / "api"):
        if str(path) not in sys.path:
            sys.path.append(str(path))


if __name__ == "__main__":
    _prepare_path()
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — said, and the status says it failed
        print(f"render_surfaces failed: {_where(exc)}", file=sys.stderr)
        sys.exit(2)
