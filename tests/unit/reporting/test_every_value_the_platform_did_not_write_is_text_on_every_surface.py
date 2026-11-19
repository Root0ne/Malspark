"""Every value of the sample, a tool, a sandbox or the operator is text on every surface.

A scan, not a list of examples. The text places of ``MalwareReport`` are read
from the model by reflection (:func:`_text_places`); each is of the provenance
:data:`PROVENANCE` declares for it: platform text (``P``) and a model's text
(``M``) are listed there by name, and every other place is the sample's, a
tool's, a sandbox's or the operator's, so a new field is scanned without this
file changing. The report is the recorded run of ``_report_shapes`` with every
empty text place filled from its type (:func:`_filled`); every text of such a
provenance then carries a payload with a token of its own (:func:`_payload`).

The free mappings have no place in the schema. The tool and sandbox records
(:data:`FREE_RECORDS`) are written under the keys the recorded run holds;
``run_summary`` is built from the keys the renderers read
(:func:`_run_summary`), taken from their code (``markdown.py``'s verdict,
run, method and limitation sections), each with the provenance of its value:
the mediator's and the analysts' quoted words and a negative claim are a
model's and carry a plain token of their own.

report.md, the evidence bundle's Markdown and the HTML of both are rendered by
the product's own path (``render_products``); the Markdown is read by the HTML
report's reader and by a reader that takes raw HTML, and each HTML tree is
parsed. A token occurs only inside text or code: never in an attribute but the
operator's reference target in its link, never as the start of a link, an
emphasis, a struck or underlined run, a heading, a list item or a table cell
the payload made, and the words between a value's first and last token are its
own, never another value's.
"""

from __future__ import annotations

import datetime as dt
import enum
import re
import types
import typing
from html.parser import HTMLParser
from typing import Any

from markdown_it import MarkdownIt
from pydantic import BaseModel

from malspark.reporting.models import ExternalReference, MalwareReport
from malspark.reporting.renderers.bundle import render_products
from malspark.reporting.renderers.html import HtmlRenderer
from malspark.reporting.renderers.markdown import _escaped_references
from tests.unit.reporting._report_shapes import rich_report

# The places of the platform's and the models' text, by path: first match
# wins; every other text place is the sample's, a tool's, a sandbox's or the
# operator's. A path is the field names from the report down, ``[]`` for a
# list's items and ``.key`` for a mapping's.
PROVENANCE: list[tuple[str, str]] = [
    # Ids, states, catalogue names and the platform's own sentences.
    (r"^report\.attck_defense", "P"),
    # The ledger entries and sandbox items a technique cites, the questions an
    # enrichment would ask, a directed-text family of the triage pack's catalogue.
    (r"^report\.capability_matrix\[\]\.absence_sources\[\]$", "P"),
    (r"^report\.enrichment_not_asked\[\]\.questions\[\]$", "P"),
    (r"^report\.directed_text\[\]\.(family|evidence_id)$", "P"),
    # A figure the platform drew, and the closing texts no code writes (a stored
    # report's platform Markdown, printed as written).
    (r"^report\.figures\[\]\.", "P"),
    (r"^report\.(appendices\[\]|disclaimer)$", "P"),
    (r"^report\.drafts_not_built", "P"),
    (r"^report\.evidence_index\[\]\.(id|repeated_of)$", "P"),
    (r"^report\.detection_signatures\[\]\.(matched_by\[\]|source_evidence\[\])$", "P"),
    (r"^report\.sections\[\]\.(evidence_ids\[\]|key|source|kind)$", "P"),
    (
        r"^report\.(ttp_mappings|capability_matrix)\[\]\.(technique_id|technique_name|tactic"
        r"|tactic_name|contributing_layers\[\]|sources\[\]|evidence_roots\[\]"
        r"|confidence_source|not_published)$",
        "P",
    ),
    (r"^report\.identity\.hashes\.", "P"),
    # The operator's reference target, held by the platform's link (written apart).
    (r"^report\.references\[\]\.url$", "P"),
    # A model's text: the judge's, the analysts', the report model's.
    (r"^report\.capability_matrix\[\]\.statements\[\]$", "M"),
    (
        r"^report\.(ttp_mappings|capability_matrix)\[\]\.(evidence\[\]|note|evidence_quotes\[\]"
        r"|rationale|justification)$",
        "M",
    ),
    *(
        (rf"^report\.{name}(\.|\[|$)", "M")
        for name in (
            "technical_analysis",
            "executive_summary",
            "key_findings",
            "defensive_recommendations",
            "capabilities_narrative",
            "claims_not_discussed",
            "intro_background",
            "severity",
            "attribution",
            "c2_channels",
            "judge_indicators",
            "malware_category",
            "question_answers",
            "flagged_statements",
            "unmapped_behaviours",
            "acknowledgements",
            "verdict_not_assessed",
            "conclusion",
            r"persistence\[\]\.(evidence_ref|technique_id)",
        )
    ),
]
_RULES = [(re.compile(pattern), kind) for pattern, kind in PROVENANCE]


def provenance(path: str) -> str:
    """``P``, ``M``, or ``V`` for a value of the sample, a tool, a sandbox or the operator."""
    return next((kind for rule, kind in _RULES if rule.search(path)), "V")


# ---------------------------------------------------------------------------
# The schema, read by reflection
# ---------------------------------------------------------------------------


def _annotations(tp: Any) -> list[Any]:
    """The types a field's annotation admits, ``None`` left out, ``Annotated`` read through."""
    origin = typing.get_origin(tp)
    if origin is typing.Annotated:
        return _annotations(typing.get_args(tp)[0])
    if origin in (typing.Union, types.UnionType):
        return [t for a in typing.get_args(tp) if a is not type(None) for t in _annotations(a)]
    return [tp]


def _text_places(
    tp: Any = MalwareReport, path: str = "report", seen: frozenset[Any] = frozenset()
) -> set[str]:
    """Every place of the schema that holds text, read from the model classes."""
    places: set[str] = set()
    for one in _annotations(tp):
        origin, args = typing.get_origin(one), typing.get_args(one)
        if one is str:
            places.add(path)
        elif isinstance(one, type) and issubclass(one, BaseModel) and one not in seen:
            for name, field in one.model_fields.items():
                places |= _text_places(field.annotation, f"{path}.{name}", seen | {one})
        elif origin in (list, tuple, set, frozenset):
            for arg in args:
                if arg is not Ellipsis:
                    places |= _text_places(arg, f"{path}[]", seen)
        elif origin is dict and len(args) == 2:
            places |= _text_places(args[1], f"{path}.key", seen)
    return places


def test_every_listed_place_of_the_platform_or_a_model_is_a_place_of_the_schema() -> None:
    # A rule that names no place of the schema any more would hide a new field.
    places = _text_places()
    for pattern, _kind in PROVENANCE:
        rule = re.compile(pattern)
        assert any(rule.search(place) for place in places), pattern


# ---------------------------------------------------------------------------
# The report: every text place filled, every value a payload
# ---------------------------------------------------------------------------


def _payload(n: int) -> str:
    """A value that would open every structure, with its token ``n`` at each part.

    ``1. # `` opens a list and a heading at a line's start; the brackets a link,
    the stars and tildes emphasis and struck text, the tags raw HTML, the
    pipes a cell; ``\\x00claim0\\x00`` is the shape of a placeholder; the line
    after the break opens a heading of its own.
    """
    return (
        f"1. # zH{n}z [zL{n}z](#zT{n}z) **zB{n}z** ~~zS{n}z~~ <u>zU{n}z</u> "
        f"<img src=zI{n}z> |zP{n}z| \x00claim0\x00 zZ{n}z\n# zN{n}z"
    )


class _Tokens:
    """The tokens handed out, each with the place it was written into and its provenance."""

    def __init__(self) -> None:
        self.places: dict[int, str] = {}
        self.kinds: dict[int, str] = {}

    def _next(self, path: str, kind: str) -> int:
        n = len(self.places)
        self.places[n], self.kinds[n] = path, kind
        return n

    def value(self, path: str) -> str:
        return _payload(self._next(path, "V"))

    def plain(self, path: str, text: str) -> str:
        return f"{text} zM{self._next(path, 'M')}z"


def _instance(tp: Any, depth: int = 0) -> Any:
    """A value of type ``tp`` with every text place holding text, read from the type alone."""
    for one in _annotations(tp):
        origin, args = typing.get_origin(one), typing.get_args(one)
        if one is str:
            return "x"
        if one is bool:
            return True
        if one in (int, float):
            return one(1)
        if one is dt.datetime:
            return dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
        if isinstance(one, type) and issubclass(one, enum.Enum):
            return next(iter(one))
        if origin is typing.Literal:
            return args[0]
        if isinstance(one, type) and issubclass(one, BaseModel):
            if depth > 3:
                return None
            fields = {}
            for name, field in one.model_fields.items():
                held = _instance(field.annotation, depth + 1)
                fields[name] = (
                    held if held is not None else field.get_default(call_default_factory=True)
                )
            return one.model_construct(**fields)
        if origin is tuple and args and args[-1] is not Ellipsis:
            parts = [_instance(arg, depth + 1) for arg in args]
            return None if None in parts else tuple(parts)
        if origin in (list, tuple, set, frozenset):
            item = _instance(args[0], depth + 1) if args else None
            if origin is tuple:
                return (item,) if item is not None else ()
            return [item] if item is not None else []
        if origin is dict and len(args) == 2:
            item = _instance(args[1], depth + 1)
            return {"k": item} if item is not None else {}
    return None


def _filled(model: BaseModel, depth: int = 0) -> None:
    """Every empty text place of ``model`` and of the models it holds given a value of its type."""
    for name, field in type(model).model_fields.items():
        held = getattr(model, name)
        if (held is None or held == [] or held == "") and _text_places(field.annotation, "x"):
            made = _instance(field.annotation, depth)
            if made not in (None, [], {}):
                object.__setattr__(model, name, made)
                held = made
        for item in held if isinstance(held, list) else [held]:
            if isinstance(item, BaseModel) and depth < 4:
                _filled(item, depth + 1)


# The free mappings of a tool's or a sandbox's records: each text value the
# recorded run holds under a key is written (the keys are the renderers' own).
FREE_RECORDS = re.compile(
    r"^report\.(static\.(embedded_resources|packer_matches|api_technique_hits)"
    r"|dynamic\.(file_operations|notable_apis))\[\]\.key$"
)


def _written(held: Any, path: str, tokens: _Tokens, places: set[str]) -> Any:
    """``held`` with each value's text a payload of its own; the platform's and a model's kept.

    Only a text place of the schema and a free record's value are written: a
    mapping's keys are read by name, and a closed set of words (a ``Literal``)
    is not text.
    """
    if isinstance(held, str):
        text = (path in places or FREE_RECORDS.match(path)) and provenance(path) == "V"
        return tokens.value(path) if text else held
    if isinstance(held, BaseModel):
        for name in type(held).model_fields:
            written = _written(getattr(held, name), f"{path}.{name}", tokens, places)
            object.__setattr__(held, name, written)
        return held
    if isinstance(held, (list, tuple)):
        return type(held)(_written(item, f"{path}[]", tokens, places) for item in held)
    if isinstance(held, dict):
        return {key: _written(item, f"{path}.key", tokens, places) for key, item in held.items()}
    return held


def _run_summary(tokens: _Tokens) -> dict[str, Any]:
    """The keys the renderers read from ``run_summary``, each value by its provenance."""

    def v(path: str) -> str:
        return tokens.value(f"report.run_summary.{path}")

    def m(path: str) -> str:
        return tokens.plain(f"report.run_summary.{path}", "said")

    return {
        "elapsed_seconds": 412.5,
        "final_decision": "Malware",
        "negotiation": {
            "rounds_completed": 2,
            "termination_reason": v("negotiation.termination_reason"),
            "final_confidence": 0.86,
            # The mediator's and the analysts' quoted words.
            "not_blocking": [m("negotiation.not_blocking[]")],
            "limit_rulings": [m("negotiation.limit_rulings[]")],
            "revision_replacements": [m("negotiation.revision_replacements[]")],
            "mediation_notes": [m("negotiation.mediation_notes[]")],
            "unread_marks": [m("negotiation.unread_marks[]")],
            "ledger_facts": [m("negotiation.ledger_facts[]")],
            "ledger_stated": [m("negotiation.ledger_stated[]")],
            "dropped_value_counts": [
                {
                    "agent": v("negotiation.dropped_value_counts[].agent"),
                    "round": 1,
                    "values": 1,
                    "claims": 1,
                }
            ],
        },
        "stages": [
            {"key": v("stages[].key"), "kind": "pipeline", "ran": True, "duration_ms": 4200},
            {"key": "judge", "kind": "judge", "ran": True, "duration_ms": 61000},
        ],
        "models": {
            v("models.<key>"): {"fallbacks": [{"reason": v("models.key.fallbacks[].reason")}]}
        },
        "settings_snapshot": {
            "llm": {
                "provider": "openai",
                "openai": {"model": v("settings_snapshot.llm.openai.model")},
            }
        },
        "profile": {
            "name": v("profile.name"),
            "analysts": [v("profile.analysts[]")],
        },
        "evidence": {
            "entries": 1,
            "ok": 1,
            "failed": 1,
            "trimmed": 0,
            "failures": [
                {
                    "tool": v("evidence.failures[].tool"),
                    "server": v("evidence.failures[].server"),
                    "error": v("evidence.failures[].error"),
                    "remediation": v("evidence.failures[].remediation"),
                }
            ],
        },
        "corroboration": {
            "T1055": {
                "asserted_by": [v("corroboration.key.asserted_by[]")],
                "claimed_by": [v("corroboration.key.claimed_by[]")],
                "associated_by": [v("corroboration.key.associated_by[]")],
            }
        },
        "coverage": {
            "v": 1,
            "tools": [
                {
                    "tool": v("coverage.tools[].tool"),
                    "kind": v("coverage.tools[].kind"),
                    "calls": 1,
                }
            ],
            "negatives": [
                {
                    "agent": v("coverage.negatives[].agent"),
                    # A model's claim, quoted.
                    "negative": m("coverage.negatives[].negative"),
                    "coverage": "unknown",
                }
            ],
        },
        "validation": {
            "retries": 1,
            "unresolved": [
                {
                    "agent": "judge",
                    "code": "stix.unpublishable_endpoint",
                    "message": v("validation.unresolved[].message"),
                }
            ],
        },
    }


def _report() -> tuple[MalwareReport, _Tokens]:
    report = rich_report()
    _filled(report)
    tokens = _Tokens()
    _written(report, "report", tokens, _text_places())
    # The operator's reference, whose target a link holds: a value that would end it.
    n = tokens._next("report.references[].url", "V")
    report.references = [
        *report.references,
        ExternalReference(
            source=tokens.value("report.references[].source"),
            url=f"https://ref.example/zL{n}z)<img src=zI{n}z> [zB{n}z](#zT{n}z)",
            note=tokens.value("report.references[].note"),
        ),
    ]
    report.run_summary = _run_summary(tokens)
    return report, tokens


# ---------------------------------------------------------------------------
# Reading what was rendered
# ---------------------------------------------------------------------------

_RAW_HTML = MarkdownIt("commonmark", {"html": True}).enable("table").enable("strikethrough")
_TOKEN = re.compile(r"z([A-Z])(\d+)z")
# The elements a payload's part would make, and the part's letter.
_MADE = {
    "a": "L",
    "strong": "B",
    "em": "B",
    "b": "B",
    "i": "B",
    "s": "S",
    "del": "S",
    "u": "U",
}
_BLOCKS = {"h1", "h2", "h3", "h4", "h5", "h6", "li", "td", "th", "pre", "blockquote"}


class _Tree(HTMLParser):
    """Each element's tag, attributes and text, in document order."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, list[tuple[str, str | None]], list[str]]] = []
        self.open: list[int] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, attrs, []))
        if tag not in {"img", "br", "hr", "meta", "input", "link", "col", "wbr"}:
            self.open.append(len(self.elements) - 1)

    def handle_endtag(self, tag: str) -> None:
        for at in range(len(self.open) - 1, -1, -1):
            if self.elements[self.open[at]][0] == tag:
                del self.open[at:]
                return

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        for at in self.open:
            self.elements[at][2].append(data)


def _faults(surface: str, rendered: str, tokens: _Tokens) -> list[str]:
    """Every place a token stands where a payload made structure, on one surface."""
    tree = _Tree()
    tree.feed(rendered)
    faults: list[str] = []
    for tag, attrs, texts in tree.elements:
        for name, held in attrs:
            for found in _TOKEN.finditer(held or ""):
                place = tokens.places.get(int(found.group(2)), "?")
                # Only the operator's reference is a target a link holds.
                if place == "report.references[].url" and tag == "a" and name == "href":
                    continue
                if found.group(1) in "HLTBSUIPZN":
                    faults.append(f"{surface}: {place} in <{tag} {name}>")
        text = " ".join("".join(texts).split())
        head = _TOKEN.match(text.lstrip("#").lstrip())
        if head is None:
            continue
        place = tokens.places.get(int(head.group(2)), "?")
        if tag in _MADE and head.group(1) == _MADE[tag] and place != "report.references[].source":
            faults.append(f"{surface}: {place} made <{tag}>")
        elif tag in _BLOCKS and head.group(1) in "HNP":
            faults.append(f"{surface}: {place} made <{tag}>")
    shown = " ".join("".join(tree.text).split())
    for first in re.finditer(r"zH(\d+)z", shown):
        n = first.group(1)
        last = shown.find(f"zZ{n}z", first.end())
        if last < 0 or last - first.end() > 400:
            continue
        others = {m.group(2) for m in _TOKEN.finditer(shown[first.end() : last])} - {n}
        if others:
            place = tokens.places.get(int(n), "?")
            faults.append(f"{surface}: {place} prints another value's words")
    return faults


def _surfaces(report: MalwareReport) -> dict[str, str]:
    products = render_products(report)
    surfaces = {"report.html": products.report_html, "bundle.html": products.bundle_html}
    for name, markdown in (
        ("report.md", products.report_markdown),
        ("bundle.md", products.bundle_markdown),
    ):
        assert "rendering failed" not in markdown, name
        closed = _escaped_references(markdown)
        surfaces[f"{name} read"] = HtmlRenderer._markdown_to_html(closed)
        surfaces[f"{name} raw"] = _RAW_HTML.render(closed)
    return surfaces


def test_no_value_the_platform_did_not_write_makes_structure_on_any_surface() -> None:
    report, tokens = _report()
    faults: list[str] = []
    printed: set[str] = set()
    for surface, rendered in _surfaces(report).items():
        faults += _faults(surface, rendered, tokens)
        printed |= {m.group(2) for m in _TOKEN.finditer(rendered)}
    assert not sorted(set(faults)), "\n".join(sorted(set(faults)))
    # The scan reaches the report: most values it wrote are printed somewhere.
    values = {str(n) for n, kind in tokens.kinds.items() if kind == "V"}
    assert len(values & printed) > len(values) // 3
