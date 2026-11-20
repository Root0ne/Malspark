"""Every value of the sample, a tool, a sandbox or the operator is text on every surface.

A scan, not a list of examples. The text places of ``MalwareReport`` are read
from the model by reflection (:func:`_text_places`); each is of the provenance
:data:`PROVENANCE` declares for it: platform text (``P``) and a model's text
(``M``) are listed there by name, and every other place is the sample's, a
tool's, a sandbox's or the operator's, so a new field is scanned without this
file changing. A platform sentence quoting a model's words, alone or with a
value, as one string, is written as text and scanned as a value
(:data:`QUOTED_WORDS`); no place is of a mixed class (:data:`MIXED_TEXT`).
The report is the recorded run of ``_report_shapes`` with every empty text
place filled from its type (:func:`_filled`); every text of such a provenance
then carries a payload with a token of its own (:func:`_payload`).

What comes from reflection: the text places of the schema and the values
written into them. What is written by hand: :data:`PROVENANCE`; the free
mappings, which have no place in the schema — the tool and sandbox records
(:data:`FREE_RECORDS`, written under the keys the recorded run holds) and the
``run_summary`` keys (:func:`_run_summary`, the keys the renderers' verdict,
run, method and limitation sections read, each with the provenance of its
value: the platform's sentences quoting the mediator's and the analysts'
words, the negotiation keys, a negative claim, a validation finding's message
and a retry's sentences are values, each listed in :data:`QUOTED_WORDS`); the
states a place is printed in only
under a condition (:func:`_states`); and the list of places no state prints
(:data:`NOT_PRINTED`). A key or a record the hand lists miss is not scanned.

report.md, the evidence bundle's Markdown and the HTML of both are rendered by
the product's own path (``render_products``); the Markdown is read by the HTML
report's reader and by a reader that takes raw HTML, and each HTML tree is
parsed. A token occurs only inside text or code: never in an attribute but the
operator's reference target in its link, never as the start of a link, an
emphasis, a struck or underlined run, a heading, a list item or a table cell
the payload made, and the words between a value's first and last token are its
own, never another value's; each value's backtick pair, a backslash and a
character reference are shown as written and the pair forms no code span;
every place written is printed in some state unless listed, and the
operator's reference is one link.
"""

from __future__ import annotations

import datetime as dt
import enum
import re
import types
import typing
from html.parser import HTMLParser
from typing import Any

import pytest
from markdown_it import MarkdownIt
from pydantic import BaseModel

from malspark.analysis.disclosure import LEFT_THE_MACHINE_RECORD
from malspark.analysis.isolation import REMOTE_SERVICE
from malspark.reporting.models import EvidenceSection, ExternalReference, MalwareReport
from malspark.reporting.renderers import markdown as markdown_module
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
    # A figure the platform drew (its caption names a decompiler's symbol and is
    # scanned), and the closing texts no code writes (a stored report's platform
    # Markdown, printed as written).
    (r"^report\.figures\[\]\.(id|kind|legend|content)$", "P"),
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
    # The operator's question: a value; the answer to it is a model's.
    (r"^report\.question_answers\[\]\.question$", "V"),
    # A platform check of the answer: the platform's words, a model's quoted
    # words and a value nobody wrote here, as one string written as text.
    (r"^report\.question_answers\[\]\.checks\[\]$", "V"),
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
    """``P``, ``M``, ``X``, or ``V`` for a value of the sample, a tool, a sandbox, the operator."""
    return next((kind for rule, kind in _RULES if rule.search(path)), "V")


# The places of mixed text (``X``): none. A string holding the platform's
# words, a model's quoted words and a value nobody wrote here is written whole
# as text, as a value is; the class stays empty.
MIXED_TEXT: frozenset[str] = frozenset()

# Each place where a platform sentence quotes a model's words, alone or with a
# value, as one string: written as text, so each is scanned with a value's
# payload and is printed in some state.
QUOTED_WORDS = frozenset(
    {
        "report.question_answers[].checks[]",
        *(
            f"report.run_summary.negotiation.{key}[]"
            for key in (
                "not_blocking",
                "limit_rulings",
                "mediation_notes",
                "revision_replacements",
                "unread_marks",
                "ledger_facts",
                "ledger_stated",
            )
        ),
        "report.run_summary.validation.unresolved[].message",
        "report.run_summary.validation.retry_drops[].sentence",
        "report.run_summary.validation.retry_withdrawals[].sentence",
        "report.run_summary.coverage.negatives[].negative",
    }
)


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
    pipes a cell; ``\\x00claim0\\x00`` and ``\\x000\\x00v0\\x000\\x00`` are the
    shapes of a placeholder; a closed backtick pair, a backslash before a star
    and ``&lt;`` are what a writer's code span, an escape and a character
    reference would take instead of showing (:data:`_SHOWN_BEFORE`,
    :data:`_SHOWN_AFTER`); the line after the break opens a heading of its own.
    """
    return (
        f"1. # zH{n}z [zL{n}z](#zT{n}z) **zB{n}z** ~~zS{n}z~~ <u>zU{n}z</u> "
        f"<img src=zI{n}z> |zP{n}z| \x00claim0\x00 \x000\x00v0\x000\x00 `zC{n}z` "
        f"\\*zK{n}z &lt;zE{n}z zZ{n}z\n# zN{n}z"
    )


# What a reader shows around a part's token where the value is printed with
# all its characters: the backtick pair, the backslash and the reference as written.
_SHOWN_BEFORE = {"C": "`", "K": "\\*", "E": "&lt;"}
_SHOWN_AFTER = {"C": "`"}


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

    return {
        "elapsed_seconds": 412.5,
        "final_decision": "Malware",
        "negotiation": {
            "rounds_completed": 2,
            "termination_reason": v("negotiation.termination_reason"),
            "final_confidence": 0.86,
            # The platform's sentences quoting the mediator's and the analysts'
            # words, and its note carrying a provider's or an exception's text.
            **{
                key: [v(f"negotiation.{key}[]")]
                for key in (
                    "not_blocking",
                    "limit_rulings",
                    "mediation_notes",
                    "revision_replacements",
                    "unread_marks",
                    "ledger_facts",
                    "ledger_stated",
                )
            },
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
            # A stage that did not run, with the reason it and an agent gave.
            {
                "key": "sandbox",
                "kind": "pipeline",
                "ran": False,
                "reason": v("stages[].reason"),
                "agent_reasons": {"dynamic": v("stages[].agent_reasons.key")},
            },
        ],
        # A tool server the run rested: its names and the reason it gave.
        "server_rests": [
            {
                "server": v("server_rests[].server"),
                "label": v("server_rests[].label"),
                "reason": v("server_rests[].reason"),
                "failures": 3,
                "cooldown_s": 60,
            }
        ],
        # A tool a degraded run went without, and why.
        "lost_tools": [{"tool": v("lost_tools[].tool"), "reason": v("lost_tools[].reason")}],
        # The operator's model and call names and the sources of a measured rate.
        "generation": {
            "models": {
                v("generation.models.<key>"): {
                    "tokens_per_second": 10.0,
                    "tokens": 100,
                    "seconds": 10.0,
                    "calls": 1,
                    "sources": [v("generation.models.key.sources[]")],
                }
            },
            "timeouts": {
                v("generation.timeouts.<key>"): {
                    "budget": v("generation.timeouts.key.budget"),
                    "configured_s": 60.0,
                    "applied_s": 60.0,
                }
            },
        },
        # What left the machine: a model service and the agents that list it.
        "disclosure": {
            "partial_reason": v("disclosure.partial_reason"),
            "models": [
                {
                    "service": v("disclosure.models[].service"),
                    "calls": 0,
                    "configured_for": [v("disclosure.models[].configured_for[]")],
                }
            ],
            # Where a source read the sample's bytes, and what it said of that.
            "isolation": {
                "rows": [
                    {
                        "where": REMOTE_SERVICE,
                        "source": v("disclosure.isolation.rows[].source"),
                        "host": v("disclosure.isolation.rows[].host"),
                        "why_not_measured": v("disclosure.isolation.rows[].why_not_measured"),
                    }
                ]
            },
            # What a tool the run called is declared to do beyond answering.
            "effects": {
                "partial_reason": v("disclosure.effects.partial_reason"),
                "tools": [
                    {
                        "tool": v("disclosure.effects.tools[].tool"),
                        "server": v("disclosure.effects.tools[].server"),
                        "calls": 1,
                        "network": True,
                    }
                ],
            },
        },
        # What the run spent its input on: why the count may be short, and the
        # run's fingerprint.
        "efficiency": {
            "v": 1,
            "partial_reason": v("efficiency.partial_reason"),
            "fingerprint": {"sha256": v("efficiency.fingerprint.sha256")},
        },
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
            "partial_reason": v("coverage.partial_reason"),
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
                    # A model's claim, quoted by the platform's sentence.
                    "negative": v("coverage.negatives[].negative"),
                    "coverage": "unknown",
                }
            ],
        },
        "validation": {
            "retries": 1,
            # A finding's message: the platform's sentence quoting a model's
            # claim or an observed value, as one string; listed, answered, an
            # export's decline of the judge's object and of a sandbox's.
            "unresolved": [
                {
                    "agent": agent,
                    "code": code,
                    "message": v("validation.unresolved[].message"),
                    **({"answered": True} if answered else {}),
                }
                for agent, code, answered in (
                    ("static", "report.citation_wrong_entry", False),
                    ("dynamic", "report.citation_wrong_entry", True),
                    ("judge", "stix.unpublishable_endpoint", False),
                    ("sandbox", "stix.unpublishable_endpoint", False),
                )
            ],
            # What a kept retry left out and what a retry withdrew: the
            # platform's sentence quoting the analyst's item and reason.
            "retry_drops": [{"sentence": v("validation.retry_drops[].sentence")}],
            "retry_withdrawals": [{"sentence": v("validation.retry_withdrawals[].sentence")}],
        },
    }


def _report() -> tuple[MalwareReport, _Tokens]:
    report = rich_report()
    _filled(report)
    tokens = _Tokens()
    _written(report, "report", tokens, _text_places())
    # The operator's reference, whose target a link holds: a value that would end
    # it, open a tag after it or a title inside it, and is still one link.
    n = tokens._next("report.references[].url", "V")
    report.references = [
        *report.references,
        ExternalReference(
            source=tokens.value("report.references[].source"),
            url=f'https://ref.example/zL{n}z)<img src=zI{n}z> (zB{n}z) "zQ{n}z"',
            note=tokens.value("report.references[].note"),
        ),
    ]
    report.run_summary = _run_summary(tokens)
    return report, tokens


def _states(report: MalwareReport, tokens: _Tokens) -> list[MalwareReport]:
    """The report, and copies of it that meet the conditions a place is printed under.

    The second: no packer signature matched (the packer hint is printed), the
    domain is a punycode name (the name it resembles), the address was made by
    processes outside the sample's tree, and the binding passes a domain the
    export publishes (where the code decoded and loaded it, the call made
    through the import), a mutex string of note was cut from a longer string
    (the publish answer quoting it, in the host table and among the strings),
    a path string carries a note (the path row's context), and an analyst's
    artifact table lists a mutex (the analyst named in its row and its
    publish answer). The third: whether the processes are the sample's is not
    known (the processes only a mark or only a file names, and the mark's
    sandbox), the binding's call is made through a slot, and the run is
    degraded (the tools it went without; the banner's reason for a skipped
    analyst is left out of this state, so the stage's reason is scanned where
    the first state prints it). Every value keeps its token.
    """
    second = report.model_copy(deep=True)
    assert second.static is not None and second.network is not None
    second.static.packer_matches = []
    second.network.domains[0].is_punycode = True
    second.network.ips[0].sample_process_tree = False
    second.bound_values[0].kind = "domain"
    second.bound_values[0].value = "bound.example"
    held = second.static.interesting_strings[0]
    # The longer string a value was cut from, short enough that the publish
    # answer quoting it holds its backtick pair whole.
    n = tokens._next("report.static.interesting_strings[].cut_from", "V")
    cut = f"zH{n}z `zC{n}z` zZ{n}z"
    second.static.interesting_strings = [
        *second.static.interesting_strings,
        held.model_copy(update={"kind": "mutex", "value": "Global\\listed", "cut_from": cut}),
        held.model_copy(update={"kind": "path", "value": "C:\\Users\\listed.txt"}),
    ]
    second.sections = [
        *second.sections,
        EvidenceSection(
            key="artifact_iocs",
            title="Indicators",
            kind="table",
            source="artifact:static",
            columns=["Listed by", "Evidence", "Type", "Value"],
            rows=[
                [tokens.value("report.sections[].rows[][]"), "ev_0001", "mutex", "Global\\named"]
            ],
        ),
    ]
    third = report.model_copy(deep=True)
    assert third.network is not None
    third.network.ips[0].sample_process_tree = None
    third.bound_values[0].kind = "domain"
    third.bound_values[0].value = "bound.example"
    third.bound_values[0].imported_as = None
    third.degraded_mode = True
    for stage in third.run_summary["stages"]:
        stage.pop("agent_reasons", None)
    return [report, second, third]


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
    "code": "C",
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
        if tag == "code":
            # Two values' backticks never pair into a span: a span holding two
            # values' words is the platform's span of a compound value (a DLL
            # and its function), which shows each value's own backtick pair.
            held = sorted({found.group(2) for found in _TOKEN.finditer(text)})
            if len(held) > 1 and not all(f"`zC{n}z`" in text for n in held):
                names = sorted({tokens.places.get(int(n), "?") for n in held})
                faults.append(f"{surface}: <code> holds the words of {', '.join(names)}")
        head = _TOKEN.match(text.lstrip("#").lstrip())
        if head is None:
            continue
        place = tokens.places.get(int(head.group(2)), "?")
        if tag in _MADE and head.group(1) == _MADE[tag] and place != "report.references[].source":
            faults.append(f"{surface}: {place} made <{tag}>")
        elif tag in _BLOCKS and head.group(1) in "HNP":
            faults.append(f"{surface}: {place} made <{tag}>")
    shown = " ".join("".join(tree.text).split())
    for found in re.finditer(r"z([CKE])(\d+)z", shown):
        before = _SHOWN_BEFORE[found.group(1)]
        if shown[: found.start()].endswith(before):
            continue
        place = tokens.places.get(int(found.group(2)), "?")
        faults.append(f"{surface}: {place} lost {before!r} before its token")
    for found in re.finditer(r"zC(\d+)z", shown):
        if not shown[found.end() :].startswith(_SHOWN_AFTER["C"]):
            place = tokens.places.get(int(found.group(1)), "?")
            faults.append(f"{surface}: {place} lost '`' after its token")
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


# The places whose value no surface prints in any state of this report: a
# field the renderers do not print, or print only for a value of its kind's
# shape, which a payload is not. A hand-written list, taken from the scan's own
# run: each listed place is asserted not printed on any surface (report.md, the
# bundle's Markdown and the HTML of both) in any state (:func:`_states`), so a
# place that starts being printed fails until it is classed, and an unlisted
# place that is not printed fails too.
NOT_PRINTED = frozenset(
    f"report.{place}"
    for place in (
        "bound_values[].role",
        "capability_matrix[].domain",
        "capability_matrix[].evidence_ids[]",
        "capability_matrix[].independent_layers[]",
        "capability_matrix[].platforms[]",
        "capability_matrix[].roots_not_read[]",
        "capability_matrix[].support",
        "code_constants[].entry",
        "code_constants[].first_offset",
        "code_constants[].meaning",
        "code_constants[].tool",
        "code_constants[].value",
        "consolidated_iocs[].context",
        "consolidated_iocs[].description",
        "consolidated_iocs[].evidence_ids[]",
        "consolidated_iocs[].indicator_type",
        "consolidated_iocs[].kind",
        "consolidated_iocs[].observed_in[].detonation",
        "consolidated_iocs[].observed_in[].launched_with",
        "consolidated_iocs[].published",
        "consolidated_iocs[].recovered_by",
        "consolidated_iocs[].source",
        "consolidated_iocs[].type",
        "consolidated_iocs[].value",
        "detection_signatures[].sample_strings[].identifier",
        "detection_signatures[].standing",
        "detection_signatures[].values_left_out[].value",
        "detection_signatures[].values_left_out[].why",
        "dynamic.process_tree[].guest_pid",
        "dynamic.process_tree[].task",
        "dynamic.registry_mods[].new_value",
        "dynamic.registry_mods[].pids[]",
        "dynamic.sandbox_signatures[].marks[]",
        "dynamic.sandbox_signatures[].observed_in[].detonation",
        "dynamic.sandbox_signatures[].observed_in[].launched_with",
        "dynamic.sandbox_signatures[].pids[]",
        "emulated_strings.partial",
        "evidence_index[].agent_role",
        "evidence_index[].agent_tab",
        "evidence_index[].observed_in[].detonation",
        "evidence_index[].observed_in[].launched_with",
        "evidence_index[].source",
        "front_matter.authors",
        "front_matter.codename",
        "front_matter.copyright",
        "front_matter.license",
        "front_matter.malware_name",
        "front_matter.subtitle",
        "front_matter.team",
        "identity.platform",
        "identity.signing.signer_thumbprint",
        "limitation_inventory.failed[].answered[][]",
        "limitation_inventory.failed[].error",
        "limitation_inventory.questions[].agent",
        "limitation_inventory.questions[].cites[]",
        "limitation_inventory.questions[].question",
        "limitation_inventory.questions[].reason",
        "network.domains[].kept_by[]",
        "network.domains[].made_by.disputed[]",
        "network.domains[].made_by.launcher[]",
        "network.domains[].made_by.outside[]",
        "network.domains[].made_by.unlisted[]",
        "network.domains[].mentioned_by[]",
        "network.domains[].observed_in[].detonation",
        "network.domains[].observed_in[].launched_with",
        "network.ips[].kept_by[]",
        "network.ips[].launcher_unsettled_processes[]",
        "network.ips[].mentioned_by[]",
        "network.ips[].observed_in[].detonation",
        "network.ips[].observed_in[].launched_with",
        "network.ips[].unlisted_processes[]",
        "network.urls[].made_by.disputed[]",
        "network.urls[].made_by.launcher[]",
        "network.urls[].made_by.outside[]",
        "network.urls[].made_by.unlisted[]",
        "network.urls[].observed_in[].detonation",
        "network.urls[].observed_in[].launched_with",
        "reputation[].detections[]",
        "reputation[].entry_id",
        "reputation[].first_seen",
        "reputation[].labels[]",
        "reputation[].last_seen",
        "reputation[].link",
        "reputation[].service",
        "reputation[].summary",
        "reputation[].tool",
        "second_source_reads[].entry",
        "second_source_reads[].holds[]",
        "second_source_reads[].standing",
        "second_source_reads[].tool",
        "sections[].source_server",
        "static.api_capabilities_evidence_ids[]",
        "static.api_capabilities_resolved_evidence_ids[]",
        "static.api_capability_corpus",
        "static.delay_imports[].dll",
        "static.delay_imports[].function",
        "static.exports[]",
        "static.imports_partial[]",
        "static.sections_partial[]",
        "ttp_mappings[].absence_sources[]",
        "ttp_mappings[].evidence_ids[]",
        "ttp_mappings[].independent_layers[]",
        "ttp_mappings[].observed_in[].detonation",
        "ttp_mappings[].observed_in[].launched_with",
        "ttp_mappings[].retry_only_layers[]",
        "ttp_mappings[].roots_not_read[]",
        "ttp_mappings[].support",
    )
)


def test_no_value_the_platform_did_not_write_makes_structure_on_any_surface() -> None:
    report, tokens = _report()
    faults: list[str] = []
    printed: set[int] = set()
    for state in _states(report, tokens):
        for surface, rendered in _surfaces(state).items():
            faults += _faults(surface, rendered, tokens)
            printed |= {int(m.group(2)) for m in _TOKEN.finditer(rendered)}
    assert not sorted(set(faults)), "\n".join(sorted(set(faults)))
    # Each place written is printed somewhere, or listed as one no surface prints.
    places = {tokens.places[n] for n, kind in tokens.kinds.items() if kind == "V"}
    shown = {tokens.places[n] for n in printed if n in tokens.places}
    assert sorted(places - shown - NOT_PRINTED) == [], "written, printed nowhere, not listed"
    for place in sorted(NOT_PRINTED):
        assert place in places, f"{place}: listed, not written"
        assert place not in shown, f"{place}: listed as printed nowhere, printed"


def test_the_operator_s_reference_is_one_link_on_every_markdown_surface() -> None:
    report, tokens = _report()
    (n,) = [n for n, place in tokens.places.items() if place == "report.references[].url"]
    for surface, rendered in _surfaces(report).items():
        if not surface.startswith(("report.md", "bundle.md")):
            continue
        tree = _Tree()
        tree.feed(rendered)
        targets = [
            held or ""
            for tag, attrs, _texts in tree.elements
            if tag == "a"
            for name, held in attrs
            if name == "href"
        ]
        assert [t for t in targets if f"zL{n}z" in t and f"zQ{n}z" in t], surface


def test_no_place_is_mixed_text_and_each_quoting_place_is_a_value_that_prints() -> None:
    # A string holding the platform's words, a model's quoted words and a
    # value is written whole as text: no place is of a mixed class, and each
    # place where a platform sentence quotes a model's words is scanned with a
    # value's payload and printed in some state.
    assert MIXED_TEXT == frozenset()
    report, tokens = _report()
    assert not {place for place in _text_places() if provenance(place) not in "PMV"}
    assert set(tokens.kinds.values()) == {"V"}
    values = {tokens.places[n] for n, kind in tokens.kinds.items() if kind == "V"}
    assert sorted(QUOTED_WORDS - values) == []
    assert not QUOTED_WORDS & NOT_PRINTED
    printed = {
        tokens.places[int(found.group(2))]
        for state in _states(report, tokens)
        for rendered in _surfaces(state).values()
        for found in _TOKEN.finditer(rendered)
        if int(found.group(2)) in tokens.places
    }
    assert sorted(QUOTED_WORDS - printed) == []


# Each place whose line is set in after its writing (:func:`_placed`), and a
# sentence of the platform's its builder writes there.
PLACING_CALLERS = {
    "limitation inventory": "Tools the run could not offer: ",
    "rested tool server": "Tool server ",
    "generation": "Generation rate of ",
    "disclosure": "Model prompts: ",
    "isolation": "Not every source that read the sample's bytes was kept from the worker",
    "effects": "Reached the network: ",
    "efficiency": "Run fingerprint: ",
    "coverage": ": coverage unknown: ",
    "analyst report's line": LEFT_THE_MACHINE_RECORD,
}


def _fenced(held: Any, fences: str) -> Any:
    """``held`` with ``fences`` after each value's text a payload of its own."""
    if isinstance(held, str):
        return f"{held} {fences}" if _TOKEN.search(held) else held
    if isinstance(held, dict):
        return {key: _fenced(item, fences) for key, item in held.items()}
    if isinstance(held, list):
        return [_fenced(item, fences) for item in held]
    return held


def test_a_line_composed_after_the_last_fence_is_the_line_a_fence_places(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every place a line's values are set in after its writing, with the
    # writers its caller passes: the line composed from its parts once no
    # fence is left to try is the line the placed values give, with no mark,
    # no character lost and no prefix left, a record holding the fence of
    # every try included.
    report, tokens = _report()
    fences = "".join(
        f"\x00{n}\x00v{n}\x00{n}\x00" for n in range(markdown_module._PLACING_TRIES + 1)
    )
    fenced = report.model_copy(deep=True)
    fenced.run_summary = _fenced(fenced.run_summary, fences)
    states = [*_states(report, tokens), fenced]

    def products(state: MalwareReport) -> tuple[str, ...]:
        made = render_products(state)
        return made.report_markdown, made.bundle_markdown, made.report_html, made.bundle_html

    placed = [products(state) for state in states]
    composed_lines: list[str] = []
    composed = markdown_module._composed

    def composing(*args: Any) -> list[str]:
        lines = composed(*args)
        composed_lines.extend(lines)
        return lines

    monkeypatch.setattr(markdown_module, "_composed", composing)
    monkeypatch.setattr(markdown_module, "_PLACING_TRIES", 0)
    assert [products(state) for state in states] == placed
    for caller, said in PLACING_CALLERS.items():
        assert any(said in line for line in composed_lines), caller
    assert any(fences in line for line in composed_lines)
