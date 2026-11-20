"""Deterministic report figures — real inline SVG from real data.

The corpus reports are figure-heavy. The local model cannot produce decompiler
screenshots, so we generate **real charts/diagrams deterministically** from the
report's own data (no fabrication, no screenshots): a process tree, an ATT&CK
tactic matrix, a section-entropy chart, a network graph, an infection-chain
flow, and decompiled code listings as ``<pre>`` text figures.

Each ``build_*`` returns a ``Figure`` or ``None`` (omit when the data is
absent). SVG uses only primitives (rect/line/text) so it renders identically in
the browser and in WeasyPrint, and is theme-neutral (uses
``currentColor`` / explicit greys so it works on the light PDF surface).
``build_figures(report)`` assembles every applicable figure in report order.
"""

from __future__ import annotations

import math
from html import escape
from typing import Any

from malspark.core.logger import logger
from malspark.core.undeclared_tools import address_arguments, code_listing, function_key
from malspark.reporting import tool_kinds
from malspark.reporting.dedupe import distinct_processes
from malspark.reporting.defang import defang
from malspark.reporting.models import Figure, MalwareReport, ProcessNode
from malspark.schemas.sandbox_report import staged_words
from malspark.utils.marked_cut import CUT_MARK, marked_cut

_INK = "#1b1f24"
_MUTED = "#57606a"
_ACCENT = "#0969da"
_DANGER = "#cf222e"
_WARN = "#bc4c00"
_LINE = "#d0d7de"


def _svg(width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" font-family="Inter, Arial, sans-serif" font-size="12">{body}</svg>'
    )


# What one figure holds: a drawing, not the record. Whatever a figure leaves
# out its legend counts, and the report's JSON form carries.
_TREE_ROWS = 40
_NETWORK_ENDPOINTS = 12
_MATRIX_CELLS = 8
_ENTROPY_SECTIONS = 12
_LISTING_CHARS = 4000
_LISTINGS = 4


def _figure_left_out(total: int, shown: int, what: str) -> str:
    """The legend's sentence for what a figure did not draw, or ``""``.

    It points at the JSON report alone: one stored figure is printed by layouts
    that print different tables, and the JSON report holds every row.
    """
    rest = int(total) - int(shown)
    if rest <= 0:
        return ""
    return f" {rest:,} more {what} are not drawn; the JSON report holds all {int(total):,}."


# A label's width is reckoned from every font a figure can be drawn in that
# this machine can measure: DejaVu Sans, the font the PDF is printed in (the
# backend image installs DejaVu alone, docker/Dockerfile.backend); Inter, the
# first name in the SVG's font stack, which a viewer that has it draws with;
# and Liberation Sans, metric-compatible with Arial, the second name. Each
# entry is a character's width, ' ' to '~', in thousandths of an em, rounded
# up, for the regular and the bold face: the largest of its advance unhinted
# and as PIL measures it with FreeType's default hinting at 9, 10, 11 and
# 12 px, in both of PIL's layout engines (basic, which reads the kern table,
# and raqm, which reads GPOS), over the three fonts; plus the largest positive
# kerning it takes before any of these characters or the cut mark, measured
# the same ways. The sum is an upper bound for those fonts at those sizes, so
# a box sized by it holds its label. It bounds nothing else: a viewer that
# substitutes another font, or a character none of these fonts has (drawn in
# a fallback font), can be wider than the estimate.
# fmt: off
_ASCII_WIDTHS: dict[str, tuple[int, ...]] = {
    "normal": (
        364, 589, 500, 889, 811, 1145, 963, 334, 474, 445, 700, 889, 364, 557, 364, 400,
        811, 811, 811, 811, 811, 811, 811, 811, 811, 811, 364, 364, 889, 889, 889, 745,
        1016, 839, 872, 922, 945, 845, 811, 963, 945, 478, 745, 812, 712, 1061, 945, 963,
        845, 963, 922, 845, 778, 922, 832, 1145, 827, 805, 872, 474, 421, 445, 889, 697,
        556, 667, 678, 611, 682, 678, 415, 667, 667, 334, 334, 600, 348, 1000, 667, 686,
        678, 667, 471, 556, 465, 667, 652, 834, 657, 652, 600, 696, 508, 667, 889,
    ),
    "bold": (
        364, 615, 600, 889, 842, 1131, 1024, 364, 519, 500, 715, 889, 417, 500, 417, 454,
        842, 842, 842, 842, 842, 842, 842, 842, 842, 842, 445, 445, 889, 889, 889, 782,
        1017, 900, 915, 893, 948, 842, 842, 948, 1004, 515, 715, 900, 749, 1115, 1004, 1015,
        893, 1015, 915, 865, 809, 948, 894, 1226, 870, 854, 893, 519, 460, 500, 889, 697,
        556, 700, 761, 647, 769, 711, 476, 760, 750, 364, 364, 709, 383, 1084, 750, 738,
        761, 760, 521, 637, 523, 750, 718, 925, 681, 718, 600, 769, 515, 750, 889,
    ),
}
# fmt: on
# Any other character counts the widest advance of any glyph in the three
# fonts, measured the same ways; a glyph a fallback font draws can exceed it
# (the limit above). The cut mark counts its own, measured as the table's
# entries are.
_OTHER_WIDTH = {"normal": 2728, "bold": 2728}
_CUT_MARK_WIDTH = {"normal": 1000, "bold": 1003}
# A box keeps as much room right of its label as left of it.
_LABEL_PAD = 8


def _label_width(text: str, size: int, weight: str = "normal") -> int:
    """How wide ``text`` is drawn at ``size`` px and ``weight``, at most (:data:`_ASCII_WIDTHS`)."""
    table = _ASCII_WIDTHS[weight]
    other = _OTHER_WIDTH[weight]
    milli = 0
    for char in text:
        code = ord(char)
        if 32 <= code < 127:
            milli += table[code - 32]
        else:
            milli += _CUT_MARK_WIDTH[weight] if char == CUT_MARK else other
    return math.ceil(milli * size / 1000)


# A defang bracket a cut never splits.
_DEFANG_BRACKETS = ("[.]", "[:]", "[@]")


def _fitted_label(text: str, chars: int, room: int, size: int) -> str:
    """``text`` whole when it is at most ``chars`` long and ``room`` px wide, else cut.

    The cut is the longest :func:`marked_cut` that fits both, made only where
    it splits no defang bracket.
    """
    split: set[int] = set()
    for bracket in _DEFANG_BRACKETS:
        start = text.find(bracket)
        while start >= 0:
            split.update(range(start + 1, start + len(bracket)))
            start = text.find(bracket, start + 1)
    width = min(len(text), chars)
    while width > 0:
        cut = marked_cut(text, width)
        whole = cut == text
        if (whole or width - len(CUT_MARK) not in split) and _label_width(cut, size) <= room:
            return cut
        width -= 1
    return CUT_MARK


def _tactic_columns() -> tuple[tuple[str, str], ...]:
    """The enterprise tactics in ATT&CK order, read from the vendored catalogue.

    ``capability_matrix.tactic_order``: a tactic the catalogue gives no column
    position, a mobile or ICS one among them, is not in it, so a figure never
    places it; it is counted as not drawn.
    """
    from malspark.extractors.capability_matrix import tactic_order

    return tactic_order("enterprise")


def _text(
    x: int, y: int, s: str, *, fill: str = _INK, size: int = 12, weight: str = "normal"
) -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
        f'font-weight="{weight}">{escape(s)}</text>'
    )


def _written(text: str) -> str:
    """A sample's or a model's text for a figure's label, every network value in it defanged."""
    from malspark.reporting.renderers.markdown import _defanged_text

    return _defanged_text(text)


def _rect(
    x: int, y: int, w: int, h: int, *, fill: str = "#fff", stroke: str = _LINE, rx: int = 4
) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}"/>'
    )


# ---------------------------------------------------------------------------
# Process tree
# ---------------------------------------------------------------------------


def build_process_tree(report: MalwareReport) -> Figure | None:
    dyn = report.dynamic
    if not dyn or not dyn.process_tree:
        return None
    rows: list[tuple[int, ProcessNode]] = []

    every: list[tuple[int, ProcessNode]] = []

    def _walk(node: ProcessNode, depth: int) -> None:
        every.append((depth, node))
        for child in node.children:
            _walk(child, depth + 1)

    for root in distinct_processes(dyn.process_tree):
        _walk(root, 0)
    # A figure holds forty rows; the rest are counted in its legend.
    rows = every[:_TREE_ROWS]
    injecting = any(node.injected_into for _depth, node in rows)
    row_h = 24
    height = max(40, len(rows) * row_h + 20)
    parts: list[str] = []
    for i, (depth, node) in enumerate(rows):
        y = 20 + i * row_h
        x = 12 + depth * 26
        injected = " ⤳ injects" if node.injected_into else ""
        # The name a sandbox recorded, defanged as the report's text is.
        from malspark.reporting.renderers.markdown import _defanged_text

        staged = f" ({staged_words(node)})" if staged_words(node) else ""
        label = f"{_defanged_text(node.name or 'proc')} (pid {node.pid}){staged}{injected}"
        if depth > 0:
            parts.append(
                f'<line x1="{x - 13}" y1="{y - 6}" x2="{x - 3}" y2="{y - 6}" stroke="{_LINE}"/>'
            )
        dot = _DANGER if node.injected_into else _ACCENT
        parts.append(f'<circle cx="{x}" cy="{y - 6}" r="3" fill="{dot}"/>')
        parts.append(_text(x + 8, y - 2, label, fill=_INK))
    return Figure(
        id="fig-process-tree",
        caption="Process tree (sandbox execution)",
        kind="process_tree",
        content=_svg(720, height, "".join(parts)),
        # The red key is printed only where a red node is drawn.
        legend=(
            ("Red node = a process injecting into another." if injecting else "")
            + _figure_left_out(len(every), len(rows), "processes")
        ).strip()
        or None,
    )


# ---------------------------------------------------------------------------
# ATT&CK tactic matrix
# ---------------------------------------------------------------------------


def build_attack_matrix(report: MalwareReport) -> Figure | None:
    if not report.ttp_mappings:
        return None
    by_tactic: dict[str, list[str]] = {}
    for m in report.ttp_mappings:
        tac = m.tactic or ""
        by_tactic.setdefault(tac, [])
        tid = m.technique_id or ""
        if tid and tid not in by_tactic[tac]:
            by_tactic[tac].append(tid)
    cols = [(tid, name) for tid, name in _tactic_columns() if tid in by_tactic]
    if not cols:
        return None
    # A mapping whose tactic has no column in the catalogue's order, or one
    # past a column's eight cells, is not drawn; the legend counts it.
    mapped = sum(len(techniques) for techniques in by_tactic.values())
    drawn = sum(min(len(by_tactic[t]), _MATRIX_CELLS) for t, _ in cols)
    # A column is as wide as its longest header needs, never narrower than 118.
    col_w = max(
        118,
        max(8 + _label_width(_written(name), 11, "bold") + _LABEL_PAD for _tid, name in cols),
    )
    gap = 8
    width = len(cols) * (col_w + gap) + gap
    max_rows = max((len(by_tactic[t]) for t, _ in cols), default=0)
    height = 60 + max_rows * 22 + 16
    parts: list[str] = []
    for i, (tid, name) in enumerate(cols):
        x = gap + i * (col_w + gap)
        parts.append(_rect(x, 12, col_w, 34, fill="#f6f8fa"))
        parts.append(_text(x + 8, 32, _written(name), fill=_INK, size=11, weight="bold"))
        for j, tech in enumerate(by_tactic[tid][:_MATRIX_CELLS]):
            ty = 52 + j * 22
            parts.append(_rect(x, ty, col_w, 18, fill="#ddf4ff", stroke=_ACCENT))
            parts.append(_text(x + 6, ty + 13, _written(tech), fill=_ACCENT, size=10))
    return Figure(
        id="fig-attack-matrix",
        caption="MITRE ATT&CK tactic coverage",
        kind="attack_matrix",
        content=_svg(width, height, "".join(parts)),
        legend=_figure_left_out(mapped, drawn, "techniques").strip() or None,
    )


# ---------------------------------------------------------------------------
# Section entropy chart
# ---------------------------------------------------------------------------


def build_entropy_chart(report: MalwareReport) -> Figure | None:
    if not report.static or not report.static.sections:
        return None
    every = report.static.sections
    sections = every[:_ENTROPY_SECTIONS]
    bar_h = 22
    height = 40 + len(sections) * (bar_h + 8)
    width = 620
    axis_x = 130
    max_w = width - axis_x - 60
    parts: list[str] = [_text(12, 20, "Section entropy (0–8)", fill=_MUTED, size=11)]
    for i, sec in enumerate(sections):
        y = 34 + i * (bar_h + 8)
        ent = max(0.0, min(8.0, float(sec.entropy or 0.0)))
        w = int(max_w * ent / 8.0)
        color = _DANGER if ent >= 7.0 else (_WARN if ent >= 6.0 else _ACCENT)
        parts.append(
            _text(12, y + 15, marked_cut(_written(sec.name or "?"), 16), fill=_INK, size=11)
        )
        parts.append(_rect(axis_x, y, max_w, bar_h, fill="#f6f8fa", stroke=_LINE))
        parts.append(_rect(axis_x, y, max(2, w), bar_h, fill=color, stroke="none", rx=0))
        parts.append(_text(axis_x + max_w + 8, y + 15, f"{ent:.2f}", fill=_MUTED, size=11))
    return Figure(
        id="fig-entropy",
        caption="Section entropy",
        kind="entropy_chart",
        content=_svg(width, height, "".join(parts)),
        legend="Red ≥ 7.0 bits per byte, orange ≥ 6.0. A name ending in … is cut to fit."
        + _figure_left_out(len(every), len(sections), "sections"),
    )


# ---------------------------------------------------------------------------
# Network graph
# ---------------------------------------------------------------------------


def _published_values(report: MalwareReport) -> set[tuple[str, str]]:
    """The network values the report publishes as ``(kind, key)`` (the IOC section's set)."""
    from malspark.reporting.detection_signatures import _published_rows
    from malspark.reporting.ledger_projection import value_key

    try:
        return {
            (str(row.kind), value_key(str(row.kind), row.value))
            for row in _published_rows(report)
            if row.kind in ("domain", "ip")
        }
    except Exception as exc:  # noqa: BLE001 — a figure is never worth a report
        logger.warning("The published network values were not read (%s).", type(exc).__name__)
        return set()


def _form_values(report: MalwareReport) -> set[tuple[str, str]]:
    """The IOC table's rows read from the file's strings that print their form.

    As ``(kind, key)`` (``reporting.string_row_form``); none where the table
    cannot be read, and every name is then drawn as the network block holds it.
    """
    from malspark.reporting.builder import ioc_table
    from malspark.reporting.string_row_form import string_row_forms

    try:
        return set(string_row_forms(report, ioc_table(report)))
    except Exception as exc:  # noqa: BLE001 — a figure is never worth a report
        logger.warning("The strings rows' forms were not read (%s).", type(exc).__name__)
        return set()


def _endpoints_left_out(total: int, shown: int, formed: int) -> str:
    """The legend's sentences for the endpoints and the strings values it did not draw.

    ``formed`` counts the values of ``_form_values`` apart from the ``total``
    endpoints, so the numbers printed add up to what the JSON report holds. The
    readers are named as the rule checks them (``reporting.string_row_form``),
    the URL reader as the host the platform reads from a URL. ``""`` where
    nothing is left out.
    """
    if formed <= 0:
        return _figure_left_out(total, shown, "endpoints")
    rest = int(total) - int(shown)
    endpoints = "endpoint" if int(total) == 1 else "endpoints"
    said = ""
    if rest > 0:
        said = (
            f" {rest:,} more " + ("endpoint is" if rest == 1 else "endpoints are") + " not drawn."
        )
    if formed == 1:
        values = "value"
        why = (
            "1 value read from the file's strings is not drawn: it is not published, it is "
            "neither a domain row of another source nor a domain the judge named, it is not the "
            "host the platform reads from a URL of this run, and it was not recovered with a "
            "spelling that reads as a host."
        )
    else:
        values = "values"
        why = (
            f"{formed:,} values read from the file's strings are not drawn: none is published, "
            "none is a domain row of another source or a domain the judge named, none is the "
            "host the platform reads from a URL of this run, and none was recovered with a "
            "spelling that reads as a host."
        )
    return (
        f"{said} {why} The JSON report holds {'all' if rest > 0 else 'the'} {int(total):,} "
        f"{endpoints} and the {formed:,} {values}."
    )


def _source_word(source: str | None, capture_only: bool = False) -> str:
    """Where a network row's value was read from, in the words its box prints.

    Read from the row's ``source`` and ``capture_only`` alone. ``network
    record`` is a resolution, a request or a flow a sandbox or a capture
    recorded (an address read only from a capture's conversations among them);
    ``TLS name only`` a name only a capture's TLS names hold; ``text only, no
    network record`` a value read from text (the file's strings, a decoder's or
    any tool's printed answer); ``analyst listing only`` a value only an
    agent's own listing holds.
    """
    if source == "sandbox":
        return "TLS name only" if capture_only else "network record"
    if source == "strings":
        return "text only, no network record"
    if source == "analyst":
        return "analyst listing only"
    return "source not recorded"


# A network box: its value, cut at 44 characters or where it would reach the
# source word, then the source word in a column of its own; the box holds the
# longest source word (:func:`_label_width`).
_NETWORK_LABEL_CHARS = 44
_NETWORK_WORD_AT = 320
_NETWORK_BOX_W = 504


def build_network_graph(report: MalwareReport) -> Figure | None:
    from malspark.reporting.ledger_projection import value_key

    net = report.network
    if not net or not (net.domains or net.ips):
        return None
    held = _published_values(report)
    forms = _form_values(report) if any(d.source == "strings" for d in net.domains) else set()
    # ``(label, red, source word, the sample's processes reached it)``.
    every: list[tuple[str, bool, str, bool]] = []
    # A value read from the file's strings that no reader the rule checks
    # holds as a host is no endpoint: it is counted in the legend, never drawn.
    formed = 0
    for d in net.domains:
        if d.source == "strings" and ("domain", value_key("domain", d.fqdn)) in forms:
            formed += 1
            continue
        flagged = bool(getattr(d, "is_suspicious", False)) or (
            ("domain", value_key("domain", d.fqdn)) in held
        )
        word = _source_word(d.source, bool(d.capture_only))
        every.append((defang(d.fqdn, "domain"), flagged, word, d.sample_process_tree is True))
    for ip in net.ips:
        address = defang(ip.address, "ip")
        flagged = bool(getattr(ip, "is_suspicious", False)) or (
            ("ip", value_key("ip", ip.address)) in held
        )
        if ip.port:
            # An address holding a colon is bracketed, so its port reads apart.
            bare = ":" in ip.address and not ip.address.startswith("[")
            label = f"[{address}]:{ip.port}" if bare else f"{address}:{ip.port}"
        else:
            label = address
        every.append((label, flagged, _source_word(ip.source), ip.sample_process_tree is True))
    # A figure holds twelve endpoints; the rest are counted in its legend.
    endpoints = every[:_NETWORK_ENDPOINTS]
    if not endpoints:
        return None
    row_h = 30
    height = max(80, len(endpoints) * row_h + 30)
    # The sample's node, and a line from it, only where a row says the
    # sample's own processes reached the endpoint.
    hub = any(reached for *_rest, reached in endpoints)
    cx, cy = 90, height // 2
    bx = 160 if hub else 12
    width = bx + _NETWORK_BOX_W + 12
    parts: list[str] = []
    if hub:
        parts.append(f'<circle cx="{cx}" cy="{cy}" r="26" fill="#ddf4ff" stroke="{_ACCENT}"/>')
        parts.append(_text(cx - 20, cy + 4, "sample", fill=_ACCENT, size=11, weight="bold"))
    for i, (label, red, word, reached) in enumerate(endpoints):
        y = 20 + i * row_h
        if reached:
            parts.append(
                f'<line x1="{cx + 26}" y1="{cy}" x2="{bx}" y2="{y + 11}" stroke="{_LINE}"/>'
            )
        col = _DANGER if red else _MUTED
        parts.append(_rect(bx, y, _NETWORK_BOX_W, 22, fill="#fff", stroke=col))
        parts.append(
            _text(
                bx + 8,
                y + 15,
                _fitted_label(label, _NETWORK_LABEL_CHARS, _NETWORK_WORD_AT - 8 - _LABEL_PAD, 11),
                fill=_INK,
                size=11,
            )
        )
        parts.append(_text(bx + _NETWORK_WORD_AT, y + 15, _written(word), fill=_MUTED, size=10))
    joined = (
        " A line from the sample joins an endpoint the sandbox records the sample's process "
        "tree reaching."
        if hub
        else ""
    )
    return Figure(
        id="fig-network",
        caption="Network endpoints",
        kind="network_graph",
        content=_svg(width, height, "".join(parts)),
        legend="Red border = flagged suspicious or published. Each box names where its value "
        "was read from. A label ending in … is cut to fit."
        + joined
        + _endpoints_left_out(len(every), len(endpoints), formed),
    )


# ---------------------------------------------------------------------------
# Infection-chain flow
# ---------------------------------------------------------------------------


# A chain box is as wide as its longest tactic name needs, never narrower than 150.
_CHAIN_BOX_W = 150


def build_infection_chain(report: MalwareReport) -> Figure | None:
    present = {m.tactic for m in report.ttp_mappings if m.tactic}
    # A tactic with no column in the catalogue's order is never placed; the
    # legend counts it.
    stages = [(tid, name) for tid, name in _tactic_columns() if tid in present]
    if len(stages) < 2:
        return None
    box_w = max(
        _CHAIN_BOX_W,
        max(8 + _label_width(_written(name), 11) + _LABEL_PAD for _tid, name in stages),
    )
    box_h, gap = 40, 26
    per_row = 4
    width = per_row * box_w + (per_row - 1) * gap + 24
    rows = (len(stages) + per_row - 1) // per_row
    height = rows * (box_h + gap) + 12
    parts: list[str] = []
    for i, (_tid, name) in enumerate(stages):
        r, c = divmod(i, per_row)
        x = 12 + c * (box_w + gap)
        y = 12 + r * (box_h + gap)
        parts.append(_rect(x, y, box_w, box_h, fill="#f6f8fa", stroke=_ACCENT))
        parts.append(_text(x + 8, y + 24, _written(name), fill=_INK, size=11))
        if i < len(stages) - 1 and c < per_row - 1:
            ax = x + box_w
            parts.append(
                f'<line x1="{ax}" y1="{y + box_h // 2}" x2="{ax + gap}" y2="{y + box_h // 2}" '
                f'stroke="{_MUTED}" marker-end="url(#arrow)"/>'
            )
    defs = (
        f'<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" '
        f'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="{_MUTED}"/></marker></defs>'
    )
    return Figure(
        id="fig-infection-chain",
        caption="Tactics of the mapped techniques, in ATT&CK order",
        kind="infection_chain",
        content=_svg(width, height, defs + "".join(parts)),
        legend="Tactics are drawn in ATT&CK order, not the order read from the run: neither the "
        "order nor the arrows come from the run's events."
        + _figure_left_out(len(present), len(stages), "tactics"),
    )


def build_execution_flow(report: MalwareReport) -> Figure | None:
    """The report's execution-flow steps as a column of boxes, entry to steady state.

    Drawn when the analyst report is rendered, from the steps the report holds
    (``renderers.analyst.flow_step_labels``, the same labels its Markdown
    diagram carries); ``None`` for fewer than two steps.
    """
    from malspark.reporting.renderers.analyst import flow_steps

    labels = flow_steps(report)
    if not labels:
        return None
    box_w, box_h, gap = 660, 30, 18
    width = box_w + 24
    height = len(labels) * (box_h + gap) - gap + 24
    parts: list[str] = []
    for i, (label, mark, sentence) in enumerate(labels):
        y = 12 + i * (box_h + gap)
        observed = mark == "observed"
        # The box's title is the step's whole first sentence: a viewer shows
        # it over a label cut at a word.
        parts.append(f"<g><title>{escape(_written(f'{sentence} ({mark})'))}</title>")
        parts.append(
            _rect(12, y, box_w, box_h, fill="#f6f8fa", stroke=_ACCENT if observed else _LINE)
        )
        parts.append(_text(22, y + 19, _written(f"{label} ({mark})"), fill=_INK, size=11))
        parts.append("</g>")
        if i < len(labels) - 1:
            x = 12 + box_w // 2
            parts.append(
                f'<line x1="{x}" y1="{y + box_h}" x2="{x}" y2="{y + box_h + gap}" '
                f'stroke="{_MUTED}" marker-end="url(#flow-arrow)"/>'
            )
    defs = (
        f'<defs><marker id="flow-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" '
        f'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="{_MUTED}"/></marker></defs>'
    )
    return Figure(
        id="fig-execution-flow",
        caption="Execution flow, entry point to steady state",
        kind="execution_flow",
        content=_svg(width, height, defs + "".join(parts)),
        legend="A step the report marks observed is outlined in blue; every other step is "
        "marked assessed. Each box holds its step's first sentence, shortened at a word where "
        "it is long; the box's title and the numbered steps hold it whole.",
    )


# ---------------------------------------------------------------------------
# Decompiled code listings (text figures), from any decompiler
# ---------------------------------------------------------------------------


def _listed_symbol(output: dict[str, Any], facts: Any) -> str:
    """What a listing's caption names: the call's symbol, else its address argument.

    The address argument is the one the tool declares for the ``address``
    role, else one named for an address (``core.undeclared_tools.
    address_arguments``), as the call gave it. ``function`` when the call
    names neither.
    """
    symbol = str(output.get("symbol") or "").strip()
    if symbol:
        return symbol
    held = output.get("args")
    args: dict[str, Any] = held if isinstance(held, dict) else {}
    for name in address_arguments(facts, tuple(args)):
        value = args.get(name)
        if isinstance(value, str | int) and not isinstance(value, bool) and str(value).strip():
            return str(value).strip()
    return "function"


# The note a listing read from an answer cut for storage carries.
LISTING_CUT_FOR_STORAGE = "The answer was cut for storage; the listing ends where the cut fell."
# The note the last function read of a batch's answer cut for storage carries.
ANSWER_CUT_AFTER_LISTING = (
    "The answer was cut for storage after this function; later functions are not shown."
)


def build_code_listings(report: MalwareReport) -> list[Figure]:
    """The first ``_LISTINGS`` decompiled functions as figures, the rest counted.

    A figure is a drawing of a few functions, not the record: the last one
    drawn says how many more the run decompiled, and the evidence ledger holds
    every listing whole.
    """
    from malspark.core.undeclared_tools import code_parts_read

    with code_parts_read():
        return _build_code_listings(report)


def _build_code_listings(report: MalwareReport) -> list[Figure]:
    """:func:`build_code_listings`, each answer read once (``undeclared_tools.code_parts_read``)."""
    # ``(caption, code, cut, cut after it, function key)``: the key is a
    # batch function's, which is drawn once, and not where a single listing
    # of the function is drawn.
    listed: list[tuple[str, str, bool, bool, str | None]] = []
    for outputs in (report.technical_evidence or {}).values():
        for o in outputs or []:
            if not tool_kinds.reads_code(o, "figures.code_listing"):
                continue
            # A failed call's answer is an error, not a listing: the ledger
            # report skips it, and no figure says a function was decompiled.
            if o.get("ok") is False:
                continue
            # An answer that lists several functions (a batch) is one listing
            # per function, captioned by the function it names.
            parts = tool_kinds.function_parts(o)
            if parts:
                listed.extend(
                    (p.where, p.code, p.cut, p.answer_cut, function_key(p.where)) for p in parts
                )
                continue
            # What is drawn is the code the answer holds: a JSON answer's code
            # field, read at the declared path or as its one code-like string,
            # with its own line breaks; a plain text answer as it was. A JSON
            # answer holding no code (a search's hits, a status record) is not
            # drawn as a decompiled function.
            facts = tool_kinds.facts_of(o)
            path = str(facts.values.get("code", "")) if facts is not None else ""
            rows = str(facts.rows or "") if facts is not None and path else ""
            body, cut = code_listing(o.get("output"), path, rows)
            if body:
                listed.append((_listed_symbol(o, facts), body, cut, False, None))
    # One function, in any spelling, is one listing: a batch's function a
    # single listing draws, or another batch listed, is not drawn again.
    seen = {function_key(item[0]) for item in listed if item[4] is None}
    drawn: list[tuple[str, str, bool, bool]] = []
    for sym, body, cut, after, key in listed:
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        drawn.append((sym, body, cut, after))
    figs: list[Figure] = []
    # A listing is printed for reading, not to compile, and a PDF viewer
    # links a URL or a host in its text: the caption and the code are
    # defanged, the run's recorded values first, then every other value.
    from malspark.reporting.defang import ProseDefanger
    from malspark.reporting.renderers.markdown import _defanged_text, run_network_values

    run_values = ProseDefanger(run_network_values(report)) if drawn else None
    for seq, (named, code, cut, after) in enumerate(drawn[:_LISTINGS]):
        sym = _defanged_text(named, run_values)
        body = _defanged_text(code, run_values)
        notes: list[str] = []
        if cut:
            notes.append(LISTING_CUT_FOR_STORAGE)
        if after:
            notes.append(ANSWER_CUT_AFTER_LISTING)
        # An answer cut for storage is held whole nowhere: beside its note the
        # pointer names the listing as it was stored.
        if len(body) > _LISTING_CHARS:
            held = "as it was stored" if cut else "whole"
            notes.append(
                f"Cut at {_LISTING_CHARS:,} of {len(body):,} characters; the evidence "
                f"ledger and the JSON report carry the listing {held}."
            )
        if seq == _LISTINGS - 1 and len(drawn) > _LISTINGS:
            notes.append(
                f"{len(drawn) - _LISTINGS} more decompiled functions are not drawn; the "
                "evidence ledger carries every one."
            )
        figs.append(
            Figure(
                id=f"fig-listing-{seq}",
                caption=f"Decompiled {sym}",
                kind="code_listing",
                content=f'<pre class="listing">{escape(marked_cut(body, _LISTING_CHARS))}</pre>',
                legend=" ".join(notes) or None,
            )
        )
    return figs


def _not_drawn(kind: str, exc: Exception) -> Figure:
    """The line a reader sees where a figure failed to draw, so its absence is explained."""
    said = f"Figure not drawn: {kind} ({type(exc).__name__})"
    return Figure(
        id=f"fig-not-drawn-{kind.replace('_', '-')}",
        caption=said,
        kind="not_drawn",
        content=f'<p class="figure-not-drawn">{escape(said)}</p>',
        legend=None,
    )


def build_figures(report: MalwareReport) -> list[Figure]:
    """Assemble every applicable figure in report order. A failure is said, never raised."""
    figs: list[Figure] = []
    for builder, kind in (
        (build_infection_chain, "infection_chain"),
        (build_attack_matrix, "attack_matrix"),
        (build_process_tree, "process_tree"),
        (build_entropy_chart, "entropy_chart"),
        (build_network_graph, "network_graph"),
    ):
        try:
            fig = builder(report)
        except Exception as exc:  # noqa: BLE001
            # One figure's failure never costs the report, and is never silent.
            logger.warning("A figure was not drawn (%s: %s).", kind, type(exc).__name__)
            fig = _not_drawn(kind, exc)
        if fig is not None:
            figs.append(fig)
    try:
        figs.extend(build_code_listings(report))
    except Exception as exc:  # noqa: BLE001
        logger.warning("The code listings were not drawn (%s).", type(exc).__name__)
        figs.append(_not_drawn("code_listing", exc))
    return figs
