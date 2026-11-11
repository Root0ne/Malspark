"""A replay record and a comparison, as text for a terminal.

Codes, ids, kinds, counts and digests. A finding's words, a claim's text and
any value from the run are in the record only when the replay was asked for
them (``--show-text``), and are printed only then.
"""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.replay.record import errors

# Controls, format characters (bidirectional overrides, zero-width marks) and the
# line and paragraph separators, and lone surrogates: none of them is printable text.
_UNPRINTABLE = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def terminal_safe(text: object, *, encoding: str | None = None) -> str:
    """``text`` with every unprintable character shown as a visible escape.

    A string read from a stored run is data, not terminal input: an escape
    sequence, a carriage return or a bidirectional override in it must not act
    on the operator's terminal. Printable text, non-ASCII letters included, is
    unchanged. A newline is shown as ``\\n`` so one value stays on one line; the
    lines of a rendered text come from the renderer alone. A backslash is shown
    doubled, so a newline and the two characters backslash and ``n`` read apart
    and the text can be turned back into the value. A character the
    stream's ``encoding`` (default: ``sys.stdout``'s) cannot carry, such as a
    letter on a Windows code page, is shown as an escape too, so printing never
    raises; a UTF-8 stream shows every printable character as it was. One pass, linear.
    """
    out: list[str] = []
    for char in str(text):
        if char == "\n":
            out.append("\\n")
        elif char == "\\":
            out.append("\\\\")
        elif unicodedata.category(char) in _UNPRINTABLE:
            code = ord(char)
            out.append(
                f"\\x{code:02x}"
                if code < 0x100
                else f"\\u{code:04x}"
                if code < 0x10000
                else f"\\U{code:08x}"
            )
        else:
            out.append(char)
    return _encodable("".join(out), encoding or getattr(sys.stdout, "encoding", None))


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def write_json(path: Path, value: Any, *, newline: bool = False, **dumps: Any) -> None:
    """``value`` as JSON text in ``path``, as UTF-8, whatever strings it holds.

    A lone surrogate, which a stored text may hold, cannot be encoded: it is
    written as its JSON escape, so the file stays valid and loads back to the
    value. Every other byte is what ``json.dumps`` gives.
    """
    text = _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", json.dumps(value, **dumps))
    path.write_text(text + ("\n" if newline else ""), encoding="utf-8")


def _encodable(text: str, encoding: str | None) -> str:
    """``text`` with each character ``encoding`` cannot carry shown as an escape."""
    if not encoding:
        return text
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        return text.encode(encoding, "backslashreplace").decode(encoding)
    except LookupError:
        return text
    return text


def _s(value: object) -> str:
    """A value read from a stored run, on one line and safe for the terminal."""
    return terminal_safe(value)


def _show(value: object) -> str:
    """``value`` as Python writes it, each string escaped once and quoted like ``repr``."""
    if isinstance(value, str):
        quote = '"' if "'" in value and '"' not in value else "'"
        body = _s(value).replace("'", "\\'") if quote == "'" else _s(value)
        return f"{quote}{body}{quote}"
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{_show(k)}: {_show(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_show(item) for item in value) + "]"
    if isinstance(value, tuple):
        return (
            "(" + ", ".join(_show(item) for item in value) + ("," if len(value) == 1 else "") + ")"
        )
    return _s(repr(value))


def _join(sep: str, values: Iterable[object]) -> str:
    return sep.join(_s(value) for value in values)


def _codes(codes: Mapping[str, int] | None) -> str:
    return (
        ", ".join(f"{_s(code)} {_s(count)}" for code, count in sorted((codes or {}).items()))
        or "none"
    )


def _flag_line(flag: Mapping[str, Any]) -> str:
    parts = [_s(flag.get("code") or "")]
    for key in ("path", "subject"):
        said = flag.get(f"{key}_text") or flag.get(key)
        if said:
            parts.append(_s(said))
    for marker, said in (
        ("advisory", "advisory"),
        ("settled", "settled by the parse"),
        ("answered", "answered"),
    ):
        if flag.get(marker):
            parts.append(said)
    if flag.get("asked") is False:
        parts.append("not shown to its producer")
    if flag.get("entries"):
        parts.append(_join(", ", flag["entries"]))
    if flag.get("arguments"):
        parts.append("argument " + _join(", ", flag["arguments"]))
    line = " | ".join(parts)
    if flag.get("claim"):
        line += f"\n        claim: {_s(flag['claim'])}"
    if flag.get("message"):
        line += f"\n        said: {_s(flag['message'])}"
    if flag.get("values"):
        values = flag["values"]
        line += f"\n        values: {_s(values) if isinstance(values, str) else _show(values)}"
    return line


def render_record(record: Mapping[str, Any]) -> str:
    """One run's replay as text; a part that raised comes first."""
    lines: list[str] = [f"Replay of {_s(record.get('run'))}"]
    for row in errors(record):
        lines.append(f"  ERROR: {_s(row.get('part'))} raised: {_s(row.get('why'))}")
    rules = record.get("rules") or {}
    lines.append(f"  rules from: {_s(rules.get('tree', 'unknown'))}")
    stored = record.get("stored") or {}
    if stored:
        lines.append(
            f"  stored run: {len(stored.get('files') or {})} file(s), unchanged "
            "(each digested before and after the replay)"
        )
    env = record.get("environment") or {}
    if env:
        lines.append(
            f"  network {_s(env.get('network'))}; ATT&CK from {_s(env.get('attck'))}; "
            f"{len(env.get('settings_from_run') or [])} setting(s) from the run's snapshot"
        )
        if env.get("settings_refused"):
            lines.append(f"  settings this tree refused: {_join(', ', env['settings_refused'])}")
        if env.get("doors_this_tree_lacks"):
            lines.append(f"  doors this tree lacks: {_join(', ', env['doors_this_tree_lacks'])}")

    lines.append("")
    lines.append("Analysts")
    for agent, entry in (record.get("analysts") or {}).items():
        answers = entry.get("answers") or []
        replayed = [a for a in answers if a.get("replayed")]
        lines.append(f"  {_s(agent)}: {len(replayed)} of {len(answers)} stored answer(s) replayed")
        for answer in replayed:
            lines.append(
                f"    {_s(answer.get('answer'))} ({_s(answer.get('source'))}): "
                f"{_s(answer.get('claims'))} claim(s); {_codes(answer.get('codes'))}"
            )
        in_force = entry.get("in_force") or {}
        if in_force.get("replayed") is False:
            lines.append(f"    claims in force: not replayed ({_s(in_force.get('why'))})")
        elif in_force:
            lines.append(
                f"    claims in force: {_s(in_force.get('claims'))} claim(s); "
                f"{_codes(in_force.get('codes'))}"
            )
            for key, said in (
                ("not_valid", "technique ids marked not valid"),
                ("kept_after_absence_question", "kept after the absence question"),
            ):
                if in_force.get(key):
                    lines.append(f"      {said}: {_join(', ', in_force[key])}")

    def _part(title: str, key: str, extra: str = "") -> None:
        part = record.get(key) or {}
        if part.get("replayed") is False:
            lines.append(f"{title}: not replayed ({_s(part.get('why'))})")
        else:
            lines.append(f"{title}: {extra}{_codes(part.get('codes'))}")

    lines.append("")
    judge = record.get("judge") or {}
    _part(
        "Judge",
        "judge",
        f"{_s(judge.get('objects', 0))} object(s), {_s(judge.get('indicators_dropped', 0))} "
        "indicator(s) it would drop; "
        if judge.get("replayed")
        else "",
    )
    _part("Narrative", "narrative")
    composer = record.get("composer") or {}
    written = len(composer.get("sections") or {})
    not_written = composer.get("not_written") or []
    _part(
        "Composer",
        "composer",
        f"{written} section(s) replayed"
        + (f", not written in the stored report: {_join(', ', not_written)}" if not_written else "")
        + "; "
        if composer.get("replayed")
        else "",
    )
    tool = record.get("tool") or {}
    _part(
        "Tool calls",
        "tool",
        f"{_s(tool.get('calls', 0))} call(s); " if tool.get("replayed") else "",
    )
    _part("Report linter", "fp_linter")

    report = record.get("report") or {}
    if report.get("replayed"):
        techniques = report.get("techniques") or {}
        published = [t for t, row in techniques.items() if row.get("published")]
        indicators = report.get("indicators") or {}
        yes = [
            k for k, row in indicators.items() if str(row.get("published") or "").startswith("yes")
        ]
        lines.append(
            f"Report: {_s(report.get('verdict'))}, severity {_s(report.get('severity'))}, "
            f"category {_s(report.get('category_text') or report.get('category'))}, "
            f"confidence {_s(report.get('confidence'))}; "
            f"{len(report.get('sections') or [])} section(s); "
            f"{len(published)} of {len(techniques)} technique(s) published; {len(yes)} of "
            f"{len(indicators)} indicator(s) published"
        )
        degradation = report.get("degradation") or {}
        lines.append(
            f"  degraded: {_s(report.get('degraded'))}"
            + (
                f" ({_s(degradation.get('decided', 0))} reason(s) decided again, "
                f"{_s(degradation.get('stored_decided_again', 0))} stored one(s) of that kind "
                f"replaced, {_s(degradation.get('kept_as_stored', 0))} kept as stored)"
                if degradation
                else ""
            )
        )
        lines.append(
            "  exported techniques: "
            + (_join(", ", report.get("export", {}).get("attack_patterns") or []) or "none")
        )
        unpublished = {
            t: row.get("why_text") or row.get("why")
            for t, row in techniques.items()
            if not row.get("published")
        }
        for tid, why in unpublished.items():
            lines.append(f"  not published: {_s(tid)} ({_s(why)})")
        if "detection_rules" in report:
            lines.append(
                f"  detection rules drafted: {_codes(report.get('detection_rules'))}; "
                f"{_s(report.get('detection_rules_not_compiled', 0))} not compiled"
            )
        uncovered = report.get("claims_not_discussed")
        if uncovered is not None:
            listed = "; ".join(
                f"{_s(agent)} {_join(', ', numbers)}" for agent, numbers in uncovered.items()
            )
            lines.append(
                "  claims in force the body does not discuss: "
                f"{sum(len(n) for n in uncovered.values())}" + (f" ({listed})" if listed else "")
            )
    else:
        lines.append(f"Report: not replayed ({_s(report.get('why'))})")
    corroboration = (record.get("corroboration") or {}).get("techniques") or {}
    if corroboration:
        agreed = [t for t, row in corroboration.items() if row.get("corroborated")]
        lines.append(
            f"Corroboration: {len(corroboration)} technique(s), {len(agreed)} corroborated"
            + (f" ({_join(', ', agreed)})" if agreed else "")
        )

    lines.extend(_against_stored_lines(record.get("against_stored") or {}))

    totals = record.get("totals") or {}
    codes = sorted({code for part in totals.values() for code in part})
    if codes:
        lines.append("")
        lines.append("Codes, by producer")
        for code in codes:
            counts = ", ".join(
                f"{_s(part.replace('_', ' '))} {_s(totals[part][code])}"
                for part in totals
                if code in totals[part]
            )
            lines.append(f"  {_s(code)}: {counts}")

    flagged = _flags(record)
    if flagged:
        lines.append("")
        lines.append("Findings")
        for where, flags in flagged:
            lines.append(f"  {_s(where)}")
            lines.extend(f"    {_flag_line(flag)}" for flag in flags)

    not_replayed = record.get("not_replayed") or []
    if not_replayed:
        lines.append("")
        lines.append("Not replayed")
        lines.extend(
            f"  {_s(row['part'])}: {_s(row['why'])}" + (" [raised]" if row.get("error") else "")
            for row in not_replayed
        )
    return "\n".join(lines)


def _said(value: Any) -> str:
    """A text the record keeps as a digest, and its words when they are there."""
    if not isinstance(value, Mapping):
        return "absent" if value is None else _s(value)
    return f"{_s(value.get('digest'))}" + (f" {_show(value['text'])}" if "text" in value else "")


def _against_stored_lines(block: Mapping[str, Any]) -> list[str]:
    """What the rebuilt report does not share with the stored one, each with its named cause.

    Each named cause is printed once, numbered, under the differences.
    """
    if not block:
        return []
    lines = ["", "Against the stored report"]
    if block.get("compared") is False:
        return [*lines, f"  not compared ({_s(block.get('why'))})"]
    numbered: dict[tuple[str, str], int] = {}

    def _cause(row: Mapping[str, Any]) -> str:
        cause = row.get("cause") or {}
        if not cause:
            return " (no named cause)"
        key = (_s(cause.get("part")), _s(cause.get("why")))
        return f" (cause {numbered.setdefault(key, len(numbered) + 1)})"

    for key, row in (block.get("values") or {}).items():
        lines.append(
            f"  {_s(key)}: stored {_show(row.get('stored'))}, replayed {_show(row.get('replayed'))}"
        )
    for name, ids in (block.get("techniques") or {}).items():
        lines.append(f"  techniques published {_s(name.replace('_', ' '))}: {_join(', ', ids)}")
    sections = block.get("sections") or {}
    for name in ("only_stored", "only_replayed", "moved"):
        for row in sections.get(name) or []:
            lines.append(f"  section {name.replace('_', ' ')}: {_s(row['section'])}{_cause(row)}")
    for row in sections.get("contents") or []:
        where = f"{_s(row['section'])} {_s(row['field'])}" + (
            f" row {_s(row['row'])}" if "row" in row else ""
        )
        if "reordered" in row:
            lines.append(f"  {where}: the same parts in another order{_cause(row)}")
            continue
        if "merged" in row:
            lines.append(
                f"  {where}: {_s(row['merged'])} row(s) one table holds more often, the same once "
                f"the key order is set aside{_cause(row)}"
            )
            continue
        lines.append(
            f"  {where} differs: stored {_said(row.get('stored'))}, replayed "
            f"{_said(row.get('replayed'))}{_cause(row)}"
        )
    indicators = block.get("indicators") or {}
    for name in ("only_stored", "only_replayed"):
        for row in indicators.get(name) or []:
            lines.append(
                f"  indicator {name.replace('_', ' ')}: {_s(row['indicator'])}{_cause(row)}"
            )
    for row in indicators.get("changed") or []:
        lines.append(
            f"  indicator {_s(row['indicator'])} answers differently: "
            f"stored {_s(row.get('stored'))}, replayed {_s(row.get('replayed'))}{_cause(row)}"
        )
    for row in block.get("export") or []:
        lines.append(
            f"  export {_s(row['type'])} objects: stored {_s(row['stored'])}, replayed "
            f"{_s(row['replayed'])}{_cause(row)}"
        )
    if block.get("not_compared"):
        lines.append(
            "  not compared (the stored report holds none): " + _join(", ", block["not_compared"])
        )
    if len(lines) == 2:
        lines.append("  the same in everything compared")
    for (part, why), number in numbered.items():
        lines.append(f"  cause {number}: {part}: {why}")
    return lines


def _flags(record: Mapping[str, Any]) -> list[tuple[str, Sequence[Mapping[str, Any]]]]:
    out: list[tuple[str, Sequence[Mapping[str, Any]]]] = []
    for agent, entry in (record.get("analysts") or {}).items():
        for answer in entry.get("answers") or []:
            if answer.get("flags"):
                out.append((f"analyst {agent}, {answer.get('answer')}", answer["flags"]))
        in_force = entry.get("in_force") or {}
        if in_force.get("flags"):
            out.append((f"analyst {agent}, claims in force", in_force["flags"]))
    for part in ("judge", "narrative", "tool", "fp_linter"):
        flags = (record.get(part) or {}).get("flags") or []
        if flags:
            out.append((part, flags))
    for section, entry in ((record.get("composer") or {}).get("sections") or {}).items():
        if entry.get("flags"):
            out.append((f"composer {section}", entry["flags"]))
    return out


def render_diff(diff: Mapping[str, Any], ref_a: str, ref_b: str) -> str:
    """Every difference between two refs' replays of one run, as text.

    A part that raised in either tree comes first, then a part left
    uncompared: the comparison is then not a decision, and "no difference" is
    said only when every part replayed in both trees and was compared on both
    sides.
    """
    lines = [f"Compare {_s(diff.get('run'))}: A = {_s(ref_a)}, B = {_s(ref_b)}"]
    raised = diff.get("errors") or {}
    for side, ref in (("a", ref_a), ("b", ref_b)):
        for row in raised.get(side) or []:
            lines.append(
                f"  ERROR under {side.upper()} ({_s(ref)}): {_s(row.get('part'))} raised: "
                f"{_s(row.get('why'))}"
            )
    if raised.get("a") or raised.get("b"):
        lines.append(
            "  A part that raised is not a decision: this comparison is incomplete (status 2)."
        )
    schema = diff.get("schema") or {}
    if schema:
        lines.append(
            f"  The records are of schema {_s(schema.get('a'))} (A) and "
            f"{_s(schema.get('b'))} (B): only what both define is compared."
        )
    left = diff.get("not_compared") or {}
    if any(left.values()):
        lines.append("  PARTIAL COMPARISON: these parts were not compared (status 2):")
        for key, said in (
            ("a", f"defined only under A ({_s(ref_a)})"),
            ("b", f"defined only under B ({_s(ref_b)})"),
            ("differently", "written in forms the two schemas do not share"),
        ):
            if left.get(key):
                lines.append(f"    not compared, {said}: {_join(', ', left[key])}")
        lines.append("  A part that was not compared is not a decision either.")
    if not any(key not in ("run", "errors", "schema", "not_compared") for key in diff):
        if not (raised.get("a") or raised.get("b")) and not any(left.values()):
            lines.append("  no difference: both refs decide the same over this run")
        else:
            lines.append("  the parts replayed and compared on both sides decide the same")
        return "\n".join(lines)
    for key, title in (
        ("codes_gained", "Codes in B, not in A"),
        ("codes_lost", "Codes in A, not in B"),
    ):
        rows = diff.get(key) or []
        if rows:
            lines.append(f"  {title}:")
            for row in rows:
                where = _join(
                    " | ", (row[k] for k in ("part", "owner", "path", "subject") if row.get(k))
                )
                lines.append(f"    {_s(row['code'])} x{_s(row['count'])}: {where}")
    for key, title in (
        ("totals", "Counts by producer and code"),
        ("answers", "Claims each answer parsed into"),
        ("judge", "The judge's bundle"),
        ("composer", "The composer's sections"),
        ("tool", "The tool calls"),
        ("environment", "Settings and guards"),
        ("corroboration", "Corroboration"),
        ("not_replayed", "Parts not replayed"),
        ("replayed", "Parts replayed"),
    ):
        if diff.get(key):
            lines.append(f"  {title}:")
            lines.extend(f"    {line}" for line in _nested(diff[key]))
    report = diff.get("report") or {}
    if report:
        lines.append("  Report:")
        lines.extend(f"    {line}" for line in _nested(report))
    return "\n".join(lines)


def _nested(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, Mapping):
        if set(value) == {"a", "b"}:
            return [f"{prefix}A {_show(value['a'])} -> B {_show(value['b'])}"]
        out: list[str] = []
        for key, inner in value.items():
            label = f"{prefix}{_s(key)}"
            if isinstance(inner, Mapping | list) and inner:
                if isinstance(inner, Mapping) and set(inner) == {"a", "b"}:
                    out.append(f"{label}: A {_show(inner['a'])} -> B {_show(inner['b'])}")
                else:
                    out.append(f"{label}:")
                    out.extend(f"  {line}" for line in _nested(inner))
            else:
                out.append(f"{label}: {_show(inner)}")
        return out
    if isinstance(value, list):
        return [line for item in value for line in _nested(item, prefix)]
    return [f"{prefix}{_show(value)}"]
