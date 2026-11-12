"""Agreement between two or more scorers of the same items, computed by code.

    python scripts/blind/run.py agreement SHEET_OR_SCORE [SHEET_OR_SCORE ...] [--json]
        [--leave-out-wrong] [--column ID]

Each file is one rater. A blind score sheet (``.csv``, the template ``prepare`` writes, filled)
is read cell by cell; a score file readable by ``scripts.benchmark.scores.read_scored`` (a key
score ``.md``) is read as its item verdicts. ``NAME=path`` names a rater, else the file stem
does. A blank cell is a missing rating. The ``beyond_human`` row is not an item.

Items are the units of comparison. A sheet with several arm columns yields one unit per
``column:item`` (so two scorers of the same sheet are compared cell for cell); a sheet with
one column, or ``--column``, and a score file yield plain item keys.

The verdict scale is the key scale of ``scores.py``, worst first::

    wrong < missed < partly (dump) < partly (body) < found

Nominal statistics (percentage agreement, Cohen's kappa, Fleiss' kappa, nominal alpha) treat the
five verdicts as unordered classes; ``wrong`` is a class of its own. The ordinal statistics
(linear weighted kappa, ordinal alpha) use the order above, ``wrong`` the lowest rank. With
``--leave-out-wrong`` they leave out every rating of ``wrong`` instead (pairwise: the items one of
the two rated ``wrong``; alpha: the ratings), and the count left out is reported.

The collapsed view recodes every verdict as credited (``partly (dump)`` or better, as
``scores.py`` credits it) or not credited, and computes the same statistics.

A statistic that has no defined value (one category only, a single item, no overlap between two
raters, fewer than three raters for Fleiss) is reported as ``None`` with a reason, never as NaN.
Standard library only.
"""

from __future__ import annotations

import csv
import json
import math
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any

from scripts.benchmark.scores import (
    CREDITED,
    KEY,
    KEY_ALIASES,
    SCALES,
    ScoreFileError,
    item_key,
    read_scored,
)

SCALE: tuple[str, ...] = SCALES[KEY]
CREDITED_FROM: int = SCALE.index(CREDITED[KEY])
COLLAPSED: tuple[str, ...] = ("not credited", "credited")
WRONG = SCALE[0]
BEYOND_ROW = "beyond_human"

# rater -> unit -> verdict (a missing rating is absent)
Ratings = dict[str, dict[str, str]]
Stat = dict[str, Any]


class AgreementError(RuntimeError):
    """An input cannot be read as ratings; the message names the file and why."""


def _stat(value: float | None, reason: str | None = None, **extra: Any) -> Stat:
    """A statistic: ``value`` is a finite float or None, with the reason when it is None."""
    if value is not None and not math.isfinite(value):
        value, reason = None, reason or "not finite"
    return {"value": value, "reason": reason if value is None else None, **extra}


# ---------------------------------------------------------------- reading


def _verdict(cell: str, where: str) -> str | None:
    word = " ".join(cell.split()).casefold()
    if not word:
        return None
    word = KEY_ALIASES.get(word, word)
    if word not in SCALE:
        raise AgreementError(f"{where}: {cell!r} is not one of {', '.join(SCALE)}")
    return word


def read_sheet(path: Path, column: str | None = None) -> dict[str, str]:
    """A filled blind score sheet as ``unit -> verdict``; blank cells are left out."""
    with Path(path).open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows or not rows[0] or rows[0][0] != "item":
        raise AgreementError(f"{path}: no header row starting with 'item'")
    columns = rows[0][1:]
    if len(set(columns)) != len(columns):
        repeated = sorted({c for c in columns if columns.count(c) > 1})
        raise AgreementError(f"{path}: duplicate column header {', '.join(map(repr, repeated))}")
    if column is not None:
        if column not in columns:
            raise AgreementError(f"{path}: no column {column!r}; it has {', '.join(columns)}")
        picked = [column]
    else:
        picked = columns
    prefixed = len(columns) > 1 and column is None
    out: dict[str, str] = {}
    seen: dict[str, str] = {}
    for row in rows[1:]:
        if not row or not row[0].strip() or row[0].strip() == BEYOND_ROW:
            continue
        label = row[0].strip()
        if item_key(label) in seen:
            raise AgreementError(f"{path}: item {label!r} is scored twice")
        seen[item_key(label)] = label
        for name in picked:
            index = columns.index(name) + 1
            cell = row[index] if index < len(row) else ""
            word = _verdict(cell, f"{path} item {row[0].strip()} column {name}")
            if word is None:
                continue
            key = item_key(row[0].strip())
            out[f"{name}:{key}" if prefixed else key] = word
    return out


def read_rater(path: Path, column: str | None = None) -> dict[str, str]:
    """One rater's ``unit -> verdict`` from a ``.csv`` sheet or a ``read_scored`` file."""
    path = Path(path)
    try:
        if path.suffix.lower() == ".csv":
            return read_sheet(path, column)
        run = read_scored(path)
    except (ScoreFileError, OSError) as exc:
        hint = "; a blind score sheet is read as .csv" if path.suffix.lower() == ".json" else ""
        raise AgreementError(f"{exc}{hint}") from exc
    out: dict[str, str] = {}
    for key, (scale, word) in run.verdicts.items():
        if scale != KEY:
            raise AgreementError(f"{path}: item {key} is on the {scale} scale, not the key scale")
        if word is not None:
            out[key] = word
    return out


def read_raters(specs: list[str], column: str | None = None) -> Ratings:
    """Every ``[NAME=]path`` as a rater; two raters may not share a name."""
    ratings: Ratings = {}
    for spec in specs:
        name, sep, rest = spec.partition("=")
        path = Path(rest if sep else spec)
        name = name if sep else path.stem
        if name in ratings:
            raise AgreementError(f"two raters are named {name!r}; name one as NAME=path")
        ratings[name] = read_rater(path, column)
        if not ratings[name]:
            raise AgreementError(f"{path}: no item is rated (an unfilled template?)")
    for first, second in combinations(ratings, 2):
        if set(ratings[first]) & set(ratings[second]):
            continue
        prefixed = [all(":" in u for u in ratings[r]) for r in (first, second)]
        hint = (
            "; one sheet has several arm columns and the other none: use --column"
            if (prefixed[0] != prefixed[1])
            else ""
        )
        raise AgreementError(f"{first} and {second} share no item{hint}")
    return ratings


# ---------------------------------------------------------------- statistics


def percent_agreement(pairs: list[tuple[str, str]]) -> Stat:
    """Observed agreement p_o = (pairs with equal verdicts) / (pairs); as a percentage."""
    if not pairs:
        return _stat(None, "no item rated by both", n=0)
    same = sum(1 for a, b in pairs if a == b)
    return _stat(100.0 * same / len(pairs), n=len(pairs), agree=same)


def cohens_kappa(pairs: list[tuple[str, str]]) -> Stat:
    """Cohen's kappa (1960): (p_o - p_e) / (1 - p_e), p_e = sum_c p_1(c) p_2(c)."""
    n = len(pairs)
    if n == 0:
        return _stat(None, "no item rated by both", n=0)
    if n == 1:
        return _stat(None, "a single item", n=n)
    po = sum(1 for a, b in pairs if a == b) / n
    first = Counter(a for a, _ in pairs)
    second = Counter(b for _, b in pairs)
    pe = sum(first[c] * second[c] for c in first) / (n * n)
    if pe >= 1.0:
        return _stat(None, "both raters used one category only: chance agreement is 1", n=n)
    return _stat((po - pe) / (1.0 - pe), n=n)


def weighted_kappa(pairs: list[tuple[str, str]], order: tuple[str, ...]) -> Stat:
    """Linear weighted kappa (Cohen 1968): 1 - sum w_ij o_ij / sum w_ij e_ij, w_ij = |i-j|/(k-1).

    ``o`` are the observed and ``e`` the chance-expected cell proportions, ``k`` the number of
    ordered categories of ``order`` (the whole scale, not only those used).
    """
    n = len(pairs)
    if n == 0:
        return _stat(None, "no item rated by both", n=0)
    if n == 1:
        return _stat(None, "a single item", n=n)
    k = len(order)
    index = {c: i for i, c in enumerate(order)}
    first = Counter(a for a, _ in pairs)
    second = Counter(b for _, b in pairs)
    observed = sum(abs(index[a] - index[b]) for a, b in pairs) / (n * (k - 1))
    expected = sum(
        first[a] * second[b] * abs(index[a] - index[b]) for a in first for b in second
    ) / (n * n * (k - 1))
    if expected == 0.0:
        return _stat(None, "chance disagreement is 0: one category only", n=n)
    return _stat(1.0 - observed / expected, n=n)


def fleiss_kappa(ratings: Ratings, categories: tuple[str, ...]) -> Stat:
    """Fleiss' kappa (1971): (P_bar - P_e) / (1 - P_e) over the items every rater rated.

    P_i = (sum_j n_ij^2 - m) / (m (m - 1)) for m raters, P_bar their mean, P_e = sum_j p_j^2.
    """
    names = sorted(ratings)
    m = len(names)
    if m < 3:
        return _stat(None, "needs three or more raters")
    units = sorted(set.intersection(*(set(ratings[r]) for r in names)))
    dropped = len(set().union(*(set(ratings[r]) for r in names))) - len(units)
    if not units:
        return _stat(None, "no item rated by every rater", n=0, left_out=dropped, units=[])
    if len(units) == 1:
        return _stat(None, "a single item", n=1, left_out=dropped, units=units)
    totals: Counter[str] = Counter()
    p_sum = 0.0
    for unit in units:
        row = Counter(ratings[r][unit] for r in names)
        totals.update(row)
        p_sum += (sum(v * v for v in row.values()) - m) / (m * (m - 1))
    p_bar = p_sum / len(units)
    pe = sum((totals[c] / (len(units) * m)) ** 2 for c in categories)
    if pe >= 1.0:
        return _stat(
            None,
            "one category only: chance agreement is 1",
            n=len(units),
            left_out=dropped,
            units=units,
        )
    return _stat((p_bar - pe) / (1.0 - pe), n=len(units), left_out=dropped, units=units)


def krippendorff_alpha(ratings: Ratings, categories: tuple[str, ...], *, ordinal: bool) -> Stat:
    """Krippendorff's alpha (2011): 1 - (n-1) sum o_ck d_ck / sum n_c n_k d_ck.

    ``o`` is the coincidence matrix (each unit with m_u >= 2 ratings adds 1/(m_u-1) per ordered
    pair of its ratings), ``n_c`` its marginals, ``n`` their sum. Nominal: d = 1 for c != k.
    Ordinal: d_ck = (n_c/2 + sum of n_g strictly between c and k + n_k/2)^2. Units with fewer
    than two ratings carry no pair and are left out; missing ratings are tolerated.
    """
    units: dict[str, list[str]] = {}
    for rater in ratings.values():
        for unit, word in rater.items():
            units.setdefault(unit, []).append(word)
    coincidence: Counter[tuple[str, str]] = Counter()
    entered = sorted(u for u, v in units.items() if len(v) > 1)
    used = len(entered)
    extra = {"left_out_units": len(units) - used, "units": entered}
    for values in units.values():
        if len(values) < 2:
            continue
        for i, a in enumerate(values):
            for j, b in enumerate(values):
                if i != j:
                    coincidence[(a, b)] += 1.0 / (len(values) - 1)
    if used == 0:
        return _stat(None, "no item rated by two raters", n=0, **extra)
    marginal: Counter[str] = Counter()
    for (a, _), weight in coincidence.items():
        marginal[a] += weight
    total = sum(marginal.values())
    present = [c for c in categories if marginal[c] > 0]
    if len(present) < 2:
        return _stat(None, "one category only: no expected disagreement", n=used, **extra)

    def delta(c: str, k: str) -> float:
        if c == k:
            return 0.0
        if not ordinal:
            return 1.0
        lo, hi = sorted((categories.index(c), categories.index(k)))
        between = sum(marginal[categories[g]] for g in range(lo + 1, hi))
        return (marginal[categories[lo]] / 2 + between + marginal[categories[hi]] / 2) ** 2

    observed = sum(w * delta(a, b) for (a, b), w in coincidence.items())
    expected = sum(marginal[c] * marginal[k] * delta(c, k) for c in present for k in present)
    if expected == 0.0:
        return _stat(None, "no expected disagreement", n=used, **extra)
    return _stat(1.0 - (total - 1.0) * observed / expected, n=used, **extra)


# ---------------------------------------------------------------- one view


def _pair_units(a: dict[str, str], b: dict[str, str]) -> list[str]:
    return sorted(set(a) & set(b))


def _confusion(pairs: list[tuple[str, str]], categories: tuple[str, ...]) -> dict[str, Any]:
    cells = Counter(pairs)
    return {
        "categories": list(categories),
        "rows_are": "first rater",
        "matrix": [[cells[(r, c)] for c in categories] for r in categories],
    }


def analyse(
    ratings: Ratings, categories: tuple[str, ...], *, ordered: bool, leave_out_wrong: bool
) -> dict[str, Any]:
    """Every statistic of one view of the ratings (``categories`` worst first)."""
    names = sorted(ratings)
    drop = leave_out_wrong and WRONG in categories
    out: dict[str, Any] = {"categories": list(categories), "raters": names, "pairs": {}}
    pooled: list[tuple[str, str]] = []
    for first, second in combinations(names, 2):
        units = _pair_units(ratings[first], ratings[second])
        pairs = [(ratings[first][u], ratings[second][u]) for u in units]
        pooled += pairs
        entry: dict[str, Any] = {
            "n": len(pairs),
            "units": units,
            "percent_agreement": percent_agreement(pairs),
            "cohens_kappa": cohens_kappa(pairs),
            "confusion": _confusion(pairs, categories),
            "disagreements": [
                {"item": u, "verdicts": {first: ratings[first][u], second: ratings[second][u]}}
                for u in units
                if ratings[first][u] != ratings[second][u]
            ],
        }
        if ordered:
            kept = [p for p in pairs if not (drop and WRONG in p)]
            order = tuple(c for c in categories if not (drop and c == WRONG))
            entry["weighted_kappa"] = weighted_kappa(kept, order)
            entry["weighted_kappa"]["left_out_wrong"] = len(pairs) - len(kept)
            entry["weighted_kappa"]["units"] = [
                u for u, p in zip(units, pairs, strict=True) if p in kept
            ]
        out["pairs"][f"{first} / {second}"] = entry
    out["percent_agreement_overall"] = percent_agreement(pooled)
    out["percent_agreement_overall"]["basis"] = "all pairwise comparisons pooled"
    out["fleiss_kappa"] = fleiss_kappa(ratings, categories)
    out["krippendorff_alpha_nominal"] = krippendorff_alpha(ratings, categories, ordinal=False)
    if ordered:
        kept_ratings = {
            r: {u: w for u, w in given.items() if not (drop and w == WRONG)}
            for r, given in ratings.items()
        }
        order = tuple(c for c in categories if not (drop and c == WRONG))
        alpha = krippendorff_alpha(kept_ratings, order, ordinal=True)
        alpha["left_out_wrong_ratings"] = sum(map(len, ratings.values())) - sum(
            map(len, kept_ratings.values())
        )
        out["krippendorff_alpha_ordinal"] = alpha
    return out


def _collapse(ratings: Ratings) -> Ratings:
    return {
        r: {u: COLLAPSED[SCALE.index(w) >= CREDITED_FROM] for u, w in given.items()}
        for r, given in ratings.items()
    }


def agreement(ratings: Ratings, *, leave_out_wrong: bool = False) -> dict[str, Any]:
    """The full report: the five-verdict view and the credited / not credited view."""
    if len(ratings) < 2:
        raise AgreementError("name at least two raters")
    return {
        "scale": list(SCALE),
        "ordinal_order": "wrong < missed < partly (dump) < partly (body) < found",
        "wrong_handling": (
            "the verdict view's ordinal statistics leave out every rating of wrong"
            if leave_out_wrong
            else "wrong is its own nominal class and the lowest ordinal rank"
        ),
        "items_rated": {r: len(given) for r, given in sorted(ratings.items())},
        "verdicts": analyse(ratings, SCALE, ordered=True, leave_out_wrong=leave_out_wrong),
        "collapsed": analyse(_collapse(ratings), COLLAPSED, ordered=True, leave_out_wrong=False),
    }


# ---------------------------------------------------------------- output


def _fmt(stat: Stat, percent: bool = False) -> str:
    if stat["value"] is None:
        return f"n/a ({stat['reason']})"
    return f"{stat['value']:.1f}%" if percent else f"{stat['value']:.3f}"


def _render_view(title: str, view: dict[str, Any]) -> list[str]:
    lines = [title, "=" * len(title), ""]
    lines.append(f"Overall % agreement: {_fmt(view['percent_agreement_overall'], True)}")
    lines.append(f"Fleiss' kappa: {_fmt(view['fleiss_kappa'])}")
    lines.append(f"Krippendorff alpha (nominal): {_fmt(view['krippendorff_alpha_nominal'])}")
    if "krippendorff_alpha_ordinal" in view:
        alpha = view["krippendorff_alpha_ordinal"]
        note = (
            f" [{alpha['left_out_wrong_ratings']} wrong ratings left out]"
            if alpha["left_out_wrong_ratings"]
            else ""
        )
        lines.append(f"Krippendorff alpha (ordinal): {_fmt(alpha)}{note}")
    for pair, entry in view["pairs"].items():
        lines += ["", f"Pair {pair} ({entry['n']} items)"]
        lines.append(f"  % agreement: {_fmt(entry['percent_agreement'], True)}")
        lines.append(f"  Cohen's kappa: {_fmt(entry['cohens_kappa'])}")
        if "weighted_kappa" in entry:
            weighted = entry["weighted_kappa"]
            note = (
                f" [{weighted['left_out_wrong']} items with wrong left out]"
                if weighted["left_out_wrong"]
                else ""
            )
            lines.append(f"  linear weighted kappa: {_fmt(weighted)}{note}")
        cats = entry["confusion"]["categories"]
        width = max(len(c) for c in cats)
        lines.append("  confusion (rows: first rater, columns: second rater)")
        lines.append("  " + " " * width + "  " + "  ".join(c for c in cats))
        for cat, row in zip(cats, entry["confusion"]["matrix"], strict=True):
            cells = "  ".join(str(v).rjust(len(c)) for v, c in zip(row, cats, strict=True))
            lines.append(f"  {cat.ljust(width)}  {cells}")
        lines.append(f"  disagreements: {len(entry['disagreements'])}")
        for row in entry["disagreements"]:
            item = row["item"]
            rest = "; ".join(f"{k} {v}" for k, v in row["verdicts"].items())
            lines.append(f"    {item}: {rest}")
    return lines


def render(report: dict[str, Any]) -> str:
    """The report as text: the verdict view, then the credited / not credited view."""
    lines = [
        f"Scale (worst first): {report['ordinal_order']}",
        f"wrong: {report['wrong_handling']}",
        "Items rated: " + ", ".join(f"{r} {n}" for r, n in report["items_rated"].items()),
        "",
    ]
    lines += _render_view("Verdicts", report["verdicts"])
    lines += ["", *_render_view("Collapsed: credited vs not credited", report["collapsed"])]
    return "\n".join(lines)


def run(specs: list[str], *, as_json: bool, leave_out_wrong: bool, column: str | None) -> str:
    """Read the raters and return the report, as JSON or text."""
    report = agreement(read_raters(specs, column), leave_out_wrong=leave_out_wrong)
    return json.dumps(report, indent=2) if as_json else render(report)
