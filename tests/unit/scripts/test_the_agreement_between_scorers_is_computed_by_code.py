"""Agreement between blind scorers: each statistic against a worked example, an independent
re-derivation from its formula, the degenerate cases, both input formats and the collapsed view.
"""

from __future__ import annotations

import csv
import json
import math
from itertools import permutations
from pathlib import Path

import pytest
from scripts.blind.agreement import (
    COLLAPSED,
    SCALE,
    AgreementError,
    agreement,
    cohens_kappa,
    fleiss_kappa,
    krippendorff_alpha,
    percent_agreement,
    read_raters,
    render,
    weighted_kappa,
)
from scripts.blind.run import main


def _pairs(table: dict[tuple[str, str], int]) -> list[tuple[str, str]]:
    return [pair for pair, count in table.items() for _ in range(count)]


def _kappa_by_hand(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    cats = {c for pair in pairs for c in pair}
    po = sum(a == b for a, b in pairs) / n
    pe = sum(
        (sum(a == c for a, _ in pairs) / n) * (sum(b == c for _, b in pairs) / n) for c in cats
    )
    return (po - pe) / (1 - pe)


# --- Cohen's kappa: the two 2x2 examples widely reproduced (50 and 100 subjects)


def test_cohens_kappa_matches_the_fifty_subject_textbook_table() -> None:
    # 20 yes/yes, 5 yes/no, 10 no/yes, 15 no/no: p_o 0.7, p_e 0.5, kappa 0.4
    pairs = _pairs({("y", "y"): 20, ("y", "n"): 5, ("n", "y"): 10, ("n", "n"): 15})
    got = cohens_kappa(pairs)["value"]
    assert got == pytest.approx(0.4)
    assert got == pytest.approx(_kappa_by_hand(pairs))
    assert percent_agreement(pairs)["value"] == pytest.approx(70.0)


def test_cohens_kappa_matches_the_hundred_subject_table() -> None:
    # 45 / 15 / 25 / 15: p_o 0.6, p_e 0.54, kappa 0.06 / 0.46 = 0.1304
    pairs = _pairs({("y", "y"): 45, ("y", "n"): 15, ("n", "y"): 25, ("n", "n"): 15})
    got = cohens_kappa(pairs)["value"]
    assert got == pytest.approx(0.06 / 0.46)
    assert round(got, 4) == 0.1304


# --- weighted kappa


def _weighted_by_hand(pairs: list[tuple[str, str]], order: tuple[str, ...], power: int) -> float:
    k, n = len(order), len(pairs)
    cell = {(a, b): sum(p == (a, b) for p in pairs) / n for a in order for b in order}
    row = {a: sum(cell[(a, b)] for b in order) for a in order}
    col = {b: sum(cell[(a, b)] for a in order) for b in order}
    w = {
        (a, b): (abs(order.index(a) - order.index(b)) / (k - 1)) ** power
        for a in order
        for b in order
    }
    return 1 - sum(w[x] * cell[x] for x in cell) / sum(
        w[(a, b)] * row[a] * col[b] for a in order for b in order
    )


def test_linear_weighted_kappa_on_a_three_by_three_table() -> None:
    order = ("low", "mid", "high")
    pairs = _pairs(
        {
            ("low", "low"): 10,
            ("low", "mid"): 4,
            ("low", "high"): 1,
            ("mid", "low"): 3,
            ("mid", "mid"): 8,
            ("mid", "high"): 4,
            ("high", "low"): 1,
            ("high", "mid"): 2,
            ("high", "high"): 7,
        }
    )
    got = weighted_kappa(pairs, order)["value"]
    assert got == pytest.approx(_weighted_by_hand(pairs, order, 1))
    # by hand, n = 40, rows (15, 15, 10), columns (14, 14, 12): observed disagreement
    # (4 + 3 + 4 + 2 + 2 * (1 + 1)) / (40 * 2) = 0.2125; expected 1380 / (2 * 1600) = 0.43125
    assert got == pytest.approx(1 - 0.2125 / 0.43125)
    assert round(got, 4) == 0.5072


def test_weighted_kappa_equals_cohens_kappa_on_two_categories() -> None:
    pairs = _pairs({("y", "y"): 20, ("y", "n"): 5, ("n", "y"): 10, ("n", "n"): 15})
    assert weighted_kappa(pairs, ("n", "y"))["value"] == pytest.approx(0.4)


# --- Fleiss' kappa: ten subjects, fourteen raters, five categories (kappa 0.210)

FLEISS_COUNTS = [
    [0, 0, 0, 0, 14],
    [0, 2, 6, 4, 2],
    [0, 0, 3, 5, 6],
    [0, 3, 9, 2, 0],
    [2, 2, 8, 1, 1],
    [7, 7, 0, 0, 0],
    [3, 2, 6, 3, 0],
    [2, 5, 3, 2, 2],
    [6, 5, 2, 1, 0],
    [0, 2, 2, 3, 7],
]
CATS5 = tuple("12345")


def _fleiss_ratings(counts: list[list[int]]) -> dict[str, dict[str, str]]:
    raters = sum(counts[0])
    ratings: dict[str, dict[str, str]] = {f"r{i:02d}": {} for i in range(raters)}
    for s, row in enumerate(counts):
        votes = [CATS5[j] for j, c in enumerate(row) for _ in range(c)]
        for i, vote in enumerate(votes):
            ratings[f"r{i:02d}"][f"s{s}"] = vote
    return ratings


def test_fleiss_kappa_matches_the_fourteen_rater_example() -> None:
    got = fleiss_kappa(_fleiss_ratings(FLEISS_COUNTS), CATS5)
    n, m = len(FLEISS_COUNTS), 14
    p_i = [(sum(x * x for x in row) - m) / (m * (m - 1)) for row in FLEISS_COUNTS]
    p_j = [sum(row[j] for row in FLEISS_COUNTS) / (n * m) for j in range(5)]
    p_bar, p_e = sum(p_i) / n, sum(p * p for p in p_j)
    assert round(p_bar, 3) == 0.378 and round(p_e, 3) == 0.213
    assert got["value"] == pytest.approx((p_bar - p_e) / (1 - p_e))
    assert round(got["value"], 3) == 0.210


# --- Krippendorff's alpha: the published four-observer, twelve-unit example with missing data

KRIPPENDORFF = {
    "A": "1 2 3 3 2 1 4 1 2 . . .",
    "B": "1 2 3 3 2 2 4 1 2 5 . 3",
    "C": ". 3 3 3 2 3 4 2 2 5 1 .",
    "D": "1 2 3 3 2 4 4 1 2 5 1 .",
}
# A second table with missing ratings, checked against the independent derivation only.
KRIPPENDORFF_LONG = {
    "A": "1 2 3 3 2 1 4 1 2 * * * 3 3 3",
    "B": "1 2 3 3 2 2 4 1 2 5 * 3 * 3 3",
    "C": "* 3 3 3 2 3 4 2 2 5 1 3 * 3 4",
    "D": "1 2 3 3 2 4 4 1 2 5 1 * * 3 4",
}


def _krip(table: dict[str, str] = KRIPPENDORFF) -> dict[str, dict[str, str]]:
    return {
        r: {f"u{i}": v for i, v in enumerate(row.split()) if v not in ".*"}
        for r, row in table.items()
    }


def _alpha_by_pairs(ratings: dict[str, dict[str, str]], metric: str) -> float:
    """alpha = 1 - D_o / D_e from the pairable values directly, no coincidence matrix."""
    units: dict[str, list[str]] = {}
    for given in ratings.values():
        for u, v in given.items():
            units.setdefault(u, []).append(v)
    units = {u: v for u, v in units.items() if len(v) > 1}
    values = [v for vs in units.values() for v in vs]
    n = len(values)
    count = {c: values.count(c) for c in set(values)}
    ranks = sorted(count)

    def d(c: str, k: str) -> float:
        if c == k:
            return 0.0
        if metric == "nominal":
            return 1.0
        lo, hi = sorted((ranks.index(c), ranks.index(k)))
        return (
            sum(count[g] for g in ranks[lo : hi + 1]) - (count[ranks[lo]] + count[ranks[hi]]) / 2
        ) ** 2

    d_o = (
        sum(sum(d(a, b) for a, b in permutations(vs, 2)) / (len(vs) - 1) for vs in units.values())
        / n
    )
    d_e = sum(d(a, b) for a, b in permutations(values, 2)) / (n * (n - 1))
    return 1 - d_o / d_e


def test_krippendorff_nominal_alpha_with_missing_data() -> None:
    ratings = _krip()
    got = krippendorff_alpha(ratings, CATS5, ordinal=False)
    assert got["value"] == pytest.approx(_alpha_by_pairs(ratings, "nominal"))
    assert round(got["value"], 3) == 0.743
    assert got["n"] == 11  # of 12 units, the one rated by one observer only carries no pair


def test_krippendorff_ordinal_alpha_with_missing_data() -> None:
    ratings = _krip()
    got = krippendorff_alpha(ratings, CATS5, ordinal=True)
    assert got["value"] == pytest.approx(_alpha_by_pairs(ratings, "ordinal"))
    assert round(got["value"], 3) == 0.815


def test_two_raters_without_missing_data_alpha_matches_the_pairwise_derivation() -> None:
    pairs = _pairs({("y", "y"): 20, ("y", "n"): 5, ("n", "y"): 10, ("n", "n"): 15})
    ratings = {"a": {}, "b": {}}
    for i, (x, y) in enumerate(pairs):
        ratings["a"][str(i)], ratings["b"][str(i)] = x, y
    alpha = krippendorff_alpha(ratings, ("n", "y"), ordinal=False)["value"]
    assert alpha == pytest.approx(_alpha_by_pairs(ratings, "nominal"))
    assert 0.39 < alpha < 0.41  # Scott's pi is 0.3939; alpha adds the small-sample term


# --- degenerate cases


def _no_nan(node: object) -> None:
    if isinstance(node, float):
        assert math.isfinite(node)
    elif isinstance(node, dict):
        for v in node.values():
            _no_nan(v)
    elif isinstance(node, list):
        for v in node:
            _no_nan(v)


def test_degenerate_statistics_return_none_with_a_reason() -> None:
    same = [("found", "found")] * 4
    for stat in (cohens_kappa(same), weighted_kappa(same, SCALE)):
        assert stat["value"] is None and "one category" in stat["reason"]
    for stat in (cohens_kappa([("found", "found")]), weighted_kappa([("found", "missed")], SCALE)):
        assert stat["value"] is None and stat["reason"] == "a single item"
    assert cohens_kappa([])["reason"] == "no item rated by both"
    assert percent_agreement([])["value"] is None
    two = {"a": {"x": "found", "y": "found"}, "b": {"x": "found", "y": "found"}}
    assert fleiss_kappa(two, SCALE)["reason"] == "needs three or more raters"
    assert krippendorff_alpha(two, SCALE, ordinal=False)["reason"].startswith("one category")
    apart = {"a": {"x": "found"}, "b": {"y": "missed"}}
    assert krippendorff_alpha(apart, SCALE, ordinal=True)["value"] is None
    assert agreement(apart)["verdicts"]["pairs"]["a / b"]["cohens_kappa"]["reason"]


def test_a_report_of_degenerate_input_holds_no_nan() -> None:
    report = agreement({"a": {"x": "found"}, "b": {"y": "missed"}, "c": {"z": "wrong"}})
    _no_nan(report)
    assert "nan" not in render(report).lower()


# --- input formats and the report


def _sheet(path: Path, cells: dict[str, list[str]]) -> Path:
    arms = sorted(cells)
    with path.open("w", encoding="utf-8", newline="") as handle:
        w = csv.writer(handle)
        w.writerow(["item", *arms])
        for i, item in enumerate(["K1.1a", "K1.2", "K2.1", "K2.2"]):
            w.writerow([item, *[cells[a][i] for a in arms]])
        w.writerow(["beyond_human", *["3"] * len(arms)])
    return path


def _score_md(path: Path, verdicts: list[str]) -> Path:
    rows = "\n".join(
        f"| {item} | label | {v} |"
        for item, v in zip(["K1.1a", "K1.2", "K2.1", "K2.2"], verdicts, strict=True)
    )
    path.write_text(
        f"# Score\n\n## Item by item\n\n| Item | What | Run |\n| --- | --- | --- |\n{rows}\n",
        encoding="utf-8",
    )
    return path


def test_sheets_and_a_score_file_are_read_as_raters(tmp_path: Path) -> None:
    one = _sheet(tmp_path / "one.csv", {"A": ["found", "partly", "missed", "wrong"]})
    two = _sheet(tmp_path / "two.csv", {"A": ["found", "partly (dump)", "missed", "missed"]})
    three = _score_md(tmp_path / "three.md", ["found", "partly (body)", "found", "wrong"])
    ratings = read_raters([str(one), f"second={two}", str(three)])
    assert ratings["one"]["K1.2"] == "partly (body)"  # a bare partly is a body partly
    assert set(ratings) == {"one", "second", "three"}
    assert len(ratings["one"]) == 4  # the beyond_human row is no item
    report = agreement(ratings)
    pair = report["verdicts"]["pairs"]["one / second"]
    assert pair["percent_agreement"]["value"] == pytest.approx(50.0)
    assert {d["item"] for d in pair["disagreements"]} == {"K1.2", "K2.2"}
    assert pair["confusion"]["matrix"][SCALE.index("wrong")][SCALE.index("missed")] == 1
    assert report["verdicts"]["fleiss_kappa"]["value"] is not None


def test_a_sheet_with_several_columns_gives_one_unit_per_cell(tmp_path: Path) -> None:
    cells = {
        "A": ["found", "found", "missed", "missed"],
        "B": ["found", "missed", "missed", "wrong"],
    }
    one = _sheet(tmp_path / "one.csv", cells)
    two = _sheet(tmp_path / "two.csv", cells)
    assert len(read_raters([str(one), str(two)])["one"]) == 8
    assert set(read_raters([str(one), str(two)], column="B")["one"]) == {
        "K1.1a",
        "K1.2",
        "K2.1",
        "K2.2",
    }


def test_a_bad_cell_and_a_repeated_name_are_refused(tmp_path: Path) -> None:
    bad = _sheet(tmp_path / "bad.csv", {"A": ["found", "maybe", "missed", "wrong"]})
    with pytest.raises(AgreementError, match="maybe"):
        read_raters([str(bad)])
    good = _sheet(tmp_path / "good.csv", {"A": ["found"] * 4})
    with pytest.raises(AgreementError, match="two raters are named"):
        read_raters([str(good), f"good={good}"])


def test_leaving_out_wrong_is_counted_and_changes_only_the_ordinal_statistics() -> None:
    ratings = {
        "a": {"1": "wrong", "2": "found", "3": "missed", "4": "partly (body)"},
        "b": {"1": "missed", "2": "found", "3": "missed", "4": "found"},
    }
    kept = agreement(ratings)["verdicts"]
    left = agreement(ratings, leave_out_wrong=True)["verdicts"]
    pair, pair_left = kept["pairs"]["a / b"], left["pairs"]["a / b"]
    assert pair["weighted_kappa"]["left_out_wrong"] == 0
    assert pair_left["weighted_kappa"]["left_out_wrong"] == 1
    assert left["krippendorff_alpha_ordinal"]["left_out_wrong_ratings"] == 1
    assert pair["cohens_kappa"] == pair_left["cohens_kappa"]
    assert kept["krippendorff_alpha_nominal"] == left["krippendorff_alpha_nominal"]
    # order used when wrong is kept: wrong is the lowest rank, one step below missed of five
    order = SCALE
    assert weighted_kappa(
        [("wrong", "missed"), ("found", "found"), ("missed", "missed"), ("partly (body)", "found")],
        order,
    )["value"] == pytest.approx(
        _weighted_by_hand(
            [
                ("wrong", "missed"),
                ("found", "found"),
                ("missed", "missed"),
                ("partly (body)", "found"),
            ],
            order,
            1,
        )
    )


def test_the_collapsed_view_credits_partly_or_better() -> None:
    ratings = {
        "a": {
            "1": "found",
            "2": "partly (dump)",
            "3": "missed",
            "4": "wrong",
            "5": "partly (body)",
        },
        "b": {"1": "partly (body)", "2": "missed", "3": "wrong", "4": "missed", "5": "found"},
    }
    view = agreement(ratings)["collapsed"]
    assert view["categories"] == list(COLLAPSED)
    pair = view["pairs"]["a / b"]
    # credited: a 1,2,5; b 1,5 -> agree on 1, 3, 4, 5; disagree on 2
    assert pair["percent_agreement"]["value"] == pytest.approx(80.0)
    assert [d["item"] for d in pair["disagreements"]] == ["2"]
    pairs = (
        [("credited", "credited"), ("credited", "not credited")]
        + [("not credited", "not credited")] * 2
        + [("credited", "credited")]
    )
    assert pair["cohens_kappa"]["value"] == pytest.approx(_kappa_by_hand(pairs))
    assert pair["weighted_kappa"]["value"] == pytest.approx(pair["cohens_kappa"]["value"])


def test_the_command_prints_a_table_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    one = _sheet(tmp_path / "one.csv", {"A": ["found", "partly", "missed", "wrong"]})
    two = _sheet(tmp_path / "two.csv", {"A": ["found", "found", "missed", "missed"]})
    three = _sheet(tmp_path / "three.csv", {"A": ["found", "partly", "wrong", "wrong"]})
    assert main(["agreement", str(one), str(two), str(three)]) == 0
    text = capsys.readouterr().out
    assert "Cohen's kappa" in text and "Fleiss' kappa" in text and "one / two" in text
    assert main(["agreement", str(one), str(two), str(three), "--json", "--leave-out-wrong"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) >= {"verdicts", "collapsed", "wrong_handling"}
    assert main(["agreement", str(one)]) == 2
    assert "at least two raters" in capsys.readouterr().err


def test_a_longer_table_with_missing_ratings_matches_the_pairwise_derivation() -> None:
    ratings = _krip(KRIPPENDORFF_LONG)
    for ordinal, metric in ((False, "nominal"), (True, "ordinal")):
        got = krippendorff_alpha(ratings, CATS5, ordinal=ordinal)["value"]
        assert got == pytest.approx(_alpha_by_pairs(ratings, metric))
