"""The score reader reads a scored sheet by a declared table of scoring rules.

The table names the verdict words worst first, the lowest one the totals credit
and the states that are no verdict and leave the denominator. Without a table
the reader is the one that existed before: the stored score files read to the
same result (``reader-before-rules.json`` was written by that reader), and a
blind sheet to the same verdicts.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from scripts.benchmark import gate as gating
from scripts.benchmark.run import main
from scripts.benchmark.scores import (
    KEY,
    KEY_RULES,
    SCALES,
    ScoredRun,
    ScoreFileError,
    ScoringRules,
    load_rules,
    rank,
    read_blind,
    read_key_score,
    read_scored,
    rules_from_dict,
)
from scripts.blind.prepare import WORDS_FILE, BlindError, prepare
from scripts.blind.reveal import render, reveal
from scripts.blind.run import main as blind_main

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "benchmark"
TABLE: dict[str, Any] = {
    "name": "side-by-side",
    "verdicts": ["wrong", "missed", "partial", "found"],
    "credited_from": "partial",
    "outside_denominator": ["under adjudication", "does not hold for this file", "unknown"],
    "aliases": {"partly found": "partial"},
    "key_folder": "not read by the reader",
}
OUTSIDE = ("under adjudication", "does not hold for this file", "unknown")
VERDICTS = {
    "G-001": "found",
    "G-002": "partial",
    "G-003": "missed",
    "G-004": "Under adjudication",
    "G-005": "does not hold for this file",
    "G-006": "Unknown",
    "G-007": "partly found",
}


@pytest.fixture
def rules() -> ScoringRules:
    return rules_from_dict(TABLE)


def _score(verdicts: dict[str, str], tmp_path: Path, name: str = "run1") -> Path:
    lines = ["# Score", "", "## 2. Item by item", "", f"| # | {name} | Note |", "|---|---|---|"]
    lines += [f"| {item} | {word} | note |" for item, word in verdicts.items()]
    path = tmp_path / name / "score.md"
    path.parent.mkdir(exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------ nothing changes


@pytest.mark.parametrize("name", ["haiku3-score.md", "haiku4-score.md"])
def test_a_stored_score_without_a_table_reads_as_the_old_reader_read_it(name: str) -> None:
    golden = json.loads((FIXTURES / "reader-before-rules.json").read_text(encoding="utf-8"))[name]
    got = dataclasses.asdict(read_scored(FIXTURES / name))
    got["verdicts"] = {k: list(v) for k, v in got["verdicts"].items()}
    got["source"] = name
    assert got.pop("rules") is None
    assert got == golden
    # the built-in rules, given explicitly, read the same
    explicit = read_scored(FIXTURES / name, KEY_RULES)
    assert explicit.verdicts == {k: tuple(v) for k, v in golden["verdicts"].items()}
    assert explicit.denominator == 57


def test_the_built_in_rules_are_the_old_scale() -> None:
    assert KEY_RULES.scale == ("wrong", "missed", "partly (dump)", "partly (body)", "found")
    assert KEY_RULES.credited_from == "partly (dump)"
    assert KEY_RULES.scale_id == KEY and KEY_RULES.outside == ()
    assert SCALES[KEY] == KEY_RULES.scale


def test_a_blind_sheet_without_a_table_reads_as_before(tmp_path: Path) -> None:
    sealed = tmp_path / "sealed-map.json"
    sealed.write_text(
        json.dumps({"items": ["K1.1a", "K2.3"], "arms": {"A": {"name": "x"}, "B": {"name": "y"}}})
    )
    sheet = tmp_path / "scores.csv"
    sheet.write_text(
        "item,A,B\nK1.1a,found,Wrong\nK2.3,missed,partly (body)\nbeyond_human,4,3\n",
        encoding="utf-8",
    )
    runs = {r.name: r for r in read_blind(sheet, sealed)}
    assert runs["x"].verdicts == {"K1.1a": (KEY, "found"), "K2.3": (KEY, "missed")}
    assert runs["y"].verdicts == {"K1.1a": (KEY, "wrong"), "K2.3": (KEY, "partly (body)")}
    assert runs["x"].rules is None and runs["x"].denominator == 2
    assert render(reveal(sheet, sealed)).splitlines()[2].split()[:3] == ["arm", "found", "partly"]


def test_a_word_of_a_table_is_refused_without_it(tmp_path: Path) -> None:
    path = _score({"G-001": "found", "G-002": "under adjudication"}, tmp_path)
    # "under adjudication" is no key-scale verdict: the column holds a cell that is not one
    with pytest.raises(ScoreFileError, match="G-002.*under adjudication"):
        read_key_score(path)


# -------------------------------------------------------------- the table


def test_a_table_is_read_with_its_words_and_its_extra_fields(rules: ScoringRules) -> None:
    assert rules.scale == ("wrong", "missed", "partial", "found")
    assert rules.credited_from == "partial" and rules.outside == OUTSIDE
    assert rules.aliases == {"partly found": "partial"}
    assert rules.extra == {"key_folder": "not read by the reader"}
    assert rules.words == (*rules.scale, *OUTSIDE)


def test_a_table_is_loaded_from_json(tmp_path: Path, rules: ScoringRules) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(TABLE), encoding="utf-8")
    assert load_rules(path) == rules
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ScoreFileError, match="not JSON"):
        load_rules(path)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"verdicts": ["found"]}, "fewer than two"),
        ({"verdicts": "found"}, "not a list of words"),
        ({"credited_from": "found or better"}, "not a verdict word"),
        ({"outside_denominator": ["missed"]}, "declared twice: missed"),
        ({"aliases": {"part": "unknown"}}, "must name a verdict word"),
        ({"aliases": {"found": "partial"}}, "may not be a word itself"),
        ({"name": ""}, "not a scoring-rules table"),
    ],
)
def test_an_unsound_table_is_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ScoreFileError, match=message):
        rules_from_dict({**TABLE, **change})


def test_two_tables_of_one_name_may_not_differ(rules: ScoringRules) -> None:
    rules.register()
    rules.register()
    other = rules_from_dict({**TABLE, "outside_denominator": ["unknown"]})
    with pytest.raises(ScoreFileError, match="declared twice, differently"):
        other.register()


# ----------------------------------------------------------- reading a sheet


def test_a_key_score_is_read_by_the_words_of_the_table(tmp_path: Path, rules: ScoringRules) -> None:
    run = read_key_score(_score(VERDICTS, tmp_path), rules)
    words = {k: v for k, (_, v) in run.verdicts.items()}
    assert words == {
        "G-001": "found",
        "G-002": "partial",
        "G-003": "missed",
        "G-004": "under adjudication",
        "G-005": "does not hold for this file",
        "G-006": "unknown",
        "G-007": "partial",
    }
    assert {s for s, _ in run.verdicts.values()} == {rules.scale_id}
    assert run.denominator == 4 and len(run.verdicts) == 7
    assert run.outside == {
        "G-004": "under adjudication",
        "G-005": "does not hold for this file",
        "G-006": "unknown",
    }
    assert run.counts() == {
        "wrong": 0,
        "missed": 1,
        "partial": 2,
        "found": 1,
        "under adjudication": 1,
        "does not hold for this file": 1,
        "unknown": 1,
    }
    assert run.rules is rules and "unchecked" in run.totals_note


def test_the_rank_follows_the_table_and_an_outside_state_has_none(rules: ScoringRules) -> None:
    rules.register()
    assert [rank(rules.scale_id, w) for w in rules.scale] == [0, 1, 2, 3]
    assert rank(rules.scale_id, "under adjudication") is None
    assert rank(rules.scale_id, None) is None
    with pytest.raises(ValueError):
        rank(rules.scale_id, "partly (body)")


def test_a_word_the_table_does_not_hold_is_refused_naming_the_row_and_the_word(
    tmp_path: Path, rules: ScoringRules
) -> None:
    path = _score({"G-001": "found", "G-002": "partly (body)"}, tmp_path)
    with pytest.raises(ScoreFileError, match=r"G-002.*partly \(body\)"):
        read_key_score(path, rules)
    path = _score({"G-001": "found", "G-002": "refuted for this file"}, tmp_path, "run2")
    with pytest.raises(ScoreFileError, match=r"G-002.*refuted for this file"):
        read_key_score(path, rules)


def test_a_run_with_per_run_denominators_scores_each_by_its_own(
    tmp_path: Path, rules: ScoringRules
) -> None:
    a = read_key_score(_score({"G-001": "found", "G-002": "unknown"}, tmp_path, "a"), rules)
    b = read_key_score(_score({"G-001": "found", "G-002": "found"}, tmp_path, "b"), rules)
    assert (a.denominator, b.denominator) == (1, 2)
    one = gating.score_arm(gating.arm([a]))
    assert one["totals"]["credit_items"] == 1 and one["totals"]["outside"] == 1
    both = gating.score_arm(gating.arm([a, b], 1))
    assert both["totals"]["credit_items"] == 2 and "outside" not in both["totals"]
    assert both["items"]["G-002"]["verdict"] == "found"


def test_the_gate_compares_runs_read_by_one_table(tmp_path: Path, rules: ScoringRules) -> None:
    base = read_key_score(_score({"G-001": "found", "G-002": "partial"}, tmp_path, "a"), rules)
    cand = read_key_score(
        _score({"G-001": "found", "G-002": "under adjudication"}, tmp_path, "b"), rules
    )
    result = gating.gate(gating.arm([base]), gating.arm([cand]))
    assert result["dropped"] == ["G-002"] and not result["passed"]
    assert gating.render(result)


# ------------------------------------------------------------- a blind sheet


def _stored(root: Path, name: str) -> Path:
    run = root / name
    run.mkdir(parents=True)
    (run / "report.md").write_text(
        f"# Report\n\nThe loader {name[0]} drops a file.\n", encoding="utf-8"
    )
    return run


def test_the_blind_template_carries_the_tables_words_and_the_reveal_reads_by_them(
    tmp_path: Path, rules: ScoringRules
) -> None:
    runs = [_stored(tmp_path / "stored", n) for n in ("one", "two")]
    done = prepare(runs, tmp_path / "out", ["G-001", "G-002"], seed=3, rules=rules)
    words = (done.scorer_dir / WORDS_FILE).read_text(encoding="utf-8").splitlines()
    assert words[1:5] == ["wrong", "missed", "partial", "found"]
    assert "unknown" in words and "under adjudication" in words
    sealed = json.loads(done.sealed.read_text(encoding="utf-8"))
    assert sealed["scoring_rules"]["credited_from"] == "partial"
    done.template.write_text(
        "item,A,B\nG-001,found,Under adjudication\nG-002,partly found,unknown\nbeyond_human,1,2\n",
        encoding="utf-8",
    )
    revealed = reveal(done.template, done.sealed)
    assert revealed.words == rules.words
    assert render(revealed).splitlines()[2].split()[:3] == ["arm", "wrong", "missed"]
    by_arm = {r.name: r for r in read_blind(done.template, done.sealed)}
    assert set(by_arm) == {"one", "two"}
    arm_a = by_arm[sealed["arms"]["A"]["name"]]
    assert arm_a.verdicts["G-002"] == (rules.scale_id, "partial") and arm_a.denominator == 2
    arm_b = by_arm[sealed["arms"]["B"]["name"]]
    assert arm_b.outside == {"G-001": "under adjudication", "G-002": "unknown"}
    assert arm_b.denominator == 0
    # a table given beside the sealed map's own must be the same one
    other = rules_from_dict({**TABLE, "outside_denominator": ["unknown"]})
    with pytest.raises(BlindError, match="not 'side-by-side'|holds the scoring rules"):
        reveal(done.template, done.sealed, other)


def test_the_blind_template_without_a_table_is_what_it_was(tmp_path: Path) -> None:
    runs = [_stored(tmp_path / "stored", n) for n in ("one", "two")]
    done = prepare(runs, tmp_path / "out", ["G-001"], seed=3)
    assert not (done.scorer_dir / WORDS_FILE).exists()
    assert "scoring_rules" not in json.loads(done.sealed.read_text(encoding="utf-8"))


def test_a_blind_word_the_table_does_not_hold_is_refused_naming_item_and_word(
    tmp_path: Path, rules: ScoringRules
) -> None:
    runs = [_stored(tmp_path / "stored", n) for n in ("one", "two")]
    done = prepare(runs, tmp_path / "out", ["G-001"], seed=3, rules=rules)
    done.template.write_text(
        "item,A,B\nG-001,found,partly (dump)\nbeyond_human,1,2\n", encoding="utf-8"
    )
    with pytest.raises(BlindError, match=r"item G-001 for B.*partly \(dump\)"):
        reveal(done.template, done.sealed)
    with pytest.raises(ScoreFileError, match=r"G-001.*partly \(dump\)"):
        read_blind(done.template, done.sealed)


def test_the_blind_command_line_takes_a_table(tmp_path: Path, rules: ScoringRules) -> None:
    runs = [_stored(tmp_path / "stored", n) for n in ("one", "two")]
    table = tmp_path / "rules.json"
    table.write_text(json.dumps(TABLE), encoding="utf-8")
    items = tmp_path / "items.txt"
    items.write_text("G-001\n", encoding="utf-8")
    out = tmp_path / "out"
    argv = [
        "prepare",
        *map(str, runs),
        "--out",
        str(out),
        "--items",
        str(items),
        "--rules",
        str(table),
    ]
    assert blind_main(argv) == 0
    assert (out / "scorer" / WORDS_FILE).is_file()
    assert (
        blind_main(
            [
                "prepare",
                *map(str, runs),
                "--out",
                str(tmp_path / "o2"),
                "--items",
                str(items),
                "--rules",
                str(tmp_path / "missing.json"),
            ]
        )
        == 2
    )


# ------------------------------------------------------------- the command


def test_the_score_command_says_each_denominator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    table = tmp_path / "rules.json"
    table.write_text(json.dumps(TABLE), encoding="utf-8")
    path = _score(VERDICTS, tmp_path)
    assert main(["score", str(path), "--rules", str(table)]) == 0
    out = capsys.readouterr().out
    assert "run1 denominator: 4 of 7 items (left out: 1 under adjudication; 1 does not hold" in out
    # the same file without the table is refused, as it was
    assert main(["score", str(path)]) == 2
    assert "is not a verdict for" in capsys.readouterr().err


def test_the_score_command_prints_what_it_printed_for_the_old_scale(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["score", str(FIXTURES / "haiku4-score.md")]) == 0
    assert "denominator" not in capsys.readouterr().out


def test_a_scored_run_has_no_outside_state_on_the_old_scale() -> None:
    run: ScoredRun = read_scored(FIXTURES / "haiku3-score.md")
    assert run.outside == {} and run.denominator == len(run.verdicts) == 57
    assert sum(run.counts().values()) == 57
