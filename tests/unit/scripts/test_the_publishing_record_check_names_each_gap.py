"""The record check names each gap between the list and the record, by kind.

A record with one entry per function and constant of classes a, b and c,
each with its digest and a test that exists, is clean. Each case breaks one thing and that
one kind is reported: an entry missing, an entry whose function left the
list or moved to another module, an entry for a function only a trace
reaches, wording changed since the entry, a test id that does not resolve,
an entry the schema refuses (a blank condition, an empty basis) and a
duplicate. A test id resolves only to a test the runner would collect, in a
file under ``tests/``, with a parameter id only where the parametrisation
holds it, and never to a fixture (also under an alias), a name rebound or
deleted after its def, or a test a false ``__test__`` turns off; an id reading
the file cannot decide (a test name or a decorator imported from outside
pytest and the standard library among them) is reported as unverified. An
entry whose text reaches no published surface may say so with a reason from a
closed list (text a model reads only, and compared text never printed, among
them) and one sentence, without a test; such entries are counted on every
check. A reason is open only to the classes the schema states for it:
"compared, never printed" only to a compared constant, and only while no
function of the tree, reached or not, hands it out (each such function is
named beside the constant in the list). The functions in the traced record
need entries without a trace file, and that record holds function keys only.
The check reports only while the record says incomplete. The trace output is
never written inside any checkout of the repository, its scratch never empties
a directory it did not create, a run directory with no stored report is
refused in one plain line, a render error or a render that runs no listed
function is a failed run, a timeout is one plain line and status 2, and the
record shipped with the tool checks clean for its own entries.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from scripts.audit import publishing_functions as pf

from tests.unit.scripts.test_the_publishing_functions_are_listed_by_one_rule import (
    SOURCES,
    listing,
    write_tree,
)

ROOT = Path(__file__).resolve().parents[3]
Setup = tuple[pf.Listing, Path, Path]
TEST_FILE = """
import pytest


def test_pin():
    pass


def helper():
    pass


@pytest.mark.parametrize("value", ["one", 2, None])
def test_cases(value):
    pass


@pytest.mark.parametrize(("a", "b"), [(1, "x"), pytest.param(2, "y", id="named")])
def test_pairs(a, b):
    pass


@pytest.mark.parametrize("value", [object()])
def test_opaque(value):
    pass


@pytest.mark.parametrize("value", CASES)
def test_from_a_name(value):
    pass


class TestGroup:
    def test_member(self):
        pass

    def helper(self):
        pass


class Group:
    def test_member(self):
        pass


@pytest.fixture
def test_fixture_named():
    pass


@pytest.fixture(scope="module")
def test_fixture_called():
    pass


class TestHolder:
    @pytest.fixture()
    def test_fixture_method(self):
        pass


def test_shadowed():
    pass


test_shadowed = None
"""


def _setup(root: Path) -> tuple[pf.Listing, Path]:
    write_tree(root)
    (root / "tests").mkdir()
    (root / "tests" / "test_pins.py").write_text(TEST_FILE, encoding="utf-8")
    records = root / "records"
    records.mkdir()
    shutil.copy(pf.RECORDS / pf.SCHEMA_FILE, records / pf.SCHEMA_FILE)
    _status(records, complete=False)
    found = listing(root)
    per: dict[str, list[dict[str, Any]]] = {}
    for key, kind in sorted(found.needs_entry().items()):
        per.setdefault(key.split(":", 1)[0], []).append(
            {
                kind: key,
                "condition": "always",
                "basis": ["the run"],
                "test": "tests/test_pins.py::test_pin",
                "text_digest": pf.text_digest(found.texts(key)),
            }
        )
    for module, entries in per.items():
        _write(records, module, entries)
    return found, records


def _status(records: Path, *, complete: bool) -> None:
    (records / pf.STATUS_FILE).write_text(json.dumps({"complete": complete}), encoding="utf-8")


def _write(records: Path, module: str, entries: list[dict[str, Any]]) -> None:
    (records / f"{module}.json").write_text(json.dumps({"entries": entries}), encoding="utf-8")


def _entries(records: Path, module: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = json.loads(
        (records / f"{module}.json").read_text(encoding="utf-8")
    )["entries"]
    return entries


def _kinds(found: pf.Listing, records: Path, root: Path, traced: list[str] | None = None) -> list:
    reports = pf.check(found, pf.read_record(records), root, traced or [])
    return [(r["kind"], r["item"]) for r in reports]


@pytest.fixture()
def setup(tmp_path: Path) -> Setup:
    found, records = _setup(tmp_path)
    return found, records, tmp_path


def test_a_full_record_is_clean(setup: Setup) -> None:
    found, records, root = setup
    assert _kinds(found, records, root) == []


def test_a_listed_function_without_an_entry_is_missing(setup: Setup) -> None:
    found, records, root = setup
    entries = [e for e in _entries(records, "pkg.out.render") if "by_call" not in str(e)]
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == [("missing", "pkg.out.render:by_call")]


def test_an_entry_whose_function_left_the_list_is_named(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    for name in ("single_word", "gone"):
        entries.append({**entries[0], "function": f"pkg.out.render:{name}"})
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == [
        ("left", "pkg.out.render:gone"),
        ("left", "pkg.out.render:single_word"),
    ]


def test_an_entry_whose_function_moved_names_where_it_is_now(setup: Setup) -> None:
    found, records, root = setup
    entries = [e for e in _entries(records, "pkg.out.render") if "by_call" not in str(e)]
    _write(records, "pkg.out.render", entries)
    moved = {**entries[0], "function": "pkg.out.old:by_call"}
    _write(records, "pkg.out.old", [moved])
    reports = pf.check(found, pf.read_record(records), root)
    assert [(r["kind"], r["item"], r["detail"]) for r in reports] == [
        ("missing", "pkg.out.render:by_call", "a listed function"),
        ("moved", "pkg.out.old:by_call", "now pkg.out.render:by_call"),
    ]


def test_an_entry_only_a_trace_reaches_needs_the_trace(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    entries.append({**entries[0], "function": "pkg.out.render:orphan"})
    entries[-1]["text_digest"] = pf.text_digest(["never reached by anything"])
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == [("not_reached_statically", "pkg.out.render:orphan")]
    assert _kinds(found, records, root, ["pkg.out.render:orphan"]) == []


def test_a_traced_function_without_an_entry_is_missing(setup: Setup) -> None:
    found, records, root = setup
    assert _kinds(found, records, root, ["pkg.out.render:orphan"]) == [
        ("missing", "pkg.out.render:orphan")
    ]


def test_a_changed_wording_moves_the_digest(tmp_path: Path) -> None:
    found, records = _setup(tmp_path)
    assert _kinds(found, records, tmp_path) == []
    copy = dict(SOURCES)
    copy["pkg/out/render.py"] = copy["pkg/out/render.py"].replace(
        "reached by a call", "reached by one call"
    )
    write_tree(tmp_path, copy)
    assert _kinds(listing(tmp_path), records, tmp_path) == [("digest", "pkg.out.render:by_call")]


def test_a_test_id_that_does_not_resolve_is_named(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    entries[0]["test"] = "tests/test_pins.py::TestGroup::test_member"
    entries[1]["test"] = "tests/test_pins.py::test_absent"
    entries[2]["test"] = "tests/test_absent.py::test_pin[case]"
    _write(records, "pkg.out.render", entries)
    names = [entries[1].get("function") or entries[1]["constant"]]
    names.append(entries[2].get("function") or entries[2]["constant"])
    assert _kinds(found, records, root) == sorted(("test", n) for n in names)


@pytest.mark.parametrize(
    "node_id",
    [
        "tests/test_pins.py::test_pin",
        "tests/test_pins.py::TestGroup::test_member",
        "tests/test_pins.py::test_cases",
        "tests/test_pins.py::test_cases[one]",
        "tests/test_pins.py::test_cases[2]",
        "tests/test_pins.py::test_cases[None]",
        "tests/test_pins.py::test_pairs[1-x]",
        "tests/test_pins.py::test_pairs[named]",
        "tests/test_pins.py::test_opaque",
        "tests/test_pins.py::test_from_a_name",
    ],
)
def test_a_test_id_the_runner_would_collect_resolves(tmp_path: Path, node_id: str) -> None:
    _setup(tmp_path)
    assert pf.test_exists(tmp_path, node_id)


@pytest.mark.parametrize(
    "node_id",
    [
        "tests/../scripts/audit/publishing_functions.py::main",
        "tests/sub/../test_pins.py::test_pin",
        "tests/test_pins.py::helper",
        "tests/test_pins.py::TestGroup::helper",
        "tests/test_pins.py::Group::test_member",
        "tests/test_pins.py::test_pin[x]",
        "tests/test_pins.py::test_cases[three]",
        "tests/test_pins.py::test_pairs[2-y]",
        "tests/test_pins.py::test_opaque[value0]",
        "tests/test_pins.py::test_from_a_name[one]",
        "tests/pins.py::test_pin",
        "tests/test_pins.py::test_fixture_named",
        "tests/test_pins.py::test_fixture_called",
        "tests/test_pins.py::TestHolder::test_fixture_method",
        "tests/test_pins.py::test_shadowed",
    ],
)
def test_a_test_id_that_names_no_collected_test_is_refused(tmp_path: Path, node_id: str) -> None:
    _setup(tmp_path)
    (tmp_path / "tests" / "pins.py").write_text(TEST_FILE, encoding="utf-8")
    assert not pf.test_exists(tmp_path, node_id)


def test_a_test_id_outside_the_tests_directory_through_a_symlink_is_refused(
    tmp_path: Path,
) -> None:
    _setup(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "test_pins.py").write_text(TEST_FILE, encoding="utf-8")
    (tmp_path / "tests" / "linked").symlink_to(outside)
    assert not pf.test_exists(tmp_path, "tests/linked/test_pins.py::test_pin")


def test_an_entry_may_name_several_tests_and_each_must_resolve(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    entries[0]["test"] = ["tests/test_pins.py::test_pin", "tests/test_pins.py::test_cases[one]"]
    entries[1]["test"] = ["tests/test_pins.py::test_pin", "tests/test_pins.py::test_absent"]
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == [
        ("test", entries[1].get("function") or entries[1]["constant"])
    ]


def test_an_entry_may_say_its_text_reaches_no_published_surface(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    entries[0]["no_published_surface"] = "logged and raised at startup; no report carries it"
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == []
    entries[0]["no_published_surface"] = " "
    _write(records, "pkg.out.render", entries)
    assert ("invalid", "pkg.out.render.json") in _kinds(found, records, root)


def _not_published(entry: dict[str, Any], reason: str, basis: str) -> dict[str, Any]:
    kind = "function" if "function" in entry else "constant"
    return {
        kind: entry[kind],
        "text_digest": entry["text_digest"],
        "not_published": {"reason": reason, "basis": basis},
    }


def test_a_not_published_entry_needs_no_test_and_is_counted(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    key = entries[0].get("function") or entries[0]["constant"]
    for reason in pf.NOT_PUBLISHED_REASONS_BY_CLASS[found.entry_class(key)]:
        entries[0] = _not_published(entries[0], reason, "Shown only in the settings form.")
        _write(records, "pkg.out.render", entries)
        record = pf.read_record(records)
        assert _kinds(found, records, root) == []
        assert pf.not_published_count(record) == 1


@pytest.mark.parametrize(
    ("reason", "basis", "extra"),
    [
        ("a model reads it", "Read by a model only.", {}),
        ("operator_text", " ", {}),
        ("operator_text", "One sentence.\nAnd a second line.", {}),
        ("operator_text", "Shown in a form.", {"test": "tests/test_pins.py::test_pin"}),
        ("operator_text", "Shown in a form.", {"condition": "always"}),
    ],
)
def test_a_not_published_entry_outside_its_form_is_invalid(
    setup: Setup, reason: str, basis: str, extra: dict[str, Any]
) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    entries[0] = {**_not_published(entries[0], reason, basis), **extra}
    _write(records, "pkg.out.render", entries)
    assert ("invalid", "pkg.out.render.json") in _kinds(found, records, root)


def test_a_not_published_entry_still_follows_its_wording(tmp_path: Path) -> None:
    found, records = _setup(tmp_path)
    entries = _entries(records, "pkg.out.render")
    index = next(i for i, e in enumerate(entries) if e.get("function") == "pkg.out.render:by_call")
    entries[index] = _not_published(entries[index], "non_sentence", "A key, never shown.")
    _write(records, "pkg.out.render", entries)
    copy = dict(SOURCES)
    copy["pkg/out/render.py"] = copy["pkg/out/render.py"].replace(
        "reached by a call", "reached by one call"
    )
    write_tree(tmp_path, copy)
    assert _kinds(listing(tmp_path), records, tmp_path) == [("digest", "pkg.out.render:by_call")]


def test_an_entry_the_schema_refuses_is_invalid(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.helpers")
    del entries[0]["test"]
    _write(records, "pkg.out.helpers", entries)
    stray = {**_entries(records, "pkg.out.render")[0], "function": "pkg.out.helpers:x"}
    _write(records, "pkg.out.render", [*_entries(records, "pkg.out.render"), stray])
    kinds = [k for k, _ in _kinds(found, records, root)]
    assert kinds.count("invalid") == 2
    assert set(kinds) == {"missing", "invalid"}


@pytest.mark.parametrize(
    ("field", "value"),
    [("condition", " "), ("condition", ""), ("basis", []), ("basis", [" "]), ("test", [])],
)
def test_a_blank_condition_or_an_empty_basis_is_invalid(
    setup: Setup, field: str, value: object
) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.helpers")
    entries[0][field] = value
    _write(records, "pkg.out.helpers", entries)
    kinds = [k for k, _ in _kinds(found, records, root)]
    assert "invalid" in kinds


def test_two_entries_for_one_function_are_a_duplicate(setup: Setup) -> None:
    found, records, root = setup
    entries = _entries(records, "pkg.out.render")
    _write(records, "pkg.out.render", [*entries, entries[0]])
    item = entries[0].get("function") or entries[0].get("constant")
    assert _kinds(found, records, root) == [("duplicate", item)]


def test_an_incomplete_record_reports_only(setup: Setup) -> None:
    found, records, root = setup
    _write(records, "pkg.out.render", [])
    record = pf.read_record(records)
    reports = pf.check(found, record, root)
    assert reports and pf.check_status(record, reports) == 0
    _status(records, complete=True)
    record = pf.read_record(records)
    assert pf.check_status(record, pf.check(found, record, root)) == 1


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_a_trace_output_inside_any_checkout_of_the_repository_is_refused(
    tmp_path: Path,
) -> None:
    main = tmp_path / "main"
    main.mkdir()
    _git("init", "-q", cwd=main)
    _git("commit", "-q", "--allow-empty", "-m", "start", cwd=main)
    other = tmp_path / "other"
    _git("worktree", "add", "-q", "--detach", str(other), cwd=main)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "link").symlink_to(main)
    for target in (
        main / "x.json",
        main / "deeper" / "not" / "yet" / "x.json",
        other / "x.json",
        outside / ".." / "main" / "x.json",
        outside / "link" / "x.json",
    ):
        assert pf.inside_a_checkout(target, other), target
        assert pf.inside_a_checkout(target, main), target
    assert not pf.inside_a_checkout(outside / "x.json", other)
    here = Path.cwd()
    try:
        os.chdir(outside)
        assert pf.inside_a_checkout(Path("../other/x.json"), main)
        assert not pf.inside_a_checkout(Path("x.json"), main)
    finally:
        os.chdir(here)


def test_trace_refuses_an_output_inside_the_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = ROOT / "publishing-trace.json"
    assert pf.main(["trace", str(tmp_path), "--out", str(target)]) == 2
    assert not target.exists()
    assert "inside a checkout of the repository" in capsys.readouterr().err


def test_a_render_error_in_a_trace_is_a_failed_run() -> None:
    result = {
        "runs": [
            {"status": 0, "modes": {"serve": {"error": None}, "build": {"error": None}}},
            {"status": 0, "modes": {"serve": {"error": "KeyError: x"}, "build": {"error": None}}},
            {"status": 1, "modes": {}},
        ]
    }
    assert pf.failed_runs(result) == (2, 1)


def _fake_listing(root: Path) -> pf.Listing:
    write_tree(root)
    return listing(root)


def test_trace_never_empties_a_directory_it_did_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = _fake_listing(tmp_path / "tree")
    out = tmp_path / "out" / "trace.json"
    kept = tmp_path / "out" / "trace.json.work"
    kept.mkdir(parents=True)
    (kept / "mine.txt").write_text("the user's own file", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        part = Path(command[-1])
        assert kept not in part.parents
        part.write_text(json.dumps({"serve": {"error": None, "called": []}}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(pf.subprocess, "run", fake_run)
    pf.trace([run], out, listing=found)
    assert (kept / "mine.txt").read_text(encoding="utf-8") == "the user's own file"
    assert sorted(p.name for p in out.parent.iterdir()) == ["trace.json.work"]


def test_a_trace_timeout_is_one_plain_line_and_status_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    found = _fake_listing(tmp_path / "tree")
    out = tmp_path / "out" / "trace.json"
    out.parent.mkdir()
    run = tmp_path / "run"
    run.mkdir()

    def slow(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout") or 0)

    (run / "report.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(pf.subprocess, "run", slow)
    monkeypatch.setattr(pf, "Tree", lambda *args, **kwargs: found.tree)
    monkeypatch.setattr(pf, "compute", lambda *args, **kwargs: found)
    assert pf.main(["trace", str(run), "--out", str(out), "--timeout", "5"]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "longer than 5" in err and "Traceback" not in err
    assert list(out.parent.iterdir()) == []


def test_the_traced_record_holds_only_function_keys(setup: Setup) -> None:
    found, records, root = setup
    path = pf.write_traced(records, ["pkg.out.render:orphan"], found.tree)
    assert path == records / pf.TRACED_FILE
    assert json.loads(path.read_text(encoding="utf-8")) == ["pkg.out.render:orphan"]
    for bad in (["stored/run-1"], ["pkg.out.render:absent"], ["/home/x:y"], [{"k": "v"}]):
        with pytest.raises(ValueError):
            pf.write_traced(records, bad, found.tree)
    assert json.loads(path.read_text(encoding="utf-8")) == ["pkg.out.render:orphan"]


def test_a_traced_record_key_must_have_an_entry_without_a_trace_file(setup: Setup) -> None:
    found, records, root = setup
    pf.write_traced(records, ["pkg.out.render:orphan"], found.tree)
    assert _kinds(found, records, root) == [("missing", "pkg.out.render:orphan")]
    entries = _entries(records, "pkg.out.render")
    entries.append({**entries[0], "function": "pkg.out.render:orphan"})
    entries[-1]["text_digest"] = pf.text_digest(["never reached by anything"])
    _write(records, "pkg.out.render", entries)
    assert _kinds(found, records, root) == []


def test_a_traced_record_key_that_no_longer_hands_out_wording_is_named(setup: Setup) -> None:
    found, records, root = setup
    (records / pf.TRACED_FILE).write_text(
        json.dumps(["pkg.out.render:gone", "pkg.out.render:single_word"]), encoding="utf-8"
    )
    assert _kinds(found, records, root) == [
        ("left", "pkg.out.render:gone"),
        ("left", "pkg.out.render:single_word"),
    ]


def test_a_traced_record_that_holds_anything_but_keys_is_invalid(setup: Setup) -> None:
    found, records, root = setup
    (records / pf.TRACED_FILE).write_text(json.dumps({"run": "x"}), encoding="utf-8")
    assert _kinds(found, records, root) == [("invalid", pf.TRACED_FILE)]


def test_the_shipped_record_checks_clean_for_its_entries(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = pf.read_record(pf.RECORDS)
    assert record.entries
    found = pf.compute(pf.Tree())
    reports = pf.check(found, record)
    assert [r for r in reports if r["kind"] != "missing"] == []
    assert pf.main(["--check"]) == pf.check_status(record, reports)
    out = capsys.readouterr().out
    assert "no entry point reaches" in out
    assert f"not_published {pf.not_published_count(record)}" in out
    assert pf.not_published_count(record) == 10


def test_the_schema_holds_the_closed_list_of_not_published_reasons() -> None:
    schema = json.loads((pf.RECORDS / pf.SCHEMA_FILE).read_text(encoding="utf-8"))
    form = schema["properties"]["entries"]["items"]["oneOf"][1]
    reasons = form["properties"]["not_published"]["properties"]["reason"]["enum"]
    assert reasons == list(pf.NOT_PUBLISHED_REASONS)


ALIASED = """
import pytest
from pytest import fixture as fx

fixture_alias = pytest.fixture


@fx
def test_alias_fixture():
    pass


@fixture_alias
def test_assigned_fixture():
    pass


def test_deleted():
    pass


del test_deleted


def test_real():
    pass


class TestOff:
    __test__ = False

    def test_member(self):
        pass
"""
OFF_MODULE = """
__test__ = False


def test_anything():
    pass
"""
UNDECIDED = """
import sys

from helpers import make_decorator

decorate = make_decorator()


@decorate
def test_wrapped():
    pass


def test_maybe_deleted():
    pass


if sys.platform == "win32":
    del test_maybe_deleted


class TestMaybe:
    __test__ = sys.platform != "win32"

    def test_member(self):
        pass
"""


@pytest.mark.parametrize(
    ("node_id", "verdict"),
    [
        ("tests/test_aliased.py::test_alias_fixture", "no"),
        ("tests/test_aliased.py::test_assigned_fixture", "no"),
        ("tests/test_aliased.py::test_deleted", "no"),
        ("tests/test_aliased.py::TestOff::test_member", "no"),
        ("tests/test_aliased.py::test_real", "yes"),
        ("tests/test_off.py::test_anything", "no"),
        ("tests/test_undecided.py::test_wrapped", "unverified"),
        ("tests/test_undecided.py::test_maybe_deleted", "unverified"),
        ("tests/test_undecided.py::TestMaybe::test_member", "unverified"),
    ],
)
def test_a_test_id_the_runner_would_not_collect_is_refused_and_an_undecided_one_said(
    tmp_path: Path, node_id: str, verdict: str
) -> None:
    _setup(tmp_path)
    for name, text in (
        ("test_aliased.py", ALIASED),
        ("test_off.py", OFF_MODULE),
        ("test_undecided.py", UNDECIDED),
    ):
        (tmp_path / "tests" / name).write_text(text, encoding="utf-8")
    assert pf.test_verdict(tmp_path, node_id) == verdict
    assert pf.test_exists(tmp_path, node_id) == (verdict == "yes")


def test_an_undecided_test_id_is_reported_and_counted_as_unverified(setup: Setup) -> None:
    found, records, root = setup
    (root / "tests" / "test_undecided.py").write_text(UNDECIDED, encoding="utf-8")
    entries = _entries(records, "pkg.out.render")
    entries[0]["test"] = "tests/test_undecided.py::test_wrapped"
    _write(records, "pkg.out.render", entries)
    item = entries[0].get("function") or entries[0]["constant"]
    assert _kinds(found, records, root) == [("unverified", item)]


@pytest.mark.parametrize("content", [None, {"job.json": "{}"}])
def test_trace_refuses_a_run_directory_that_holds_no_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    content: dict[str, str] | None,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    for name, text in (content or {}).items():
        (run / name).write_text(text, encoding="utf-8")
    out = tmp_path / "out" / "trace.json"

    def never(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("nothing is rendered")

    monkeypatch.setattr(pf, "trace", never)
    assert pf.main(["trace", str(run), "--out", str(out)]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "holds no report" in err
    assert not out.exists()


def test_a_trace_whose_render_ran_no_listed_function_is_a_failed_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = _fake_listing(tmp_path / "tree")
    run = tmp_path / "run"
    run.mkdir()

    def empty_render(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        modes: dict[str, Any] = {mode: {"error": None, "called": []} for mode in ("serve", "build")}
        Path(command[-1]).write_text(json.dumps(modes), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(pf.subprocess, "run", empty_render)
    result = pf.trace([run], tmp_path / "out" / "trace.json", listing=found)
    assert pf.failed_runs(result) == (1, 0)


def test_text_read_by_a_model_only_is_a_closed_not_published_reason() -> None:
    assert "model_text" in pf.NOT_PUBLISHED_REASONS
    record = pf.read_record(pf.RECORDS)
    reasons = {
        entry["function"]: entry["not_published"]["reason"]
        for entry in record.entries
        if "not_published" in entry
    }
    assert reasons["malspark.agents.output_shortening:shortening_sentence"] == "model_text"
    assert reasons["malspark.core.plugins:registration_refusal"] == "operator_text"


IMPORTED = """
from unittest.mock import patch

from helpers import fx, test_borrowed


@fx
def test_decorated_from_elsewhere():
    pass


@patch("os.getcwd")
def test_patched(getcwd):
    pass
"""


@pytest.mark.parametrize(
    ("node_id", "verdict"),
    [
        ("tests/test_imported.py::test_borrowed", "unverified"),
        ("tests/test_imported.py::test_decorated_from_elsewhere", "unverified"),
        ("tests/test_imported.py::test_patched", "yes"),
    ],
)
def test_a_name_imported_into_the_test_file_is_unverified(
    tmp_path: Path, node_id: str, verdict: str
) -> None:
    _setup(tmp_path)
    (tmp_path / "tests" / "test_imported.py").write_text(IMPORTED, encoding="utf-8")
    assert pf.test_verdict(tmp_path, node_id) == verdict


def test_compared_and_never_printed_is_a_closed_not_published_reason() -> None:
    assert "compared_only" in pf.NOT_PUBLISHED_REASONS
    schema = json.loads((pf.RECORDS / pf.SCHEMA_FILE).read_text(encoding="utf-8"))
    form = schema["properties"]["entries"]["items"]["oneOf"][1]
    assert "compared_only" in form["properties"]["not_published"]["properties"]["reason"]["enum"]


COMPARED = {
    "pkg/__init__.py": "",
    "pkg/gen.py": """
        LABEL = "the column heading words"
        GATE = ("the gate word one", "the gate word two")
        HANDED = "a handed out constant line"


        def render(sink, key):
            if key == LABEL:
                pass
            if key in GATE:
                pass
            return [HANDED, "a handed out line here"]


        def build(sink):
            return [LABEL]
    """,
}


def _compared_record(root: Path, reasons: dict[str, str]) -> tuple[pf.Listing, Path]:
    write_tree(root, COMPARED)
    found = pf.compute(pf.Tree(root, (("src", "pkg"),)), {"r": ["pkg.gen:render"]}, routes=())
    records = root / "records"
    records.mkdir()
    shutil.copy(pf.RECORDS / pf.SCHEMA_FILE, records / pf.SCHEMA_FILE)
    _status(records, complete=True)
    entries = []
    for key, kind in sorted(found.needs_entry().items()):
        entry = {kind: key, "text_digest": pf.text_digest(found.texts(key))}
        entries.append(
            _not_published(entry, reasons[key], "Never shown.")
            if key in reasons
            else {
                **entry,
                "condition": "always",
                "basis": ["the run"],
                "test": "tests/test_t.py::test_t",
            }
        )
    _write(records, "pkg.gen", entries)
    (root / "tests").mkdir()
    (root / "tests" / "test_t.py").write_text("def test_t():\n    pass\n", encoding="utf-8")
    return found, records


def test_a_compared_constant_an_unreached_function_hands_out_is_named_beside_it(
    tmp_path: Path,
) -> None:
    found, _ = _compared_record(tmp_path, {})
    assert found.compared_constants == ["pkg.gen:GATE", "pkg.gen:LABEL"]
    assert found.compared_handed_out == {"pkg.gen:LABEL": ["pkg.gen:build"]}
    table = found.table()
    assert (
        "compared in a reached function (constant): pkg.gen:LABEL; handed out by a function "
        "no entry point reaches: pkg.gen:build" in table
    )
    assert "compared in a reached function (constant): pkg.gen:GATE\n" in table + "\n"
    assert found.as_json()["compared_constants_handed_out"] == {"pkg.gen:LABEL": ["pkg.gen:build"]}


@pytest.mark.parametrize(
    ("key", "reason", "refused"),
    [
        ("pkg.gen:GATE", "compared_only", False),
        ("pkg.gen:LABEL", "compared_only", True),
        ("pkg.gen:LABEL", "operator_text", False),
        ("pkg.gen:render", "compared_only", True),
        ("pkg.gen:render", "operator_text", False),
        ("pkg.gen:HANDED", "compared_only", True),
        ("pkg.gen:HANDED", "non_sentence", False),
    ],
)
def test_compared_only_is_accepted_only_for_a_compared_constant_nothing_hands_out(
    tmp_path: Path, key: str, reason: str, refused: bool
) -> None:
    found, records = _compared_record(tmp_path, {key: reason})
    reports = pf.check(found, pf.read_record(records), tmp_path)
    assert [(r["kind"], r["item"]) for r in reports] == ([("invalid", key)] if refused else [])


def test_the_schema_states_which_reasons_each_class_may_give() -> None:
    schema = json.loads((pf.RECORDS / pf.SCHEMA_FILE).read_text(encoding="utf-8"))
    form = schema["properties"]["entries"]["items"]["oneOf"][1]
    by_class = form["properties"]["not_published"]["reasons_by_class"]
    assert by_class == {cls: list(r) for cls, r in pf.NOT_PUBLISHED_REASONS_BY_CLASS.items()}
    assert "compared_only" in by_class["h"]
    assert all("compared_only" not in by_class[cls] for cls in ("a", "b", "c"))
