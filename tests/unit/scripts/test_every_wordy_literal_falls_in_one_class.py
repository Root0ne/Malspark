"""Every wordy literal of the tree read falls in exactly one class of the partition.

Over a small synthetic package: a literal handed out by a reached function is
class a; one in a constant a reached function hands out, also through a table
derived from it, is b; wordy text in a reached function the rule cannot
place, a constant a reached function only names, a field default of a class
it names or of a class a field of such a class holds, and a constant a
``default_factory`` lambda names are c; text in an
unreached function or constant of a reached module is d, named per module;
text in a module no entry point reaches is e, counted per package; a
docstring, a logging call, a pattern and an ``assert`` message, and a literal
whose strongest use is one of them, are f, counted per kind; a comparison
operand or a literal only compared in a reached function is h, and a constant
a reached function only compares with needs an entry. A literal takes the
strongest of its uses, so adding a log line, a comparison or a pass-through
never lowers a class or removes an entry (checked over generated functions); a
walrus's value, a name a nested class binds, a class statement inside a
reached function and a call that stores its argument inside a logging call
take their strongest use too. A name bound more than once resolves to every
thing it can refer to, so adding a rebinding, a binding in a branch, a
shadowing parameter, a rebound import alias or a ``del`` never drops a listed
function, a listed constant or a required entry (checked over generated
functions). A
``raise`` message is g, and one a route sends as a response body (an
``HTTPException``, a class whose registered handler reads it, a class a
reached catch answers with such a raise) is named. The classes sum to the
total, each is printed with its count, the limit lines name what classes d and
e are known to hold, and a literal the rule reads in no class is an error
status.
"""

from __future__ import annotations

import textwrap
from collections.abc import Sequence
from pathlib import Path

import pytest
from scripts.audit import publishing_functions as pf

ENTRIES = {"render": ["pkg.out.render:render"], "api": ["pkg.out.routes:get_report"]}

SOURCES = {
    "pkg/__init__.py": "",
    "pkg/out/__init__.py": "",
    "pkg/far/__init__.py": "",
    "pkg/out/render.py": '''
        import logging
        import re
        from dataclasses import dataclass, field

        logger = logging.getLogger(__name__)
        HANDED = "a handed out constant"
        NAMED = "a constant only named here"
        UNUSED = "a constant nobody names"
        TABLE = (("k", "a derived table row"),)
        BY_KEY = {key: text for key, text in TABLE}
        DEFAULTS = ("a default factory line",)


        @dataclass
        class Front:
            banner: str = "a carried banner line"


        @dataclass
        class Config:
            product_type: str = "Malware Analysis Report"
            lookups: list = field(default_factory=lambda: list(DEFAULTS))
            front: Front | None = None


        def check(value):
            return bool(value)


        def helper(writer, text):
            writer.line(text)


        def render(config: Config, key, writer):
            """A docstring of many words."""
            logger.info("a log line of words")
            assert key, "an assert message here"
            if key == "compared against words":
                return []
            if re.match("a pattern of words", key):
                return []
            quiet = "held for a log only"
            logger.warning(quiet)
            helper(writer, "a helper call argument")
            check(NAMED)
            if not key:
                raise ValueError("a renderer refusal here")
            return [HANDED, BY_KEY[key], "a handed out line"]


        def writer_at_build():
            return "a build time writer line"


        def annotated(value: "Two Words") -> "More Words":
            return value
    ''',
    "pkg/out/routes.py": """
        class HTTPException(Exception):
            pass


        def _load(key):
            if not key:
                raise HTTPException(404, "Report not found here")
            return key


        def get_report(key):
            return _load(key)


        def unrouted():
            raise ValueError("an unrouted refusal here")
    """,
    "pkg/far/lone.py": """
        FAR = "a far constant line"


        def lone():
            return "a lone module line"
    """,
}


def write_tree(root: Path, sources: dict[str, str] = SOURCES) -> Path:
    for name, text in sources.items():
        path = root / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return root


def listing(root: Path) -> pf.Listing:
    tree = pf.Tree(root, (("src", "pkg"),))
    return pf.compute(tree, ENTRIES, routes=("api",))


@pytest.fixture()
def listed(tmp_path: Path) -> pf.Listing:
    return listing(write_tree(tmp_path))


@pytest.mark.parametrize(
    ("text", "cls"),
    [
        ("a handed out line", "a"),
        ("a handed out constant", "b"),
        ("a derived table row", "b"),
        ("a helper call argument", "c"),
        ("a constant only named here", "c"),
        ("Malware Analysis Report", "c"),
        ("a default factory line", "c"),
        ("a carried banner line", "c"),
        ("a constant nobody names", "d"),
        ("a build time writer line", "d"),
        ("an unrouted refusal here", "g"),
        ("a far constant line", "e"),
        ("a lone module line", "e"),
        ("a docstring of many words.", "f"),
        ("a log line of words", "f"),
        ("an assert message here", "f"),
        ("compared against words", "h"),
        ("a pattern of words", "f"),
        ("held for a log only", "f"),
        ("Two Words", "d"),
        ("More Words", "d"),
        ("a renderer refusal here", "g"),
        ("Report not found here", "g"),
    ],
)
def test_each_wordy_literal_falls_in_its_class(listed: pf.Listing, text: str, cls: str) -> None:
    classes = {p.text.lower(): p.cls for p in listed.partition.literals}
    assert classes[text.lower()] == cls


def test_the_classes_sum_to_the_total_and_no_literal_is_in_two(listed: pf.Listing) -> None:
    partition = listed.partition
    counts = partition.counts()
    assert set(counts) == set(pf.PARTITION_CLASSES)
    assert sum(counts.values()) == partition.total == len(partition.literals)
    assert partition.total == 23
    assert partition.unassigned == []
    places = [(p.path, p.line, p.col) for p in partition.literals]
    assert len(places) == len(set(places))


def test_position_classes_are_counted_per_kind(listed: pf.Listing) -> None:
    kinds = listed.partition.per_kind("f")
    assert kinds == {
        "assert": 1,
        "docstring": 1,
        "held": 1,
        "log": 1,
        "pattern": 1,
    }


def test_a_raise_a_route_handler_reaches_is_named(listed: pf.Listing) -> None:
    served = [(p.holder, p.text) for p in listed.partition.route_served()]
    assert served == [("pkg.out.routes:_load", "Report not found here")]
    assert listed.partition.counts()["g"] == 3


def test_unreached_text_is_named_per_module_and_far_text_counted_per_package(
    listed: pf.Listing,
) -> None:
    assert listed.partition.per_module("d") == {"pkg.out.render": 4}
    assert listed.partition.per_package("e") == {"pkg.far": 2}
    holders = sorted(p.holder for p in listed.partition.literals if p.cls == "d")
    assert holders == [
        "pkg.out.render:UNUSED",
        "pkg.out.render:annotated",
        "pkg.out.render:annotated",
        "pkg.out.render:writer_at_build",
    ]


def test_constants_named_or_fields_of_a_named_class_need_entries(listed: pf.Listing) -> None:
    assert set(listed.constants) == {"pkg.out.render:HANDED", "pkg.out.render:TABLE"}
    assert listed.constants["pkg.out.render:TABLE"] == ["pkg.out.render:render"]
    assert listed.not_placed_constants == [
        "pkg.out.render:Config.product_type",
        "pkg.out.render:DEFAULTS",
        "pkg.out.render:Front.banner",
        "pkg.out.render:NAMED",
    ]
    needs = listed.needs_entry()
    assert needs["pkg.out.render:render"] == "function"
    assert "pkg.out.render:render" in listed.not_placed
    assert needs["pkg.out.render:Config.product_type"] == "constant"
    assert "pkg.out.render:UNUSED" not in needs


def test_every_class_is_printed_with_its_count_and_the_total(listed: pf.Listing) -> None:
    table = listed.table()
    counts = listed.partition.counts()
    for cls in pf.PARTITION_CLASSES:
        assert f"class {cls}: {counts[cls]} " in table
    assert f"partition: {listed.partition.total} wordy literal(s)" in table
    document = listed.as_json()["partition"]
    assert document["total"] == 23
    assert document["classes"] == counts
    assert document["f_per_kind"]["log"] == 1
    assert document["e_per_package"] == {"pkg.far": 2}


def test_each_class_can_be_listed_by_name(listed: pf.Listing) -> None:
    rows = pf.class_rows(listed, "e")
    assert len(rows) == 2
    assert all("src/pkg/far/lone.py:" in row for row in rows)
    assert any("pkg.far.lone:lone" in row for row in rows)


def test_the_limit_lines_name_classes_d_to_g_in_true_words(listed: pf.Listing) -> None:
    lines = pf.limit_lines(listed)
    joined = "\n".join(lines)
    assert "limit: class d, 4 wordy literal(s)" in joined
    assert "limit: class e, 2 wordy literal(s)" in joined
    assert "limit: class f, 5 wordy literal(s)" in joined
    assert "limit: class g, 3 raise message(s)" in joined
    assert "1 of them a route sends" in joined


def test_a_literal_the_rule_reads_in_no_class_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path)
    original = pf.Tree._place

    def forgetful(self: pf.Tree, function: pf.Function) -> None:
        if function.qualname != "writer_at_build":
            original(self, function)

    monkeypatch.setattr(pf.Tree, "_place", forgetful)
    found = listing(tmp_path)
    assert [p.text for p in found.partition.unassigned] == ["a build time writer line"]
    assert sum(found.partition.counts().values()) == found.partition.total - 1
    assert pf.partition_status(found) == 2
    assert "in no class" in "\n".join(pf.partition_errors(found))


def test_a_def_inside_a_branch_of_a_function_is_read(tmp_path: Path) -> None:
    sources = dict(SOURCES)
    sources["pkg/out/render.py"] += textwrap.indent(
        textwrap.dedent(
            """

            def branchy(flag):
                if flag:
                    def inner():
                        return "a branch nested line"
                    return inner()
                return ""
            """
        ),
        "        ",
    )
    found = listing(write_tree(tmp_path, sources))
    assert found.partition.unassigned == []
    assert "pkg.out.render:branchy.<locals>.inner" in found.tree.functions


def test_the_real_tree_has_no_literal_outside_the_partition() -> None:
    found = pf.compute(pf.Tree())
    assert found.partition.unassigned == []
    assert sum(found.partition.counts().values()) == found.partition.total
    assert pf.partition_status(found) == 0


HELD_SOURCES = {
    "pkg/__init__.py": "",
    "pkg/out/__init__.py": "",
    "pkg/out/held.py": """
        import logging

        logger = logging.getLogger(__name__)


        def note(sink, text):
            sink.emit(text)


        def logged_and_passed(sink):
            said = "the retry left out two claims"
            logger.warning(said)
            note(sink, said)
            return []


        def recorded_and_raised(sink):
            detail = "the loop exceeded its hard cap"
            sink.record_budget(detail)
            raise RuntimeError(detail)


        def logged_and_returned():
            told = "a sentence logged and returned"
            logger.info(told)
            return [told]


        def logged_and_compared(key):
            marker = "a marker only compared"
            logger.info(marker)
            if key == marker:
                return []
            return [key]


        def logged_then_raised():
            refusal = "a refusal logged then raised"
            logger.error(refusal)
            raise ValueError(refusal)


        def passed_into_a_result(sink):
            noted = "a sentence passed to a call"
            logger.info(noted)
            outcome = sink.note(noted)
            logger.info(outcome)
            return []


        def composed_then_logged(key):
            base = "a sentence composed then logged"
            line = "{} for {}".format(base, key)
            logger.info(line)
            return []


        def render(sink, key):
            passed_into_a_result(sink)
            composed_then_logged(key)
            logged_and_passed(sink)
            recorded_and_raised(sink)
            logged_and_compared(key)
            logged_then_raised()
            return logged_and_returned()
    """,
}
HELD_ENTRIES = {"render": ["pkg.out.held:render"]}


def held_listing(root: Path, sources: dict[str, str] = HELD_SOURCES) -> pf.Listing:
    write_tree(root, sources)
    return pf.compute(pf.Tree(root, (("src", "pkg"),)), HELD_ENTRIES, routes=())


@pytest.mark.parametrize(
    ("text", "cls", "kind"),
    [
        ("the retry left out two claims", "c", "not placed"),
        ("a sentence passed to a call", "c", "not placed"),
        ("a sentence composed then logged", "f", "held"),
        ("the loop exceeded its hard cap", "c", "not placed"),
        ("a sentence logged and returned", "a", "handed out"),
        ("a marker only compared", "h", "compared in a reached function"),
        ("a refusal logged then raised", "g", "held in a name, then raised"),
    ],
)
def test_a_name_is_quiet_only_when_every_read_of_it_is_quiet(
    tmp_path: Path, text: str, cls: str, kind: str
) -> None:
    found = held_listing(tmp_path)
    placed = {p.text: (p.cls, p.kind) for p in found.partition.literals}
    assert placed[text] == (cls, kind)


def test_a_log_line_added_to_a_reached_function_never_removes_a_required_entry(
    tmp_path: Path,
) -> None:
    with_log = held_listing(tmp_path / "with")
    without = dict(HELD_SOURCES)
    without["pkg/out/held.py"] = without["pkg/out/held.py"].replace("logger.warning(said)", "pass")
    bare = held_listing(tmp_path / "without", without)
    assert "pkg.out.held:logged_and_passed" in bare.needs_entry()
    assert set(bare.needs_entry()) <= set(with_log.needs_entry())
    assert "pkg.out.held:recorded_and_raised" in with_log.needs_entry()


def test_the_limit_lines_name_what_classes_d_and_e_hold_besides_build_time_text(
    listed: pf.Listing,
) -> None:
    joined = "\n".join(pf.limit_lines(listed))
    for words in ("job package", "command line", "job event feed", "job error message"):
        assert words in joined


ROUTE_SOURCES = {
    "pkg/__init__.py": "",
    "pkg/api/__init__.py": "",
    "pkg/api/main.py": """
        from pkg.api.routes import Refused, Quiet


        async def refused_response(request, exc):
            return {"detail": str(exc)}


        async def quiet_response(request, exc):
            return {"detail": "unavailable"}


        def create(app):
            app.add_exception_handler(Refused, refused_response)
            app.add_exception_handler(Quiet, quiet_response)
    """,
    "pkg/api/routes.py": """
        from fastapi import HTTPException


        class Unavailable(Exception):
            pass


        class Refused(Exception):
            pass


        class Quiet(Exception):
            pass


        class NarrowRefused(Refused):
            pass


        def validate(value):
            if not value:
                raise ValueError("a validator refusal here")
            if value == 1:
                raise Unavailable("the renderer is not installed")
            if value == 2:
                raise Refused("a stored value is refused")
            if value == 3:
                raise Quiet("a quiet refusal text")
            if value == 4:
                raise NarrowRefused("a narrower refusal text")
            return value


        def get_report(key):
            try:
                validate(key)
            except Unavailable as exc:
                raise HTTPException(503, detail=str(exc)) from exc
            if key is None:
                raise HTTPException(404, detail="Report not found here")
            return key
    """,
}


def test_a_raise_is_named_route_served_only_when_its_text_reaches_a_body(
    tmp_path: Path,
) -> None:
    write_tree(tmp_path, ROUTE_SOURCES)
    tree = pf.Tree(tmp_path, (("src", "pkg"),))
    found = pf.compute(tree, {"api": ["pkg.api.routes:get_report"]}, routes=("api",))
    served = sorted(p.text for p in found.partition.route_served())
    assert served == [
        "Report not found here",
        "a narrower refusal text",
        "a stored value is refused",
        "the renderer is not installed",
    ]
    assert found.partition.counts()["g"] == 6
    assert "4 of them a route sends" in "\n".join(pf.limit_lines(found))


GATED_SOURCES = {
    "pkg/__init__.py": "",
    "pkg/out/__init__.py": "",
    "pkg/out/gate.py": """
        import logging

        logger = logging.getLogger(__name__)
        ALLOWED = frozenset({"payload delivery", "artifacts dropped"})
        TABLE = {"md5": frozenset({"payload installation", "persistence mechanism"})}
        PLAIN = ("observed only", "partly read here")


        def note(sink, text):
            sink.emit(text)
            return True


        def direct(row):
            out = []
            if row in ALLOWED:
                out.append(row)
            return out


        def through(kind, category):
            allowed = TABLE.get(kind)
            if allowed is not None and category not in allowed:
                return "fallback"
            return category


        def form(cells):
            plain = PLAIN
            out = []
            for cell in cells:
                if cell not in plain:
                    out.append("`" + cell + "`")
                else:
                    out.append(cell)
            return out


        def local(row):
            allowed = {"the local category one", "the local category two"}
            if row in allowed:
                return row
            return ""


        def checked(sink):
            ok = note(sink, "the retry left out two claims")
            if ok is None:
                return []
            return [1]


        def kept_then_logged(sink):
            kept = note(sink, f"the value is not one command line: {sink}")
            logger.info(kept)
            return [1]


        def outer(sink):
            failure = ""

            def keep():
                nonlocal failure
                said = "the retry was kept aside"
                failure = said
                logger.info(said)

            keep()
            return [failure]


        def render(sink, row, kind, category, cells):
            outer(sink)
            direct(row)
            through(kind, category)
            form(cells)
            local(row)
            checked(sink)
            return kept_then_logged(sink)
    """,
}


def test_a_comparison_is_no_quiet_position_and_a_compared_constant_needs_an_entry(
    tmp_path: Path,
) -> None:
    write_tree(tmp_path, GATED_SOURCES)
    found = pf.compute(
        pf.Tree(tmp_path, (("src", "pkg"),)), {"render": ["pkg.out.gate:render"]}, routes=()
    )
    placed = {p.text: (p.cls, p.kind) for p in found.partition.literals}
    assert placed["the local category one"] == ("h", "compared in a reached function")
    assert placed["the retry left out two claims"] == ("c", "not placed")
    assert placed["the retry was kept aside"] == ("c", "not placed")
    assert placed["the value is not one command line:  {} "] == ("c", "not placed")
    for constant in ("ALLOWED", "TABLE", "PLAIN"):
        assert found.needs_entry()[f"pkg.out.gate:{constant}"] == "constant"
    assert placed["payload delivery"] == ("h", "constant compared")
    assert found.compared_constants == [
        "pkg.out.gate:ALLOWED",
        "pkg.out.gate:PLAIN",
        "pkg.out.gate:TABLE",
    ]
    assert "pkg.out.gate:local" not in found.needs_entry()
    assert "class h: " in "\n".join(pf.partition_lines(found))
    assert "compared in a reached function" in found.table()


# The uses a generated function may give its name ``t``, strongest last.
_USES = {
    "log": "    logger.info(t)\n",
    "compare": "    if t == key:\n        pass\n",
    "raise": "    if key is None:\n        raise ValueError(t)\n",
    "pass": "    note(sink, t)\n",
    "chain": "    u = t\n    logger.info(u)\n",
    "return": "    return [t]\n",
}
_RANK = {"f": 1, "g": 2, "h": 3, "c": 4, "a": 5}


def _generated(seed: int, extra: str | None) -> dict[str, str]:
    import random

    chooser = random.Random(seed)
    bodies = []
    for index in range(24):
        uses = chooser.sample(sorted(set(_USES) - {"return"}), chooser.randint(0, 3))
        body = f'def f{index}(sink, key):\n    t = "a generated sentence number {index}"\n'
        body += "".join(_USES[u] for u in uses)
        if extra is not None:
            body += _USES[extra]
        if chooser.random() < 0.2:
            body += _USES["return"]
        bodies.append(body)
    calls = "".join(f"    f{index}(sink, key)\n" for index in range(24))
    module = (
        "import logging\n\nlogger = logging.getLogger(__name__)\n\n\n"
        "def note(sink, text):\n    sink.emit(text)\n\n\n"
        + "\n\n".join(bodies)
        + f"\n\ndef render(sink, key):\n{calls}    return []\n"
    )
    return {"pkg/__init__.py": "", "pkg/gen.py": module}


@pytest.mark.parametrize("extra", ["log", "compare", "pass", "chain", "raise"])
@pytest.mark.parametrize("seed", [7, 70, 770])
def test_adding_a_use_never_lowers_a_literal_class_or_removes_an_entry(
    tmp_path: Path, seed: int, extra: str
) -> None:
    def classes(where: str, added: str | None) -> tuple[dict[str, str], set[str]]:
        root = write_tree(tmp_path / where, _generated(seed, added))
        found = pf.compute(pf.Tree(root, (("src", "pkg"),)), {"r": ["pkg.gen:render"]}, routes=())
        return {p.text: p.cls for p in found.partition.literals}, set(found.needs_entry())

    before, needed = classes("before", None)
    after, needed_after = classes("after", extra)
    for text, cls in before.items():
        assert _RANK[after[text]] >= _RANK[cls], (text, cls, after[text])
    assert needed <= needed_after


REBOUND_HEAD = """
class Writer:
    def emit(self, sink):
        return "the writer emits this sentence"


class Other:
    def emit(self, sink):
        return None


"""
REBOUND_BODIES = {
    "once": "    w = Writer()\n    out = w.emit(sink)\n    return [out]\n",
    "rebound before the call": (
        "    w = Other()\n    w.emit(sink)\n    w = Writer()\n    out = w.emit(sink)\n"
        "    return [out]\n"
    ),
    "bound in a branch": (
        "    if key:\n        w = Other()\n    w = Writer()\n    out = w.emit(sink)\n"
        "    return [out]\n"
    ),
    "annotated, then rebound": ("    w = Other()\n    out = w.emit(sink)\n    return [out]\n"),
}


@pytest.mark.parametrize("shape", sorted(REBOUND_BODIES))
def test_a_name_bound_more_than_once_resolves_to_everything_it_can_refer_to(
    tmp_path: Path, shape: str
) -> None:
    head = "def render(sink, key):\n"
    if shape == "annotated, then rebound":
        head = "def render(sink, key, w: Writer = None):\n"
    write_tree(
        tmp_path, {"pkg/__init__.py": "", "pkg/gen.py": REBOUND_HEAD + head + REBOUND_BODIES[shape]}
    )
    found = pf.compute(pf.Tree(tmp_path, (("src", "pkg"),)), {"r": ["pkg.gen:render"]}, routes=())
    placed = {p.text: p.cls for p in found.partition.literals}
    assert placed["the writer emits this sentence"] == "a"
    assert found.needs_entry()["pkg.gen:Writer.emit"] == "function"


_FULL_RANK = {"f": 1, "d": 1, "e": 1, "g": 2, "h": 3, "c": 4, "a": 5, "b": 5}
# Generated functions that reach a method, an annotated parameter's method, a
# function, a constant and a module's function, each through one name ``N``.
_REACHES = {
    "method": ("", ["w = Writer{i}()"], ["out = w.emit(sink)", "return [out]"], "w"),
    "annotated": (", w: Writer{i} = None", [], ["return [w.emit(sink)]"], "w"),
    "call": ("", [], ["return [speak{i}(sink)]"], "speak{i}"),
    "constant": ("", [], ["return [LABEL{i}]"], "LABEL{i}"),
    "module": ("", [], ["return [voice.say{i}(sink)]"], "voice"),
}
# What may be added to such a function: (where, parameter, lines).
_BINDS = {
    "rebound before the call": ("head", "", ["{N} = Other()", "{N}.emit(sink)"]),
    "rebound after the binding": ("mid", "", ["{N} = Other()"]),
    "bound in a branch": ("mid", "", ["if key:", "    {N} = Other()"]),
    "shadowing parameter": ("head", ", {N}: Other = None", []),
    "shadowed in a nested scope": (
        "mid",
        "",
        ["def inner({N}: Other):", "    return {N}.emit(sink)", "inner(Other())"],
    ),
    "import alias rebound": ("head", "", ["from pkg import other as {N}"]),
    "deleted": ("mid", "", ["del {N}"]),
}


def _bound_module(added: Sequence[str]) -> dict[str, str] | None:
    lines = [
        "import logging",
        "import pkg.voice as voice",
        "",
        "logger = logging.getLogger(__name__)",
    ]
    lines += ["", "", "class Other:", "    def emit(self, sink):", "        return None", ""]
    calls = []
    for i, (name, (param, setup, use, n)) in enumerate(sorted(_REACHES.items())):
        name_n = n.format(i=i)
        params = param.format(i=i)
        head: list[str] = []
        mid: list[str] = []
        for bind in added:
            where, extra, body = _BINDS[bind]
            if extra and f" {name_n}:" in params:
                continue  # the name is a parameter already
            params += extra.format(N=name_n)
            (head if where == "head" else mid).extend(b.format(N=name_n) for b in body)
        body_lines = head + [s.format(i=i) for s in setup] + mid + [u.format(i=i) for u in use]
        lines += [
            "",
            f'LABEL{i} = "a generated label number {i}"',
            "",
            f"class Writer{i}:",
            "    def emit(self, sink):",
            f'        return "the writer {i} emits this sentence"',
            "",
            f"def speak{i}(sink):",
            f'    return "a spoken sentence number {i}"',
            "",
            f"def f_{name}(sink, key{params}):",
            *("    " + b for b in body_lines),
            "",
        ]
        calls.append(f"    f_{name}(sink, key)")
    lines += ["def render(sink, key):", *calls, "    return []", ""]
    module = "\n".join(lines)
    try:
        compile(module, "gen.py", "exec")
    except SyntaxError:
        return None
    voice = "".join(
        f'def say{i}(sink):\n    return "a voiced sentence number {i}"\n\n\n'
        for i in range(len(_REACHES))
    )
    return {
        "pkg/__init__.py": "",
        "pkg/gen.py": module,
        "pkg/voice.py": voice,
        "pkg/other.py": "def thing(sink):\n    return None\n",
    }


@pytest.mark.parametrize("first", [None, *sorted(_BINDS)])
def test_adding_a_binding_never_lowers_a_class_or_drops_a_listed_key_or_an_entry(
    tmp_path: Path, first: str | None
) -> None:
    def read(where: str, sources: dict[str, str]) -> tuple[dict[str, str], set[str], set[str]]:
        root = write_tree(tmp_path / where, sources)
        found = pf.compute(pf.Tree(root, (("src", "pkg"),)), {"r": ["pkg.gen:render"]}, routes=())
        listed = {*found.functions, *found.constants}
        return {p.text: p.cls for p in found.partition.literals}, listed, set(found.needs_entry())

    base = [first] if first else []
    sources = _bound_module(base)
    assert sources is not None
    before, listed, needed = read("before", sources)
    assert "pkg.voice:say4" in listed
    tried = 0
    for second in sorted(set(_BINDS) - set(base)):
        added = _bound_module([*base, second])
        if added is None:
            continue
        tried += 1
        after, listed_after, needed_after = read(second.replace(" ", "-"), added)
        for text, cls in before.items():
            assert _FULL_RANK[after[text]] >= _FULL_RANK[cls], (second, text, cls, after[text])
        assert listed <= listed_after, (second, sorted(listed - listed_after))
        assert needed <= needed_after, (second, sorted(needed - needed_after))
    assert tried == len(_BINDS) - len(base)


STRONGEST_SOURCES = {
    "pkg/__init__.py": "",
    "pkg/gen.py": """
        import logging

        logger = logging.getLogger(__name__)


        def note(sink, text):
            sink.emit(text)
            return text


        def walrus(sink):
            note(sink, (t := "a walrus value passed on"))


        def class_attribute(sink):
            t = "a class attribute sentence here"

            class K:
                a = t

            sink.take(K)


        def class_body(sink):
            class K:
                a = "a nested class body sentence"

            return K.a


        def stored_in_a_log(sink):
            logger.info("kept %s", note(sink, "a sentence stored inside a log call"))


        def appended_in_a_log(sink):
            logger.info("kept %s", sink.append("a sentence appended inside a log call"))


        def logged(sink):
            logger.info("a plain logged sentence %s", "an argument formatted in".upper())


        def render(sink):
            walrus(sink)
            class_attribute(sink)
            class_body(sink)
            stored_in_a_log(sink)
            appended_in_a_log(sink)
            logged(sink)
            return []
    """,
}


def test_a_walrus_a_nested_class_and_a_call_inside_a_log_take_their_strongest_use(
    tmp_path: Path,
) -> None:
    write_tree(tmp_path, STRONGEST_SOURCES)
    found = pf.compute(pf.Tree(tmp_path, (("src", "pkg"),)), {"r": ["pkg.gen:render"]}, routes=())
    placed = {p.text: p.cls for p in found.partition.literals}
    assert placed["a walrus value passed on"] == "c"
    assert placed["a class attribute sentence here"] == "c"
    assert placed["a nested class body sentence"] == "c"
    assert placed["a sentence stored inside a log call"] == "c"
    assert placed["a sentence appended inside a log call"] == "a"
    assert placed["a plain logged sentence %s"] == "f"
    assert placed["an argument formatted in"] == "f"
    needed = found.needs_entry()
    for function in ("walrus", "class_attribute", "class_body", "stored_in_a_log"):
        assert needed[f"pkg.gen:{function}"] == "function"
    assert needed["pkg.gen:appended_in_a_log"] == "function"
    lines = "\n".join([*pf.partition_lines(found), *pf.limit_lines(found)])
    assert "needs no entry, also where the value it lets through is printed" in lines
    assert "even where a call in that expression stores or hands it out" in lines
