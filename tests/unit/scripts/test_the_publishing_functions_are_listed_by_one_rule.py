"""The publishing functions are the ones the rule reaches and that hand out wording.

Over a small synthetic package: a function is reached from an entry point by
a call or a reference (``key=f``, a lambda, ``map``), through ``self.``,
``super()``, an import or a module alias, and a nested def by the function
that holds it, whatever its package. It is listed when a literal of two or
more words reaches a hand-out position of its own body (returned, yielded,
appended, ``+=``-ed, assigned to what it returns or to what its caller holds),
also through a local name, a subscript, an attribute, a table of sentences, a
lambda body, ``str.format``, ``%``, a join or an f-string placeholder; a
docstring, a ``raise`` or ``assert`` message (also through a name), a logging
argument, a ``re`` pattern and a comparison operand never count, nor a single
word. A reached function whose wording stands in no hand-out position is named
as not placed. A wordy constant a reached function hands out, a class's
included, is listed once with the functions that hand it out. A wordy function
no entry point reaches is counted, never listed, and its text and a constant
only it hands out fall in class d. The digest moves with any change of the
wording, a changed or swapped placeholder among them, and with a changed or
swapped argument of a ``%``, a ``.format`` or a concatenation; the list is the
same under any string hash seed.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from scripts.audit import publishing_functions as pf

ROOT = Path(__file__).resolve().parents[3]
ENTRIES = {"render": ["pkg.out.render:render", "pkg.out.render:Child.render"]}

SOURCES = {
    "pkg/__init__.py": "",
    "pkg/out/__init__.py": "",
    "pkg/core/__init__.py": "",
    "pkg/core/words.py": """
        def core_line():
            return "outside the scope entirely"
    """,
    "pkg/out/helpers.py": """
        HELPER_NOTE = "a helper's own note"

        def by_import():
            return "reached through an import"

        def by_alias():
            return "reached through a module alias"
    """,
    "pkg/out/render.py": """
        import logging
        import re

        from pkg.core.words import core_line
        from pkg.out import helpers as h
        from pkg.out.helpers import by_import

        logger = logging.getLogger(__name__)
        HEADING = "Key findings of the run"
        PHRASES = ("matched model words",)
        ORPHAN_NOTE = "a note only an orphan hands out"


        def by_call():
            return "reached by a call"


        def by_key(row):
            return f"sorted by {row} key"


        def by_lambda():
            return "reached through a lambda"


        def by_map(item):
            return f"mapped over {item} here"


        def _safe(make):
            return make()


        def yielded():
            yield "a yielded line here"


        def appended(lines):
            lines.append("an appended line here")


        def added(text):
            text += "an added clause here"
            return text


        def assigned():
            line = "an assigned then returned line"
            return line


        def single_word():
            return "Benign"


        def documented():
            \"\"\"A docstring of many words.\"\"\"
            return None


        def raising():
            raise ValueError("a refusal message here")


        def asserting(value):
            assert value, "an assert message here"
            return value


        def logging_only():
            logger.info("a log line of words")
            return None


        def pattern(text):
            return re.compile("two words").search(text)


        def compared(text):
            return text == "compared against words"


        def heading():
            return HEADING


        def matched(text):
            return text in PHRASES


        def helper_note():
            return h.HELPER_NOTE


        def orphan():
            return "never reached by anything"


        def orphan_note():
            return ORPHAN_NOTE


        def via_local(lines):
            text = "a local then appended line"
            lines.append(text)


        def via_subscript():
            row = {}
            row["note"] = "a subscript assigned line"
            return row


        def via_attribute(note):
            note.text = "an attribute assigned line"


        def via_table(kind):
            table = {
                "a": "a table of sentences",
                "b": ("a tuple of sentences",),
                "c": ["a list of sentences"],
            }
            chosen = table[kind]
            return chosen


        def via_lambda(failed, html):
            fixed = failed.sub(lambda match: "a lambda body sentence", html)
            del fixed


        def via_format(value):
            template = "a format template {} here"
            return template.format(value)


        def via_percent(value):
            template = "a percent template %s here"
            return template % value


        def via_join(parts):
            head = ["a joined head line"]
            return " ".join(head + parts)


        def via_placeholder(value):
            return f"{'a placeholder literal' if value else ''}"


        def via_loop(out):
            for line in ("a looped line here",):
                out.append(line)


        def not_placed(writer):
            writer.line("a helper call argument here")


        def raised_through_a_name():
            message = "a refusal held in a name"
            raise ValueError(message)


        def logged_through_self(self):
            self.logger.warning("a log line through an attribute")
            return None


        def dialog_line(dialog):
            dialog.warning("a dialog box warning line")


        class Holder:
            title = "a class level title"


        def via_annotated(holder: Holder):
            return holder.title


        def via_instance():
            return Holder().title


        def mixed(value):
            if value:
                return f"{value!r:>8} is the verdict"
            return "Benign"


        def render(rows):
            def nested():
                return "a nested def's words"

            def unnamed():
                return "a nested def nobody names"

            out = [by_call(), nested(), by_import(), h.by_alias(), core_line()]
            out += sorted(rows, key=by_key)
            out.append(_safe(lambda: by_lambda()))
            out += list(map(by_map, rows))
            out += [yielded, appended, added, assigned, single_word, documented]
            out += [raising, asserting, logging_only, pattern, compared]
            out += [heading, matched, helper_note]
            out += [via_local, via_subscript, via_attribute, via_table, via_lambda, via_format]
            out += [via_percent, via_join, via_placeholder, via_loop, not_placed]
            out += [raised_through_a_name, logged_through_self, dialog_line]
            out += [via_annotated, via_instance, mixed]
            return out


        class Base:
            def _base(self):
                return "reached through super"


        class Child(Base):
            def render(self):
                return [self._own(), super()._base()]

            def _own(self):
                return "reached through self"
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
    return pf.compute(tree, ENTRIES)


@pytest.fixture()
def listed(tmp_path: Path) -> pf.Listing:
    return listing(write_tree(tmp_path))


@pytest.mark.parametrize(
    "name",
    [
        "by_call",
        "by_key",
        "by_lambda",
        "by_map",
        "Child._own",
        "Base._base",
        "render.<locals>.nested",
        "render.<locals>.unnamed",
    ],
)
def test_a_function_reached_by_a_call_or_a_reference_is_listed(
    listed: pf.Listing, name: str
) -> None:
    assert f"pkg.out.render:{name}" in listed.functions


def test_a_function_reached_through_an_import_or_a_module_alias_is_listed(
    listed: pf.Listing,
) -> None:
    assert {"pkg.out.helpers:by_import", "pkg.out.helpers:by_alias"} <= set(listed.functions)


@pytest.mark.parametrize("name", ["yielded", "appended", "added", "assigned"])
def test_each_hand_out_position_lists_the_function(listed: pf.Listing, name: str) -> None:
    assert f"pkg.out.render:{name}" in listed.functions


@pytest.mark.parametrize(
    "name",
    [
        "via_local",
        "via_subscript",
        "via_attribute",
        "via_table",
        "via_lambda",
        "via_format",
        "via_percent",
        "via_join",
        "via_placeholder",
        "via_loop",
    ],
)
def test_wording_that_reaches_a_hand_out_through_a_name_or_a_form_lists_the_function(
    listed: pf.Listing, name: str
) -> None:
    assert f"pkg.out.render:{name}" in listed.functions


def test_a_reached_function_whose_wording_stands_in_no_hand_out_is_named_not_placed(
    listed: pf.Listing,
) -> None:
    assert listed.not_placed == ["pkg.out.render:dialog_line", "pkg.out.render:not_placed"]
    document = listed.as_json()["wordy_not_placed"]
    assert document["count"] == 2
    assert document["functions"] == listed.not_placed
    table = listed.table()
    assert "class c: 2 wordy literal(s) in 2 reached function(s) and 0 constant(s)" in table
    assert "wordy, not placed: pkg.out.render:not_placed" in table


@pytest.mark.parametrize(
    "name",
    [
        "single_word",
        "documented",
        "raising",
        "asserting",
        "logging_only",
        "pattern",
        "compared",
        "matched",
        "_safe",
        "raised_through_a_name",
        "logged_through_self",
    ],
)
def test_what_never_counts_leaves_a_reached_function_off_the_list(
    listed: pf.Listing, name: str
) -> None:
    key = f"pkg.out.render:{name}"
    assert key in pf.reach(listed.tree, ENTRIES)
    assert key not in listed.functions
    assert key not in listed.not_placed
    if name not in ("single_word", "matched", "_safe"):
        # Nor is its wording: the digest reads no literal in such a position.
        assert listed.tree.functions[key].texts == []


def test_a_function_of_any_package_an_entry_point_reaches_is_listed(listed: pf.Listing) -> None:
    assert "pkg.core.words:core_line" in listed.functions
    assert listed.per_package() == {
        "pkg.core": (1, 0),
        "pkg.out": (len(listed.functions) - 1, len(listed.constants)),
    }
    assert listed.as_json()["per_package"]["pkg.core"] == {"functions": 1, "constants": 0}
    assert "pkg.core" in listed.table()


def test_a_handed_out_constant_is_listed_once_with_who_hands_it_out(listed: pf.Listing) -> None:
    assert listed.constants == {
        "pkg.out.helpers:HELPER_NOTE": ["pkg.out.render:helper_note"],
        "pkg.out.render:HEADING": ["pkg.out.render:heading"],
        "pkg.out.render:Holder.title": [
            "pkg.out.render:via_annotated",
            "pkg.out.render:via_instance",
        ],
    }
    assert "pkg.out.render:PHRASES" not in listed.constants


def test_an_unreachable_wordy_function_and_its_constant_are_counted_not_listed(
    listed: pf.Listing,
) -> None:
    assert "pkg.out.render:orphan" not in listed.functions
    assert listed.unreachable == ["pkg.out.render:orphan"]
    assert "pkg.out.render:ORPHAN_NOTE" not in listed.constants
    document = listed.as_json()["unreachable_wordy_functions"]
    assert document["count"] == 1
    unreached = {p.holder: p.cls for p in listed.partition.literals if p.cls == "d"}
    assert sorted(unreached) == ["pkg.out.render:ORPHAN_NOTE", "pkg.out.render:orphan"]
    assert "class d, 2 wordy literal(s)" in listed.table()
    # A constant reached functions read only in a comparison is compared: it needs an entry.
    assert listed.compared_constants == ["pkg.out.render:PHRASES"]
    assert listed.needs_entry()["pkg.out.render:PHRASES"] == "constant"


def test_each_listed_function_names_its_groups_and_the_digest_of_its_words(
    listed: pf.Listing,
) -> None:
    rows = {row["function"]: row for row in listed.as_json()["functions"]}
    row = rows["pkg.out.render:by_call"]
    assert row["groups"] == ["render"]
    assert row["path"] == "src/pkg/out/render.py"
    assert row["text_digest"] == pf.text_digest(["reached by a call"])


def test_the_digest_covers_every_literal_handed_out_and_each_placeholder_form(
    listed: pf.Listing,
) -> None:
    assert listed.tree.functions["pkg.out.render:mixed"].texts == [
        "{value!r:>8} is the verdict",
        "Benign",
    ]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('return "Benign"', 'return "Malicious"'),
        ("{value!r:>8}", "{value:>8}"),
        ("{value!r:>8}", "{value!r}"),
        ("{value!r:>8}", "{other!r:>8}"),
        ("is the verdict", "is  the verdict"),
    ],
)
def test_any_change_of_the_wording_moves_the_digest(tmp_path: Path, old: str, new: str) -> None:
    before = listing(write_tree(tmp_path)).as_json()
    copy = dict(SOURCES)
    copy["pkg/out/render.py"] = copy["pkg/out/render.py"].replace(old, new)
    after = listing(write_tree(tmp_path, copy)).as_json()

    def digest(document: dict[str, Any]) -> str:
        rows = {row["function"]: row for row in document["functions"]}
        return str(rows["pkg.out.render:mixed"]["text_digest"])

    assert digest(before) != digest(after)


def test_the_digest_moves_when_a_placeholder_changes_or_two_swap() -> None:
    def digest(source: str) -> str:
        return pf.text_digest([pf.handed_text(ast.parse(source, mode="eval").body)])

    base = digest('f"{a} then {b} here"')
    assert digest('f"{a} then {b} here"') == base
    assert digest('f"{b} then {a} here"') != base
    assert digest('f"{c} then {b} here"') != base
    assert digest('f"{a.b} then {b} here"') != base


def _function_digest(root: Path, body: str) -> str:
    write_tree(root, {"pkg/__init__.py": "", "pkg/m.py": body})
    tree = pf.Tree(root, (("src", "pkg"),))
    return pf.text_digest(tree.functions["pkg.m:f"].texts)


@pytest.mark.parametrize(
    ("base", "changed"),
    [
        ('"%s came before %s" % (x, y)', '"%s came before %s" % (y, x)'),
        ('"%s came before %s" % (x, y)', '"%s came before %s" % (x, z)'),
        ('"{} came before {}".format(x, y)', '"{} came before {}".format(y, x)'),
        ('"{a} came before {b}".format(a=x, b=y)', '"{a} came before {b}".format(a=y, b=x)'),
        ('x + " came before " + y', 'y + " came before " + x'),
        ('x + " came before " + y', 'x + " came before " + z'),
        (
            't.format(x, y) if (t := "{} came before {}") else ""',
            't.format(y, x) if (t := "{} came before {}") else ""',
        ),
    ],
)
def test_the_digest_moves_when_the_arguments_of_a_format_or_a_concatenation_change(
    tmp_path: Path, base: str, changed: str
) -> None:
    def digest(expression: str, where: str) -> str:
        return _function_digest(tmp_path / where, f"def f(x, y, z):\n    return {expression}\n")

    assert digest(base, "a") == digest(base, "b")
    assert digest(base, "a") != digest(changed, "c")


def test_the_digest_moves_when_a_template_held_in_a_name_is_formatted_otherwise(
    tmp_path: Path,
) -> None:
    def digest(arguments: str, where: str) -> str:
        body = (
            "def f(x, y):\n"
            '    template = "{} came before {}"\n'
            f"    return template.format({arguments})\n"
        )
        return _function_digest(tmp_path / where, body)

    assert digest("x, y", "a") == digest("x, y", "b")
    assert digest("x, y", "a") != digest("y, x", "c")


def test_the_limit_lines_say_what_the_rule_does_not_list(listed: pf.Listing) -> None:
    lines = pf.limit_lines(listed)
    assert lines[0].startswith("limit: class d, 2 wordy literal(s)")
    assert "1 function(s) among them hand out wording" in lines[0]
    assert lines[1].startswith("limit: class e, 0 wordy literal(s)")
    assert lines[2].startswith("limit: class f, ")
    assert lines[3].startswith("limit: class g, 2 raise message(s)")


def test_a_missing_entry_point_is_refused(listed: pf.Listing) -> None:
    with pytest.raises(LookupError, match="pkg.out.render:gone"):
        pf.entry_points(listed.tree, {"render": ["pkg.out.render:gone"]}, {})


def test_the_list_is_the_same_under_two_hash_seeds(tmp_path: Path) -> None:
    write_tree(tmp_path)
    program = (
        "import json, sys; from pathlib import Path; "
        "from scripts.audit import publishing_functions as pf; "
        f"tree = pf.Tree(Path(sys.argv[1]), (('src', 'pkg'),)); "
        f"print(json.dumps(pf.compute(tree, {ENTRIES!r}).as_json(), sort_keys=True))"
    )
    outputs = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
        done = subprocess.run(
            [sys.executable, "-c", program, str(tmp_path)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            check=True,
        )
        outputs.append(done.stdout)
    assert outputs[0] == outputs[1]
    assert json.loads(outputs[0])["functions"]
