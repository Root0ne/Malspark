"""No surface asks the publish rule: each reads the row the IOC table built.

The rule is asked once per value, by the table's builder
(``builder.ioc_table``), and the row records the answer, its role and the type
an export carries it under. A surface that asked the rule again could ask it
with other arguments, which is how the export and the feed came to publish
different values for one run. This test reads the source.

What counts as the rule: the functions that answer for it (:data:`RULE`) and
every function of any module of the reporting package or the API app
(:data:`RULE_MODULES`) that names one of them, directly or through another such
function. A function that reaches the rule only through one an allowance names
(:data:`ALLOWED`: the table the builder builds, the identifier answers) reads
what the rule decided and is not the rule itself. A name is read as imported,
whatever alias it is imported under, and a name used under an alias is read as
the name it aliases.

How far it follows a call: from the export's methods through every function of
the export's own module they name, transitively; an imported function is not
followed into, it is judged by the set above. Every other surface module is
read whole. A surface may reach a function of the rule only where
:data:`ALLOWED` names it, with the reason.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPORTING = ROOT / "src" / "malspark" / "reporting"
EXPORT = REPORTING / "renderers" / "stix_renderer.py"

# The rule and the functions that answer for it.
RULE = frozenset(
    {
        "publish_answer",
        "indicator_publish_reason",
        "_evidence_reason",
        "judge_value_answer",
        "judge_indicator_rows",
        "withheld_by_the_verdict",
        "table_row_record",
        "publication_for",
        "published_url_hosts",
        "emulation_kwargs",
        "sandbox_host_kwargs",
        "bound_kwargs",
    }
)

# The modules whose functions can ask the rule: a function of one of them that
# names the rule, directly or through another, counts as the rule.
RULE_MODULES = tuple(
    sorted([*REPORTING.rglob("*.py"), *(ROOT / "apps" / "api" / "app").rglob("*.py")])
)

# Every other surface of a report's indicators: the Markdown, HTML and analyst
# reports, MISP, the rule drafts and the ``/iocs`` feed.
SURFACES = (
    REPORTING / "misp.py",
    REPORTING / "detection_signatures.py",
    REPORTING / "renderers" / "markdown.py",
    REPORTING / "renderers" / "html.py",
    REPORTING / "renderers" / "analyst.py",
    ROOT / "apps" / "api" / "app" / "services" / "report_service.py",
)

# What a surface may reach of the rule, one line each with the reason.
_THE_TABLE = "the table the builder builds once; reading it is reading the rows"
_IDENTIFIERS = (
    "the identifier table prints the answer for every identifier the analysis states, refused "
    "ones too, which the IOC table holds no row for; the builder records the same answer on the "
    "rows it publishes"
)
ALLOWED: dict[str, dict[str, str]] = {
    "stix_renderer.py": {"ioc_table": _THE_TABLE},
    "markdown.py": {"ioc_table": _THE_TABLE, "identifier_answers": _IDENTIFIERS},
    "analyst.py": {"identifier_answers": _IDENTIFIERS},
    "detection_signatures.py": {"build_consolidated_iocs": _THE_TABLE},
    "report_service.py": {
        "ioc_table": _THE_TABLE,
        "identity_rows": "the sample's own rows the table builds, for a stored table that will "
        "not read",
        "with_record": "the record the table gives each row, for those same rows",
    },
}


def _aliases(tree: ast.AST) -> dict[str, str]:
    """``{name used: name imported}`` for every ``import ... as`` and ``from ... import ... as``."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                imported = alias.name.rsplit(".", 1)[-1]
                out[alias.asname or imported] = imported
    return out


def _names(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Every name ``node`` reads or imports, an alias read as the name it imports."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(aliases.get(child.id, child.id))
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.alias):
            found.add(child.name.rsplit(".", 1)[-1])
            if child.asname:
                found.add(child.asname)
    return found


def _functions(tree: ast.Module) -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _allowed_anywhere(allowed: dict[str, dict[str, str]]) -> set[str]:
    return {name for names in allowed.values() for name in names}


def _asking(
    modules: Iterable[Path] = RULE_MODULES, allowed: dict[str, dict[str, str]] | None = None
) -> set[str]:
    """The rule and every function of the modules read that reaches it, not through an allowance."""
    through = _allowed_anywhere(ALLOWED if allowed is None else allowed)
    reads: dict[str, set[str]] = {}
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        aliases = _aliases(tree)
        for name, node in _functions(tree).items():
            reads.setdefault(name, set()).update(_names(node, aliases))

    def _closure(seed: set[str], blocked: set[str]) -> set[str]:
        asking = set(seed)
        while True:
            more = {name for name, read in reads.items() if (read & asking) - blocked} - asking
            if not more:
                return asking
            asking |= more

    # An allowed function that reaches the rule is the rule; a function that
    # reaches it only through one is not.
    reaching = _closure(set(RULE), set())
    return _closure(set(RULE) | (through & reaching), through)


def _export_reach() -> dict[str, set[str]]:
    """The export's methods and every function of its module they reach, with what each reads."""
    tree = ast.parse(EXPORT.read_text(encoding="utf-8"))
    aliases = _aliases(tree)
    functions = _functions(tree)
    (renderer,) = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ExtendedSTIXRenderer"
    ]
    reached: dict[str, set[str]] = {}
    queue = [
        (f"ExtendedSTIXRenderer.{m.name}", m)
        for m in renderer.body
        if isinstance(m, ast.FunctionDef)
    ]
    while queue:
        name, node = queue.pop()
        if name in reached:
            continue
        reached[name] = _names(node, aliases)
        for called in reached[name] & set(functions):
            queue.append((called, functions[called]))
    return reached


def _forbidden(path_name: str, names: set[str], asking: set[str]) -> set[str]:
    return (names & asking) - set(ALLOWED.get(path_name, {}))


def test_the_export_reaches_no_part_of_the_rule() -> None:
    asking = _asking()
    reached = _export_reach()

    assert "ExtendedSTIXRenderer._render" in reached
    found = {
        name: sorted(_forbidden(EXPORT.name, names, asking))
        for name, names in reached.items()
        if _forbidden(EXPORT.name, names, asking)
    }
    assert found == {}


def test_the_export_reads_the_table_the_builder_built() -> None:
    assert "ioc_table" in _export_reach()["ExtendedSTIXRenderer._render"]


def test_no_other_surface_reaches_the_rule() -> None:
    asking = _asking()
    for path in SURFACES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        named = _forbidden(path.name, _names(tree, _aliases(tree)), asking)
        assert not named, f"{path.name} reaches {sorted(named)}"


def test_an_alias_and_a_helper_that_asks_the_rule_are_the_rule(tmp_path: Path) -> None:
    """The two shapes a surface could reach the rule by and not name it."""
    asking = _asking()
    for source in (
        "from malspark.reporting.renderers.stix_renderer import publish_answer as _pa\n",
        "from malspark.reporting.builder import identity_rows as _ir\n",
    ):
        tree = ast.parse(source)
        assert _forbidden("misp.py", _names(tree, _aliases(tree)), asking), source


def _stale(allowed: dict[str, dict[str, str]]) -> list[tuple[str, str]]:
    """Each allowance that names no part of the rule, or that its surface does not read."""
    asking = _asking(allowed=allowed)
    out: list[tuple[str, str]] = []
    for path in (EXPORT, *SURFACES):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        read = _names(tree, _aliases(tree))
        for name in allowed.get(path.name, {}):
            if name not in asking or name not in read:
                out.append((path.name, name))
    return out


def test_every_allowance_is_a_part_of_the_rule_its_surface_reaches() -> None:
    assert _stale(ALLOWED) == []


def test_an_allowance_no_surface_uses_fails_the_guard() -> None:
    unused = {**ALLOWED, "misp.py": {"ioc_table": _THE_TABLE}}

    assert _stale(unused) == [("misp.py", "ioc_table")]


def test_a_helper_anywhere_in_the_reporting_package_or_the_api_app_is_read() -> None:
    every = {*REPORTING.rglob("*.py"), *(ROOT / "apps" / "api" / "app").rglob("*.py")}

    assert set(RULE_MODULES) == every


def test_a_helper_of_another_module_that_asks_the_rule_is_the_rule(tmp_path: Path) -> None:
    helper = tmp_path / "helper.py"
    helper.write_text(
        "from malspark.reporting.renderers.stix_renderer import publish_answer\n\n"
        "def answer_for(kind, value):\n    return publish_answer(kind, value, 'strings')\n",
        encoding="utf-8",
    )

    assert "answer_for" in _asking((*RULE_MODULES, helper))
