"""The surface render serves or names every route, and re-runs or names every report node function.

Both lists are read from the code, never kept by hand: every GET route of the
application's route table is a request the render serves or a route named
not rendered, and each query parameter of a served route is in a request it
serves or named; every function the report node names is called by the
modules the replay's build imports (``scripts.replay.rules`` and the replay
modules it imports, transitively), run by the render itself, or named not
rebuilt. A route or
a function added later fails here until it is rendered or named. What is
named is in the limits, the help and the docstring, and each name is one the
application serves or the report node's module holds.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import params
from scripts.replay import render_surfaces as rs

_ROOT = Path(__file__).resolve().parents[3]


def _build_modules() -> list[Path]:
    """``scripts/replay/rules.py`` and each ``scripts.replay`` module it imports, transitively."""
    found: list[Path] = []
    pending = ["scripts.replay.rules"]
    while pending:
        name = pending.pop()
        path = _ROOT / (name.replace(".", "/") + ".py")
        if not name.startswith("scripts.replay.") or path in found or not path.is_file():
            continue
        found.append(path)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                pending.append(node.module)
                pending += [f"{node.module}.{alias.name}" for alias in node.names]
            elif isinstance(node, ast.Import):
                pending += [alias.name for alias in node.names]
    return found


def test_the_build_s_modules_are_read_from_its_imports() -> None:
    names = {p.name for p in _build_modules()}
    assert {"rules.py", "stored.py", "guard.py"} <= names
    assert "limitation_inventory.py" not in names and Path(rs.__file__).name not in names


def _help(capsys: pytest.CaptureFixture[str]) -> str:
    with pytest.raises(SystemExit):
        rs.main(["--help"])
    return " ".join(capsys.readouterr().out.split())


@pytest.fixture(scope="module")
def routes() -> list[tuple[frozenset[str], str, Any]]:
    from app.main import create_app

    return rs.served_routes(create_app())


def _get_routes(routes: list[tuple[frozenset[str], str, Any]]) -> dict[str, Any]:
    return {rs.route_key(path): endpoint for methods, path, endpoint in routes if "GET" in methods}


def test_each_route_and_function_named_is_in_the_limits_the_help_and_the_doc(
    capsys: pytest.CaptureFixture[str],
) -> None:
    said = _help(capsys)
    limits = " ".join(rs.LIMITS)
    doc = " ".join(str(rs.__doc__).split())
    for name in (*rs.NOT_RENDERED, *rs.NOT_REBUILT):
        assert name in limits and name in said, name
    for name in rs.NOT_REBUILT:
        assert f"``{name}``" in doc, name


def test_every_get_route_of_the_application_is_served_or_named(
    routes: list[tuple[frozenset[str], str, Any]],
) -> None:
    served = {key for key, _values, _query in rs.REQUESTS.values()}
    unnamed = [
        path
        for path in _get_routes(routes)
        if path not in served and not rs.not_rendered_covers(path)
    ]
    assert unnamed == []


def test_every_query_parameter_of_a_served_route_is_asked_or_named(
    routes: list[tuple[frozenset[str], str, Any]],
) -> None:
    endpoints = _get_routes(routes)
    asked: dict[str, set[str]] = {}
    for key, _values, query in rs.REQUESTS.values():
        asked.setdefault(key, set()).update(name for name, _value in query)
    named = {
        (said.split("?", 1)[0], said.split("?", 1)[1].split("=", 1)[0])
        for said in rs.NOT_RENDERED
        if "?" in said
    }
    for key in asked:
        path_parameters = set(re.findall(r"\{(\w+)\}", key)) | {"report_id", "job_id"}
        for name, parameter in inspect.signature(endpoints[key]).parameters.items():
            if name in path_parameters or isinstance(parameter.default, params.Depends):
                continue
            assert name in asked[key] or (key, name) in named, (key, name)


def test_each_request_and_each_route_named_is_one_the_application_serves(
    routes: list[tuple[frozenset[str], str, Any]],
) -> None:
    served = _get_routes(routes)
    for key, _values, _query in rs.REQUESTS.values():
        assert key in served, key
    for said in rs.NOT_RENDERED:
        path = said.split("?", 1)[0].split(" ", 1)[0]
        if path.endswith("/*"):
            assert any(p == path[:-2] or p.startswith(path[:-1]) for p in served), said
        else:
            assert path in served, said
    assert rs.not_rendered_covers("/samples/{sample_id}/sandbox-reports")
    assert not rs.not_rendered_covers("/reports/{id}/markdown")
    # A kind no request asks is named; the route itself is served.
    assert "/reports/{id}/signatures/{kind} (a kind other than yara, sigma, suricata, snort)" in (
        rs.NOT_RENDERED
    )
    assert not rs.not_rendered_covers("/reports/{id}/signatures/{kind}")


def test_every_function_the_report_node_names_is_re_run_or_named() -> None:
    from malspark.pipeline import nodes

    stages = rs.report_node_stages(nodes)
    assert "_ask_section_agreement" in stages and "answer_questions" in stages
    replay = rs.code_names(_build_modules())
    unnamed = [
        name
        for name in stages
        if name not in replay and name not in rs.RERUN_BY_THE_RENDER and name not in rs.NOT_REBUILT
    ]
    assert unnamed == []


def test_each_function_named_is_the_platform_s_and_the_build_never_calls_it() -> None:
    from malspark.pipeline import nodes

    stages = set(rs.report_node_stages(nodes))
    replay = rs.code_names(_build_modules())
    for name in rs.NOT_REBUILT:
        assert name in stages or hasattr(nodes, name), name
        assert name not in replay, name
    own = Path(rs.__file__).read_text(encoding="utf-8")
    for name in rs.RERUN_BY_THE_RENDER:
        assert name in stages, name
        assert re.search(rf'entry\(\s*"platform\.[\w.]+",\s*"{name}"\s*\)', own), name
