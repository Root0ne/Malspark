"""The surface render names every route it does not render and every stage it does not run.

They are named in its limits, its help and its docstring.

Each route or variant named is one the API serves, and each stage named is
one the report node has and the replay's build never calls.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest
from scripts.replay import render_surfaces as rs

_ROOT = Path(__file__).resolve().parents[3]


def _help(capsys: pytest.CaptureFixture[str]) -> str:
    with pytest.raises(SystemExit):
        rs.main(["--help"])
    return " ".join(capsys.readouterr().out.split())


def test_each_route_and_stage_is_named_in_the_limits_the_help_and_the_doc(
    capsys: pytest.CaptureFixture[str],
) -> None:
    said = _help(capsys)
    limits = " ".join(rs.LIMITS)
    doc = " ".join(str(rs.__doc__).split())
    for name in (*rs.NOT_RENDERED, *rs.NOT_REBUILT):
        assert name in limits and name in said, name
    for name in rs.NOT_REBUILT:
        assert f"``{name}``" in doc, name


def test_each_route_named_is_one_the_api_serves() -> None:
    from app.api.v1 import jobs, reports

    served: dict[str, set[str]] = {}
    for route in [*reports.router.routes, *jobs.router.routes]:
        path = re.sub(r"\{(report|job)_id\}", "{id}", str(getattr(route, "path", "")))
        served[path] = set(inspect.signature(route.endpoint).parameters)
    for named in rs.NOT_RENDERED:
        path, _, query = named.partition("?")
        assert path in served, named
        parameter = query.split("=", 1)[0]
        assert not parameter or parameter in served[path], named


def test_each_stage_named_is_the_platform_s_and_the_build_never_calls_it() -> None:
    from malspark.pipeline import nodes

    replay = " ".join(
        p.read_text(encoding="utf-8")
        for p in (_ROOT / "scripts" / "replay").glob("*.py")
        if p.name != Path(rs.__file__).name
    )
    for name in rs.NOT_REBUILT:
        assert hasattr(nodes, name), name
        assert re.search(rf"\b{name}\b", replay) is None, name
