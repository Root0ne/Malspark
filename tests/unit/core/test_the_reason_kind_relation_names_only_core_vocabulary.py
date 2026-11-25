"""The relation between an open question's reason and a request kind names only core vocabulary.

Each key is a reason of the closed set an analyst picks from, each value a
kind a built-in tool declares and the kind that files on the job's request
record; no key or value is a tool's, a server's, a sandbox's or an agent's
name. The question an analyst is put reads a held tool through that kind
alone: a tool of the kind under any name is read, a tool named like one that
declares nothing is not.
"""

from __future__ import annotations

from malspark.core import builtin_declarations as bd
from malspark.core.builtin_declarations import REQUEST_KIND_BY_OPEN_QUESTION_REASON
from malspark.providers.detonation_requests import REQUEST_KIND
from malspark.schemas.isr_models import OPEN_QUESTION_REASONS


def _built_in_kinds() -> set[str]:
    kinds: set[str] = set()
    for name, value in vars(bd).items():
        if not name.startswith("_") or not isinstance(value, dict):
            continue
        for facts in value.values():
            if isinstance(facts, dict) and isinstance(facts.get("kind"), str):
                kinds.add(facts["kind"])
    return kinds


def _built_in_tool_names() -> set[str]:
    names: set[str] = set()
    for name, value in vars(bd).items():
        if name.startswith("_") and isinstance(value, dict):
            names.update(str(key) for key in value)
    return names


def test_every_key_is_a_reason_of_the_closed_set() -> None:
    assert REQUEST_KIND_BY_OPEN_QUESTION_REASON
    assert set(REQUEST_KIND_BY_OPEN_QUESTION_REASON) <= set(OPEN_QUESTION_REASONS)


def test_every_value_is_a_declared_kind_that_files_on_the_request_record() -> None:
    kinds = _built_in_kinds()
    for kind in REQUEST_KIND_BY_OPEN_QUESTION_REASON.values():
        assert kind in kinds
        assert kind == REQUEST_KIND
        assert kind in bd.MOVING_KINDS


def test_it_names_no_tool() -> None:
    names = _built_in_tool_names()
    for reason, kind in REQUEST_KIND_BY_OPEN_QUESTION_REASON.items():
        assert reason not in names and kind not in names


def test_no_outward_submission_kind_is_in_it() -> None:
    assert not set(REQUEST_KIND_BY_OPEN_QUESTION_REASON.values()) & set(bd.OUTWARD_KINDS)
