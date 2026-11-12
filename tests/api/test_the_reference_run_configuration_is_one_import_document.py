"""The benchmark run's configuration is one document the settings import takes as it is.

``docs/examples/profiles/all-tools-reference-run.json`` holds the all-tools
team (``all-tools.json``) and the model and effort of every agent the
benchmark run set (``core.llm.agents``). These send it through
``POST /api/v1/settings/import`` and the real ``SettingsService.save`` over a
fake database that holds the Qu1cksc0pe server the team names, then read the
models the saved settings give each agent: no model is called and nothing is
stored.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import settings_service as svc
from app.services.agent_map import AGENT_DEFINITIONS_KEY, AGENT_PROFILES_KEY
from malspark.core.model_assignments import assignments_for
from malspark.core.settings_catalog import (
    _SECRET_NAMES,
    _reads_as_a_credential,
    configured_secret_values,
)
from malspark.core.settings_overrides import build_settings
from tests.unit.test_the_published_benchmark_numbers_agree_with_one_another import (
    PAGE,
    stated_models,
)

PROFILES = Path(__file__).resolve().parents[2] / "docs" / "examples" / "profiles"
DOCUMENT = PROFILES / "all-tools-reference-run.json"
TEAM_DOCUMENT = PROFILES / "all-tools.json"
LLM_AGENTS_KEY = "core.llm.agents"
TEAM = "all_tools"

# What an operator's store holds before the import: the Qu1cksc0pe server the
# team names (the import refuses a reference to a server that does not exist).
# A stub command: the server is never started here.
SERVERS_KEY = "core.mcp.servers"
STORED_SERVERS = {
    "qu1cksc0pe": {
        "enabled": True,
        "transport": "stdio",
        "command": "qu1cksc0pe-mcp",
        "label": "Qu1cksc0pe",
    },
}


def _document() -> dict[str, Any]:
    return json.loads(DOCUMENT.read_text(encoding="utf-8"))


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db() -> MagicMock:
    from app.models import RuntimeSetting

    rows = [RuntimeSetting(key=SERVERS_KEY, value=STORED_SERVERS, is_secret=False)]
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _import(body: dict[str, Any]) -> tuple[int, dict[str, Any], MagicMock]:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    db = _db()
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        answer = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/settings/import", json=body
        )
    return answer.status_code, answer.json(), db


def _written(db: MagicMock) -> dict[str, Any]:
    """The rows the save added, by key."""
    return {call.args[0].key: call.args[0] for call in db.add.call_args_list}


def _holds(stored: Any, sent: Any) -> bool:
    """Whether ``stored`` carries every field of ``sent`` at its value, at any depth."""
    if isinstance(sent, dict):
        return isinstance(stored, dict) and all(
            key in stored and _holds(stored[key], value) for key, value in sent.items()
        )
    if isinstance(sent, list):
        return (
            isinstance(stored, list)
            and len(stored) == len(sent)
            and all(_holds(a, b) for a, b in zip(stored, sent, strict=True))
        )
    return bool(stored == sent)


def _team_agents(values: dict[str, Any]) -> dict[str, list[str]]:
    """The agents the team's stages name, by stage kind."""
    out: dict[str, list[str]] = {}
    for stage in values[AGENT_PROFILES_KEY][TEAM]["stages"]:
        out.setdefault(stage["kind"], []).extend(stage.get("agents", []))
    return out


def test_the_team_is_the_all_tools_team_as_it_ships() -> None:
    """Its team part is ``all-tools.json`` itself, so the two cannot drift."""
    document = _document()
    team = json.loads(TEAM_DOCUMENT.read_text(encoding="utf-8"))
    assert document["format"] == team["format"]
    assert set(document["values"]) == {*team["values"], LLM_AGENTS_KEY}
    for key in (AGENT_DEFINITIONS_KEY, AGENT_PROFILES_KEY):
        assert document["values"][key] == team["values"][key]


def test_it_imports_through_the_settings_import_unchanged() -> None:
    document = _document()
    status, body, db = _import(document)
    assert status == 200, body
    assert sorted(body["applied"]) == sorted(document["values"])
    assert body["warnings"] == {}
    db.commit.assert_awaited_once()
    written = _written(db)
    assert set(written) == set(document["values"])
    for key, row in written.items():
        # The save writes each agent and stage out with its defaults; every
        # field the document gives is stored as the document gives it.
        assert _holds(row.value, document["values"][key]), key
        assert row.is_secret is False, key


def test_the_import_gives_every_agent_the_model_and_effort_the_benchmark_page_states() -> None:
    document = _document()
    status, body, db = _import(document)
    assert status == 200, body
    stored = {SERVERS_KEY: STORED_SERVERS}
    stored.update({key: row.value for key, row in _written(db).items()})
    settings = build_settings({key.removeprefix("core."): value for key, value in stored.items()})
    stated = stated_models(PAGE.read_text(encoding="utf-8"), _team_agents(document["values"]))
    resulting = {
        assignment.agent: (assignment.model, assignment.effort)
        for assignment in assignments_for(settings, list(stated))
    }
    assert resulting == stated
    # Each stage agent of the team has its own entry, and nothing falls back.
    assert set(document["values"][LLM_AGENTS_KEY]) == set(stated)
    assert all(not entry.fallbacks for entry in settings.llm.agents.values())


def _keys_and_strings(value: Any) -> tuple[list[str], list[str]]:
    keys: list[str] = []
    strings: list[str] = []

    def _walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, inner in item.items():
                keys.append(str(key))
                _walk(inner)
        elif isinstance(item, list):
            for inner in item:
                _walk(inner)
        elif isinstance(item, str):
            strings.append(item)

    _walk(value)
    return keys, strings


def test_the_document_holds_no_credential_and_no_host_path() -> None:
    document = _document()
    # As the platform reads stored rows: a credential field or an entry whose
    # name names a credential (a stage's ``key`` is the stage's name).
    assert configured_secret_values(document["values"]) == set()
    keys, strings = _keys_and_strings(document)
    assert not set(keys) & _SECRET_NAMES
    words = [word for text in strings for word in text.split()]
    assert [word for word in words if _reads_as_a_credential(word)] == []
    for text in strings:
        assert not re.search(r"(?:^|\s)(?:/|~/|[A-Za-z]:\\)", text), text
        assert not re.search(r"://|localhost|\b\d{1,3}(?:\.\d{1,3}){3}\b", text), text


def test_the_settings_built_from_it_hold_no_secret_the_defaults_lack() -> None:
    document = _document()
    stored = {SERVERS_KEY: STORED_SERVERS, **document["values"]}
    settings = build_settings({key.removeprefix("core."): value for key, value in stored.items()})
    bare = build_settings({SERVERS_KEY.removeprefix("core."): STORED_SERVERS})
    assert configured_secret_values(settings) == configured_secret_values(bare)
