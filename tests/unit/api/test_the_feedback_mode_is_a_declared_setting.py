"""``validation.feedback`` is a declared setting a profile document carries (T-672).

The catalogue declares it, the settings model refuses a value it does not
know, a settings document importing ``record_only`` is applied through the
same save every edit takes, and the mode reader returns what the run's
settings hold.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

KEY = "core.validation.feedback"
DOCUMENT = {"format": "malspark-settings/1", "values": {KEY: "record_only"}}


def _client() -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin
    from app.models.user import UserRole

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001", role=UserRole.ADMIN
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_the_catalogue_declares_the_setting_with_both_values() -> None:
    from app.services.settings_catalog_api import catalog_index

    entry = catalog_index()[KEY]
    assert entry.editable
    assert list(entry.choices or []) == ["feed_back", "record_only"]


def test_the_default_is_feed_back_and_a_profile_value_is_read() -> None:
    from malspark.core.settings_overrides import build_settings
    from malspark.pipeline.feedback_mode import feedback_mode, feeds_back

    default = build_settings({})
    assert default.validation.feedback == "feed_back"
    assert feeds_back(default)
    chosen = build_settings({"validation": {"feedback": "record_only"}})
    assert feedback_mode(chosen) == "record_only"
    assert not feeds_back(chosen)


def test_a_value_the_setting_does_not_know_is_refused() -> None:
    from pydantic import ValidationError

    from malspark.core.settings_overrides import build_settings

    with pytest.raises(ValidationError):
        build_settings({"validation": {"feedback": "sometimes"}})


def test_a_reader_handed_no_validation_block_reads_the_default() -> None:
    from malspark.pipeline.feedback_mode import feedback_mode

    assert feedback_mode(SimpleNamespace()) == "feed_back"


def test_a_settings_document_imports_record_only() -> None:
    from app.services.settings_service import SaveResult

    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=SaveResult([KEY], {"next_job": 1})),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()),
    ):
        r = _client().post("/api/v1/settings/import", json=DOCUMENT)
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == [KEY]
    assert save.call_args.args[0] == {KEY: "record_only"}


def test_the_saved_value_validates_as_the_save_validates_it() -> None:
    from app.services.settings_service import SettingsService, SettingsValidationError

    service = SettingsService(MagicMock())
    service.validate({"validation": {"feedback": "record_only"}}, {})
    with pytest.raises(SettingsValidationError) as refused:
        service.validate({"validation": {"feedback": "sometimes"}}, {})
    assert KEY in refused.value.errors
