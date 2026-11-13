"""The worker hands a job's launch arguments to the run as the job carries them."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker import analysis_worker

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
ARGS = "--password hunter2 /S"


class TestTheWorker:
    @pytest.fixture(autouse=True)
    def _worker_dirs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        from unittest.mock import patch

        from app import config as api_config
        from app import runtime_config as rc
        from malspark.core.config import reset_settings_cache

        async def _mock_mode_allowed() -> dict[str, Any]:
            return {"api.mock_mode_allowed": True}

        monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed)
        api_config._settings = None
        with patch.dict(
            "os.environ",
            {
                "MALSPARK_MOCK_MODE": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ):
            yield
        api_config._settings = None
        reset_settings_cache()

    async def _launch_handed(self, config: dict[str, Any] | None) -> Any:
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.services import object_store

        def _download(_client: Any, _path: str, destination: str) -> None:
            Path(destination).write_bytes(BYTES)

        seen: dict[str, Any] = {}

        async def _arun(self_: Any, **_kwargs: Any) -> dict[str, Any]:
            seen["launch"] = _kwargs.get("launch_arguments")
            return {
                "final_decision": "Malware",
                "judge_report": "the judge answered",
                "malware_report": {"summary": {"verdict": "Malware"}},
                "isr_reports": {},
                "evidence_ledger": [],
            }

        job = fake_job(config=config)
        sample = fake_sample(job.sample_id, sha256=INTAKE)
        sample.file_size_bytes = len(BYTES)
        factory = SessionFactory(rows_for(job, sample))
        redis = MagicMock()
        for name in ("publish", "aclose", "set", "delete"):
            setattr(redis, name, AsyncMock())
        redis.get = AsyncMock(return_value=None)
        with (
            patch.object(object_store, "client", return_value=MagicMock()),
            patch.object(object_store, "download", side_effect=_download),
            patch("malspark.app.MalsparkApp.arun", new=_arun),
        ):
            result = await analysis_worker.run_analysis(
                {"redis": redis, "db_session": factory}, str(job.id)
            )
        assert result["status"] == "completed"
        return seen["launch"]

    @pytest.mark.asyncio
    async def test_the_job_s_arguments_reach_the_run_verbatim(self) -> None:
        assert await self._launch_handed({"sandbox_launch_arguments": ARGS}) == ARGS

    @pytest.mark.asyncio
    @pytest.mark.parametrize("config", [None, {}])
    async def test_without_them_the_run_is_handed_none(self, config: Any) -> None:
        assert await self._launch_handed(config) == ""
