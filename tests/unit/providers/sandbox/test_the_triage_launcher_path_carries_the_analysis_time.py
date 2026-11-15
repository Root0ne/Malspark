"""The analysis time reaches the hosted sandbox where the path taken reads it (T-701).

On a submission that names a ``profiles`` entry with a picked member (the
generated launcher's archive), Triage does not apply ``defaults.timeout`` and
runs its own default; a ``timeout`` inside a profile object embedded in that
entry is applied. So on the launcher path with no profile configured the time
is sent inside the pick entry's embedded profile, with ``defaults.timeout``
kept beside it; the plain path, a request with no time set and a request that
names a configured profile are sent as before, byte for byte. The statement of
how the time is sent names the fields of the path taken, and the record states
the time asked and the time granted on every path, so a shorter grant is said.

The live fixture ``triage_live_pick_with_profile_timeout`` is a public
sandbox's overview of a harmless archive (two text files and a PowerShell
script that starts cmd.exe) submitted on the launcher path with the time in
the embedded profile; ``triage_live`` holds the same archive's overview with
the time only in ``defaults``. Nothing here reaches a network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from malspark.analysis.run_environment import detonations_record
from malspark.core.config import Settings
from malspark.providers.detonation import stated_by
from malspark.providers.errors import ProviderError
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox.triage import TriageSandboxProvider
from malspark.providers.submission import SubmissionOptions
from tests.unit.providers.sandbox.test_submit_format_options import _form_fields

FIX = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"
EMBEDDED = FIX / "triage_live_pick_with_profile_timeout"
DEFAULTS_ONLY = FIX / "triage_live"
LAUNCH = SubmissionOptions(launch_arguments="-k 1")


def _pe() -> bytes:
    blob = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    blob += b"PE\0\0" + b"\x00" * 18 + (0x0102).to_bytes(2, "little")
    return bytes(blob + b"\x00" * 64)


def _triage(handler: Any, **over: Any) -> TriageSandboxProvider:
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "triage"
    cfg.sandbox.triage.api_token = SecretStr("not-a-real-token")
    for key, value in over.items():
        setattr(cfg.sandbox.triage, key, value)
    provider = TriageSandboxProvider.from_settings(cfg)
    provider._http = httpx.Client(
        base_url=cfg.sandbox.triage.base_url, transport=httpx.MockTransport(handler)
    )
    return provider


def _sent(tmp_path: Path, options: SubmissionOptions | None, **over: Any) -> str:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "s1"})

    sample = tmp_path / "s.exe"
    sample.write_bytes(_pe())
    assert _triage(handler, **over).submit(sample, options=options) == "s1"
    return _form_fields(seen[0])["_json"]


# ---------------------------------------------------------------------------
# The request on each path


# The bodies the base sends, byte for byte: every path but the launcher's with
# a time set and no profile configured is sent exactly so.
PLAIN = '{"kind": "file", "interactive": false}'
PLAIN_TIMED = '{"kind": "file", "interactive": false, "defaults": {"timeout": 600}}'
PLAIN_PROFILE = (
    '{"kind": "file", "interactive": false, "profiles": [{"profile": "win10", "pick": "default"}]}'
)
PLAIN_PROFILE_TIMED = (
    '{"kind": "file", "interactive": false, "profiles": [{"profile": "win10", "pick": "default"}],'
    ' "defaults": {"timeout": 600}}'
)
LAUNCHER = '{"kind": "file", "interactive": false, "profiles": [{"pick": "launch.ps1"}]}'
LAUNCHER_PROFILE = (
    '{"kind": "file", "interactive": false, "profiles": [{"profile": "win10", "pick": '
    '"launch.ps1"}]}'
)
LAUNCHER_PROFILE_TIMED = (
    '{"kind": "file", "interactive": false, "profiles": [{"profile": "win10", "pick": '
    '"launch.ps1"}], "defaults": {"timeout": 600}}'
)
# The shape the live check proved applied: the time in the pick entry's embedded
# profile, ``defaults`` kept beside it.
LAUNCHER_TIMED = (
    '{"kind": "file", "interactive": false, "profiles": [{"pick": "launch.ps1", "profile": '
    '{"timeout": 600}}], "defaults": {"timeout": 600}}'
)


class TestTheRequestOnEachPath:
    @pytest.mark.parametrize(
        ("options", "over", "body"),
        [
            pytest.param(None, {}, PLAIN, id="plain"),
            pytest.param(None, {"analysis_seconds": 600}, PLAIN_TIMED, id="plain-timed"),
            pytest.param(None, {"profile": "win10"}, PLAIN_PROFILE, id="plain-profile"),
            pytest.param(
                None,
                {"profile": "win10", "analysis_seconds": 600},
                PLAIN_PROFILE_TIMED,
                id="plain-profile-timed",
            ),
            pytest.param(LAUNCH, {}, LAUNCHER, id="launcher"),
            pytest.param(LAUNCH, {"profile": "win10"}, LAUNCHER_PROFILE, id="launcher-profile"),
            pytest.param(
                LAUNCH,
                {"profile": "win10", "analysis_seconds": 600},
                LAUNCHER_PROFILE_TIMED,
                id="launcher-profile-timed",
            ),
            pytest.param(
                LAUNCH,
                {"profile_by_format": {"*": "win10"}, "analysis_seconds": 600},
                LAUNCHER_PROFILE_TIMED,
                id="launcher-profile-by-format-timed",
            ),
            pytest.param(LAUNCH, {"analysis_seconds": 600}, LAUNCHER_TIMED, id="launcher-timed"),
        ],
    )
    def test_the_body_sent(
        self, tmp_path: Path, options: SubmissionOptions | None, over: dict[str, Any], body: str
    ) -> None:
        sent = _sent(tmp_path, options, **over)
        assert sent == body
        assert json.loads(sent) == json.loads(body)

    def test_the_launcher_s_time_is_the_whole_entry_the_live_check_sent(
        self, tmp_path: Path
    ) -> None:
        sent = json.loads(_sent(tmp_path, LAUNCH, analysis_seconds=600))
        assert sent == {
            "kind": "file",
            "interactive": False,
            "profiles": [{"pick": "launch.ps1", "profile": {"timeout": 600}}],
            "defaults": {"timeout": 600},
        }

    def test_a_fraction_is_sent_whole_in_both_places(self, tmp_path: Path) -> None:
        sent = json.loads(_sent(tmp_path, LAUNCH, analysis_seconds=420.9))
        assert sent["profiles"] == [{"pick": "launch.ps1", "profile": {"timeout": 420}}]
        assert sent["defaults"] == {"timeout": 420}


# ---------------------------------------------------------------------------
# The statement of how the time is sent


def _refused(tmp_path: Path, options: SubmissionOptions | None, **over: Any) -> str:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "INVALID_OPTIONS", "message": "no"})

    sample = tmp_path / "s.exe"
    sample.write_bytes(_pe())
    with pytest.raises(ProviderError) as refused:
        _triage(handler, **over).submit(sample, options=options)
    return str(refused.value)


class TestTheStatementNamesTheFieldsOfThePathTaken:
    def test_the_launcher_path_names_the_embedded_profile_and_defaults(
        self, tmp_path: Path
    ) -> None:
        said = _refused(tmp_path, LAUNCH, analysis_seconds=600)
        assert said.endswith(
            "(sent profiles[0].profile.timeout=600 and defaults.timeout=600 from "
            "sandbox.triage.analysis_seconds)"
        )

    @pytest.mark.parametrize(
        ("options", "over"),
        [
            (None, {}),
            (None, {"profile": "win10"}),
            (LAUNCH, {"profile": "win10"}),
        ],
    )
    def test_every_other_path_names_defaults(
        self, tmp_path: Path, options: SubmissionOptions | None, over: dict[str, Any]
    ) -> None:
        said = _refused(tmp_path, options, analysis_seconds=600, **over)
        assert said.endswith("(sent defaults.timeout=600 from sandbox.triage.analysis_seconds)")

    @pytest.mark.parametrize("options", [None, LAUNCH])
    def test_no_time_set_states_none(self, tmp_path: Path, options: Any) -> None:
        said = _refused(tmp_path, options)
        assert "timeout" not in said and "(sent" not in said


# ---------------------------------------------------------------------------
# The record on every path


def _overview(folder: Path) -> dict[str, Any]:
    return json.loads((folder / "overview.json").read_text())


def _limitations(facts: dict[str, Any]) -> list[str]:
    from malspark.reporting.limitation_inventory import build_inventory, printed_rows
    from tests.unit.test_the_detonation_states_the_analysis_time_the_sandbox_gave import (
        _record,
        _report,
    )

    (row,) = detonations_record(SimpleNamespace(detonations=[_record(facts)])) or []
    inventory = build_inventory(_report(row), [])
    return [r.text for r in printed_rows(inventory) if r.part == "sandbox"]


class TestTheRecordOnEveryPath:
    def test_the_time_in_the_embedded_profile_was_granted_and_no_limitation_is_said(
        self,
    ) -> None:
        facts = required_reader("triage").run_facts(_overview(EMBEDDED))
        assert facts["granted_seconds"] == {"behavioral1": 600, "behavioral2": 600}
        facts["requested_seconds"] = 600
        assert _limitations(facts) == []

    def test_the_time_only_in_defaults_was_not_and_the_limitation_says_so(self) -> None:
        facts = required_reader("triage").run_facts(_overview(DEFAULTS_ONLY))
        facts["requested_seconds"] = 600
        (text,) = _limitations(facts)
        assert (
            "d1's tasks behavioral1 and behavioral2 were given 150 s, not the 600 s asked" in text
        )

    @pytest.mark.parametrize(
        ("options", "over"),
        [
            pytest.param(None, {}, id="plain"),
            pytest.param(LAUNCH, {}, id="launcher"),
            pytest.param(LAUNCH, {"profile": "win10"}, id="launcher-profile"),
            pytest.param(None, {"profile": "win10"}, id="plain-profile"),
        ],
    )
    def test_a_posted_submission_states_the_time_asked_and_a_shorter_grant_is_said(
        self, tmp_path: Path, options: SubmissionOptions | None, over: dict[str, Any]
    ) -> None:
        overview = (DEFAULTS_ONLY / "overview.json").read_bytes()
        tasks = {
            name: (DEFAULTS_ONLY / f"{name}.json").read_bytes()
            for name in ("behavioral1", "behavioral2")
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(200, json={"id": "261114-x2ds4scy5t"})
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, content=overview)
            for name, body in tasks.items():
                if f"/{name}/" in request.url.path:
                    return httpx.Response(200, content=body)
            return httpx.Response(404)

        provider = _triage(handler, analysis_seconds=600, **over)
        provider._sleep = lambda _s: None
        provider._now_utc = lambda: datetime(2026, 11, 14, 19, 25, 0, tzinfo=UTC)
        sample = tmp_path / "s.exe"
        sample.write_bytes(_pe())
        sample_id = provider.submit(sample, options=options)
        facts = stated_by(provider, provider.fetch(sample_id)) or {}
        assert facts["requested_seconds"] == 600
        (text,) = _limitations(facts)
        assert "were given 150 s, not the 600 s asked" in text
