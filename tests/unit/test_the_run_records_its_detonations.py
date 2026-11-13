"""A finished run records each detonation's sandbox run (``run_summary.environment.detonations``).

For every detonation of the job — its own first and each one an agent asked
for — which it is, who asked, the launch text it asked for, the sandbox
provider, how it ended, and what the provider stated of the sandbox run while
the report was in hand: its identifiers, the guest, the sandbox's version,
start and end, whether the sample was run, and the SHA-256 and length of each
raw report part as it was read. The provider is asked through one method
(``SandboxProvider.detonation_facts``); one that does not answer it states
nothing, and what is not stated is "not reported". A job that asked no sandbox
records an empty list.

Every value here is made up for the test.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from malspark.analysis import run_environment
from malspark.analysis.run_environment import (
    ENVIRONMENT_VERSION,
    STATED_PARTS,
    STATED_TEXT_CHARS,
    detonations_record,
    environment_record,
)
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.core.config import Settings
from malspark.loaders.sandbox_client import report_part
from malspark.providers.base import SandboxProvider
from malspark.providers.detonation import (
    AGENT_ORIGIN,
    DetonationRecord,
    report_facts,
    stated_by,
)
from malspark.tools.capabilities import NOT_REPORTED
from tests.credential_shapes import prefixed_key

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "sandbox"
NR = NOT_REPORTED
# The analysis machine the CAPE fixture names.
CAPE_GUEST = {"name": "win10", "label": "win10", "platform": "windows", "manager": "KVM"}


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _facts(**over: Any) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "detonated": True,
        "task_ids": {"/info/id": "19159"},
        "guest": {"name": "win10", "platform": "windows"},
        "sandbox_version": "2.5",
        "started": "2026-08-13 13:06:05",
        "ended": "2026-08-13 13:09:06",
        "report_parts": [report_part("report", b"{}")],
    }
    facts.update(over)
    return facts


def _record(**over: Any) -> DetonationRecord:
    fields: dict[str, Any] = {
        "provider": "cape2",
        "task_id": "19159",
        "report": {"signatures": []},
        "sandbox_facts": _facts(),
    }
    fields.update(over)
    return DetonationRecord(**fields)


def _held(*records: DetonationRecord) -> Any:
    return SimpleNamespace(detonations=list(records))


# ---------------------------------------------------------------------------
# The record, from built detonations


class TestTheRecord:
    def test_one_detonation_is_one_row_of_every_fact(self) -> None:
        rows = detonations_record(_held(_record()))
        assert rows == [
            {
                "detonation": "d1",
                "origin": "job",
                "provider": "cape2",
                "task_id": "19159",
                "reported": True,
                "detonated": True,
                "task_ids": {"/info/id": "19159"},
                "guest": {"name": "win10", "platform": "windows"},
                "sandbox_version": "2.5",
                "started": "2026-08-13 13:06:05",
                "ended": "2026-08-13 13:09:06",
                "report_parts": [{"name": "report", "sha256": _sha(b"{}"), "bytes": 2}],
            }
        ]

    def test_three_detonations_with_their_launches_and_one_that_failed(self) -> None:
        first = _record()
        second = _record(
            ordinal=2,
            origin=AGENT_ORIGIN,
            arguments="--install /quiet",
            requested_by=[
                {"agent": "static", "cited_entries": ["ev_0003"]},
                {"agent": "network", "cited_entries": ["ev_0007"]},
            ],
            launch={"provider": "cape2", "arguments": "--install /quiet", "honoured": True},
            task_id="19160",
            sandbox_facts=_facts(task_ids={"/info/id": "19160"}),
        )
        third = _record(
            ordinal=3,
            origin=AGENT_ORIGIN,
            arguments="-k netsvcs",
            requested_by=[{"agent": "static", "cited_entries": ["ev_0009"]}],
            launch={
                "provider": "cape2",
                "arguments": "-k netsvcs",
                "honoured": False,
                "sent": True,
                "via": "options",
            },
            task_id="19161",
            report=None,
            failure="sandbox task 19161 ended with status 'failed_analysis'",
            sandbox_facts=None,
        )
        rows = detonations_record(_held(first, second, third))
        assert rows is not None
        assert [row["detonation"] for row in rows] == ["d1", "d2", "d3"]
        assert "launched_with" not in rows[0] and "requested_by" not in rows[0]
        assert rows[1]["origin"] == "agent"
        assert rows[1]["requested_by"] == ["static", "network"]
        assert rows[1]["launched_with"] == "--install /quiet"
        assert rows[1]["arguments_honoured"] is True
        assert rows[1]["task_ids"] == {"/info/id": "19160"}
        assert rows[2] == {
            "detonation": "d3",
            "origin": "agent",
            "requested_by": ["static"],
            "launched_with": "-k netsvcs",
            "arguments_honoured": False,
            "arguments_via": "options",
            "provider": "cape2",
            "task_id": "19161",
            "reported": False,
            "failure": "sandbox task 19161 ended with status 'failed_analysis'",
            "detonated": NR,
            "task_ids": NR,
            "guest": NR,
            "sandbox_version": NR,
            "started": NR,
            "ended": NR,
            "report_parts": [],
        }

    def test_a_provider_that_states_nothing_is_not_reported_throughout(self) -> None:
        (row,) = detonations_record(_held(_record(sandbox_facts={}))) or []
        for key in ("detonated", "task_ids", "guest", "sandbox_version", "started", "ended"):
            assert row[key] == NR, key
        # A report was read, and its parts were not stated: not "none read".
        assert row["report_parts"] == NR
        assert row["task_id"] == "19159" and row["reported"] is True

    def test_a_job_that_asked_no_sandbox_records_an_empty_list(self) -> None:
        # Mock mode or no sample file: the job's record holds no provider.
        assert detonations_record(_held(DetonationRecord())) == []
        assert detonations_record(_held()) == []
        assert detonations_record(SimpleNamespace()) is None

    def test_a_submission_that_failed_before_a_provider_was_chosen_is_recorded(self) -> None:
        failed = DetonationRecord(failure="the sample file to submit was not found")
        (row,) = detonations_record(_held(failed)) or []
        assert row["provider"] == NR and row["reported"] is False
        assert row["failure"] == "the sample file to submit was not found"
        assert row["report_parts"] == []

    def test_the_environment_carries_the_rows_and_its_version_moved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        record = environment_record(_held(_record()))
        assert ENVIRONMENT_VERSION == 3
        assert record == {"v": 3, "detonations": detonations_record(_held(_record()))}
        assert environment_record(_held()) == {"v": 3, "detonations": []}

    def test_an_unreadable_row_is_left_out_and_never_raises(self) -> None:
        class _Broken:
            provider = "cape2"

            @property
            def name(self) -> str:
                raise RuntimeError("broken")

        assert detonations_record(_held(_Broken(), _record())) == detonations_record(
            _held(_record())
        )


# ---------------------------------------------------------------------------
# A hostile launch text, and what no row may carry


HOSTILE = ("a\x00b\x1b[31m\r\n`|<x>{y}‮" * 400)[:5000]


class TestWhatARowCarries:
    def test_a_hostile_launch_text_is_kept_exactly_and_the_summary_holds(self) -> None:
        assert len(HOSTILE) == 5000
        record = _record(
            ordinal=2,
            origin=AGENT_ORIGIN,
            arguments=HOSTILE,
            requested_by=[{"agent": "static"}],
        )
        environment = {"v": ENVIRONMENT_VERSION, "detonations": detonations_record(_held(record))}
        summary = RunSummaryBuilder(start_time=0.0).set_environment(environment).build().to_dict()
        stored = json.loads(json.dumps(summary))
        assert stored["environment"]["detonations"][0]["launched_with"] == HOSTILE
        assert stored["environment"] == environment

    def test_no_credential_signed_url_or_host_path_survives_a_provider_s_words(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.core.paths import OUTSIDE_PROJECT

        key = prefixed_key("ghs_")
        home = str(Path.home())
        signed = f"https://operator:{key}@sandbox.example.org/r?token={key}&X-Amz-Signature={key}"
        facts = {
            "detonated": True,
            "task_ids": {"task": f"{signed}", "path": f"{home}/reports/19159.json"},
            "guest": {"image": f"/var/lib/sandbox/{key}.qcow2"},
            "sandbox_version": signed,
            "started": "x" * 5000,
            "ended": {"not": "a text"},
            "report_parts": [
                {"name": f"{home}/report.json", "sha256": "A" * 64, "bytes": 3},
                {"name": "no digest", "bytes": 3},
                {"name": "a negative length", "sha256": "0" * 64, "bytes": -1},
            ]
            + [{"name": f"p{n}", "sha256": "1" * 64, "bytes": n} for n in range(STATED_PARTS)],
            "url": signed,
        }
        record = _record(sandbox_facts=facts, failure=f"failed reading {home}/x/report.json")
        (row,) = detonations_record(_held(record)) or []
        text = json.dumps(row)
        assert key not in text
        assert home not in text
        assert "/var/lib/sandbox" not in text
        assert OUTSIDE_PROJECT in row["task_ids"]["path"]
        assert "url" not in row
        assert len(row["started"]) <= STATED_TEXT_CHARS
        assert row["ended"] == NR
        assert row["report_parts"][0]["sha256"] == "a" * 64
        assert [p["name"] for p in row["report_parts"][1:3]] == ["p0", "p1"]
        assert len(row["report_parts"]) == STATED_PARTS
        assert row["report_parts_cut"] == "1 more part(s) left out"


# ---------------------------------------------------------------------------
# The provider is asked through one method


class _PlugIn:
    """A plug-in provider written before the method: it states nothing."""

    id = "plugin"


class _Failing(_PlugIn):
    def detonation_facts(self, run: Any) -> dict[str, Any]:
        raise RuntimeError("cannot say")


class _OddAnswer(_PlugIn):
    def detonation_facts(self, run: Any) -> Any:
        return ["not", "a", "mapping"]


class TestTheQuestion:
    def test_a_plug_in_without_the_method_states_nothing(self) -> None:
        assert stated_by(_PlugIn(), object()) is None
        assert stated_by(_Failing(), object()) is None
        assert stated_by(_OddAnswer(), object()) is None

    def test_the_contract_s_default_states_nothing(self) -> None:
        assert SandboxProvider.detonation_facts(_PlugIn(), object()) is None  # type: ignore[arg-type]

    def test_a_plug_in_row_is_not_reported_beside_what_the_platform_knows(self) -> None:
        record = _record(provider="plugin", task_id="t-1", sandbox_facts=None)
        (row,) = detonations_record(_held(record)) or []
        assert row["provider"] == "plugin" and row["task_id"] == "t-1"
        assert row["reported"] is True
        for key in ("detonated", "task_ids", "guest", "sandbox_version", "started", "ended"):
            assert row[key] == NR, key
        assert row["report_parts"] == NR

    def test_no_provider_is_named_outside_its_own_module(self) -> None:
        """The recorder and the question name no provider: each states its own facts."""
        root = Path(run_environment.__file__).resolve().parents[1]
        modules = (root / "analysis" / "run_environment.py", root / "providers" / "detonation.py")
        for module in modules:
            text = module.read_text(encoding="utf-8")
            for name in ('"triage"', '"cape2"', '"mock"', '"upload"', '"rest"'):
                assert name not in text, (module.name, name)


# ---------------------------------------------------------------------------
# Each built-in provider states its run, with the parts as read


class TestEachBuiltInStatesItsRun:
    def test_cape_states_its_info_block_and_the_report_as_fetched(self) -> None:
        from malspark.loaders.cape2_client import CAPEv2Client
        from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider

        body = (FIX / "cape2_report.json").read_bytes()
        client = CAPEv2Client(base_url="http://cape.invalid:8000", api_token="t")
        client._http = httpx.Client(
            base_url="http://cape.invalid:8000",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body)),
        )
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        provider._client = client
        run = provider.fetch("19159")
        facts = stated_by(provider, run)
        assert facts == {
            "task_ids": {"/info/id": "19159"},
            "guest": CAPE_GUEST,
            "sandbox_version": "2.5",
            "started": "2026-08-13 13:06:05",
            "ended": "2026-08-13 13:09:06",
            "detonated": True,
            "report_parts": [{"name": "report", "sha256": _sha(body), "bytes": len(body)}],
        }

    def test_triage_states_its_overview_and_each_body_as_fetched(self) -> None:
        from tests.unit.providers.sandbox.test_triage_provider import _provider

        overview = (FIX / "triage_overview.json").read_bytes()
        task = (FIX / "triage_report_behavioral1.json").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, content=overview)
            return httpx.Response(200, content=task)

        provider = _provider(handler)
        facts = stated_by(provider, provider.fetch("260904-abcdefgh1"))
        assert facts == {
            "task_ids": {"/sample/id": "260904-abcdefgh1"},
            "guest": {"behavioral1": {"target": "win10"}},
            "ended": "2026-09-04T10:09:00Z",
            "detonated": True,
            "report_parts": [
                {"name": "overview", "sha256": _sha(overview), "bytes": len(overview)},
                {"name": "behavioral1", "sha256": _sha(task), "bytes": len(task)},
            ],
        }

    def test_the_rest_provider_states_the_report_as_fetched(self) -> None:
        from tests.unit.providers.sandbox.test_rest_provider import _cfg, _provider

        body = b'{"procs": [], "target": {"sha256": "ab"}}'
        provider = _provider(lambda request: httpx.Response(200, content=body), _cfg())
        facts = stated_by(provider, provider.fetch("T-9"))
        assert facts == {
            "detonated": True,
            "report_parts": [{"name": "report", "sha256": _sha(body), "bytes": len(body)}],
        }

    def test_the_mock_states_the_fixture_it_read_and_that_nothing_was_detonated(
        self, tmp_path: Path
    ) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        body = (FIX / "cape2_report.json").read_bytes()
        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / "s.json").write_bytes(body)
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        provider = MockSandboxProvider(str(tmp_path))
        facts = stated_by(provider, provider.fetch(provider.submit(str(sample))))
        assert facts is not None
        assert facts["detonated"] is False
        assert facts["report_parts"] == [
            {"name": "s.json", "sha256": _sha(body), "bytes": len(body)}
        ]
        assert facts["sandbox_version"] == "2.5"

    def test_the_mock_s_stand_in_was_read_from_nothing(self, tmp_path: Path) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        sample = tmp_path / "none.exe"
        sample.write_bytes(b"payload")
        provider = MockSandboxProvider(str(tmp_path))
        facts = stated_by(provider, provider.fetch(provider.submit(str(sample))))
        assert facts == {"detonated": False, "report_parts": []}

    def test_the_upload_provider_states_the_bytes_it_read_and_that_nothing_was_detonated(
        self,
    ) -> None:
        from malspark.providers.sandbox.upload import UploadSandboxProvider

        blob = (FIX / "cape2_report.json").read_bytes()
        provider = UploadSandboxProvider.from_settings(Settings(_env_file=None))
        provider.set_pending_blob(blob, filename="r.json")
        facts = stated_by(provider, provider.fetch("uploaded"))
        assert facts is not None
        assert facts["detonated"] is False
        assert facts["report_parts"] == [
            {"name": "report", "sha256": _sha(blob), "bytes": len(blob)}
        ]
        assert facts["task_ids"] == {"/info/id": "19159"}

    def test_a_run_built_without_parts_states_none(self) -> None:
        from tests.unit.test_sandbox_container import _stub_run

        assert report_facts(_stub_run(), detonated=True)["report_parts"] == []


# ---------------------------------------------------------------------------
# Through the real path: the job's detonation, made by the app


def _detonated(provider: Any, sample: Path) -> Any:
    import asyncio

    from malspark.app import MalsparkApp

    app = MalsparkApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    asyncio.run(app._submit_to_sandbox(str(sample)))
    return app.container


class TestThroughTheRun:
    def test_the_mock_sandbox_s_detonation_is_recorded_with_its_fixture(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        body = (FIX / "cape2_report.json").read_bytes()
        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / "s.json").write_bytes(body)
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")

        container = _detonated(MockSandboxProvider(str(tmp_path)), sample)
        record = environment_record(container)
        assert record is not None
        assert record["detonations"] == [
            {
                "detonation": "d1",
                "origin": "job",
                "provider": "mock",
                "task_id": "1",
                "reported": True,
                "detonated": False,
                "task_ids": {"/info/id": "19159"},
                "guest": CAPE_GUEST,
                "sandbox_version": "2.5",
                "started": "2026-08-13 13:06:05",
                "ended": "2026-08-13 13:09:06",
                "report_parts": [{"name": "s.json", "sha256": _sha(body), "bytes": len(body)}],
            }
        ]
        summary = RunSummaryBuilder(start_time=0.0).set_environment(record).build().to_dict()
        assert summary["environment"]["detonations"] == record["detonations"]

    def test_a_plug_in_through_the_run_is_recorded_as_not_reported(self, tmp_path: Path) -> None:
        from tests.unit.test_sandbox_container import _StubProvider

        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        container = _detonated(_StubProvider(), sample)
        (row,) = detonations_record(container) or []
        assert row["provider"] == "stub" and row["task_id"] == "42"
        assert row["reported"] is True
        assert row["detonated"] == NR and row["report_parts"] == NR

    def test_a_run_in_mock_mode_records_no_detonation(self, tmp_path: Path) -> None:
        import asyncio

        from malspark.app import MalsparkApp

        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        app = MalsparkApp(mock=True)
        asyncio.run(app._submit_to_sandbox(str(sample)))
        assert detonations_record(app.container) == []
