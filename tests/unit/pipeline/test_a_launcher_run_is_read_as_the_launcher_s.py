"""A run whose arguments a generated launcher carried reads the launcher as the platform's.

The sandbox is handed an archive and runs its picked script, so its report
names the archive as its target and its process tree starts at the script
host. The report reader, given the launch record's generated names, keeps the
launcher's processes, flows, signatures and techniques out of the sample's,
and the sample's own in; the archive is the submitted archive, not another
target; a failed launcher submission still names the archive; "sent" is said
only once the submit call returned. Synthetic bytes only; nothing is run.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
from pathlib import Path
from typing import Any

import pytest

from malspark.analysis.disclosure import disclosure_lines, disclosure_record
from malspark.analysis.sample_integrity import sandbox_target_record, submitted_archive_of
from malspark.pipeline import sandbox_status as status
from malspark.providers.base import SandboxCapabilities
from malspark.providers.launcher import (
    BuiltLauncher,
    LauncherSupport,
    build_launcher_archive,
    launcher_answer,
)
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import sandbox_processes, sandbox_signatures
from malspark.schemas.sandbox_document import place, sandbox_document
from malspark.schemas.sandbox_report import (
    CTI_ANALYSED_KEY,
    FLOW_PROCESS_KEY,
    LAUNCHER_SIGNATURES_CHANNEL,
    LINEAGE_KEY,
    SAMPLE_TREE_KEY,
    SandboxReport,
    SandboxRun,
    attribute_the_launcher,
    sample_process_tree,
)
from tests.unit.pipeline.test_a_sandbox_naming_another_target_is_told import _app


def _pe() -> bytes:
    blob = bytearray(b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little"))
    blob += b"PE\0\0" + b"\x00" * 18 + (0x0102).to_bytes(2, "little")
    return bytes(blob + b"\x00" * 64)


PE = _pe()
INTAKE = hashlib.sha256(PE).hexdigest()
ARGS = "--key zq81-secret"
BUILT = build_launcher_archive(PE, "Evil.exe", ARGS)
LAUNCHER = BUILT.record
ARCHIVE = LAUNCHER["archive_sha256"]
TEMP = "C:\\Users\\admin\\AppData\\Local\\Temp\\unpack001"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def _overview(*extra_signatures: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": {"id": "s1", "target": "submission.zip", "sha256": ARCHIVE},
        "analysis": {"score": 8, "family": ["somefam"]},
        "signatures": [
            # Fires on the script host alone: the launcher's, not the sample's.
            {
                "name": "Command and Scripting Interpreter: PowerShell",
                "score": 5,
                "ttp": ["T1059.001"],
                "indicators": [{"procid": 1, "ioc": "powershell.exe -File launch.ps1"}],
            },
            # Fires on the sample's own process.
            {
                "name": "Modifies a Run key",
                "score": 8,
                "ttp": ["T1547.001"],
                "indicators": [{"procid": 2}],
            },
            # Seen in both: not the launcher's alone, so kept as it is.
            {
                "name": "Reads the system information",
                "score": 3,
                "ttp": ["T1082"],
                "indicators": [{"procid": 1}, {"procid": 3}],
            },
            *extra_signatures,
        ],
    }


def _task(*extra_processes: dict[str, Any]) -> dict[str, Any]:
    return {
        "processes": [
            {
                "procid": 1,
                "procid_parent": 0,
                "image": PS,
                "cmd": f'powershell.exe -ExecutionPolicy Bypass -File "{TEMP}\\launch.ps1"',
                # The sandbox's mark sits on the picked script's process.
                "orig": True,
            },
            {"procid": 4, "procid_parent": 1, "image": "C:\\Windows\\System32\\conhost.exe"},
            {
                "procid": 2,
                "procid_parent": 1,
                "image": f"{TEMP}\\sample.exe",
                "cmd": f'"{TEMP}\\sample.exe" {ARGS}',
            },
            {
                "procid": 3,
                "procid_parent": 2,
                "image": "C:\\Windows\\System32\\cmd.exe",
                "cmd": "cmd.exe /c whoami",
            },
            *extra_processes,
        ],
        "network": {
            "flows": [
                {"proto": "tcp", "dst": "203.0.113.5:443", "procid": 2},
                {"proto": "tcp", "dst": "198.51.100.7:80", "procid": 1},
                {"proto": "udp", "dst": "192.0.2.9:53", "procid": 3},
            ]
        },
    }


def _report(overview: dict[str, Any] | None = None, task: dict[str, Any] | None = None) -> Any:
    return required_reader("triage").read(
        overview or _overview(),
        provider="lab-box",
        task_id="s1",
        task_reports={"behavioral1": task or _task()},
    )


def _attributed(**kw: Any) -> SandboxReport:
    report = _report(**kw)
    attribute_the_launcher(report, LAUNCHER)
    return report


def _lineage(report: SandboxReport) -> dict[int, str]:
    return {p.pid: str(p.extra.get(LINEAGE_KEY) or "") for p in report.processes}


def _techniques(document: dict[str, Any]) -> set[str]:
    from malspark.providers.sandbox_tools import _signature_techniques

    found = set(document.get("ttp_tags") or [])
    for row in sandbox_signatures(document)["signatures"]:
        found.update(_signature_techniques(row))
    return found


class TestTheReaderKeepsTheLauncherApart:
    def test_the_launcher_s_processes_are_its_and_the_sample_s_are_rooted_at_sample_exe(
        self,
    ) -> None:
        assert _lineage(_attributed()) == {1: "launcher", 4: "launcher", 2: "sample", 3: "sample"}

    def test_flows_follow_the_sample_s_tree(self) -> None:
        report = _attributed()
        by_dst = {row["dst"]: row for row in (*report.network.tcp, *report.network.udp)}
        assert by_dst["203.0.113.5"][SAMPLE_TREE_KEY] is True
        assert by_dst["192.0.2.9"][SAMPLE_TREE_KEY] is True
        launcher_flow = by_dst["198.51.100.7"]
        assert launcher_flow[SAMPLE_TREE_KEY] is False
        assert launcher_flow[LINEAGE_KEY] == "launcher"
        assert launcher_flow[FLOW_PROCESS_KEY] == "powershell.exe"
        # Before: the sandbox's mark on the script host put every flow in the tree.
        unread = _report()
        assert all(row.get(SAMPLE_TREE_KEY) is True for row in unread.network.tcp)

    def test_a_signature_of_the_launcher_alone_is_kept_out_of_the_sample_s_channels(
        self,
    ) -> None:
        document = sandbox_document(_attributed())
        names = [s["name"] for s in sandbox_signatures(document)["signatures"]]
        assert names == ["Modifies a Run key", "Reads the system information"]
        techniques = _techniques(document)
        assert "T1059.001" not in techniques
        assert {"T1547.001", "T1082"} <= techniques
        # Still recorded, and marked as the launcher's.
        (moved,) = document["channels"][LAUNCHER_SIGNATURES_CHANNEL]
        assert moved["name"] == "Command and Scripting Interpreter: PowerShell"
        assert moved[LINEAGE_KEY] == "launcher" and moved["ttp_tags"] == ["T1059.001"]

    def test_the_process_view_never_marks_a_launcher_process_as_the_sample_s(self) -> None:
        rows = sandbox_processes(sandbox_document(_attributed()))["processes"]
        by_pid = {row["pid"]: row for row in rows}
        assert by_pid[1][LINEAGE_KEY] == "launcher" and "marked" not in by_pid[1]
        assert by_pid[4][LINEAGE_KEY] == "launcher" and "marked" not in by_pid[4]
        assert by_pid[2]["marked"] is True and by_pid[3]["marked"] is True
        # The rule every surface places a process by now roots the tree at the
        # sample, whatever name the job gave it.
        tree = sample_process_tree(rows, "Evil.exe", INTAKE)
        assert tree.pids == {"2", "3"}

    def test_the_score_and_family_are_stated_to_judge_the_archive(self) -> None:
        cti = sandbox_document(_attributed())["cti"]
        assert cti["score"] == 8 and cti["family"] == ["somefam"]
        assert "picked launcher script" in cti[CTI_ANALYSED_KEY]

    def test_powershell_the_sample_starts_is_the_sample_s(self) -> None:
        own = {
            "procid": 5,
            "procid_parent": 2,
            "image": PS,
            "cmd": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        }
        # Even one that names the launcher's file: the sample started it.
        named = {
            "procid": 6,
            "procid_parent": 2,
            "image": PS,
            "cmd": f'powershell.exe -File "{TEMP}\\launch.ps1"',
        }
        signature = {
            "name": "PowerShell started by the sample",
            "score": 6,
            "ttp": ["T1059.001"],
            "indicators": [{"procid": 5}, {"procid": 6}],
        }
        task = _task(own, named)
        task["network"]["flows"].append({"proto": "tcp", "dst": "203.0.113.77:8080", "procid": 5})
        report = _attributed(overview=_overview(signature), task=task)
        assert _lineage(report)[5] == "sample" and _lineage(report)[6] == "sample"
        document = sandbox_document(report)
        names = [s["name"] for s in sandbox_signatures(document)["signatures"]]
        assert "PowerShell started by the sample" in names
        assert "T1059.001" in _techniques(document)
        flow = next(r for r in report.network.tcp if r["dst"] == "203.0.113.77")
        assert flow[SAMPLE_TREE_KEY] is True

    def test_a_sample_that_never_started_leaves_nothing_the_sample_s(self) -> None:
        task = _task()
        task["processes"] = task["processes"][:2]
        report = _attributed(task=task)
        assert _lineage(report) == {1: "launcher", 4: "launcher"}
        by_dst = {row["dst"]: row for row in (*report.network.tcp, *report.network.udp)}
        assert by_dst["198.51.100.7"][SAMPLE_TREE_KEY] is False
        # A flow of a process the listing does not hold is attributed to no one.
        assert SAMPLE_TREE_KEY not in by_dst["203.0.113.5"]
        assert not any(row.get(SAMPLE_TREE_KEY) for row in by_dst.values())

    @pytest.mark.parametrize(
        "launcher",
        [None, {}, {"sample_member": "sample.exe"}, {**LAUNCHER, "script_host_images": []}],
    )
    def test_without_a_launcher_record_the_report_is_byte_identical(self, launcher: Any) -> None:
        report = _report()
        before = copy.deepcopy(sandbox_document(report))
        attribute_the_launcher(report, launcher)
        assert sandbox_document(report) == before


# ---------------------------------------------------------------------------
# Through the run: submission, fetch, the target and the failure paths
# ---------------------------------------------------------------------------
SUPPORT = LauncherSupport(script_types=("ps1",), picked_by="the pick field")


class _LauncherBox:
    """A sandbox that runs a picked script from an archive, as a launcher provider declares."""

    def __init__(self, *, fails: bool = False, host: str | None = "lab.example") -> None:
        self.id = "lab-box"
        self.fails, self.host = fails, host
        self.sent: list[BuiltLauncher] = []

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(can_submit=True, can_poll=True, launcher=SUPPORT)

    def submission_address(self) -> str | None:
        return self.host

    def launch_arguments_answer(self, arguments: str, *, sample_path: Any = None) -> Any:
        return launcher_answer(SUPPORT, arguments, sample_path)

    def submit(self, sample_path: str, **kwargs: Any) -> str:
        if self.fails:
            raise RuntimeError("the sandbox refused the request")
        self.sent.append(kwargs["options"].launcher)
        return "s1"

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def fetch(self, task_id: str) -> SandboxRun:
        overview = _overview()
        overview["sample"]["sha256"] = self.sent[-1].record["archive_sha256"]
        report = _report(overview=overview)
        return SandboxRun(task_id=task_id, report=report, raw=overview, status="reported")

    def signature_scale(self, run: Any, formats: Any = None) -> Any:
        return None


def _sample(tmp_path: Path) -> str:
    path = tmp_path / "Evil.exe"
    path.write_bytes(PE)
    return str(path)


class TestThroughTheRun:
    def test_the_archive_is_the_submitted_archive_not_another_target(self, tmp_path: Path) -> None:
        from app.worker.sample_integrity import sandbox_target_of

        box = _LauncherBox()
        app = _app(box)
        app.launch_arguments = ARGS
        document = asyncio.run(app._submit_to_sandbox(_sample(tmp_path)))
        assert document is not None
        record = app.container.launch_record
        # Built once, as the provider answered, and that archive was the one sent.
        (sent,) = box.sent
        assert sent.record["archive_sha256"] == record["launcher"]["archive_sha256"]
        assert app.container.sandbox_target_claim["sha256"] == sent.record["archive_sha256"]
        handed = app._mark_the_launch(app._tell_the_target(document, INTAKE))
        assert status.TARGET_KEY not in handed
        app.container.sample_sha256 = INTAKE
        assert sandbox_target_of(app.container) is None
        text = status.sandbox_status(handed).statement
        assert "names its target SHA-256 as" not in text
        assert "is the submitted archive holding the sample, not another target" in text
        assert "its analysis of the archive run from the picked launcher script" in text
        # The archive's file facts are never the sample's.
        assert status.names_another_target(handed) is True
        # And the run read the report with the launch record's names.
        processes = place(handed, "processes")
        lineage = {p["pid"]: p.get("extra", {}).get(LINEAGE_KEY) for p in processes}
        assert lineage == {1: "launcher", 4: "launcher", 2: "sample", 3: "sample"}

    def test_another_hash_is_still_another_target(self) -> None:
        other = "f" * 64
        record = {"launcher": {"archive_sha256": ARCHIVE}}
        assert sandbox_target_record(INTAKE, ARCHIVE, submitted_archive=ARCHIVE) is None
        assert sandbox_target_record(INTAKE, ARCHIVE.upper(), submitted_archive=ARCHIVE) is None
        assert sandbox_target_record(INTAKE, other, submitted_archive=ARCHIVE) is not None
        assert sandbox_target_record(INTAKE, ARCHIVE) is not None
        assert submitted_archive_of(record) == ARCHIVE
        assert submitted_archive_of(None) == "" and submitted_archive_of({}) == ""

    def test_a_failed_launcher_submission_still_names_the_archive(self, tmp_path: Path) -> None:
        app = _app(_LauncherBox(fails=True))
        app.launch_arguments = ARGS
        assert asyncio.run(app._submit_to_sandbox(_sample(tmp_path))) is None
        record = app.container.launch_record
        assert record["honoured"] is False and "may not have been sent" in record["note"]
        assert record["launcher"]["archive_sha256"]
        assert record["via"] == "a generated PowerShell launcher in the submitted archive"
        (upload,) = app.container.sample_uploads
        assert upload["launch_launcher"] == record["launcher"]
        lines = disclosure_lines(disclosure_record({}, uploads=[upload]))
        (line,) = [x for x in lines if x.startswith("Sample upload")]
        assert f"an archive (SHA-256 `{record['launcher']['archive_sha256']}`)" in line

    def test_sent_is_said_only_once_the_submit_call_returned(self, tmp_path: Path) -> None:
        # No upload row (a provider that names no host) and a submit that raised:
        # nothing says the arguments were sent.
        app = _app(_LauncherBox(fails=True, host=None))
        app.launch_arguments = ARGS
        assert asyncio.run(app._submit_to_sandbox(_sample(tmp_path))) is None
        assert app.container.sample_uploads == []
        record = app.container.launch_record
        assert record.get("sent") is not True
        reason = status.launch_arguments_reason(record) or ""
        assert "may not have been sent" in reason and "sent to" not in reason
