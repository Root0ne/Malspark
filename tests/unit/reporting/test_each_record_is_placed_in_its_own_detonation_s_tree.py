"""Each sandbox record is placed against the process tree of its own detonation.

The job's own detonation's processes are the report's process tree; each
further detonation's are a tree of their own (``detonation_trees``), with the
guest pids that detonation's answers state. A file, digest or mutex record
observed in a detonation is placed in that detonation's tree, never in
another's, where the same task and process id may name another process. In a
launched detonation the launcher is not the sample: the process view marks
only the sample's lineage, so a record of the launcher's process is placed
outside the sample's tree.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.detonations import platform_reads
from malspark.providers import sandbox_tools
from malspark.providers.detonation import DetonationRecord
from malspark.reporting.ledger_projection import dynamic_from_ledger
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    ProcessNode,
    SampleIdentity,
)
from malspark.reporting.renderers.stix_renderer import sandbox_host_kwargs
from malspark.schemas.evidence import LedgerEntry

SHA256 = "7" * 64
SAMPLE = "sample.exe"
HOST_IMAGE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
D2 = [{"detonation": "d2", "launched_with": "--key k"}]
FIRST_DIGEST = "1" * 64
SECOND_DIGEST = "2" * 64


def _job_tree() -> list[ProcessNode]:
    """The job's own detonation: the sample runs as process 10 of task t1."""
    return [ProcessNode(pid=10, name=f"C:\\t\\{SAMPLE}", task="t1")]


def _launched_tree() -> list[ProcessNode]:
    """A launched detonation: process 10 of task t1 is the launcher, 12 the sample it started."""
    sample = ProcessNode(pid=12, ppid=10, name=f"C:\\t\\{SAMPLE}", task="t1", marked=True)
    launcher = ProcessNode(
        pid=10,
        name=HOST_IMAGE,
        command_line=f"{HOST_IMAGE} -File C:\\t\\launch.ps1",
        task="t1",
        children=[sample],
    )
    return [launcher]


def _report(*records: dict[str, Any]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256), file_name=SAMPLE),
        verdict="Malware",
        overall_confidence=0.9,
        dynamic=DynamicBehavior(
            process_tree=_job_tree(),
            detonation_trees={"d2": _launched_tree()},
            file_operations=list(records),
        ),
        judge_indicators=[
            JudgeIndicator(kind="hash", value=FIRST_DIGEST),
            JudgeIndicator(kind="hash", value=SECOND_DIGEST),
        ],
    )


def _write(digest: str, pid: str, observed_in: list[dict[str, str]] | None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "operation": "write",
        "path": f"C:\\out\\{digest[:4]}.bin",
        "sha256": digest,
        "pids": [pid],
        "task": "t1",
    }
    if observed_in:
        record["observed_in"] = observed_in
    return record


class TestARecordIsPlacedInItsOwnDetonationSTree:
    def test_the_launcher_s_record_in_a_launched_detonation_is_not_the_sample_s(self) -> None:
        report = _report(_write(FIRST_DIGEST, "10", D2))
        said = sandbox_host_kwargs(report, "hash", FIRST_DIGEST)
        assert said.get("unattributed", "").startswith("the publish rule matched pid 10 of task t1")
        assert "outside the sample's process tree" in said["unattributed"]

    def test_the_sample_s_record_in_a_launched_detonation_is_the_sample_s(self) -> None:
        report = _report(_write(SECOND_DIGEST, "12", D2))
        said = sandbox_host_kwargs(report, "hash", SECOND_DIGEST)
        assert "unattributed" not in said
        assert said["kept_by"] == "the judge's indicator"

    def test_the_same_id_in_the_job_s_own_detonation_is_the_sample_s(self) -> None:
        report = _report(_write(FIRST_DIGEST, "10", None))
        assert "unattributed" not in sandbox_host_kwargs(report, "hash", FIRST_DIGEST)


ARGS = "--key k"
LAUNCHED_REPORT: dict[str, Any] = {
    "behavior": {
        "processes": [
            {"pid": 10, "process_name": "powershell.exe"},
            {"pid": 12, "ppid": 10, "process_name": SAMPLE},
        ]
    },
}
JOB_REPORT: dict[str, Any] = {"behavior": {"processes": [{"pid": 10, "process_name": SAMPLE}]}}


class _Container:
    event_sink = None
    detonations: list[Any] = []


def _ledger() -> list[LedgerEntry]:
    view = sandbox_tools.sandbox_processes(JOB_REPORT)
    ledger = [
        LedgerEntry(
            id="ev_0011",
            tool="sandbox_processes",
            agent="pipeline",
            output=json.dumps(view),
            structured=view,
        )
    ]
    record = DetonationRecord(
        ordinal=2,
        origin="agent",
        arguments=ARGS,
        report=LAUNCHED_REPORT,
        requested_by=[{"agent": "reversing", "cited_entries": ["ev_0001"]}],
    )
    return ledger + [
        LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")
    ]


class TestTheProjectionKeepsEachDetonationSProcessesApart:
    def test_a_further_detonation_s_processes_are_its_own_tree(self) -> None:
        dynamic = dynamic_from_ledger(_ledger())
        assert dynamic is not None
        assert [node.pid for node in dynamic.process_tree] == [10]
        assert dynamic.process_tree[0].children == []
        (root,) = dynamic.detonation_trees["d2"]
        assert root.pid == 10 and [child.pid for child in root.children] == [12]

    def test_a_run_with_one_detonation_dumps_no_further_tree(self) -> None:
        dynamic = dynamic_from_ledger(_ledger()[:1])
        assert dynamic is not None
        assert "detonation_trees" not in dynamic.model_dump()
