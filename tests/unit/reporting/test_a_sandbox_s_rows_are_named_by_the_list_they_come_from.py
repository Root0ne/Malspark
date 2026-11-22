"""A sandbox report's rows are counted under the name of the list each comes from (C49, C47).

The report's ``dynamic.file_operations`` holds the rows the projection reads from a sandbox's
dropped-files list (``operation`` ``write``) and from its mutex list (``operation``
``mutex``). The line that counts what a held sandbox report lists names each by that list: a
row of the dropped-files list is no file operation the record shows. A row of any other
operation is counted as the file-operation row it is recorded as.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    ProcessNode,
    SampleIdentity,
    SandboxSignature,
)
from malspark.reporting.renderers import MarkdownRenderer
from malspark.reporting.renderers.layout import ANALYST, BUNDLE
from malspark.reporting.renderers.markdown import _sandbox_held

ROOT = Path(__file__).resolve().parents[3]


def _report(rows: list[dict[str, Any]], *, network: bool = True) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        verdict="Malware",
        dynamic=DynamicBehavior(
            process_tree=[
                ProcessNode(pid=1, name="a.exe", children=[ProcessNode(pid=2, name="b")])
            ],
            sandbox_signatures=[SandboxSignature(name="sig")],
            file_operations=rows,
        ),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="a.example", source="sandbox")])
        if network
        else None,
    )


def _line(markdown: str, start: str) -> str:
    return next(line for line in markdown.splitlines() if line.startswith(start))


_DROPPED = {"operation": "write", "name": "4280-1-0x1000-memory.dmp", "path": ""}


def test_rows_of_the_dropped_files_list_are_named_so() -> None:
    report = _report([_DROPPED, {**_DROPPED, "name": "b.dmp"}])
    said = (
        "A sandbox report is held listing 2 processes, 1 signature and 2 rows of its "
        "dropped-files list, and the sandbox is the source of 1 network row."
    )
    assert said in MarkdownRenderer(layout=BUNDLE).render(report)
    assert said in MarkdownRenderer(layout=ANALYST).render(report)
    assert _line(MarkdownRenderer(layout=BUNDLE).render(report), "- Sandbox:") == (
        "- Sandbox: a report is held listing 2 processes, 1 signature and 2 rows of its "
        "dropped-files list; the source of 1 network row"
    )


def test_one_row_of_each_list_is_named_by_its_list() -> None:
    report = _report(
        [
            _DROPPED,
            {"operation": "mutex", "name": "Global\\gate"},
            {"operation": "delete", "path": "C:\\x.dat"},
        ]
    )
    assert _sandbox_held(report) == [
        "a report is held listing 2 processes, 1 signature, 1 row of its dropped-files list, "
        "1 mutex name and 1 file-operation row",
        "the source of 1 network row",
    ]


def test_several_rows_of_each_list() -> None:
    report = _report(
        [
            _DROPPED,
            _DROPPED,
            {"operation": "mutex", "name": "a"},
            {"operation": "mutex", "name": "b"},
            {"operation": "delete", "path": "C:\\x"},
            {"path": "C:\\y"},
        ],
        network=False,
    )
    assert _sandbox_held(report) == [
        "a report is held listing 2 processes, 1 signature, 2 rows of its dropped-files list, "
        "2 mutex names and 2 file-operation rows"
    ]


def test_a_report_listing_nothing_says_what_it_counted() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="ab" * 32), file_name="s.exe"),
        verdict="Malware",
        dynamic=DynamicBehavior(),
    )
    assert _sandbox_held(report) == [
        "a report is held listing no process, signature, dropped-files row, mutex name, "
        "file-operation row or registry row"
    ]


def test_no_model_reads_the_count() -> None:
    """The count is written by the report renderer only: no module of the pipeline, the
    agents, the prompts or the model-facing reporting code names it or the sandbox sentence."""
    readers = sorted(
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*.py")
        if "_sandbox_held" in (text := path.read_text(encoding="utf-8"))
        or "sandbox_sentence(" in text
    )
    assert readers == [
        "src/malspark/reporting/renderers/analyst.py",
        "src/malspark/reporting/renderers/markdown.py",
    ]
