"""A process image the export writes is a file named by its base name in a directory object.

STIX 2.1 names a file by its last component and the folder it is in by a
``directory`` object its ``parent_directory_ref`` names; a consumer matching
``file:name`` on a whole path matches nothing. An image name that is wholly
one path is split there: the file carries the base name, the directory the
folder, and the file's id is derived from both, as the standard derives it, so
two images of one name in two folders are two files and one folder is one
object. A name that is not wholly one path (a path followed by arguments or a
note, a quoted path, a name with no folder) is written whole, as before.

The file model a judge's answer is read with is not touched: the id of a
judge's file is derived as it always was. Every reference of the export names
an object the export holds. The run comparison reads such a file as its folder
joined to its name, so a file written whole and the same file written in its
folder are one file, and two images of one name in two folders are two.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from stix2validator import ValidationOptions, validate_instance

from malspark.reporting.builder import MalwareReportBuilder
from malspark.reporting.dedupe import distinct_processes
from malspark.reporting.models import DynamicBehavior, MalwareReport, ProcessNode
from malspark.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    _processes_to_observables,
    image_path_parts,
    unresolved_references,
)
from malspark.reporting.run_diff import ADDED, REMOVED, UNCHANGED, RunRecord, diff_runs
from malspark.schemas.stix_models import SCO_NAMESPACE, File, json_canonical

SVCHOST = r"C:\Windows\system32\svchost.exe"


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        (SVCHOST, (r"C:\Windows\system32", "svchost.exe")),
        (r"C:\a.exe", ("C:\\", "a.exe")),
        (r"C:\Program Files\Vendor\a.exe", (r"C:\Program Files\Vendor", "a.exe")),
        ("/usr/bin/python3", ("/usr/bin", "python3")),
        ("C:/Users/a/b.exe", ("C:/Users/a", "b.exe")),
    ],
)
def test_a_name_wholly_one_path_is_its_folder_and_its_base_name(
    name: str, parts: tuple[str, str]
) -> None:
    assert image_path_parts(name) == parts


@pytest.mark.parametrize(
    "name",
    [
        # A path followed by arguments.
        r"C:\Windows\system32\svchost.exe -k GPSvcGroup",
        r"C:\Program Files\x\a.exe -k arg",
        r"C:\Windows\system32\rundll32.exe C:\Users\a\x.dll,#1",
        # A path followed by a note.
        r"C:\Windows\system32\rundll32.exe (cmdline: ...6091f2....dll,#1)",
        r"C:\Windows\system32\rundll32.exe (byte-identical cmdline, parent 83)",
        # An ordinal form and names with no folder.
        "2 (ordinal #1 load of the %TEMP% copy)",
        "SecurityHealthHost.exe (ambient)",
        "svchost.exe",
        # A quoted path with arguments, and a quoted path.
        '"C:\\Program Files\\x\\a.exe" -k arg',
        '"C:\\Program Files\\x\\a.exe"',
        # Separators of both kinds, a run of them, a folder that is no root.
        r"C:\Users/a\b.exe",
        r"C:\\Users\\a\\b.exe",
        r"%TEMP%\x.exe",
        r"Windows\system32\svchost.exe",
        r"\\?\C:\x\a.exe",
        r"\\server\share\a.exe",
        "",
        " C:\\x\\a.exe",
    ],
)
def test_a_name_that_is_not_wholly_one_path_is_left_whole(name: str) -> None:
    assert image_path_parts(name) is None
    roots = [ProcessNode(pid=1, name=name, command_line="x")] if name else []
    files = [o for o in _processes_to_observables(roots) if o.type == "file"]
    if name:
        (image,) = files
        assert image.name == name
        assert image.parent_directory_ref is None
        assert image.id == File(name=name).id


def _sco_id(kind: str, contributing: dict[str, Any]) -> str:
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, json_canonical(contributing))}"


def test_an_image_is_its_base_name_in_a_directory_object() -> None:
    root = ProcessNode(pid=1, name=SVCHOST, command_line="svchost.exe -k netsvcs")
    objects = _processes_to_observables([root])

    (directory,) = [o for o in objects if o.type == "directory"]
    (image,) = [o for o in objects if o.type == "file"]
    (process,) = [o for o in objects if o.type == "process"]
    assert directory.path == r"C:\Windows\system32"
    assert directory.id == _sco_id("directory", {"path": r"C:\Windows\system32"})
    assert image.name == "svchost.exe"
    assert image.parent_directory_ref == directory.id
    assert image.id == _sco_id(
        "file", {"name": "svchost.exe", "parent_directory_ref": directory.id}
    )
    assert process.image_ref == image.id
    # Each object stands after what it names.
    assert [o.type for o in objects] == ["directory", "file", "process"]


def test_two_images_of_one_name_in_two_folders_are_two_files_and_one_folder_is_one() -> None:
    tree = ProcessNode(
        pid=1,
        name=SVCHOST,
        command_line="a",
        children=[
            ProcessNode(pid=2, ppid=1, name=r"C:\Users\a\svchost.exe", command_line="b"),
            ProcessNode(pid=3, ppid=1, name=r"C:\Windows\system32\sihost.exe", command_line="c"),
            ProcessNode(pid=4, ppid=1, name=SVCHOST, command_line="d"),
        ],
    )
    objects = _processes_to_observables(distinct_processes([tree]))

    files = [o for o in objects if o.type == "file"]
    directories = {o.id: o.path for o in objects if o.type == "directory"}
    assert sorted((directories[f.parent_directory_ref], f.name) for f in files) == [
        (r"C:\Users\a", "svchost.exe"),
        (r"C:\Windows\system32", "sihost.exe"),
        (r"C:\Windows\system32", "svchost.exe"),
    ]
    assert len({f.id for f in files}) == 3
    assert sorted(directories.values()) == [r"C:\Users\a", r"C:\Windows\system32"]


def test_a_judge_s_file_keeps_the_id_it_was_always_derived_with() -> None:
    parent = _sco_id("directory", {"path": r"C:\x"})
    judge_file = File.model_validate(
        {"type": "file", "name": "a.exe", "parent_directory_ref": parent}
    )
    assert judge_file.id == _sco_id("file", {"name": "a.exe"})
    assert File(name=SVCHOST).id == _sco_id("file", {"name": SVCHOST})


def _report() -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash="ab" * 32,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()
    report.executive_summary = "A loader that starts a service host."
    report.dynamic = DynamicBehavior(
        process_tree=[
            ProcessNode(
                pid=100,
                name=r"C:\Users\Admin\AppData\Local\Temp\sample.exe",
                command_line="sample.exe -install",
                children=[
                    ProcessNode(pid=101, ppid=100, name=SVCHOST, command_line="svchost.exe"),
                    ProcessNode(
                        pid=102,
                        ppid=100,
                        name=SVCHOST + " -k GPSvcGroup",
                        command_line="svchost.exe -k GPSvcGroup",
                    ),
                ],
            )
        ]
    )
    return report


def _bundle() -> dict[str, Any]:
    return ExtendedSTIXRenderer().render(_report(), None).model_dump(mode="json")


def test_the_export_holds_the_directories_and_stays_valid() -> None:
    bundle = _bundle()
    result = validate_instance(bundle, ValidationOptions(version="2.1"))
    assert [str(e) for e in result.errors] == []
    directories = {o["id"]: o["path"] for o in bundle["objects"] if o["type"] == "directory"}
    assert sorted(directories.values()) == [
        r"C:\Users\Admin\AppData\Local\Temp",
        r"C:\Windows\system32",
    ]
    (observed,) = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert set(directories) <= set(observed["object_refs"])
    names = sorted(o["name"] for o in bundle["objects"] if o["type"] == "file")
    assert names == [SVCHOST + " -k GPSvcGroup", "sample.exe", "svchost.exe"]


def test_every_reference_of_the_export_names_an_object_it_holds() -> None:
    bundle = _bundle()
    assert unresolved_references(bundle["objects"]) == []


def test_a_reference_to_no_object_of_the_bundle_is_found() -> None:
    objects = [
        {"type": "file", "id": "file--1", "name": "a.exe", "parent_directory_ref": "directory--9"},
        {
            "type": "process",
            "id": "process--1",
            "image_ref": "file--1",
            "child_refs": ["process--8"],
        },
        {"type": "marking-definition", "id": "marking-definition--1"},
        {
            "type": "note",
            "id": "note--1",
            "object_refs": ["file--1"],
            "object_marking_refs": ["marking-definition--1"],
        },
    ]
    assert unresolved_references(objects) == [
        ("file--1", "parent_directory_ref", "directory--9"),
        ("process--1", "child_refs", "process--8"),
    ]


def _record(objects: list[dict[str, Any]]) -> RunRecord:
    return RunRecord(report_id="r", job_id="j", stix_bundle={"objects": objects})


def _stix(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> dict[str, Any]:
    (section,) = [s for s in diff_runs(_record(a), _record(b))["sections"] if s["key"] == "stix"]
    return section


def test_a_file_written_whole_and_written_in_its_folder_are_one_file_to_the_comparison() -> None:
    whole = [{"type": "file", "id": "file--a", "name": SVCHOST}]
    folder = {"type": "directory", "id": "directory--d", "path": r"C:\Windows\system32"}
    split = [
        folder,
        {
            "type": "file",
            "id": "file--b",
            "name": "svchost.exe",
            "parent_directory_ref": "directory--d",
        },
    ]

    section = _stix(whole, split)

    assert section["counts"][UNCHANGED] == 1
    assert section["counts"][ADDED] == section["counts"][REMOVED] == 0
    (row,) = section["rows"]
    assert row["key"] == f"file|name:{SVCHOST}"
    assert row["label"] == f"file: {SVCHOST}"
    assert row["b"]["name"] == SVCHOST


def test_two_images_of_one_name_in_two_folders_are_two_files_to_the_comparison() -> None:
    def split(path: str, oid: str) -> list[dict[str, Any]]:
        return [
            {"type": "directory", "id": f"directory--{oid}", "path": path},
            {
                "type": "file",
                "id": f"file--{oid}",
                "name": "svchost.exe",
                "parent_directory_ref": f"directory--{oid}",
            },
        ]

    a = split(r"C:\Windows\system32", "1") + split(r"C:\Users\a", "2")
    b = split(r"C:\Windows\system32", "3")

    section = _stix(a, b)

    assert section["counts"][UNCHANGED] == 1
    assert section["counts"][REMOVED] == 1
    (removed,) = [r for r in section["rows"] if r["status"] == REMOVED]
    assert removed["key"] == r"file|name:C:\Users\a\svchost.exe"
