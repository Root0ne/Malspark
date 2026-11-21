"""The isolation part says each copy's reading and a sandbox's other target in whole words.

``analysis.sample_integrity.integrity_lines`` says whether the copies of the
sample the platform handed out read as the intake SHA-256, and which did not,
when and why; ``sandbox_target_lines`` says a sandbox report named another
target. Each sentence is pinned whole here, by the record it is written from
(T-770), so a change of wording is a change this file sees.
"""

from __future__ import annotations

import hashlib

from malspark.analysis.sample_integrity import integrity_lines, sandbox_target_lines

INTAKE = hashlib.sha256(b"intake bytes").hexdigest()
OTHER = hashlib.sha256(b"other bytes").hexdigest()


def _code(text: str) -> str:
    return f"`{text}`"


def _reading(at: str, sha256: str = INTAKE, **kw: str) -> dict[str, str]:
    return {"copy": "download", "where": "", "at": at, "sha256": sha256, "error": "", **kw}


def test_copies_that_all_read_the_intake_digest_are_said_in_one_line_and_none_in_none() -> None:
    one = {"expected_sha256": INTAKE, "readings": [_reading("start")]}
    two = {
        "expected_sha256": INTAKE,
        "readings": [_reading("start"), _reading("end", copy="mirror", where="r2")],
    }

    assert integrity_lines(one, _code) == [
        "The sample the platform handed out (copy) was hashed when the job started, and every "
        f"reading was its intake SHA-256 `{INTAKE}`."
    ]
    assert integrity_lines(two, _code) == [
        "The sample the platform handed out (2 copies) was hashed when the job started and "
        f"when the run ended, and every reading was its intake SHA-256 `{INTAKE}`."
    ]
    # A part stored without readings says nothing.
    assert integrity_lines(None, _code) == []
    assert integrity_lines({"expected_sha256": INTAKE}, _code) == []
    assert integrity_lines({"expected_sha256": INTAKE, "readings": []}, _code) == []


def test_each_copy_that_did_not_read_the_intake_digest_is_said_with_when_and_why() -> None:
    record = {
        "expected_sha256": INTAKE,
        "readings": [
            _reading("start"),
            _reading("start", OTHER),
            _reading("end", OTHER, copy="mirror", where="r2", seen_at="2026-10-23T10:00:00+00:00"),
            {"copy": "mirror", "where": "", "at": "", "sha256": "", "error": ""},
            _reading("end", "", error="FileNotFoundError"),
        ],
    }

    assert integrity_lines(record, _code) == [
        f"A copy of the sample the platform handed out did not read as its intake SHA-256 "
        f"`{INTAKE}`. The run was not failed for it; which findings it touches is the "
        "analyst's call.",
        f"The worker's copy read `{OTHER}` when the job started.",
        f"The mirror in `r2` read `{OTHER}` when the run ended (2026-10-23T10:00:00+00:00).",
        "A mirror was not hashed at a time not recorded: no reason recorded.",
        "The worker's copy was not hashed when the run ended: FileNotFoundError.",
    ]


def test_a_sandbox_naming_another_target_is_said_by_what_it_named() -> None:
    tail = " The run was not failed for it; which findings it touches is the analyst's call."
    other = {"expected_sha256": INTAKE, "sandbox_sha256": OTHER}
    not_a_hash = {**other, "sandbox_sha256": "sample.exe", "sandbox_sha256_valid": False}
    empty = {**other, "sandbox_sha256": "", "sandbox_sha256_valid": False}

    assert sandbox_target_lines(other, _code) == [
        f"The sandbox report names its target SHA-256 as `{OTHER}`, not the sample's intake "
        f"SHA-256 `{INTAKE}`: what it observed may be of other bytes." + tail
    ]
    assert sandbox_target_lines({**not_a_hash, "provider": "cape2"}, _code) == [
        "The report of the sandbox `cape2` names its target with a value that is not a "
        "SHA-256, `sample.exe`, so what it observed cannot be tied to the sample's intake "
        f"SHA-256 `{INTAKE}`." + tail
    ]
    assert sandbox_target_lines({**empty, "provider": "cape2", "task_id": "7"}, _code) == [
        "The report of the sandbox `cape2` (task `7`) names its target with a value that holds "
        "no printable character, so what it observed cannot be tied to the sample's intake "
        f"SHA-256 `{INTAKE}`." + tail
    ]
    assert sandbox_target_lines({"sandbox_sha256": OTHER}, _code) == []
    assert sandbox_target_lines({"expected_sha256": INTAKE}, _code) == []
