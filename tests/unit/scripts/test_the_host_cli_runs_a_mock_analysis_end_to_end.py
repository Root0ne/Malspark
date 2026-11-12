"""The host command line runs a whole mock analysis, as a real process, on every platform.

``malspark analyze <file> --mock`` is the one entry point an operator reaches
without a container, a worker or a model. It is run here as a subprocess of
the interpreter that runs the tests, in an empty working directory, with no
provider key and a home of its own, and what it says and writes is read back:
exit code 0, no traceback, the report files it names, and every tool error the
run recorded in the platform's typed shape (``malspark.tools.errors``) and
never as an exception text. The platform's CI runs this file on Linux, macOS
and Windows, so a missing import or a subprocess the platform lacks that
crashes the run is found where it happens.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import malspark
from malspark.tools import errors

REPO = Path(__file__).resolve().parents[3]
# Only a key the run could use to reach a model or a service is removed; the
# rest of the environment (SYSTEMROOT on Windows, PATH) is what a run needs.
SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "MALSPARK_", "DATABASE", "REDIS")
CODES = {
    value for name, value in vars(errors).items() if name.isupper() and isinstance(value, str)
} & set(errors.REMEDIATIONS)


def _environment(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not any(m in k.upper() for m in SECRET_MARKERS)}
    for name in ("HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "XDG_CONFIG_HOME"):
        env[name] = str(home)
    # The process under test reads the same source tree as this one.
    source = str(Path(malspark.__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join([source, *filter(None, [env.get("PYTHONPATH")])])
    return env


def _git_state() -> str | None:
    try:
        done = subprocess.run(
            ["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _tool_errors(node: Any) -> list[Any]:
    """Every tool-error object in a parsed document: the value under an ``error`` key."""
    found: list[Any] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "error" and isinstance(value, dict) and "code" in value:
                found.append(value)
            found.extend(_tool_errors(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_tool_errors(item))
    return found


def test_the_mock_run_exits_clean_writes_its_reports_and_types_its_tool_errors(
    tmp_path: Path,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    sample = work / "sample.bin"
    sample.write_bytes(b"a harmless text file, not a program\n")
    before = _git_state()

    done = subprocess.run(
        [
            sys.executable, "-m", "malspark.cli", "analyze", "0" * 64,
            "--sample", str(sample), "--mock",
            "--report", str(work / "report.md"), "--output", str(work / "stix.json"),
        ],
        cwd=work,
        env=_environment(tmp_path),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )  # fmt: skip

    said = f"stdout:\n{done.stdout[-3000:]}\nstderr:\n{done.stderr[-3000:]}"
    assert done.returncode == 0, said
    assert "Traceback" not in done.stdout + done.stderr, said

    report = work / "report.md"
    assert report.read_text(encoding="utf-8").strip(), "the Markdown report is empty"
    documents = [json.loads(path.read_text(encoding="utf-8")) for path in work.glob("*.json")]
    assert {path.name for path in work.glob("*.json")} >= {"stix.json", "evidence-bundle.json"}
    assert (work / "evidence-bundle.html").read_text(encoding="utf-8").strip()

    for error in _tool_errors(documents):
        assert error["code"] in CODES, error
        assert isinstance(error.get("message"), str) and "Traceback" not in error["message"], error

    after = _git_state()
    assert before == after, "the run wrote into the repository"
