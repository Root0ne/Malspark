"""A comparison given its work folder creates nothing in the system's temporary directory.

The temporary directory is one of the test's own (``TMPDIR``, which both the
comparing process and each render inherit), so another process's entries
never meet the check. Its listing and its modification time are read before
and after a comparison of two refs given ``--work``: an entry made there is
seen even when it was removed again.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import platform_repository, stored_run


def _state(folder: Path) -> tuple[list[str], int]:
    return sorted(os.listdir(folder)), folder.stat().st_mtime_ns


@pytest.mark.slow
def test_a_comparison_given_its_work_folder_makes_no_entry_in_the_system_temp_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, first = platform_repository(tmp_path)
    run = stored_run(tmp_path)
    system = tmp_path / "system-temp"
    system.mkdir()
    monkeypatch.setenv("TMPDIR", str(system))
    monkeypatch.setattr(tempfile, "tempdir", None)
    assert Path(tempfile.gettempdir()) == system
    work = tmp_path / "work"
    before = _state(system)
    argv = [str(run), "--repo", str(repo), "--work", str(work), "--mode", "serve"]
    status = rs.main([*argv, "--compare", first, first, "--quiet", "--accept-not-compared"])
    assert status == 0
    assert _state(system) == before
    assert not [name for name in os.listdir(system) if name.startswith("malspark-surfaces")]
