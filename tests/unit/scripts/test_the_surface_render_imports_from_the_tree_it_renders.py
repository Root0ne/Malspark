"""The surface render imports the platform, the API and the replay scripts from the tree it renders.

Run as a command with ``--out`` alone, the tree is this checkout: its root,
its ``src`` and its API come first on the import path, before any entry of
the environment (an editable install of another checkout, a directory on
``PYTHONPATH`` holding a package of the same name), and the record says each
was imported from it. A render whose packages came from elsewhere is refused
with status 2 and a sentence naming the package.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — this driver, an argument list only
import sys
from pathlib import Path

import pytest
from scripts.replay import render_surfaces as rs

from tests.unit.scripts._surfaces_render_run import stored_run

ROOT = Path(__file__).resolve().parents[3]
DRIVER = ROOT / "scripts" / "replay" / "render_surfaces.py"


@pytest.mark.slow
def test_the_command_imports_every_package_from_this_checkout(tmp_path: Path) -> None:
    # A package named as the API is, first on the environment's import path.
    decoy = tmp_path / "decoy"
    (decoy / "app").mkdir(parents=True)
    (decoy / "app" / "__init__.py").write_text("", encoding="utf-8")
    run = stored_run(tmp_path)
    out = tmp_path / "out"
    env = {k: v for k, v in os.environ.items() if k != rs.TREE_VARIABLE}
    env["PYTHONPATH"] = str(decoy)

    done = subprocess.run(  # nosec B603 — this driver, an argument list
        [sys.executable, str(DRIVER), str(run), "--out", str(out), "--mode=serve", "--quiet"],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=600,
    )

    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]
    [record] = json.loads((out / rs.RECORD_FILE).read_text(encoding="utf-8"))
    assert Path(record["tree"]) == ROOT
    for name in ("app", "scripts.replay"):
        assert ROOT in Path(record["imported_from"][name]).parents, name


def test_a_render_that_imported_a_package_from_elsewhere_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = str(tmp_path / "elsewhere" / "app")
    monkeypatch.setattr(rs, "imported_from", lambda: {"app": elsewhere, "scripts.replay": None})
    run = stored_run(tmp_path)

    with pytest.raises(SystemExit) as ended:
        rs.main([str(run), "--out", str(tmp_path / "out"), "--mode=serve", "--quiet"])

    assert ended.value.code == 2
    assert f"imported app from {elsewhere}" in capsys.readouterr().err
