"""One public function replays one run directory, and the command line uses it.

``scripts.replay.run.replay_run(run, show_text=...)`` replays one stored run
with the rules this process imports and returns its record. It digests every
file of the run before and after, fails when one changed, and writes nothing.
The private ``_replay`` of several runs and ``main`` go through it.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import run as replay_cli
from scripts.replay.stored import digests

from tests.unit.scripts._replay_tiny import EXPECTED_TOTALS, FIXTURE


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "tiny"
    shutil.copytree(FIXTURE, target)
    return target


class TestOnePublicReplay:
    def test_it_replays_a_run_directory_to_a_record_with_the_stored_digests(self) -> None:
        record = replay_cli.replay_run(FIXTURE)
        assert record["stored"] == {"files": digests(FIXTURE)}
        assert record["totals"] == EXPECTED_TOTALS

    def test_it_leaves_every_file_of_the_run_as_it_was(self, tmp_path: Path) -> None:
        run = _copy(tmp_path)
        before = digests(run)

        replay_cli.replay_run(run)

        assert digests(run) == before
        assert sorted(p.name for p in tmp_path.iterdir()) == ["tiny"]

    def test_it_leaves_no_temporary_directory_of_its_own_behind(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import tempfile

        made: list[Path] = []
        real = tempfile.mkdtemp

        def _recording(*args: Any, **kwargs: Any) -> str:
            path = real(*args, **kwargs)
            made.append(Path(path))
            return path

        monkeypatch.setattr(tempfile, "mkdtemp", _recording)

        replay_cli.replay_run(_copy(tmp_path))

        assert made and not any(path.exists() for path in made)

    def test_the_command_line_and_the_private_name_use_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        seen: list[tuple[Path, bool]] = []

        def _fake(run: Path, *, show_text: bool = False) -> dict[str, Any]:
            seen.append((run, show_text))
            return {"run": str(run), "stored": {"files": {}}}

        monkeypatch.setattr(replay_cli, "replay_run", _fake)

        assert replay_cli._replay([tmp_path, tmp_path / "b"], True) == [
            {"run": str(tmp_path), "stored": {"files": {}}},
            {"run": str(tmp_path / "b"), "stored": {"files": {}}},
        ]
        assert seen == [(tmp_path, True), (tmp_path / "b", True)]

    def test_a_run_changed_while_it_replays_fails_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from scripts.replay import rules
        from scripts.replay.stored import StoredRunChanged

        run = _copy(tmp_path)
        real = rules.replay_run

        def _touching(stored: Any, *, show_text: bool = False) -> dict[str, Any]:
            (run / "job.json").write_text("{}", encoding="utf-8")
            return real(stored, show_text=show_text)

        monkeypatch.setattr(rules, "replay_run", _touching)

        with pytest.raises(StoredRunChanged):
            replay_cli.replay_run(run)
