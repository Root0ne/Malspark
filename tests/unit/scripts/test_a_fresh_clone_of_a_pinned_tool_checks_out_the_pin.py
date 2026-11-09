"""A fresh clone of a pinned external tree ends at the pin, whatever the default branch added.

A tool's default branch can add a ``.gitattributes`` with line-ending
normalisation while the pinned tag still holds CRLF files. A clone that checks
out the default branch first sees those files as modified and the checkout of
the pin stops. The setup entry point clones without a checkout, so that tree
is never written. Everything here is a local ``file://`` repository.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_clone_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()


@pytest.fixture(autouse=True)
def _own_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


# The developer's own git config (core.autocrlf, url.*.insteadOf) never reaches these runs.
_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        [
            "git",
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.com",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=cwd,
        env=_ENV,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _upstream(tmp_path: Path) -> Path:
    """A repo with CRLF files at tag v1 and a default branch that normalises them."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "setup.ps1").write_bytes(b"echo one\r\necho two\r\n")
    (repo / "gradlew.bat").write_bytes(b"@echo off\r\nexit\r\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "crlf files")
    _git(repo, "tag", "v1")
    # The default branch moves on in the same files, still CRLF, so they differ from the tag ...
    (repo / "setup.ps1").write_bytes(b"echo three\r\n")
    (repo / "gradlew.bat").write_bytes(b"@echo off\r\nexit 1\r\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "move on")
    # ... and then adds the rule, which makes those CRLF files look modified once checked out.
    (repo / ".gitattributes").write_text("* text eol=lf\n")
    _git(repo, "add", ".gitattributes")
    _git(repo, "commit", "--quiet", "-m", "normalise line endings")
    return repo


def _fetch(tmp_path: Path, url: str, ref: str) -> tuple[int, Path]:
    """The one target `tool` fetched from the local repo, with nothing else fetched."""
    tree = tmp_path / "tree"
    # Present and not checkouts: the corpora are said to be there, not fetched.
    for corpus in ("sigma_rules", "capa-rules", "capa-signatures"):
        (tree / "data" / corpus).mkdir(parents=True)
    status = dev.fetch_external([], dev.Layout.of(tree, {}), (dev.Target("tool", url, ref),))
    return status, tree


class TestAFreshCloneEndsAtThePin:
    def test_a_tag_whose_files_the_default_branch_normalises(self, tmp_path: Path) -> None:
        upstream = _upstream(tmp_path)
        status, tree = _fetch(tmp_path, upstream.as_uri(), "v1")
        assert status == 0
        dest = tree / "external" / "tool"
        assert _git(dest, "rev-parse", "HEAD") == _git(upstream, "rev-parse", "v1^{commit}")
        assert (dest / "setup.ps1").read_bytes() == b"echo one\r\necho two\r\n"
        assert not (dest / ".gitattributes").exists()

    def test_a_commit_sha_and_a_branch_are_checked_out_as_well(self, tmp_path: Path) -> None:
        upstream = _upstream(tmp_path)
        _git(upstream, "branch", "release", "v1")
        sha = _git(upstream, "rev-parse", "v1^{commit}")
        for number, ref in enumerate((sha, "release")):
            status, tree = _fetch(tmp_path / str(number), upstream.as_uri(), ref)
            assert status == 0
            assert _git(tree / "external" / "tool", "rev-parse", "HEAD") == sha
