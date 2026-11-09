"""A pinned tree whose tag does not build as released is patched after the checkout, once.

``scripts/dev/patches/<name>-<ref>.patch`` is applied to the tree the setup
entry point checked out. A second run finds it in place and leaves the tree
alone; a patch that neither applies nor is in place stops the fetch, so an
image is never built from a tree that is neither the release nor the fixed
release. Named targets fetch only those trees, a target fetched only on
request waits to be named, and ``MALSPARK_EXTERNAL_DIR`` moves them.
Everything here is a local ``file://`` repository.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]
PATCHES = ROOT / "scripts" / "dev" / "patches"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

# The developer's own git config (core.autocrlf, url.*.insteadOf) never reaches these runs.
_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

_PATCH = """A note before the diff, as the shipped patches carry.

diff --git a/build.txt b/build.txt
--- a/build.txt
+++ b/build.txt
@@ -1,2 +1,2 @@
-version=1
+version=2
 name=tool
"""


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "malspark_dev_patch_under_test", ROOT / "scripts" / "dev" / "malspark_dev.py"
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


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", *args],
        cwd=cwd,
        env=_ENV,
        check=True,
        capture_output=True,
        text=True,
    )
    return done.stdout.strip()


def _upstream(tmp_path: Path, content: bytes = b"version=1\r\nname=tool\r\n") -> Path:
    """A repo whose tag v1 holds a CRLF file, as a release built on Windows does."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "build.txt").write_bytes(content)
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "release")
    _git(repo, "tag", "v1")
    return repo


def _tree(tmp_path: Path, url: str, patch: str | None = _PATCH) -> Path:
    """A checkout whose rule corpora are there already, so only the trees are fetched."""
    tree = tmp_path / "tree"
    (tree / "scripts" / "dev" / "patches").mkdir(parents=True)
    for corpus in ("sigma_rules", "capa-rules", "capa-signatures"):
        (tree / "data" / corpus).mkdir(parents=True)
    if patch is not None:
        (tree / "scripts" / "dev" / "patches" / "tool-v1.patch").write_text(patch, encoding="utf-8")
    (tree / "url").write_text(url, encoding="utf-8")
    return tree


@dataclass
class Done:
    returncode: int
    stdout: str
    stderr: str

    @property
    def reached_the_corpora(self) -> bool:
        return "capa rules" in self.stdout


Fetch = Callable[..., Done]


@pytest.fixture
def fetch(capfd: pytest.CaptureFixture[str]) -> Fetch:
    """The fetch of `tool` and `other` (fetched only when named) from the local repo."""

    def run(tree: Path, *names: str, env: dict[str, str] | None = None, ref: str = "v1") -> Done:
        url = (tree / "url").read_text(encoding="utf-8")
        targets = (dev.Target("tool", url, ref), dev.Target("other", url, ref, default=False))
        capfd.readouterr()
        status = dev.fetch_external(list(names), dev.Layout.of(tree, env or {}), targets)
        said = capfd.readouterr()
        return Done(status, said.out, said.err)

    return run


class TestThePatchIsAppliedOnce:
    def test_a_fresh_clone_is_patched_and_a_second_run_leaves_it(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        first = fetch(tree)
        assert first.returncode == 0, first.stderr
        assert "patch    tool tool-v1.patch" in first.stdout
        built = tree / "external" / "tool" / "build.txt"
        # Only the changed line takes the patch's ending; the rest of the CRLF file is kept.
        assert built.read_bytes() == b"version=2\nname=tool\r\n"

        second = fetch(tree)
        assert second.returncode == 0, second.stderr
        assert "ok       tool carries tool-v1.patch" in second.stdout
        assert built.read_bytes() == b"version=2\nname=tool\r\n"

    def test_a_tree_whose_line_endings_an_editor_changed_still_counts_as_patched(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        assert fetch(tree).returncode == 0
        built = tree / "external" / "tool" / "build.txt"
        built.write_bytes(built.read_bytes().replace(b"\r\n", b"\n"))
        again = fetch(tree)
        assert again.returncode == 0, again.stderr
        assert "carries tool-v1.patch" in again.stdout

    def test_a_tree_without_a_patch_is_only_checked_out(self, tmp_path: Path, fetch: Fetch) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri(), patch=None)
        done = fetch(tree)
        assert done.returncode == 0, done.stderr
        assert (
            tree / "external" / "tool" / "build.txt"
        ).read_bytes() == b"version=1\r\nname=tool\r\n"


class TestAPatchThatNoLongerFitsStopsTheFetch:
    def test_a_tag_the_patch_does_not_fit(self, tmp_path: Path, fetch: Fetch) -> None:
        upstream = _upstream(tmp_path, content=b"version=7\nname=tool\n")
        tree = _tree(tmp_path, upstream.as_uri())
        done = fetch(tree)
        assert done.returncode == 1
        assert "FAIL     tool: tool-v1.patch neither applies" in done.stderr
        assert not done.reached_the_corpora
        assert (tree / "external" / "tool" / "build.txt").read_bytes() == b"version=7\nname=tool\n"


class TestNamedTargetsAndAnotherDirectory:
    def test_a_named_target_fetches_that_tree_and_nothing_after_it(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        done = fetch(tree, "tool")
        assert done.returncode == 0, done.stderr
        assert (tree / "external" / "tool" / "build.txt").exists()
        assert not (tree / "external" / "other").exists()
        assert not done.reached_the_corpora

    def test_a_run_without_names_reaches_the_rule_corpora(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        done = fetch(tree)
        assert done.returncode == 0, done.stderr
        assert (tree / "external" / "tool").exists()
        assert done.reached_the_corpora

    def test_a_tree_fetched_on_request_waits_to_be_named(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        unnamed = fetch(tree)
        assert not (tree / "external" / "other").exists()
        assert "opt-in   other: fetched only when named" in unnamed.stdout
        named = fetch(tree, "other")
        assert named.returncode == 0, named.stderr
        assert (tree / "external" / "other" / "build.txt").exists()

    def test_the_trees_land_in_the_directory_the_variable_names(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        tree = _tree(tmp_path, _upstream(tmp_path).as_uri())
        elsewhere = tmp_path / "elsewhere"
        done = fetch(tree, "tool", env={"MALSPARK_EXTERNAL_DIR": str(elsewhere)})
        assert done.returncode == 0, done.stderr
        assert (elsewhere / "tool" / "build.txt").read_bytes() == b"version=2\nname=tool\r\n"
        assert not (tree / "external").exists()


class TestANewPin:
    def _upstream_with_v2(self, tmp_path: Path) -> Path:
        upstream = _upstream(tmp_path)
        (upstream / "build.txt").write_bytes(b"version=1b\r\nname=tool\r\n")
        _git(upstream, "commit", "--quiet", "-am", "next release")
        _git(upstream, "tag", "v2")
        return upstream

    def test_the_old_pin_s_patch_comes_off_before_the_checkout(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        upstream = self._upstream_with_v2(tmp_path)
        tree = _tree(tmp_path, upstream.as_uri())
        assert fetch(tree, "tool").returncode == 0

        done = fetch(tree, "tool", ref="v2")

        assert done.returncode == 0, done.stderr
        assert "unpatch  tool tool-v1.patch" in done.stdout
        dest = tree / "external" / "tool"
        assert _git(dest, "rev-parse", "HEAD") == _git(upstream, "rev-parse", "v2^{commit}")
        assert (dest / "build.txt").read_bytes() == b"version=1b\r\nname=tool\r\n"

    def test_only_the_patch_named_for_the_tree_s_ref_comes_off(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        """A patch named for another ref is left alone, even one that would come off."""
        upstream = self._upstream_with_v2(tmp_path)
        tree = _tree(tmp_path, upstream.as_uri())
        patches = tree / "scripts" / "dev" / "patches"
        assert fetch(tree, "tool").returncode == 0
        (patches / "tool-v0.patch").write_text(_PATCH, encoding="utf-8")

        done = fetch(tree, "tool", ref="v2")

        assert done.returncode == 0, done.stderr
        assert "unpatch  tool tool-v1.patch" in done.stdout
        assert "tool-v0.patch" not in done.stdout

    def test_a_patched_tree_an_editor_converted_moves_to_the_new_pin(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        upstream = self._upstream_with_v2(tmp_path)
        tree = _tree(tmp_path, upstream.as_uri())
        assert fetch(tree, "tool").returncode == 0
        built = tree / "external" / "tool" / "build.txt"
        built.write_bytes(built.read_bytes().replace(b"\r\n", b"\n"))

        done = fetch(tree, "tool", ref="v2")

        assert done.returncode == 0, done.stderr
        assert built.read_bytes() == b"version=1b\r\nname=tool\r\n"

    def test_a_local_change_in_the_way_stops_the_fetch_with_the_reason(
        self, tmp_path: Path, fetch: Fetch
    ) -> None:
        upstream = self._upstream_with_v2(tmp_path)
        tree = _tree(tmp_path, upstream.as_uri(), patch=None)
        assert fetch(tree, "tool").returncode == 0
        built = tree / "external" / "tool" / "build.txt"
        built.write_bytes(b"an operator's own edit\n")

        done = fetch(tree, ref="v2")

        assert done.returncode == 1
        assert "FAIL     tool: cannot check out v2; local changes" in done.stderr
        assert built.read_bytes() == b"an operator's own edit\n"
        assert not done.reached_the_corpora


def test_a_name_that_is_no_target_stops_the_fetch(tmp_path: Path, fetch: Fetch) -> None:
    tree = _tree(tmp_path, _upstream(tmp_path).as_uri())

    done = fetch(tree, "tool", "toll")

    assert done.returncode == 2
    assert "FAIL     no target named toll; the targets are: tool other" in done.stderr
    assert not (tree / "external").exists()


def test_every_shipped_patch_names_a_pinned_target() -> None:
    pins = {f"{target.name}-{target.ref}.patch" for target in dev.TARGETS}
    shipped = {path.name for path in PATCHES.glob("*.patch")}
    assert shipped, "no patch shipped"
    assert shipped <= pins, shipped - pins


def test_only_the_inference_engine_waits_to_be_named() -> None:
    assert [t.name for t in dev.TARGETS if not t.default] == ["ik_llama.cpp"]
