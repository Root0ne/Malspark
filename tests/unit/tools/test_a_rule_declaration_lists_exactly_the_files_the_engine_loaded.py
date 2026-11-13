"""The YARA and Sigma declarations list exactly the files their engines loaded.

The engines read ``*.yml`` and ``*.yaml`` and nothing else; a name such as
``c.yara.html`` or ``d.y.xml`` loaded as a rule would change which rules run
and what the digest covers.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from malspark.tools import rules, sidecar_needs
from malspark.tools.capabilities import data_files, data_held


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    for name in ("a.yml", "b.yaml", "c.yara.html", "d.y.xml", "sub/f.yml"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("need", [sidecar_needs.SIGMA_RULES, sidecar_needs.YARA_RULES])
def test_only_yml_and_yaml_files_are_listed(need: object, corpus: Path) -> None:
    pattern = need.pattern  # type: ignore[attr-defined]
    assert [name for name, _ in data_files(corpus, pattern)] == ["a.yml", "b.yaml", "sub/f.yml"]


def test_a_directory_of_other_names_holds_no_rules(tmp_path: Path) -> None:
    (tmp_path / "c.yara.html").write_text("x", encoding="utf-8")
    assert not data_held(tmp_path, sidecar_needs.SIGMA_RULES.pattern)


def test_the_repository_s_sigma_folder_lists_what_the_engine_read_before() -> None:
    folder = Path(rules.DEFAULT_SIGMA_RULES)
    if not folder.is_dir():
        pytest.skip("the Sigma folder is not present")
    before = {*folder.rglob("*.yml"), *folder.rglob("*.yaml")}
    listed = {path for _, path in data_files(folder, sidecar_needs.SIGMA_RULES.pattern)}
    assert listed == {path for path in before if path.is_file()}
