"""capa's rules and signatures are fetched for the flare-capa version uv.lock pins.

The backend image's ``capa-data`` stage and the setup entry point's
``external`` (``scripts/dev/malspark_dev.py``) each name the version and two
sha256 digests: the rules archive's, recorded when it was pinned, and
flare-capa's sdist's, which is the digest uv.lock records for it. They agree
with uv.lock and with each other, both leave the rules' CI folder out, both
syncs of the image install the ``capa`` extra, and the image puts the two
directories where the settings point by default, with a workstation's own
copies kept out of it. The entry point checks each archive's digest, unpacks
it as ``tar --strip-components`` would under tarfile's ``data`` filter, and
never touches a directory already there; it says whether that is the pinned
version.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import re
import sys
import tarfile
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from malspark.core.config import StaticCapaConfig

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "Dockerfile.backend"
SETUP = ROOT / "scripts" / "dev" / "malspark_dev.py"
PINS = ("CAPA_VERSION", "CAPA_RULES_SHA256", "CAPA_SDIST_SHA256")


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("malspark_dev_capa_under_test", SETUP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dev = _load()


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _image_pins() -> dict[str, str]:
    return dict(re.findall(r"^ARG (CAPA_[A-Z0-9_]+)=(\S+)$", _text(DOCKERFILE), re.M))


def _locked_capa() -> tuple[str, str]:
    lock = tomllib.loads(_text(ROOT / "uv.lock"))
    (package,) = [p for p in lock["package"] if p["name"] == "flare-capa"]
    return str(package["version"]), str(package["sdist"]["hash"]).removeprefix("sha256:")


def test_the_image_fetches_for_the_locked_capa() -> None:
    version, sdist_digest = _locked_capa()
    pins = _image_pins()

    assert sorted(pins) == sorted(PINS)
    assert pins["CAPA_VERSION"] == version
    assert pins["CAPA_SDIST_SHA256"] == sdist_digest
    assert re.fullmatch(r"[0-9a-f]{64}", pins["CAPA_RULES_SHA256"])


def test_the_setup_entry_point_pins_what_the_image_pins() -> None:
    assert {name: getattr(dev, name) for name in PINS} == _image_pins()
    capa = dev.Capa()
    assert capa.rules_url.endswith(f"/refs/tags/v{dev.CAPA_VERSION}.tar.gz")
    assert capa.sdist_url.endswith(f"/flare_capa-{dev.CAPA_VERSION}.tar.gz")


def test_both_syncs_of_the_image_install_the_capa_extra() -> None:
    syncs = [line for line in _text(DOCKERFILE).splitlines() if line.startswith("RUN uv sync")]
    extras = [sorted(re.findall(r"--extra (\S+)", line)) for line in syncs]

    assert len(extras) == 2
    assert extras[0] == extras[1], "a second sync naming fewer extras prunes the others"
    assert "capa" in extras[0]


def test_the_image_puts_them_where_the_settings_point() -> None:
    defaults = StaticCapaConfig()
    copied = re.findall(r"^COPY --from=capa-data \S+ (\S+)$", _text(DOCKERFILE), re.M)
    kept_out = set(_text(ROOT / ".dockerignore").splitlines())
    untracked = set(_text(ROOT / ".gitignore").splitlines())

    assert copied == [defaults.rules_dir, defaults.signatures_dir]
    for directory in copied:
        assert f"{directory}/" in kept_out
        assert f"{directory}/" in untracked


def test_the_image_unpacks_the_rules_without_their_ci_folder() -> None:
    """capa skips the rules' .github workflows; the provider's count would not.

    The entry point's unpacking is run below, on an archive with that folder.
    """
    (unpack,) = [
        line
        for line in _text(DOCKERFILE).splitlines()
        if "tar -xzf" in line and "rules.tar.gz" in line
    ]
    assert "--exclude=.github" in unpack


def test_a_run_without_names_fetches_the_sigma_rules_and_capa_s_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[str] = []
    monkeypatch.setattr(dev, "fetch_sigma", lambda dest, url, ref: ran.append(f"sigma {ref}"))
    monkeypatch.setattr(dev, "fetch_capa", lambda layout, capa: ran.append("capa"))
    assert dev.fetch_external([], dev.Layout(tmp_path, tmp_path / "external"), targets=()) == 0
    assert ran == [f"sigma {dev.SIGMA_REF}", "capa"]


# The Sigma corpus rides the same way (T-556): the image's ``sigma-data``
# stage fetches the tag the setup entry point clones, checked by its digest,
# and puts it where the in-process pass and the analysis server read it.
SIGMA_PINS = ("SIGMA_REF", "SIGMA_ARCHIVE_SHA256")


def _sigma_image_pins() -> dict[str, str]:
    return dict(re.findall(r"^ARG (SIGMA_[A-Z0-9_]+)=(\S+)$", _text(DOCKERFILE), re.M))


def test_the_image_fetches_the_sigma_tag_setup_clones() -> None:
    from malspark.tools.rules import DEFAULT_SIGMA_RULES

    pins = _sigma_image_pins()

    assert sorted(pins) == sorted(SIGMA_PINS)
    assert pins["SIGMA_REF"] == dev.SIGMA_REF
    assert re.fullmatch(r"[0-9a-f]{64}", pins["SIGMA_ARCHIVE_SHA256"])
    stage = _text(DOCKERFILE).split("AS sigma-data", 1)[1].split("\nFROM ", 1)[0]
    assert "sha256sum -c -" in stage and "${SIGMA_ARCHIVE_SHA256}" in stage
    assert "refs/tags/${SIGMA_REF}.tar.gz" in stage
    copied = re.findall(r"^COPY --from=sigma-data \S+ (\S+)$", _text(DOCKERFILE), re.M)
    assert copied == [DEFAULT_SIGMA_RULES]
    assert f"{DEFAULT_SIGMA_RULES}/" in set(_text(ROOT / ".dockerignore").splitlines())
    assert f"{DEFAULT_SIGMA_RULES}/" in set(_text(ROOT / ".gitignore").splitlines())


def test_the_image_copies_the_fetched_corpora_after_the_context_s_data() -> None:
    """A later ``COPY data/`` would lay the context over the pinned corpora."""
    lines = _text(DOCKERFILE).splitlines()
    context = lines.index("COPY data/ data/")
    for stage in ("capa-data", "sigma-data"):
        at = [i for i, line in enumerate(lines) if line.startswith(f"COPY --from={stage} ")]
        assert at and min(at) > context


def test_docker_up_names_a_missing_fetched_corpus(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The compose stack mounts ./data over the image's, so the image's copies are not read."""
    assert dev.CORPORA == ("data/sigma_rules", "data/capa-rules", "data/capa-signatures")
    dev.warn_missing_corpora(tmp_path)
    warned = capsys.readouterr().err.splitlines()
    assert len(warned) == 3 and all("make external" in line for line in warned)
    assert "$(DEV) docker-up" in _text(ROOT / "Makefile").split("\ndocker-up:", 1)[1]


def _run_in(tree: Path, capa: Any = None) -> list[str]:
    """The fetch run in ``tree``: a directory already there is only said to be there."""
    import contextlib

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        dev.fetch_capa(dev.Layout(tree, tree / "external"), capa)
    return out.getvalue().splitlines()


def test_a_directory_already_there_is_said_to_be_pinned_or_not_and_left_alone(
    tmp_path: Path,
) -> None:
    pins = _image_pins()
    version = pins["CAPA_VERSION"]
    rules = tmp_path / "data" / "capa-rules"
    signatures = tmp_path / "data" / "capa-signatures"
    rules.mkdir(parents=True)
    signatures.mkdir()
    (rules / "a.yml").write_text("rule:\n", encoding="utf-8")
    (signatures / "PINNED.txt").write_text(
        f"flare-capa {version} sigs sha256:{pins['CAPA_SDIST_SHA256']}\n", encoding="utf-8"
    )

    said = _run_in(tmp_path)

    assert said == [
        f"  present  capa rules in data/, but not the pinned v{version}: left as they are",
        f"  ok       capa signatures v{version}",
    ]
    assert sorted(p.name for p in rules.iterdir()) == ["a.yml"]
    (rules / "PINNED.txt").write_text(
        f"capa-rules v{version} sha256:{pins['CAPA_RULES_SHA256']}\n", encoding="utf-8"
    )
    assert _run_in(tmp_path)[0] == f"  ok       capa rules v{version}"


# The two archives as the entry point meets them, built here: GitHub's archive
# of the rules' tag (one top directory, the CI folder inside) and flare-capa's
# sdist (sigs/ and the licence beside the package).
def _tarball(path: Path, members: dict[str, bytes]) -> str:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _archives(tmp_path: Path, rules: dict[str, bytes] | None = None) -> Any:
    source = tmp_path / "source"
    source.mkdir()
    rules_sha = _tarball(
        source / "rules.tar.gz",
        rules
        or {
            "capa-rules-9.9.9/LICENSE.txt": b"rules licence",
            "capa-rules-9.9.9/host/a.yml": b"rule: a",
            "capa-rules-9.9.9/.github/workflows/ci.yml": b"ci",
        },
    )
    sdist_sha = _tarball(
        source / "sdist.tar.gz",
        {
            "flare_capa-9.9.9/LICENSE.txt": b"capa licence",
            "flare_capa-9.9.9/sigs/1_flare_msvc.sig": b"sig one",
            "flare_capa-9.9.9/sigs/more/2.pat": b"sig two",
            "flare_capa-9.9.9/capa/main.py": b"code",
        },
    )
    return dev.Capa(
        version="9.9.9",
        rules_sha256=rules_sha,
        sdist_sha256=sdist_sha,
        rules_url=(source / "rules.tar.gz").as_uri(),
        sdist_url=(source / "sdist.tar.gz").as_uri(),
    )


def _files(directory: Path) -> dict[str, bytes]:
    return {
        p.relative_to(directory).as_posix(): p.read_bytes()
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def test_both_archives_are_checked_unpacked_and_pinned(tmp_path: Path) -> None:
    capa = _archives(tmp_path)
    said = _run_in(tmp_path, capa)

    assert said == [
        "  fetch    capa rules v9.9.9",
        "  fetch    capa signatures from flare-capa 9.9.9",
    ]
    assert _files(tmp_path / "data" / "capa-rules") == {
        "LICENSE.txt": b"rules licence",
        "PINNED.txt": f"capa-rules v9.9.9 sha256:{capa.rules_sha256}\n".encode(),
        "host/a.yml": b"rule: a",
    }
    assert _files(tmp_path / "data" / "capa-signatures") == {
        "1_flare_msvc.sig": b"sig one",
        "LICENSE.txt": b"capa licence",
        "PINNED.txt": f"flare-capa 9.9.9 sigs sha256:{capa.sdist_sha256}\n".encode(),
        "more/2.pat": b"sig two",
    }
    # Nothing of the unpacking is left beside them.
    assert sorted(p.name for p in (tmp_path / "data").iterdir()) == [
        "capa-rules",
        "capa-signatures",
    ]
    assert _run_in(tmp_path, capa) == [
        "  ok       capa rules v9.9.9",
        "  ok       capa signatures v9.9.9",
    ]


def test_an_archive_whose_digest_is_not_the_pin_leaves_no_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import dataclasses

    capa = dataclasses.replace(_archives(tmp_path), rules_sha256="0" * 64)
    with pytest.raises(dev.Stop) as stopped:
        _run_in(tmp_path, capa)

    assert stopped.value.status == 1
    assert "is not the pinned " + "0" * 64 in capsys.readouterr().err
    assert list((tmp_path / "data").iterdir()) == []


def test_a_member_that_would_land_outside_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capa = _archives(tmp_path, rules={"capa-rules-9.9.9/../../escaped.yml": b"rule: out"})
    with pytest.raises(dev.Stop):
        _run_in(tmp_path, capa)

    assert "FAIL" in capsys.readouterr().err
    assert not (tmp_path / "escaped.yml").exists()
    assert list((tmp_path / "data").iterdir()) == []
