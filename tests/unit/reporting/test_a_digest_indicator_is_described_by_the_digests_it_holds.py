"""The indicator of the sample's similarity digests is described by the digests its pattern holds.

An import table's digest also matches files that share the sample's imports, a
fuzzy digest (ssdeep, TLSH) files that share most of its bytes. The description
names the kinds the pattern compares and says what each of them also matches;
a kind the run computed no digest of is not named (T-785).
"""

from __future__ import annotations

from typing import Any

import pytest

from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from malspark.schemas.stix_models import Bundle

SHA256 = "a" * 64
IMPHASH = "d" * 32
SSDEEP = "96:abcdefghijklmnop:qrstuvwx"
TLSH = "T1" + "0" * 70


def _similar(**hashes: str) -> dict[str, Any]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256, **hashes)),
        verdict="Malware",
        overall_confidence=0.9,
    )
    bundle = ExtendedSTIXRenderer().render(report, Bundle(objects=[]))
    (indicator,) = [
        o
        for o in bundle.model_dump(mode="json")["objects"]
        if o.get("type") == "indicator" and str(o.get("name", "")).startswith("Files like")
    ]
    return indicator


def _described(indicator: dict[str, Any]) -> str:
    """The description's own sentence, before the publish answer the export appends."""
    return str(indicator["description"]).split(" Published because:", 1)[0]


def test_an_import_table_digest_alone_is_described_as_that_digest() -> None:
    indicator = _similar(imphash=IMPHASH)

    assert "SSDEEP" not in indicator["pattern"] and "TLSH" not in indicator["pattern"]
    assert _described(indicator) == (
        "The sample's import-table digest (imphash); it also matches files that share its imports."
    )


def test_one_fuzzy_digest_alone_is_described_as_that_digest() -> None:
    indicator = _similar(ssdeep=SSDEEP)

    assert _described(indicator) == (
        "The sample's similarity digest (ssdeep); it also matches files that share most of "
        "its bytes."
    )


def test_every_kind_the_pattern_holds_is_named_with_what_it_also_matches() -> None:
    indicator = _similar(imphash=IMPHASH, ssdeep=SSDEEP, tlsh=TLSH)

    assert _described(indicator) == (
        "The sample's import-table digest (imphash) and similarity digests (ssdeep, TLSH); "
        "each also matches files that share its imports or most of its bytes."
    )


@pytest.mark.parametrize(
    "hashes",
    [{"imphash": IMPHASH}, {"ssdeep": SSDEEP}, {"tlsh": TLSH}, {"ssdeep": SSDEEP, "tlsh": TLSH}],
)
def test_the_description_names_no_kind_the_pattern_does_not_compare(
    hashes: dict[str, str],
) -> None:
    indicator = _similar(**hashes)
    pattern = indicator["pattern"].lower()

    for kind, said in (("imphash", "imphash"), ("ssdeep", "ssdeep"), ("tlsh", "tlsh")):
        assert (said in _described(indicator).lower()) == (kind in pattern)
