"""A refused identifier with an empty or dots-only value gets no row in the full indicator list.

Such a value names nothing: its key under every kind's spelling is empty, and
an empty key would hold one slot for every value of that kind. The full list
leaves it out where it lists the refused identifier rows; the spelling every
lookup shares (``value_key``) is not touched, and any other refused value is
listed as before.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from malspark.reporting import builder, stated_host_values
from malspark.reporting.builder import full_ioc_list
from malspark.reporting.ledger_projection import value_key
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity

REFUSED = "no: not a name that resolves outside the analysed network"


def _stated(value: str, kind: str) -> SimpleNamespace:
    return SimpleNamespace(
        value=value, table_kind=kind, label=kind or "Install marker", written_kind=kind, held_in=()
    )


def _listed(monkeypatch: pytest.MonkeyPatch, *stated: SimpleNamespace) -> list[str]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        verdict="Malware",
    )
    monkeypatch.setattr(builder, "ioc_table", lambda _report: [])
    monkeypatch.setattr(
        stated_host_values, "identifier_answers", lambda _report: [(s, REFUSED) for s in stated]
    )
    return [row.value for row in full_ioc_list(report)]


@pytest.mark.parametrize("kind", ["domain", "folder", "url", ""])
@pytest.mark.parametrize("value", ["", "   ", ".", "...", " .. "])
def test_an_empty_or_dots_only_value_is_not_listed(
    monkeypatch: pytest.MonkeyPatch, kind: str, value: str
) -> None:
    assert _listed(monkeypatch, _stated(value, kind)) == []


def test_a_value_beside_it_is_listed_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    listed = _listed(
        monkeypatch, _stated("...", "domain"), _stated("a.b", "domain"), _stated(".x", "")
    )
    assert listed == ["a.b", ".x"]


@pytest.mark.parametrize(
    ("kind", "value", "key"),
    [("domain", "...", ""), ("path", "C:\\x\\.", "c:\\x\\"), ("ip", ".", ""), ("url", "", "")],
)
def test_the_shared_spelling_is_as_it_was(kind: str, value: str, key: str) -> None:
    assert value_key(kind, value) == key
