"""A device or pipe path the network block holds as a name is not exported as a domain (T-761).

A typed cell or a string the network block keeps as a domain because it holds
a dot can be a path of the analysed machine's device namespace
(``\\\\.\\pipe\\<name>``). Nothing in the run reads such a value as a host, so
it is a form row (``reporting.string_row_form``): ``/iocs`` and the console's
table carry it under the form it has, ``text_not_a_plain_host_name``, with the
type §9 prints, never under ``domain``, and with no suspicion flag or note. Its
row, its answer and its publish decision stay as they are. Nothing here reads a
device, pipe or tool name: the form reader reads separators and prefixes.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows, with_current_iocs
from malspark.reporting.builder import ioc_table
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from malspark.reporting.string_row_form import EXPORTED_FORM_KINDS, NOT_A_PLAIN_HOST_BY_FORM

_NOT_A_HOST = EXPORTED_FORM_KINDS[NOT_A_PLAIN_HOST_BY_FORM]

# Paths of the device namespace and of a local volume, each holding a dot.
_PATHS = (
    "\\\\.\\pipe\\relay-share.1",
    "//./pipe/relay-share.1",
    "\\\\.\\mailslot\\relay.box",
    "\\\\?\\C:\\relay\\x.dat",
    "\\??\\C:\\relay\\x.sys",
)


def _report(value: str) -> MalwareReport:
    return MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_name="sample.bin"),
        executive_summary="",
        network=NetworkIOCs(
            domains=[
                # Kept by an analyst's artifact, as a typed cell is.
                NetworkDomain(
                    fqdn=value,
                    source="strings",
                    kept_by=["an analyst artifact"],
                    is_suspicious=True,
                    reason="DGA-like (score 0.66: entropy 0.90, bigram-rarity 0.70)",
                ),
                NetworkDomain(fqdn="seen.example.org", source="sandbox"),
            ]
        ),
    )


def _row(rows: list[dict[str, Any]], value: str) -> dict[str, Any]:
    [row] = [row for row in rows if row["value"] == value]
    return row


@pytest.mark.parametrize("value", _PATHS)
def test_the_feed_serves_the_path_as_its_form(value: str) -> None:
    report = _report(value)
    mr = report.model_dump(mode="json")
    row = _row(ioc_feed_rows(mr), value)
    assert (row["kind"], row["type"]) == (_NOT_A_HOST, NOT_A_PLAIN_HOST_BY_FORM)
    assert (row["is_suspicious"], row["notes"]) == (False, None)
    assert value not in {row["value"] for row in ioc_feed_rows(mr, "domain")}
    assert "seen.example.org" in {row["value"] for row in ioc_feed_rows(mr, "domain")}


@pytest.mark.parametrize("value", _PATHS)
def test_its_row_answer_and_decision_stay(value: str) -> None:
    report = _report(value)
    [table_row] = [row for row in ioc_table(report) if row.value == value]
    assert table_row.kind == "domain"
    row = _row(ioc_feed_rows(report.model_dump(mode="json")), value)
    assert row["published"] is False
    assert row["publish_answer"] == table_row.published
    assert row["source"] == table_row.source


@pytest.mark.parametrize("value", _PATHS)
def test_the_console_table_serves_the_path_as_its_form(value: str) -> None:
    served, _note = with_current_iocs(_report(value).model_dump(mode="json"), "r")
    row = _row(served["consolidated_iocs"], value)
    assert (row["kind"], row["type"], row["is_network"]) == (
        _NOT_A_HOST,
        NOT_A_PLAIN_HOST_BY_FORM,
        False,
    )
