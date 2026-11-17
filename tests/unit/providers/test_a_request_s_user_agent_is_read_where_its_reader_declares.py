"""A request's user agent is read where its reader declares the record states it.

Which field of a request record states the User-Agent header is the reader's
declaration (``Reading.request_user_agent_fields``, the channel that declares a
dropped row's size fields): every declared field is read, then the generic
``user_agent``. The network view states it under ``user_agent`` beside the
record's own fields, so the report reads it whichever sandbox wrote it.
Synthetic reports only.
"""

from __future__ import annotations

from typing import Any

from malspark.providers.sandbox.readers import required_reader
from malspark.providers.sandbox_tools import read_view
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import sandbox_document

AGENT = "Mozilla/4.0 (compatible; MSIE 8.0)"


def _cape(http: list[dict[str, Any]]) -> dict[str, Any]:
    raw = {
        "target": {"file": {"name": "a.exe", "sha256": "a" * 64}},
        "behavior": {"processes": []},
        "network": {"http": http},
    }
    return sandbox_document(required_reader("cape2").read(raw, provider="lab"))


def _row(document: dict[str, Any], reader: Any) -> dict[str, Any]:
    (row,) = read_view("sandbox_network", document, reader)["http"]
    return row


CAPE_ROW = {"host": "c.example.com", "uri": "/g", "method": "GET", "user-agent": AGENT}


def test_the_cape_reader_s_declared_field_is_read() -> None:
    row = _row(_cape([CAPE_ROW]), ("lab", "cape2"))

    assert row["user_agent"] == AGENT
    # Nothing the record states is lost.
    assert row["user-agent"] == AGENT


def test_the_report_prints_it() -> None:
    answer = read_view("sandbox_network", _cape([CAPE_ROW]), ("lab", "cape2"))
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="layer0",
        tool="sandbox_network",
        args={},
        server=None,
        output="{}",
    ).model_copy(update={"structured": answer})
    network = network_from_ledger([entry])
    assert network is not None
    (url,) = network.urls

    assert (url.method, url.user_agent) == ("GET", AGENT)


def test_a_document_read_with_no_reader_keeps_its_rows_as_they_are() -> None:
    row = _row(_cape([CAPE_ROW]), None)

    assert "user_agent" not in row


def test_a_row_that_states_the_generic_name_keeps_it() -> None:
    row = _row(_cape([{**CAPE_ROW, "user_agent": "Own/1.0"}]), ("lab", "cape2"))

    assert row["user_agent"] == "Own/1.0"
