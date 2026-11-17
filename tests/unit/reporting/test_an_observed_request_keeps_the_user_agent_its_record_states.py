"""An observed request keeps the user agent its record states.

A sandbox's request record states the User-Agent header the request carried,
and the report printed "-" for every observed URL: the method was read from
the record and the user agent was not. The user agent is read the way the
method is: the first record of the URL that states one, and none where no
record states one.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.reporting.ledger_projection import network_from_ledger
from malspark.schemas.evidence import build_entry

AGENT = "Microsoft-CryptoAPI/10.0"
READ_ONLY = "https://other.example.net/live/"


def _entry(seq: int, tool: str, payload: dict[str, Any]) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=json.dumps(payload),
    )


def _urls(*http: dict[str, Any]) -> dict[str, Any]:
    network = network_from_ledger(
        [
            _entry(1, "sandbox_network", {"http": list(http)}),
            _entry(2, "iocs_from_file", {"iocs": [{"kind": "url", "value": READ_ONLY}]}),
        ]
    )
    assert network is not None
    return {row.url: row for row in network.urls}


def test_an_observed_request_keeps_the_user_agent_its_record_states() -> None:
    urls = _urls({"host": "c.example.com", "uri": "/r1.crl", "method": "GET", "user_agent": AGENT})

    assert urls["http://c.example.com/r1.crl"].user_agent == AGENT


def test_the_first_record_that_states_one_is_kept() -> None:
    urls = _urls(
        {"host": "c.example.com", "uri": "/a"},
        {"host": "c.example.com", "uri": "/a", "user_agent": AGENT},
        {"host": "c.example.com", "uri": "/a", "user_agent": "Other/1.0"},
    )

    assert urls["http://c.example.com/a"].user_agent == AGENT


def test_a_request_that_records_none_states_none() -> None:
    urls = _urls({"host": "plain.example.org", "uri": "/"})

    assert urls["http://plain.example.org/"].user_agent is None


def test_a_url_read_from_the_file_states_no_user_agent() -> None:
    assert _urls({"host": "plain.example.org", "uri": "/"})[READ_ONLY].user_agent is None


def test_the_method_and_the_user_agent_come_from_one_record() -> None:
    # The row prints the first record's method; that record states no agent,
    # so none is printed: another request's agent is not joined to it.
    urls = _urls(
        {"host": "c.example.com", "uri": "/m", "method": "GET"},
        {"host": "c.example.com", "uri": "/m", "method": "POST", "user_agent": AGENT},
    )
    row = urls["http://c.example.com/m"]

    assert (row.method, row.user_agent) == ("GET", None)


def test_the_record_whose_method_is_printed_gives_its_own_user_agent() -> None:
    urls = _urls(
        {"host": "c.example.com", "uri": "/n", "user_agent": "Other/1.0"},
        {"host": "c.example.com", "uri": "/n", "method": "POST", "user_agent": AGENT},
    )
    row = urls["http://c.example.com/n"]

    assert (row.method, row.user_agent) == ("POST", AGENT)
