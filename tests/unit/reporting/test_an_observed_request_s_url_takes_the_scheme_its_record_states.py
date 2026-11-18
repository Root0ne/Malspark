"""An observed request's URL takes the scheme its record states.

A sandbox splits a request into its host and its path, and states whether it
was encrypted, or its scheme, and the port. One joiner makes the URL of such
a record for every reader (``schemas.sandbox_document.joined_url``): the
stated scheme, else ``https`` for an encrypted request, and a port its scheme
leaves unwritten only where it is not that scheme's default. A record that
states neither a scheme nor ``encrypted`` is joined as ``http``, as it always
was.

Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.reporting.ledger_projection import network_from_ledger
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_document import joined_url


def _urls(*http: dict[str, Any]) -> set[str]:
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="static",
        tool="sandbox_network",
        args={},
        server="analysis",
        output=json.dumps({"http": list(http)}),
    )
    network = network_from_ledger([entry])
    assert network is not None
    return {row.url for row in network.urls}


def test_an_encrypted_request_is_an_https_url() -> None:
    urls = _urls({"host": "c.example.com", "uri": "/gate", "encrypted": True})

    assert urls == {"https://c.example.com/gate"}


def test_a_request_that_states_its_scheme_takes_it() -> None:
    urls = _urls({"host": "c.example.com", "uri": "/gate", "scheme": "https"})

    assert urls == {"https://c.example.com/gate"}


def test_a_port_other_than_the_scheme_s_default_is_written() -> None:
    urls = _urls({"host": "c.example.com", "uri": "/gate", "encrypted": False, "port": 8080})

    assert urls == {"http://c.example.com:8080/gate"}


def test_the_scheme_s_default_port_is_not_written() -> None:
    urls = _urls({"host": "c.example.com", "uri": "/gate", "encrypted": True, "port": 443})

    assert urls == {"https://c.example.com/gate"}


def test_a_request_that_states_nothing_is_an_http_url_as_it_was() -> None:
    urls = _urls({"host": "c.example.com", "uri": "gate", "port": 8080})

    assert urls == {"http://c.example.com/gate"}


def test_without_a_default_a_request_that_states_nothing_joins_no_url() -> None:
    assert joined_url("/gate", "c.example.com", {}) == ""
    assert joined_url("/gate", "c.example.com", {}, default="http") == "http://c.example.com/gate"
