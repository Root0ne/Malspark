"""A name's answer names each kind of record the publish rule counted, with the makers it gave.

A name is decided from its HTTP requests, the DNS requests that state their own
process and the flows to the addresses it resolved to (``ledger_projection``):
where every one names a process of another lineage, the answer says so. It says
it as what the publish rule counted, and names every kind of record with the
processes those records name: its requests with theirs, the flows to an address
it resolved to with theirs, never one list of processes laid over several kinds
of record. An address is "an address it resolved to", never "the address": a
name may resolve to more addresses than its counted flows reach. The clause
carries no "," or ";" outside brackets, so every reader of the clause after a
value reads it whole, and a word-for-word restatement of it is a restatement.

Each truth test reads the record the clause names: the requests' rows, the
flows to each address, the DNS answer. Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.validation import _states_publish_state
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import NetworkIOCs
from malspark.reporting.publish_parts import refused
from malspark.reporting.renderers.stix_renderer import (
    made_by_reason,
    name_made_by_reason,
    sandbox_facts_for_the_judge,
    unlisted_reasons,
)
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_report import (
    FLOW_PROCESS_KEY,
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_FLOWS_LEFT_OUT_KEY,
    TRAFFIC_PROCESS_KEY,
)

NAME = "cdn.example.net"
ADDRESS = "203.0.113.20"
OTHER = "203.0.113.21"
RESOLVER = "8.8.8.8"


def _unlisted(procid: str, dst: str = ADDRESS) -> dict[str, Any]:
    return {"dst": dst, TRAFFIC_PROCESS_KEY: procid, PROCESS_UNLISTED_KEY: True}


def _outside(procid: str, image: str, dst: str = ADDRESS) -> dict[str, Any]:
    return {
        "dst": dst,
        TRAFFIC_PROCESS_KEY: procid,
        SAMPLE_TREE_KEY: False,
        FLOW_PROCESS_KEY: image,
    }


def _request(procid: str) -> dict[str, Any]:
    return {"host": NAME, "uri": "/a.bin", TRAFFIC_PROCESS_KEY: procid, PROCESS_UNLISTED_KEY: True}


def _lookup(*answers: str, **process: Any) -> dict[str, Any]:
    return {"request": NAME, "type": "A", "answers": [{"data": a} for a in answers], **process}


def _network(view: dict[str, Any]) -> NetworkIOCs:
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(view),
        )
    ]
    network = network_from_ledger(ledger)
    assert network is not None
    return network


def _said(network: NetworkIOCs, name: str = NAME) -> str:
    facts = sandbox_facts_for_the_judge(network)
    assert facts is not None
    return facts("domain", name)


def _restated(fact: str) -> bool:
    """Whether a writer's verbatim restatement of the fact, written after the name, passes."""
    answer = refused(fact, facts=["a listing does not change what the sandbox recorded about it"])
    return _states_publish_state(f" ({fact}) was looked up.", answer) and (
        _states_publish_state(f" {fact}; the request fetched a file.", answer)
    )


class TestEachKindOfRecordIsNamedWithItsOwnMakers:
    def test_requests_and_flows_made_by_different_processes(self) -> None:
        # The request rides on procid 46's flow; a listed process outside the
        # tree also reached the address the name resolved to.
        network = _network(
            {
                "dns": [_lookup(ADDRESS)],
                "http": [_request("46")],
                "tcp": [_unlisted("46"), _outside("12", "svchost.exe")],
            }
        )
        said = _said(network)

        assert said == (
            "the publish rule counted its requests as made by a process the report does not "
            "list (procid 46) and the flows to 203.0.113.20 (an address it resolved to) as made "
            "by a process outside the sample's process tree (svchost.exe (procid 12)) and by a "
            "process the report does not list (procid 46)"
        )
        # Against the records it names: the requests name procid 46 alone.
        (domain,) = [d for d in network.domains if d.fqdn == NAME]
        assert domain.made_by is not None
        requests, flows = domain.made_by.sources
        assert (requests.source, requests.unlisted, requests.outside) == (
            "requests",
            ["procid 46"],
            [],
        )
        assert (flows.source, flows.addresses) == ("flows", [ADDRESS])
        assert (flows.outside, flows.unlisted) == (["svchost.exe (procid 12)"], ["procid 46"])
        assert _restated(said)

    def test_a_tail_of_further_makers_stays_with_the_flows(self) -> None:
        flows = [_unlisted(str(1000 + i)) for i in range(20)]
        network = _network({"dns": [_lookup(ADDRESS)], "http": [_request("46")], "tcp": flows})
        said = _said(network)

        named = ", ".join(f"procid {1000 + i}" for i in range(16))
        assert said == (
            "the publish rule counted its requests as made by a process the report does not "
            "list (procid 46) and the flows to 203.0.113.20 (an address it resolved to) as made "
            f"by a process the report does not list ({named}) (and by further processes each "
            "such address's own row names)"
        )
        assert ";" not in said and _restated(said)

    def test_a_name_with_two_addresses_and_flows_to_one(self) -> None:
        network = _network({"dns": [_lookup(ADDRESS, OTHER)], "tcp": [_unlisted("46")]})
        said = _said(network)

        assert said == (
            "the publish rule counted the flows to 203.0.113.20 (an address it resolved to) as "
            "made by a process the report does not list (procid 46)"
        )
        (domain,) = [d for d in network.domains if d.fqdn == NAME]
        assert domain.resolved_ips == [ADDRESS, OTHER]

    def test_two_addresses_whose_flows_name_the_same_process_are_one_source(self) -> None:
        network = _network(
            {
                "dns": [_lookup(ADDRESS, OTHER)],
                "tcp": [_unlisted("46"), _unlisted("46", OTHER)],
            }
        )

        assert _said(network) == (
            "the publish rule counted the flows to 2 addresses it resolved to (203.0.113.20, "
            "203.0.113.21) as made by a process the report does not list (procid 46)"
        )

    def test_two_addresses_whose_flows_name_other_processes_are_two_sources(self) -> None:
        network = _network(
            {
                "dns": [_lookup(ADDRESS, OTHER)],
                "tcp": [_unlisted("46"), _outside("12", "svchost.exe", OTHER)],
            }
        )

        assert _said(network) == (
            "the publish rule counted the flows to 203.0.113.20 (an address it resolved to) as "
            "made by a process the report does not list (procid 46) and the flows to "
            "203.0.113.21 (an address it resolved to) as made by a process outside the "
            "sample's process tree (svchost.exe (procid 12))"
        )

    def test_a_lookup_that_states_its_process(self) -> None:
        lookup = _lookup(ADDRESS, **{TRAFFIC_PROCESS_KEY: "77", PROCESS_UNLISTED_KEY: True})
        network = _network({"dns": [lookup]})

        assert _said(network) == (
            "the publish rule counted its lookups that state their process as made by a process "
            "the report does not list (procid 77)"
        )

    def test_a_name_the_resolver_itself_answered(self) -> None:
        # The flow to the resolver's address is a flow to an address it resolved to.
        network = _network({"dns": [_lookup(RESOLVER)], "udp": [_unlisted("35", RESOLVER)]})

        assert _said(network) == (
            "the publish rule counted the flows to 8.8.8.8 (an address it resolved to) as made "
            "by a process the report does not list (procid 35)"
        )

    def test_an_address_is_printed_as_the_answer_records_it(self) -> None:
        # The answer writes the address in capitals; the flow row in lower case.
        network = _network(
            {"dns": [_lookup("2001:DB8::20")], "tcp": [_unlisted("35", "2001:db8::20")]}
        )

        assert _said(network) == (
            "the publish rule counted the flows to 2001:DB8::20 (an address it resolved to) as "
            "made by a process the report does not list (procid 35)"
        )

    def test_further_makers_of_requests_stay_in_their_own_brackets(self) -> None:
        # A request carrying part of its flow id's flows names part of its makers.
        request = {**_request("46"), TRAFFIC_FLOWS_LEFT_OUT_KEY: True}
        network = _network(
            {"dns": [_lookup(ADDRESS)], "http": [request], "tcp": [_outside("12", "svchost.exe")]}
        )

        assert _said(network) == (
            "the publish rule counted its requests as made by a process the report does not "
            "list (procid 46) (and by further processes) and the flows to 203.0.113.20 (an "
            "address it resolved to) as made by a process outside the sample's process tree "
            "(svchost.exe (procid 12))"
        )

    def test_a_name_with_no_counted_record_has_no_made_by_clause(self) -> None:
        network = _network({"dns": [_lookup(ADDRESS)]})
        (domain,) = [d for d in network.domains if d.fqdn == NAME]

        assert domain.made_by is None
        assert "counted" not in _said(network)


class TestOtherReadersTakeTheSameWords:
    def test_the_code_links_reader_takes_the_name_s_clause(self) -> None:
        network = _network({"dns": [_lookup(ADDRESS)], "tcp": [_unlisted("46")]})

        assert unlisted_reasons(network)[("domain", NAME)] == _said(network)

    def test_a_name_whose_tally_kept_no_sources_is_said_as_any_traffic_is(self) -> None:
        stored = {"unlisted": ["procid 46"]}

        assert name_made_by_reason(stored) == made_by_reason(stored)
        assert made_by_reason(stored) == (
            "the sandbox report says it was made by a process the report does not list (procid 46)"
        )

    def test_a_stored_dump_without_sources_reads_as_it_was_written(self) -> None:
        network = _network({"dns": [_lookup(ADDRESS)], "tcp": [_unlisted("46")]})
        (domain,) = [d for d in network.domains if d.fqdn == NAME]
        assert domain.made_by is not None

        dumped = domain.made_by.model_dump()
        assert dumped["sources"] == [
            {"source": "flows", "addresses": [ADDRESS], "unlisted": ["procid 46"]}
        ]
        domain.made_by.sources = []
        assert "sources" not in domain.made_by.model_dump()
