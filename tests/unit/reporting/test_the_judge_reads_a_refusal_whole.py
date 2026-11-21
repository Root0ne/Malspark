"""The judge's question carries the publish rule's refusing part whole, however long.

A value the sandbox recorded and the rule does not count as the sample's is
asked about once, with the rule's finding beside it
(``validation.unattributed_indicator_violations``). That finding is the row's
refusing part, and a refusing part is never cut: a name whose requests, lookups
and flows were made by three different processes is asked with every source and
every maker, past the bound a model-written value is held to. Every value is
synthetic.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline.events import FINDING_VALUE_LIMIT
from malspark.pipeline.validation import unattributed_indicator_violations
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.renderers.stix_renderer import sandbox_facts_for_the_judge
from malspark.schemas.evidence import build_entry
from malspark.schemas.sandbox_report import (
    FLOW_PROCESS_KEY,
    PROCESS_UNLISTED_KEY,
    SAMPLE_TREE_KEY,
    TRAFFIC_PROCESS_KEY,
)
from malspark.schemas.stix_models import Bundle

NAME = "cdn.example.net"
ADDRESS = "203.0.113.20"


def _view() -> dict[str, Any]:
    return {
        "dns": [
            {
                "request": NAME,
                "type": "A",
                "answers": [{"data": ADDRESS}],
                TRAFFIC_PROCESS_KEY: "47",
                SAMPLE_TREE_KEY: False,
                FLOW_PROCESS_KEY: "dnscache.exe",
            }
        ],
        "http": [
            {"host": NAME, "uri": "/a.bin", TRAFFIC_PROCESS_KEY: "46", PROCESS_UNLISTED_KEY: True}
        ],
        "tcp": [
            {
                "dst": ADDRESS,
                TRAFFIC_PROCESS_KEY: "12",
                SAMPLE_TREE_KEY: False,
                FLOW_PROCESS_KEY: "svchost.exe",
            }
        ],
    }


def test_a_refusal_longer_than_the_bound_is_asked_whole() -> None:
    ledger = [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(_view()),
        )
    ]
    network = network_from_ledger(ledger)
    assert network is not None
    facts = sandbox_facts_for_the_judge(network)
    assert facts is not None
    said = facts("domain", NAME)
    # Three sources, each with its own maker, and longer than the bound.
    assert "(procid 46)" in said
    assert "dnscache.exe (procid 47)" in said
    assert "svchost.exe (procid 12)" in said
    assert len(said) > FINDING_VALUE_LIMIT
    bundle = Bundle.model_validate(
        {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "judge indicator",
                    "pattern": f"[domain-name:value = '{NAME}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                    "valid_from": "2026-01-01T00:00:00Z",
                }
            ],
        }
    )

    (found,) = unattributed_indicator_violations(bundle, facts)

    assert f" and {said}: " in found.message
