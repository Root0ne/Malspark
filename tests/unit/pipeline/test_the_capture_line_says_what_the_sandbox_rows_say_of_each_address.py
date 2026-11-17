"""The capture line says, per conversation, what the sandbox's rows say of the remote address.

From the record only: when the pack records the capture, it reads its own
network view entry with the run's reader, as the report's network block is
read (``ledger_projection.address_flow_facts``), and keeps beside the
capture's answer what those rows say of each conversation's remote address
(``triage_pack.SANDBOX_ROWS_KEY``), in the publish rule's words
(``stix_renderer.address_flow_reason``): a flow of the sample's process tree,
the process the rows name, or that no row of the view holds the address. A
view that is a page cannot say that no row holds an address, a pack with no
network view adds nothing, and a capture recorded without the facts renders
as it did.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline import triage_pack
from malspark.reporting import ledger_projection
from malspark.reporting.renderers.stix_renderer import UNATTRIBUTED_FLOW, made_by_reason
from malspark.schemas.evidence import build_entry

TREE = "198.51.100.1"
UNLISTED = "198.51.100.2"
NO_ROW = "198.51.100.3"
SILENT = "198.51.100.4"
ADDRESSES = (TREE, UNLISTED, NO_ROW, SILENT)


def _capture(*addresses: str) -> dict[str, Any]:
    return {
        "summary": "#### Packet Capture Analysis (deterministic, whole capture):\n...",
        "empty": False,
        "packets_read": 400,
        "packets_in_capture": 400,
        "packet_limit": None,
        "bytes": 40_000,
        "duration_s": 60.0,
        "protocols": {"tcp": 400},
        "conversations": [
            {"dst": address, "dport": 80, "proto": "tcp", "packets": 100 - i, "bytes": 9000 - i}
            for i, address in enumerate(addresses)
        ],
        "sni": {},
        "beacons": [],
    }


def _flows() -> dict[str, Any]:
    return {
        "tcp": [
            {"dst": TREE, "dport": 80, "platform_process": "83", "sample_process_tree": True},
            {"dst": UNLISTED, "dport": 80, "platform_process": "46", "process_not_listed": True},
        ],
        "hosts": [{"ip": SILENT}],
    }


def _entry(tool: str, payload: Any, number: int, args: dict[str, Any] | None = None) -> Any:
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent="pipeline",
        tool=tool,
        args=args or {},
        server="pipeline",
        output=json.dumps(payload),
        stage="triage_pack",
        source=triage_pack.PACK_SOURCE,
    )


def _rows(line: str) -> dict[str, str]:
    """Each conversation's part of the capture line, by its remote address."""
    listed = line.split("external conversations by volume: ", 1)[1]
    parts = listed.split("; contacts at a regular interval", 1)[0].split(" | ")
    return {part.split(":", 1)[0]: part for part in parts}


def _recorded(network_args: dict[str, Any] | None = None, network: bool = True) -> dict[str, Any]:
    """The capture's answer as the pack records it, beside the pack's network view."""
    ledger = [_entry("sandbox_network", _flows(), 13, network_args)] if network else []
    return triage_pack.with_sandbox_rows(_capture(*ADDRESSES), ledger, None)


def _line(answer: dict[str, Any]) -> str:
    return triage_pack._pack_line(_entry("pcap_summary", answer, 17))


class TestEachConversation:
    def test_a_flow_of_the_sample_s_tree_is_said(self) -> None:
        assert _rows(_line(_recorded()))[TREE].endswith(f"; {ledger_projection.SAMPLE_TREE_FLOW}")

    def test_a_process_the_report_does_not_list_is_named_as_the_rows_name_it(self) -> None:
        said = made_by_reason({"unlisted": ["procid 46"]})
        assert _rows(_line(_recorded()))[UNLISTED].endswith(f"; {said}")

    def test_an_address_no_row_holds_says_so(self) -> None:
        line = _line(_recorded())
        assert _rows(line)[NO_ROW].endswith(f"; {ledger_projection.NO_SANDBOX_ROW}")

    def test_a_row_naming_no_process_says_the_report_does_not_say(self) -> None:
        assert _rows(_line(_recorded()))[SILENT].endswith(f"; {UNATTRIBUTED_FLOW}")

    def test_the_facts_are_kept_by_address_beside_the_capture_s_own_answer(self) -> None:
        answer = _recorded()
        held = answer[triage_pack.SANDBOX_ROWS_KEY]
        assert set(held) == set(ADDRESSES)
        assert {k: v for k, v in answer.items() if k != triage_pack.SANDBOX_ROWS_KEY} == (
            _capture(*ADDRESSES)
        )


class TestWhatTheRecordCannotSay:
    def test_a_page_of_the_view_never_says_no_row_holds_an_address(self) -> None:
        line = _line(_recorded({"offset": 0, "limit": 2}))
        assert ledger_projection.NO_SANDBOX_ROW not in line

    def test_without_a_network_view_the_answer_and_the_line_are_as_they_were(self) -> None:
        answer = _recorded(network=False)
        assert answer == _capture(*ADDRESSES)
        assert ledger_projection.NO_SANDBOX_ROW not in _line(answer)

    def test_a_capture_recorded_without_the_facts_renders_as_before(self) -> None:
        line = _line(_capture(*ADDRESSES))
        assert all(part.endswith("not recorded") for part in _rows(line).values())
