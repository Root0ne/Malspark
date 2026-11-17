"""The capture line says, per conversation, what the sandbox's rows say of the remote address.

From the record only: the pack's own network view, read by the one reading
the report's network block is (``ledger_projection.network_from_ledger``) and
said in the publish rule's words (``stix_renderer.address_flow_reason``): a
flow of the sample's process tree, the process the rows name, or that no row
of the view holds the address. A view that is a page cannot say that no row
holds an address, and a pack with no network view says nothing beside the
conversations.
"""

from __future__ import annotations

import json
from typing import Any

from malspark.pipeline import triage_pack
from malspark.reporting import ledger_projection
from malspark.reporting.renderers.stix_renderer import made_by_reason
from malspark.schemas.evidence import build_entry

TREE = "198.51.100.1"
UNLISTED = "198.51.100.2"
NO_ROW = "198.51.100.3"
SILENT = "198.51.100.4"


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


def _rows(pack: str) -> dict[str, str]:
    """Each conversation's part of the capture line, by its remote address."""
    line = next(row for row in pack.splitlines() if "external conversations" in row)
    listed = line.split("external conversations by volume: ", 1)[1]
    parts = listed.split("; contacts at a regular interval", 1)[0].split(" | ")
    return {part.split(":", 1)[0]: part for part in parts}


def _pack(network_args: dict[str, Any] | None = None, network: bool = True) -> dict[str, str]:
    entries = [_entry("pcap_summary", _capture(TREE, UNLISTED, NO_ROW, SILENT), 17)]
    if network:
        entries.insert(0, _entry("sandbox_network", _flows(), 13, network_args))
    return _rows(triage_pack.render_pack(entries, 0))


class TestEachConversation:
    def test_a_flow_of_the_sample_s_tree_is_said(self) -> None:
        assert _pack()[TREE].endswith(f"; {ledger_projection.SAMPLE_TREE_FLOW}")

    def test_a_process_the_report_does_not_list_is_named_as_the_rows_name_it(self) -> None:
        said = made_by_reason({"unlisted": ["procid 46"]})
        assert _pack()[UNLISTED].endswith(f"; {said}")

    def test_an_address_no_row_holds_says_so(self) -> None:
        assert _pack()[NO_ROW].endswith(f"; {ledger_projection.NO_SANDBOX_ROW}")

    def test_a_row_naming_no_process_says_the_report_does_not_say(self) -> None:
        from malspark.reporting.renderers.stix_renderer import UNATTRIBUTED_FLOW

        assert _pack()[SILENT].endswith(f"; {UNATTRIBUTED_FLOW}")


class TestWhatTheRecordCannotSay:
    def test_a_page_of_the_view_never_says_no_row_holds_an_address(self) -> None:
        rows = _pack({"offset": 0, "limit": 2})
        assert ledger_projection.NO_SANDBOX_ROW not in rows[NO_ROW]

    def test_a_further_detonation_s_capture_is_not_read_against_the_job_s_rows(self) -> None:
        later = {**_capture(TREE, NO_ROW), "detonation": "d2", "launched_with": "a second launch"}
        entries = [_entry("sandbox_network", _flows(), 13), _entry("pcap_summary", later, 30)]
        # The pack and the heads a question shows render every entry in one view.
        for shown in (
            triage_pack.render_pack(entries, 0),
            *triage_pack.pack_row_heads(entries).values(),
        ):
            assert ledger_projection.NO_SANDBOX_ROW not in shown
            assert ledger_projection.SAMPLE_TREE_FLOW not in shown

    def test_without_a_network_view_the_line_is_as_it_was(self) -> None:
        alone = triage_pack._pack_line(
            _entry("pcap_summary", _capture(TREE, UNLISTED, NO_ROW, SILENT), 17)
        )
        rows = _pack(network=False)
        assert " | ".join(rows.values()) in alone
        assert ledger_projection.NO_SANDBOX_ROW not in alone
