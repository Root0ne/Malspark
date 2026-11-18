"""The capture line says, per conversation, what the sandbox's flow rows say of the remote address.

From the record only, and where the pack line is written: the pack reads its
own network view entry with the run's reader, as the report's network block
is read (``ledger_projection.address_flow_facts``), and hands the capture's
renderer what the flow rows say of each conversation's address, in the
publish rule's words (``stix_renderer.address_flow_reason``): a flow of the
sample's process tree, the process the rows name, or that no flow row of the
view holds the address. The capture entry holds what its tool returned and
nothing else. A view that is not whole says nothing of any address, a value
that does not parse as an address gets no words, and the words never cost a
conversation the line would print without them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from malspark.pipeline import triage_pack
from malspark.reporting import ledger_projection
from malspark.reporting.renderers.stix_renderer import UNATTRIBUTED_FLOW, made_by_reason
from malspark.schemas.evidence import build_entry
from malspark.tools import pcap

TREE = "198.51.100.1"
UNLISTED = "198.51.100.2"
NO_ROW = "198.51.100.3"
SILENT = "198.51.100.4"
ADDRESSES = (TREE, UNLISTED, NO_ROW, SILENT)
# A flow row naming a process the task does not list, as the reader writes one.
UNLISTED_ROW = {"platform_process": "46", "process_not_listed": True}


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


def _flows(**more: Any) -> dict[str, Any]:
    return {
        "tcp": [
            {"dst": TREE, "dport": 80, "platform_process": "83", "sample_process_tree": True},
            {"dst": UNLISTED, "dport": 80, **UNLISTED_ROW},
            {"dst": SILENT, "dport": 80},
        ],
        **more,
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
    listed = re.split(r"external conversations by volume(?: \([^)]*\))?: ", line, maxsplit=1)[1]
    parts = listed.split("; contacts at a regular interval", 1)[0].split(" | ")
    return {part.split(":", 1)[0]: part for part in parts}


def _capture_line(
    *views: Any, capture: dict[str, Any] | None = None, room: int = 0, reader: bool = True
) -> str:
    """The capture's line of the pack written with the run's reader, beside ``views``."""
    entries = [*views, _entry("pcap_summary", capture or _capture(*ADDRESSES), 17)]
    over = {"normalised_by": ("box", "box")} if reader else {}
    block = triage_pack.pack_block(entries, room, **over)
    return next(line for line in block.splitlines() if line.startswith("[ev_0017]"))


def _view(network: dict[str, Any] | None = None, args: dict[str, Any] | None = None) -> Any:
    return _entry("sandbox_network", _flows() if network is None else network, 13, args)


class TestEachConversation:
    def test_a_flow_of_the_sample_s_tree_is_said(self) -> None:
        said = _rows(_capture_line(_view()))[TREE]
        assert said.endswith(f"; {ledger_projection.SAMPLE_TREE_FLOW}")

    def test_a_process_the_report_does_not_list_is_named_as_the_rows_name_it(self) -> None:
        said = made_by_reason({"unlisted": ["procid 46"]})
        assert _rows(_capture_line(_view()))[UNLISTED].endswith(f"; {said}")

    def test_a_flow_row_naming_no_process_says_the_report_does_not_say(self) -> None:
        assert _rows(_capture_line(_view()))[SILENT].endswith(f"; {UNATTRIBUTED_FLOW}")


class TestTheWordsSayWhatWasRead:
    def test_an_address_no_flow_row_holds_says_no_flow_row_holds_it(self) -> None:
        said = _rows(_capture_line(_view()))[NO_ROW]
        assert said.endswith("; no flow row of the sandbox's network view holds it")

    def test_an_address_only_a_dns_answer_holds_is_held_by_no_flow_row(self) -> None:
        dns = [{"request": "c2.example.test", "type": "A", "answers": [{"data": NO_ROW}]}]
        said = _rows(_capture_line(_view(_flows(dns=dns))))[NO_ROW]
        assert said.endswith(f"; {ledger_projection.NO_FLOW_ROW}")

    def test_an_address_only_the_host_list_holds_is_held_by_no_flow_row(self) -> None:
        said = _rows(_capture_line(_view(_flows(hosts=[{"ip": NO_ROW}]))))[NO_ROW]
        assert said.endswith(f"; {ledger_projection.NO_FLOW_ROW}")

    def test_the_two_rows_one_unlisted_one_naming_none_are_worded_as_the_publish_rule(
        self,
    ) -> None:
        network = {"tcp": [{"dst": UNLISTED, **UNLISTED_ROW}, {"dst": UNLISTED}]}
        assert _rows(_capture_line(_view(network)))[UNLISTED].endswith(f"; {UNATTRIBUTED_FLOW}")

    @pytest.mark.parametrize("value", ["c2.example.test", "12345", f"{NO_ROW}:53", "not an ip"])
    def test_a_value_that_does_not_parse_as_an_address_gets_no_words(self, value: str) -> None:
        line = _capture_line(_view(), capture=_capture(value))
        listed = line.split("external conversations by volume: ", 1)[1]
        assert ledger_projection.NO_FLOW_ROW not in listed
        assert listed.split("; contacts at a regular interval", 1)[0].endswith("not recorded")


class TestAViewNotReadWholeSaysNothing:
    @pytest.mark.parametrize(
        "args", [{"offset": 0, "limit": 2}, {"limit": 50}, {"offset": 2}], ids=str
    )
    def test_a_page_or_a_bounded_view_says_nothing_of_any_address(
        self, args: dict[str, Any]
    ) -> None:
        assert _capture_line(_view(args=args)) == _capture_line(reader=False)

    def test_a_shortened_answer_says_nothing_of_any_address(self) -> None:
        shortened = _view(_flows(shortened=True, tcp_total=9))
        assert _capture_line(shortened) == _capture_line(reader=False)

    def test_a_truncated_entry_says_nothing_of_any_address(self) -> None:
        truncated = _view().model_copy(update={"truncated": True})
        assert _capture_line(truncated) == _capture_line(reader=False)

    def test_a_whole_view_beside_a_part_of_one_says_nothing(self) -> None:
        part = _entry("sandbox_network", _flows(), 14, {"offset": 0, "limit": 1})
        assert _capture_line(_view(), part) == _capture_line(reader=False)

    def test_without_a_network_view_the_line_is_as_it_was(self) -> None:
        assert _capture_line() == _capture_line(reader=False)


class TestTheWordsNeverCostAConversation:
    def _facts(self) -> Any:
        return ledger_projection.address_flow_facts([_view()], normalised_by=("box", "box"))

    def test_a_room_of_the_line_without_words_prints_every_conversation(self) -> None:
        bare = triage_pack._pcap(_capture(*ADDRESSES))
        line = triage_pack._pcap(_capture(*ADDRESSES), max_chars=len(bare), facts=self._facts())
        assert line == bare
        assert f"all {len(ADDRESSES)} external conversations by volume" in line

    def test_the_words_are_added_in_order_while_room_remains(self) -> None:
        facts = self._facts()
        bare = triage_pack._pcap(_capture(*ADDRESSES))
        whole = triage_pack._pcap(_capture(*ADDRESSES), facts=facts)
        first = f"; {facts(TREE)}"
        line = triage_pack._pcap(
            _capture(*ADDRESSES), max_chars=len(bare) + len(first), facts=facts
        )
        rows = _rows(line)
        assert set(rows) == set(ADDRESSES)
        assert rows[TREE] == _rows(whole)[TREE]
        assert all(rows[one] == _rows(bare)[one] for one in ADDRESSES if one != TREE)

    def test_the_conversations_are_chosen_as_without_the_words(self) -> None:
        many = _capture(*(f"198.51.100.{n}" for n in range(1, 60)))
        bare = triage_pack._pcap(many, max_chars=900)
        line = triage_pack._pcap(many, max_chars=900, facts=lambda _address: "x" * 40)
        assert "of 59 external conversations by volume (the rest are in the entry)" in bare
        assert list(_rows(line)) == list(_rows(bare))
        assert len(line) <= 900


class TestTheEntryIsTheToolsAnswer:
    def _capture_entry(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flows: bool) -> Any:
        from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _pack, _write
        from tests.unit.tools.test_binary import _pe

        capture = tmp_path / "run.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        monkeypatch.setattr(pcap, "pcap_summary", lambda path, **_: _capture(*ADDRESSES))
        network: dict[str, Any] = {"pcap_local_path": str(capture)}
        if flows:
            network["tcp"] = _flows()["tcp"]
        report = {**SANDBOX_REPORT, "network": network}
        result = _pack(
            _write(tmp_path, "s.exe", _pe()),
            "pe",
            sandbox_report=report,
            sandbox_normalised_by=("box", "box"),
        )
        return next(entry for entry in result.entries if entry.tool == "pcap_summary"), result

    def test_the_capture_entry_is_byte_identical_with_or_without_a_network_view(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with_flows, _ = self._capture_entry(tmp_path, monkeypatch, flows=True)
        without, _ = self._capture_entry(tmp_path, monkeypatch, flows=False)
        assert with_flows.output == without.output
        assert with_flows.structured == without.structured == _capture(*ADDRESSES)

    def test_the_words_are_written_on_the_pack_line_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry, result = self._capture_entry(tmp_path, monkeypatch, flows=True)
        assert ledger_projection.SAMPLE_TREE_FLOW not in entry.output
        block = triage_pack.pack_block(
            triage_pack.pack_entries(result.entries), 0, normalised_by=("box", "box")
        )
        line = next(one for one in block.splitlines() if one.startswith(f"[{entry.id}]"))
        assert _rows(line)[TREE].endswith(f"; {ledger_projection.SAMPLE_TREE_FLOW}")


class TestThePackRowHeads:
    def test_a_row_s_head_carries_the_words_with_the_run_s_reader(self) -> None:
        capture = _entry("pcap_summary", _capture(*ADDRESSES), 17)
        rows = [_view().model_dump(mode="json"), capture.model_dump(mode="json")]
        heads = triage_pack.pack_row_heads(rows, normalised_by=("box", "box"))
        assert ledger_projection.SAMPLE_TREE_FLOW in heads["ev_0017"]
        assert ledger_projection.SAMPLE_TREE_FLOW not in triage_pack.pack_row_heads(rows)["ev_0017"]
