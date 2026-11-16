"""A capture's conversation line names both ends of the flow and what each end sent.

The line keyed each conversation on its public end and called that end's share
"from the host". Every reader took "the host" for the sandbox's own machine, the
word the rest of the platform uses for it, so a download read as an upload. The
line now names the internal end, told from the capture by the module's own
internal/external rule, and the public peer, and states the packets and bytes
each of them sent: each direction names only the addresses that sent in it, and
the peer's names the internal ends it sent to wherever they are not exactly the
ones that sent to it. A capture that gives no internal end says so, and a record
stored with the old keys is printed with the peer's share as the peer's.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import struct
from pathlib import Path
from typing import Any

import pytest

from malspark.analysis.pcap_summary import capture_facts, conversation_line, summary_text

GUEST = b"\x0a\x00\x00\x02"  # 10.0.0.2
OTHER_GUEST = b"\x0a\x00\x00\x03"  # 10.0.0.3
PEER = b"\x08\x08\x08\x08"  # 8.8.8.8
PUBLIC = b"\x01\x02\x03\x04"  # 1.2.3.4
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def _tcp(src: bytes, dst: bytes, sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src, dst) + tcp


def _udp(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes = b"") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0, src, dst) + udp


def _pcap(records: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 101)
    for at, frame in records:
        seconds = int(at)
        micros = int(round((at - seconds) * 1_000_000))
        out += struct.pack("<IIII", 1_700_000_000 + seconds, micros, len(frame), len(frame))
        out += frame
    return out


def _download(sport: int = 50000) -> list[tuple[float, bytes]]:
    """A request out and a large answer back: the peer sends most of the bytes."""
    body = b"x" * 1400
    return [
        (0.0, _tcp(GUEST, PEER, sport, 80, SYN)),
        (0.01, _tcp(PEER, GUEST, 80, sport, SYN | ACK)),
        (0.02, _tcp(GUEST, PEER, sport, 80, PSH | ACK, b"GET /payload.bin HTTP/1.1\r\n\r\n")),
        *[(0.03 + i / 100, _tcp(PEER, GUEST, 80, sport, PSH | ACK, body)) for i in range(5)],
        (0.1, _tcp(GUEST, PEER, sport, 80, FIN | ACK)),
    ]


def _write(tmp_path: Path, records: list[tuple[float, bytes]]) -> Path:
    target = tmp_path / "c.pcap"
    target.write_bytes(_pcap(records))
    return target


def _facts(tmp_path: Path, records: list[tuple[float, bytes]]) -> dict[str, Any]:
    facts = capture_facts(str(_write(tmp_path, records)))
    assert facts is not None
    return facts


def _sent(records: list[tuple[float, bytes]], src: bytes) -> tuple[int, int]:
    frames = [f for _, f in records if f[12:16] == src]
    return len(frames), sum(len(f) for f in frames)


# ---------------------------------------------------- the line names both ends


def test_a_download_reads_as_the_peer_sending_to_the_guest(tmp_path: Path) -> None:
    records = _download()
    facts = _facts(tmp_path, records)
    out_p, out_b = _sent(records, GUEST)
    in_p, in_b = _sent(records, PEER)
    assert in_b > out_b  # the case the old label turned into an upload
    row = facts["conversations"][0]
    assert row == {
        "dst": "8.8.8.8",
        "dport": 80,
        "proto": "tcp",
        "packets": out_p + in_p,
        "bytes": out_b + in_b,
        "internal": ["10.0.0.2"],
        "packets_to_peer": out_p,
        "bytes_to_peer": out_b,
        "packets_from_peer": in_p,
        "bytes_from_peer": in_b,
    }
    assert conversation_line(row) == (
        f"8.8.8.8:80/tcp — {out_p + in_p} pkts, {out_b + in_b} bytes: "
        f"10.0.0.2 sent {out_p} pkts, {out_b} bytes; 8.8.8.8 sent {in_p} pkts, {in_b} bytes"
    )


def test_a_flow_the_peer_alone_sent_says_the_other_way_carried_none(tmp_path: Path) -> None:
    records = [(float(i), _udp(PEER, GUEST, 6000, 40000, b"push")) for i in range(3)]
    row = _facts(tmp_path, records)["conversations"][0]
    assert row["inbound_only"] is True
    assert (row["packets_to_peer"], row["bytes_to_peer"]) == (0, 0)
    assert conversation_line(row) == (
        "8.8.8.8:6000/udp — 3 pkts, 96 bytes: 8.8.8.8 sent 3 pkts, 96 bytes to 10.0.0.2 "
        "(inbound only)"
    )


def test_a_flow_the_guest_alone_sent_says_the_peer_sent_none(tmp_path: Path) -> None:
    records = [(float(i), _udp(GUEST, PEER, 40000, 9, b"abc")) for i in range(2)]
    row = _facts(tmp_path, records)["conversations"][0]
    assert "inbound_only" not in row
    assert conversation_line(row) == (
        "8.8.8.8:9/udp — 2 pkts, 62 bytes: 10.0.0.2 sent 2 pkts, 62 bytes; 8.8.8.8 sent none"
    )


def test_two_internal_ends_of_one_conversation_are_both_named(tmp_path: Path) -> None:
    records = [
        (0.0, _udp(GUEST, PEER, 40000, 53, b"q")),
        (1.0, _udp(OTHER_GUEST, PEER, 40001, 53, b"q")),
        (2.0, _udp(PEER, OTHER_GUEST, 53, 40001, b"answer")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert row["internal"] == ["10.0.0.2", "10.0.0.3"]
    assert (row["internal_to_peer"], row["internal_from_peer"]) == (
        ["10.0.0.2", "10.0.0.3"],
        ["10.0.0.3"],
    )
    # 10.0.0.2 only asked: the peer's direction names 10.0.0.3, the one it answered.
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 3 pkts, 92 bytes: 10.0.0.2 and 10.0.0.3 sent 2 pkts, 58 bytes; "
        "8.8.8.8 sent 1 pkts, 34 bytes to 10.0.0.3"
    )
    _no_address_credited_with_traffic_it_did_not_send(row, records)


def test_the_internal_ends_are_listed_in_address_order(tmp_path: Path) -> None:
    tenth, ninth = b"\x0a\x00\x00\x0a", b"\x0a\x00\x00\x09"
    records = [
        (0.0, _udp(tenth, PEER, 40000, 53, b"q")),
        (1.0, _udp(ninth, PEER, 40001, 53, b"q")),
    ]
    assert _facts(tmp_path, records)["conversations"][0]["internal"] == ["10.0.0.9", "10.0.0.10"]


def test_the_directions_add_up_to_the_conversation(tmp_path: Path) -> None:
    records = [
        *_download(50000),
        (1.0, _udp(GUEST, PEER, 40000, 53, b"q")),
        (1.1, _udp(PEER, GUEST, 53, 40000, b"answer")),
        (2.0, _udp(PUBLIC, PEER, 7000, 53, b"q")),
    ]
    for row in _facts(tmp_path, records)["conversations"]:
        packets = row["packets_to_peer"] + row["packets_from_peer"]
        size = row["bytes_to_peer"] + row["bytes_from_peer"]
        packets += row.get("packets_public_to_peer", 0)
        size += row.get("bytes_public_to_peer", 0)
        assert (packets, size) == (row["packets"], row["bytes"]), row


# ----------------------------------------------- a capture with no internal end


def test_a_capture_with_no_internal_end_says_so(tmp_path: Path) -> None:
    records = [(float(i), _udp(PUBLIC, PEER, 7000, 53, b"q")) for i in range(2)]
    row = _facts(tmp_path, records)["conversations"][0]
    assert row["internal"] == []
    assert (row["packets_to_peer"], row["packets_from_peer"]) == (0, 0)
    assert row["public_senders"] == ["1.2.3.4"]
    # The peer sent nothing: a public sender talking to it is no inbound-only flow.
    assert "inbound_only" not in row
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 58 bytes: no internal end in the capture; "
        "1.2.3.4 sent 2 pkts, 58 bytes"
    )


def test_a_public_sender_beside_the_guest_is_named_apart(tmp_path: Path) -> None:
    records = [
        (0.0, _udp(GUEST, PEER, 40000, 53, b"q")),
        (1.0, _udp(PUBLIC, PEER, 7000, 53, b"qq")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 59 bytes: 10.0.0.2 sent 1 pkts, 29 bytes; "
        "8.8.8.8 sent none to 10.0.0.2; 1.2.3.4 sent 1 pkts, 30 bytes"
    )


# ---------------------------------------- each direction names who sent in it

_SENT = re.compile(r"(?:^|: |; )((?:[0-9.]+)(?: and [0-9.]+)*) sent (\d+) pkts, (\d+) bytes")


def _no_address_credited_with_traffic_it_did_not_send(
    row: dict[str, Any], records: list[tuple[float, bytes]]
) -> None:
    """Each "<addresses> sent K pkts, B bytes" of the line is what those addresses sent in it."""
    peer, port = bytes(int(x) for x in row["dst"].split(".")), row["dport"]
    # A packet is the conversation's when it goes to the peer's port, or comes
    # from it to an address that is not public (to a public one it is that one's).
    ours = [
        f
        for _, f in records
        if (f[16:20] == peer and int.from_bytes(f[22:24], "big") == port)
        or (
            f[12:16] == peer
            and int.from_bytes(f[20:22], "big") == port
            and not ipaddress.ip_address(f[16:20]).is_global
        )
    ]
    said = _SENT.findall(conversation_line(row))
    assert said, conversation_line(row)
    for named, packets, size in said:
        senders = {bytes(int(x) for x in ip.split(".")) for ip in named.split(" and ")}
        assert all(any(f[12:16] == ip for f in ours) for ip in senders), (named, row)
        frames = [f for f in ours if f[12:16] in senders]
        assert (len(frames), sum(len(f) for f in frames)) == (int(packets), int(size)), named


def test_an_end_that_only_received_is_named_as_the_peer_s_receiver(tmp_path: Path) -> None:
    records = [
        (0.0, _udp(GUEST, PEER, 1000, 53, b"q")),
        (1.0, _udp(PEER, OTHER_GUEST, 53, 1000, b"r" * 100)),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 157 bytes: 10.0.0.2 sent 1 pkts, 29 bytes; "
        "8.8.8.8 sent 1 pkts, 128 bytes to 10.0.0.3"
    )
    _no_address_credited_with_traffic_it_did_not_send(row, records)


def test_a_broadcast_the_peer_sent_to_is_no_sender(tmp_path: Path) -> None:
    broadcast = b"\xff\xff\xff\xff"
    records = [
        (0.0, _udp(GUEST, b"\xe0\x00\x00\xfb", 5353, 5353, b"q")),
        (0.0, _udp(GUEST, broadcast, 68, 67, b"q")),
        (0.0, _udp(PEER, broadcast, 68, 67, b"q")),
    ]
    (row,) = _facts(tmp_path, records)["conversations"]
    assert conversation_line(row) == (
        "8.8.8.8:68/udp — 1 pkts, 29 bytes: 8.8.8.8 sent 1 pkts, 29 bytes to "
        "255.255.255.255 (inbound only)"
    )
    _no_address_credited_with_traffic_it_did_not_send(row, records)


def test_an_end_that_sent_nothing_beside_a_public_sender_is_said_to_send_nothing_back(
    tmp_path: Path,
) -> None:
    records = [
        (0.0, _udp(PUBLIC, PEER, 7000, 53, b"q")),
        (1.0, _udp(PEER, GUEST, 53, 40000, b"push")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert "inbound_only" not in row
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 61 bytes: 8.8.8.8 sent 1 pkts, 32 bytes to 10.0.0.2 "
        "(none back); 1.2.3.4 sent 1 pkts, 29 bytes"
    )
    _no_address_credited_with_traffic_it_did_not_send(row, records)


def test_the_peer_s_receiver_is_named_beside_a_public_sender(tmp_path: Path) -> None:
    # The peer answered the guest and the public sender both: its answer to the
    # public one is that one's own conversation, so this line says whom it answered.
    records = [
        (0.0, _udp(GUEST, PEER, 1000, 53, b"q")),
        (0.1, _udp(PUBLIC, PEER, 1000, 53, b"q")),
        (0.2, _udp(PEER, GUEST, 53, 1000, b"r")),
        (0.3, _udp(PEER, PUBLIC, 53, 1000, b"r")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 3 pkts, 87 bytes: 10.0.0.2 sent 1 pkts, 29 bytes; "
        "8.8.8.8 sent 1 pkts, 29 bytes to 10.0.0.2; 1.2.3.4 sent 1 pkts, 29 bytes"
    )
    _no_address_credited_with_traffic_it_did_not_send(row, records)


def test_a_direction_of_empty_packets_is_not_none() -> None:
    # Packets with no byte counted (an empty record) are still packets sent.
    row = {
        "dst": "8.8.8.8", "dport": 53, "proto": "udp", "packets": 3, "bytes": 29,
        "internal": ["10.0.0.2"], "packets_to_peer": 1, "bytes_to_peer": 29,
        "packets_from_peer": 2, "bytes_from_peer": 0,
    }  # fmt: skip
    assert conversation_line(row).endswith("; 8.8.8.8 sent 2 pkts, 0 bytes")


# ------------------------------------------------------- no line says "host"


def test_no_text_of_the_summary_says_host(tmp_path: Path) -> None:
    records = [
        *_download(50000),
        *[(10.0 * i, _udp(GUEST, PEER, 40000, 53, b"q")) for i in range(5)],
        *[(float(i), _udp(PEER, GUEST, 6000, 40000, b"push")) for i in range(3)],
    ]
    facts = _facts(tmp_path, records)
    text = summary_text(facts)
    assert (
        "External conversations (all 3, by volume; each names its two ends and the bytes "
        "each sent):"
    ) in text
    assert re.search(r"\bhost\b", text) is None, text
    assert not any("host" in key for row in facts["conversations"] for key in row)


# ---------------------------------------------- a record stored with old keys

_OLD_ROWS = [
    {"dst": "93.123.17.252", "dport": 80, "proto": "tcp", "packets": 103, "bytes": 87527,
     "packets_from_host": 65, "bytes_from_host": 84775},
    {"dst": "8.8.4.4", "dport": 6000, "proto": "udp", "packets": 3, "bytes": 96,
     "packets_from_host": 3, "bytes_from_host": 96, "inbound_only": True},
    {"dst": "8.8.8.8", "dport": 9, "proto": "udp", "packets": 2, "bytes": 62},
]  # fmt: skip
_OLD_LINES = [
    "93.123.17.252:80/tcp — 103 pkts, 87527 bytes: 93.123.17.252 was sent 38 pkts, 2752 bytes "
    "and sent 65 pkts, 84775 bytes; the other end is not recorded",
    "8.8.4.4:6000/udp — 3 pkts, 96 bytes: 8.8.4.4 was sent none and sent 3 pkts, 96 bytes "
    "(inbound only); the other end is not recorded",
    "8.8.8.8:9/udp — 2 pkts, 62 bytes: 8.8.8.8 was sent 2 pkts, 62 bytes; what it sent and "
    "the other end are not recorded",
]
# The text the summary's writer stored with those rows, its protocols and TLS names in the
# writer's order; the record holds them in the order a JSON store keeps keys, not that one.
_OLD_SUMMARY = "\n".join(
    [
        "#### Packet Capture Analysis (deterministic, whole capture):",
        "1162 of 1162 packets in the capture read: 900000 bytes over 576.0s. Protocols: "
        "other=2, tcp=1150, udp=10",
        "",
        "External conversations (all 3, by volume):",
        "- 93.123.17.252:80/tcp — 103 pkts, 87527 bytes (65 pkts, 84775 bytes from the host)",
        "- 8.8.4.4:6000/udp — 3 pkts, 96 bytes (3 pkts, 96 bytes from the host; inbound only)",
        "- 8.8.8.8:9/udp — 2 pkts, 62 bytes",
        "",
        "TLS SNI (encrypted destinations):",
        "- a.example (3 ClientHello)",
        "- zz.io (1 ClientHello)",
        "",
        "Beaconing detected (periodic callbacks — strong C2 signal):",
        "- 93.123.17.252:80/tcp — 12 connections opened, ~30.0s interval (regular; likely C2 "
        "beacon)",
    ]
)


def _old_record() -> dict[str, Any]:
    return {
        "summary": _OLD_SUMMARY,
        "empty": False,
        "packets_read": 1162,
        "packets_in_capture": 1162,
        "packet_limit": None,
        "bytes": 900000,
        "duration_s": 576.0,
        "protocols": {"tcp": 1150, "udp": 10, "other": 2},
        "conversations": [dict(row) for row in _OLD_ROWS],
        "sni": {"zz.io": 1, "a.example": 3},
        "beacons": [
            {"dst": "93.123.17.252", "dport": 80, "proto": "tcp", "callbacks": 12,
             "interval_s": 30.0, "unit": "connection"},
        ],
    }  # fmt: skip


def beside_the_flows(text: str) -> list[str]:
    """``text``'s lines with its conversation lines and their heading taken out."""
    out: list[str] = []
    listing = False
    for line in text.split("\n"):
        if line.startswith("External conversations ("):
            listing = True
            continue
        if listing and line.startswith("- "):
            continue
        listing = False
        out.append(line)
    return out


def _entry(record: dict[str, Any]) -> Any:
    from malspark.schemas.evidence import build_entry, format_entry_id

    return build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="network",
        tool="pcap_summary",
        args={},
        server=None,
        output=json.dumps(record),
    )


def _section(record: dict[str, Any]) -> str:
    from malspark.reporting.ledger_report import build_sections

    return {s.key: s for s in build_sections([_entry(record)])}["pcap_summary"].text


def test_an_old_record_s_line_gives_the_peer_s_share_as_the_peer_s() -> None:
    assert [conversation_line(row) for row in _OLD_ROWS] == _OLD_LINES


def test_a_record_that_counted_only_toward_the_peer_says_nothing_of_what_it_sent() -> None:
    # Before the replies were counted, a row held the packets toward the peer
    # alone: the peer's packets were not read, so they are not "none".
    line = conversation_line(_OLD_ROWS[2])
    assert re.search(r"8\.8\.8\.8 sent (\d|none)", line) is None
    assert "none" not in line
    assert line.endswith(
        "8.8.8.8 was sent 2 pkts, 62 bytes; what it sent and the other end are not recorded"
    )


def test_a_rebuilt_record_differs_from_its_stored_text_only_in_its_flow_lines() -> None:
    record = _old_record()
    rebuilt = summary_text(record)
    assert len(rebuilt.split("\n")) == len(_OLD_SUMMARY.split("\n"))
    assert beside_the_flows(rebuilt) == beside_the_flows(_OLD_SUMMARY)
    flows = [line for line in rebuilt.split("\n") if line.startswith("- ") and " — " in line]
    assert flows[:3] == [f"- {line}" for line in _OLD_LINES]


def test_the_report_prints_an_old_record_truthfully() -> None:
    text = _section(_old_record())
    assert "from the host" not in text
    for line in _OLD_LINES:
        assert f"- {line}" in text
    # Its overview, TLS names and beacons are the lines the writer stored.
    assert beside_the_flows(text) == beside_the_flows(_OLD_SUMMARY)


def test_a_record_without_the_capture_s_counts_prints_its_stored_text() -> None:
    # Recorded before the summary carried how much of the capture it read: its
    # conversations are no whole set of facts, so its own text is printed.
    record = {key: value for key, value in _old_record().items() if key != "packets_read"}
    assert _section(record) == _OLD_SUMMARY


def test_the_triage_pack_prints_an_old_record_truthfully() -> None:
    from malspark.pipeline.triage_pack import _pcap

    line = _pcap(_old_record())
    assert "host" not in line
    assert " | ".join(_OLD_LINES) in line


def test_the_triage_pack_parts_its_conversations_by_a_mark_no_line_holds(tmp_path: Path) -> None:
    from malspark.pipeline.triage_pack import _pcap

    pushed = [(1.0 + i, _udp(PEER, GUEST, 6000, 1, b"p")) for i in range(2)]
    records = [*_download(), *pushed, (5.0, _udp(PUBLIC, PEER, 7000, 53, b"q"))]
    facts = _facts(tmp_path, records)
    lines = [conversation_line(row) for row in facts["conversations"]]
    assert len(lines) == 3
    assert not any("|" in line for line in lines)
    rows = _pcap(facts).split(" by volume: ", 1)[1].rsplit("; contacts at a regular", 1)[0]
    assert rows.split(" | ") == lines


# ----------------------------------- a section over its cap leaves out flows


def _busy_record(conversations: int) -> dict[str, Any]:
    record = _old_record()
    record["conversations"] = [
        {"dst": f"198.51.{i // 250}.{i % 250 + 1}", "dport": 443, "proto": "tcp",
         "packets": 1000 - i, "bytes": 100_000 - i, "internal": ["10.0.0.2"],
         "packets_to_peer": 400, "bytes_to_peer": 40_000 - i,
         "packets_from_peer": 600 - i, "bytes_from_peer": 60_000}
        for i in range(conversations)
    ]  # fmt: skip
    return record


def _capture_cap() -> int:
    from malspark.reporting import ledger_report

    return int(ledger_report.CAPTURE_TEXT_CHARS)


def _flows(text: str) -> list[str]:
    return [line for line in text.split("\n") if line.startswith("- ") and " pkts, " in line]


def _left_out(kind: str, rest: int) -> str:
    said = f"{rest:,} more {kind} not shown here"
    return f"{said}; the evidence endpoint carries every one under ev_0001."


def test_a_section_over_its_cap_leaves_out_flows_and_says_how_many() -> None:
    record = _busy_record(400)
    assert len(summary_text(record)) > _capture_cap()
    text = _section(record)
    assert len(text) <= _capture_cap()
    assert "Cut here" not in text
    shown = [line for line in text.split("\n") if line.startswith("- 198.51.")]
    lines = [f"- {conversation_line(row)}" for row in record["conversations"]]
    assert shown == lines[: len(shown)]
    assert 0 < len(shown) < 400
    assert f"External conversations ({len(shown)} of 400, by volume;" in text
    assert _left_out("conversations", 400 - len(shown)) in text
    # One more conversation would not have fitted.
    rest = 400 - len(shown) - 1
    assert len(summary_text(record, len(shown) + 1, _left_out("conversations", rest))) > (
        _capture_cap()
    )
    # The overview, the TLS names and the beacons are never what is cut.
    kept = [line for line in beside_the_flows(text) if "more conversations not shown" not in line]
    assert kept == beside_the_flows(_OLD_SUMMARY)


def test_a_section_within_its_cap_lists_every_flow() -> None:
    record = _busy_record(10)
    text = _section(record)
    assert text == summary_text(record)
    assert "External conversations (all 10, by volume;" in text


# --------------------------- what dev printed whole is printed whole, and the cut order


def _reviewer_facts(
    flows: int, names: int, beacons: int, most: int = 900, unanswered: int = 0
) -> dict[str, Any]:
    """A capture of ``flows`` conversations of up to ``most`` packets each way (every
    ``unanswered``-th one never answered), ``names`` TLS names and ``beacons`` beacons."""
    rng = random.Random(1)
    rows = []
    for at in range(flows):
        to_p, from_p = rng.randint(5, most), rng.randint(5, most)
        from_p = 0 if unanswered and at % unanswered == 0 else from_p
        to_b, from_b = to_p * rng.randint(60, 200), from_p * rng.randint(60, 1400)
        peer = ".".join(
            str(n)
            for n in (
                rng.randint(11, 223),
                rng.randint(0, 255),
                rng.randint(0, 255),
                rng.randint(1, 254),
            )
        )
        rows.append(
            {"dst": peer, "dport": 443, "proto": "tcp", "packets": to_p + from_p,
             "bytes": to_b + from_b, "internal": ["192.168.122.10"], "packets_to_peer": to_p,
             "bytes_to_peer": to_b, "packets_from_peer": from_p, "bytes_from_peer": from_b}
        )  # fmt: skip
    rows.sort(key=lambda row: -row["bytes"])
    facts: dict[str, Any] = {
        "packets_read": 1000, "packets_in_capture": 1000, "packet_limit": None,
        "bytes": 10**6, "duration_s": 600.0, "protocols": {"tcp": 900, "udp": 90, "other": 10},
        "conversations": rows,
        "sni": {f"host{i}.some-long-cdn-name.example.net": i + 1 for i in range(names)},
        "beacons": [
            {"dst": rows[0]["dst"], "dport": 443, "proto": "tcp", "callbacks": 30 + i,
             "interval_s": 60.0}
            for i in range(beacons)
        ],
    }  # fmt: skip
    facts["summary"] = summary_text(facts)
    return facts


def _dev_line(row: dict[str, Any]) -> str:
    line = f"- {row['dst']}:{row['dport']}/{row['proto']} — {row['packets']} pkts, "
    line += f"{row['bytes']} bytes"
    if row["packets_from_peer"]:
        line += f" ({row['packets_from_peer']} pkts, {row['bytes_from_peer']} bytes from the host)"
    return line


def _dev_text(facts: dict[str, Any]) -> str:
    """The summary as dev wrote it: the peer's share "from the host" after the totals."""
    dev = {f"- {conversation_line(row)}": _dev_line(row) for row in facts["conversations"]}
    lines = []
    for line in summary_text(facts).split("\n"):
        if line.startswith("External conversations ("):
            line = line.split(";", 1)[0] + "):"
        lines.append(dev.get(line, line))
    return "\n".join(lines)


def _every_block(facts: dict[str, Any], text: str) -> None:
    assert _flows(text) == [f"- {conversation_line(row)}" for row in facts["conversations"]]
    assert f"External conversations (all {len(facts['conversations'])}, by volume;" in text
    assert beside_the_flows(text) == beside_the_flows(summary_text(facts))
    assert "not shown" not in text
    assert "Cut here" not in text


@pytest.mark.parametrize(
    ("flows", "names", "beacons", "most", "unanswered"), [(32, 5, 2, 900, 0), (45, 2, 1, 900, 2)]
)
def test_a_capture_dev_printed_whole_is_printed_whole(
    flows: int, names: int, beacons: int, most: int, unanswered: int
) -> None:
    from malspark.reporting.ledger_report import MAX_TEXT_CHARS

    facts = _reviewer_facts(flows, names, beacons, most, unanswered)
    assert len(_dev_text(facts)) <= MAX_TEXT_CHARS  # dev printed this capture whole
    _every_block(facts, _section(facts))


def test_thirty_flows_and_ninety_names_are_printed_whole() -> None:
    facts = _reviewer_facts(30, 90, 2)
    _every_block(facts, _section(facts))


def test_past_the_cap_the_flows_go_first_then_the_names_never_the_beacons() -> None:
    facts = _reviewer_facts(30, 400, 2)
    text = _section(facts)
    assert len(text) <= _capture_cap()
    assert _flows(text) == []
    assert "External conversations (0 of 30, by volume;" in text
    assert _left_out("conversations", 30) in text
    names = [line for line in text.split("\n") if line.endswith(" ClientHello)")]
    assert 0 < len(names) < 400
    assert (
        names == [f"- {n} ({c} ClientHello)" for n, c in sorted(facts["sni"].items())][: len(names)]
    )
    assert _left_out("TLS names", 400 - len(names)) in text
    beacons = [line for line in text.split("\n") if "likely C2 beacon" in line]
    assert len(beacons) == 2
    overview = summary_text(facts).split("\n")[:2]
    assert text.split("\n")[:2] == overview
    # One more name would not have fitted.
    from malspark.reporting.ledger_report import CONVERSATIONS_LEFT_OUT, NAMES_LEFT_OUT

    more = summary_text(
        facts,
        0,
        CONVERSATIONS_LEFT_OUT.format(rest=30, ids="ev_0001"),
        len(names) + 1,
        NAMES_LEFT_OUT.format(rest=400 - len(names) - 1, ids="ev_0001"),
    )
    assert len(more) > _capture_cap()


def _most() -> int:
    from malspark.reporting import ledger_report

    return int(ledger_report.CAPTURE_TEXT_MOST)


def _short_facts(rows: list[dict[str, Any]], beacons: int = 0) -> dict[str, Any]:
    return {
        "packets_read": 10, "packets_in_capture": 10, "packet_limit": None, "bytes": 10,
        "duration_s": 1.0, "protocols": {"tcp": 1}, "conversations": rows, "sni": {},
        "beacons": [
            {"dst": row["dst"], "dport": row["dport"], "proto": row["proto"], "callbacks": 9,
             "interval_s": 60.0}
            for row in rows[:beacons]
        ],
        "summary": "x",
    }  # fmt: skip


def _outbound_only(flows: int, ends: int) -> dict[str, Any]:
    """``flows`` peers each sent one datagram by ``ends`` internal ends, never answered."""
    internal = [f"192.168.{100 + j}.{200 + j}" for j in range(ends)]
    return _short_facts(
        [
            {"dst": f"1.1.{i // 250}.{i % 250 + 1}", "dport": 1, "proto": "udp", "packets": 1,
             "bytes": 9, "internal": internal, "packets_to_peer": 1, "bytes_to_peer": 9,
             "packets_from_peer": 0, "bytes_from_peer": 0}
            for i in range(flows)
        ]
    )  # fmt: skip


def test_the_old_form_is_measured_as_dev_wrote_it() -> None:
    from malspark.reporting.ledger_report import _old_form_chars

    for facts in (
        _reviewer_facts(32, 5, 2),
        _reviewer_facts(45, 2, 1, 900, 2),
        _outbound_only(9, 3),
    ):
        assert _old_form_chars(facts, summary_text(facts)) == len(_dev_text(facts))
    record = _old_record()
    assert _old_form_chars(record, summary_text(record)) == len(_OLD_SUMMARY)


def test_a_capture_the_old_line_fitted_is_printed_whole_past_the_room() -> None:
    from malspark.reporting.ledger_report import MAX_TEXT_CHARS

    facts = _outbound_only(107, 3)
    assert len(_dev_text(facts)) <= MAX_TEXT_CHARS  # dev printed it whole
    assert len(summary_text(facts)) > _capture_cap()  # the new line does not fit the room
    _every_block(facts, _section(facts))


def test_a_capture_the_old_line_did_not_fit_is_fitted_to_the_room() -> None:
    from malspark.reporting.ledger_report import MAX_TEXT_CHARS

    facts = _outbound_only(130, 3)
    assert len(_dev_text(facts)) > MAX_TEXT_CHARS
    text = _section(facts)
    assert len(text) <= _capture_cap()
    assert 0 < len(_flows(text)) < 130


def test_beacons_past_the_room_keep_those_of_the_heaviest_conversations() -> None:
    rows = [
        {"dst": f"1.{i // 62500}.{i // 250 % 250}.{i % 250 + 1}", "dport": 443, "proto": "tcp",
         "packets": 10, "bytes": 10_000 - i, "internal": ["10.0.0.2"], "packets_to_peer": 5,
         "bytes_to_peer": 500, "packets_from_peer": 5, "bytes_from_peer": 9_500 - i}
        for i in range(3000)
    ]  # fmt: skip
    facts = _short_facts(rows, beacons=3000)
    facts["beacons"].reverse()  # the writer's order is not the conversations' weight
    text = _section(facts)
    assert len(text) <= _capture_cap()
    lines = text.split("\n")
    assert lines[:2] == summary_text(facts).split("\n")[:2]  # the overview is never cut
    assert _flows(text) == []
    assert _left_out("conversations", 3000) in text
    shown = [line for line in lines if "likely C2 beacon" in line]
    assert 0 < len(shown) < 3000
    assert _left_out("beacons", 3000 - len(shown)) in text
    # Those of the heaviest conversations, in the writer's order.
    heaviest = {row["dst"] for row in rows[: len(shown)]}
    assert {line[2:].split(":", 1)[0] for line in shown} == heaviest
    assert [line[2:].split(":", 1)[0] for line in shown] == [
        b["dst"] for b in facts["beacons"] if b["dst"] in heaviest
    ]
    # One more beacon would not have fitted.
    from malspark.reporting.ledger_report import (
        BEACONS_LEFT_OUT,
        CONVERSATIONS_LEFT_OUT,
        NAMES_LEFT_OUT,
    )

    more = {row["dst"] for row in rows[: len(shown) + 1]}
    longer = summary_text(
        {**facts, "beacons": [b for b in facts["beacons"] if b["dst"] in more]},
        0,
        CONVERSATIONS_LEFT_OUT.format(rest=3000, ids="ev_0001"),
        0,
        NAMES_LEFT_OUT.format(rest=0, ids="ev_0001"),
        BEACONS_LEFT_OUT.format(rest=3000 - len(shown) - 1, ids="ev_0001"),
    )
    assert len(longer) > _capture_cap()


def test_no_capture_summary_is_longer_than_its_bound() -> None:
    assert _most() == 40_000
    for facts in (
        _outbound_only(100, 400),  # the old line fitted; the new one is longer than the bound
        _reviewer_facts(30, 400, 2),
        _reviewer_facts(5, 3, 200),
        _outbound_only(107, 3),
    ):
        text = _section(facts)
        assert len(text) <= _most()
        assert text.split("\n")[:2] == summary_text(facts).split("\n")[:2]
    assert len(_section(_outbound_only(100, 400))) <= _capture_cap()


# ----------------------------------------------- one writer, every surface


def test_every_surface_writes_the_conversation_by_the_one_line(tmp_path: Path) -> None:
    from malspark.analysis.pcap_summary import summarize_pcap
    from malspark.pipeline.triage_pack import _pcap
    from malspark.reporting.ledger_report import build_sections
    from malspark.schemas.evidence import build_entry, format_entry_id
    from malspark.tools.pcap import pcap_summary

    pushed = [(1.0 + i, _udp(PEER, GUEST, 6000, 1, b"p")) for i in range(2)]
    path = _write(tmp_path, [*_download(), *pushed])
    answer = pcap_summary(str(path))
    lines = [conversation_line(row) for row in answer["conversations"]]
    assert len(lines) == 2
    entry = build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="network",
        tool="pcap_summary",
        args={},
        server=None,
        output=json.dumps(answer),
    )
    report = {s.key: s for s in build_sections([entry])}["pcap_summary"].text
    for text in (answer["summary"], summarize_pcap(str(path)), report):
        for line in lines:
            assert f"- {line}" in text
    assert " | ".join(lines) in _pcap(answer)
