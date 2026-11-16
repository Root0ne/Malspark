"""A capture's conversation line names both ends of the flow and what each end sent.

The line keyed each conversation on its public end and called that end's share
"from the host". Every reader took "the host" for the sandbox's own machine, the
word the rest of the platform uses for it, so a download read as an upload. The
line now names the internal end, told from the capture by the module's own
internal/external rule, and the public peer, and states the packets and bytes
each of them sent. A capture that gives no internal end says so, and a record
stored with the old keys is printed with the peer's share as the peer's.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

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
        f"10.0.0.2 → 8.8.8.8 {out_p} pkts, {out_b} bytes; "
        f"8.8.8.8 → 10.0.0.2 {in_p} pkts, {in_b} bytes"
    )


def test_a_flow_the_peer_alone_sent_says_the_other_way_carried_none(tmp_path: Path) -> None:
    records = [(float(i), _udp(PEER, GUEST, 6000, 40000, b"push")) for i in range(3)]
    row = _facts(tmp_path, records)["conversations"][0]
    assert row["inbound_only"] is True
    assert (row["packets_to_peer"], row["bytes_to_peer"]) == (0, 0)
    assert conversation_line(row) == (
        "8.8.8.8:6000/udp — 3 pkts, 96 bytes: 10.0.0.2 → 8.8.8.8 none; "
        "8.8.8.8 → 10.0.0.2 3 pkts, 96 bytes (inbound only)"
    )


def test_a_flow_the_guest_alone_sent_says_the_peer_sent_none(tmp_path: Path) -> None:
    records = [(float(i), _udp(GUEST, PEER, 40000, 9, b"abc")) for i in range(2)]
    row = _facts(tmp_path, records)["conversations"][0]
    assert "inbound_only" not in row
    assert conversation_line(row) == (
        "8.8.8.8:9/udp — 2 pkts, 62 bytes: 10.0.0.2 → 8.8.8.8 2 pkts, 62 bytes; "
        "8.8.8.8 → 10.0.0.2 none"
    )


def test_two_internal_ends_of_one_conversation_are_both_named(tmp_path: Path) -> None:
    records = [
        (0.0, _udp(GUEST, PEER, 40000, 53, b"q")),
        (1.0, _udp(OTHER_GUEST, PEER, 40001, 53, b"q")),
        (2.0, _udp(PEER, OTHER_GUEST, 53, 40001, b"answer")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert row["internal"] == ["10.0.0.2", "10.0.0.3"]
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 3 pkts, 92 bytes: 10.0.0.2 and 10.0.0.3 → 8.8.8.8 2 pkts, 58 bytes; "
        "8.8.8.8 → 10.0.0.2 and 10.0.0.3 1 pkts, 34 bytes"
    )


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
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 58 bytes: no internal end in the capture; "
        "1.2.3.4 → 8.8.8.8 2 pkts, 58 bytes"
    )


def test_a_public_sender_beside_the_guest_is_named_apart(tmp_path: Path) -> None:
    records = [
        (0.0, _udp(GUEST, PEER, 40000, 53, b"q")),
        (1.0, _udp(PUBLIC, PEER, 7000, 53, b"qq")),
    ]
    row = _facts(tmp_path, records)["conversations"][0]
    assert conversation_line(row) == (
        "8.8.8.8:53/udp — 2 pkts, 59 bytes: 10.0.0.2 → 8.8.8.8 1 pkts, 29 bytes; "
        "8.8.8.8 → 10.0.0.2 none; 1.2.3.4 → 8.8.8.8 1 pkts, 30 bytes"
    )


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
    "93.123.17.252:80/tcp — 103 pkts, 87527 bytes: toward 93.123.17.252 38 pkts, 2752 bytes; "
    "from 93.123.17.252 65 pkts, 84775 bytes; the record does not name the internal end",
    "8.8.4.4:6000/udp — 3 pkts, 96 bytes: toward 8.8.4.4 none; from 8.8.4.4 3 pkts, 96 bytes "
    "(inbound only); the record does not name the internal end",
    "8.8.8.8:9/udp — 2 pkts, 62 bytes: toward 8.8.8.8 2 pkts, 62 bytes; the record does not "
    "state what 8.8.8.8 sent or name the internal end",
]


def _old_record() -> dict[str, Any]:
    return {
        "summary": "#### Packet Capture Analysis (deterministic, whole capture):\n"
        "1162 of 1162 packets in the capture read: 900000 bytes over 576.0s. Protocols: tcp=1162"
        "\n\nExternal conversations (all 3, by volume):\n"
        "- 93.123.17.252:80/tcp — 103 pkts, 87527 bytes (65 pkts, 84775 bytes from the host)",
        "empty": False,
        "packets_read": 1162,
        "packets_in_capture": 1162,
        "packet_limit": None,
        "bytes": 900000,
        "duration_s": 576.0,
        "protocols": {"tcp": 1162},
        "conversations": [dict(row) for row in _OLD_ROWS],
        "sni": {},
        "beacons": [],
    }


def test_an_old_record_s_line_gives_the_peer_s_share_as_the_peer_s() -> None:
    assert [conversation_line(row) for row in _OLD_ROWS] == _OLD_LINES


def test_a_record_that_counted_only_toward_the_peer_says_nothing_of_what_it_sent() -> None:
    # Before the replies were counted, a row held the packets toward the peer
    # alone: the peer's packets were not read, so they are not "none".
    line = conversation_line(_OLD_ROWS[2])
    assert "from 8.8.8.8" not in line
    assert "none" not in line
    assert "does not state what 8.8.8.8 sent" in line


def test_the_report_prints_an_old_record_truthfully() -> None:
    from malspark.reporting.ledger_report import build_sections
    from malspark.schemas.evidence import build_entry, format_entry_id

    entry = build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="network",
        tool="pcap_summary",
        args={},
        server=None,
        output=json.dumps(_old_record()),
    )
    section = {s.key: s for s in build_sections([entry])}["pcap_summary"]
    assert "from the host" not in section.text
    for line in _OLD_LINES:
        assert f"- {line}" in section.text


def test_the_triage_pack_prints_an_old_record_truthfully() -> None:
    from malspark.pipeline.triage_pack import _pcap

    line = _pcap(_old_record())
    assert "host" not in line
    assert ", ".join(_OLD_LINES) in line


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
    assert ", ".join(lines) in _pcap(answer)
