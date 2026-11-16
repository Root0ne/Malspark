"""Deterministic whole-capture analysis for the network analyst.

The structured CAPE ``network`` block (dns/tcp/udp/hosts) lists *what* was
contacted, but not the packet-level dynamics — regular callback intervals
(C2 beaconing), byte volumes (exfiltration), or the encrypted destination
names inside TLS ClientHello (SNI). Those live only in the raw PCAP.

The capture is read once, as a stream: one packet in memory at a time, and
every packet in the file unless a caller asked for fewer. A count that stops
early is not a picture of the capture — one live capture held 14,887 packets
and the network server read the first 5,000 of them — so every answer carries
how many packets were read and how many the capture holds.

``capture_facts(path)`` is the structured view (counts, protocols, every
external conversation, SNI names, beacons); ``summarize_pcap(path)`` is the
same facts as a text block. Both are best-effort and side-effect free: a file
that cannot be read as a capture returns ``None``. The capture is read by
``analysis.capture_reader``.
"""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from malspark.analysis.capture_reader import Capture, Packet, ReadNotes
from malspark.core.logger import logger
from malspark.utils.written_forms import pack_escaped

# Beaconing: a destination contacted at least this many times with a stable
# inter-arrival interval (coefficient of variation below the threshold) is a
# regular callback — the classic C2 heartbeat the structured block can't show.
_BEACON_MIN_HITS = 4
_BEACON_MAX_CV = 0.35
_BEACON_MIN_INTERVAL_S = 1.0


@dataclass
class CaptureRead:
    """How much of one capture a reader read: the fact every answer states.

    ``limit`` is the caller's own, and ``None`` when it gave none — a read with
    no limit reads the whole capture. The rest is what the reader had to skip
    or where it stopped (``capture_reader.ReadNotes``): pcapng blocks it could
    not read, by kind of reason; the byte cap a gzip capture reached; where a
    gzip stream could not be decompressed further; where the capture's framing
    ended before the file did, and why; records whose headers could
    not be walked to the end. A surface adds what it could not extract: DNS
    names longer than DNS allows, and values it could not write. Each appears
    in the fields only when it happened, and the statement grows with the
    kinds of what happened, never with how many times.
    """

    packets_read: int = 0
    packets_in_capture: int = 0
    limit: int | None = None
    blocks_unreadable: int = 0
    unreadable_reasons: dict[str, dict[str, Any]] = field(default_factory=dict)
    byte_cap: int | None = None
    stream_error: str | None = None
    framing_end: str | None = None
    packets_undecoded: int = 0
    dns_names_malformed: int = 0
    dns_name_octets_first: int = 0
    values_unwritable: int = 0
    unwritable_reason: str = ""

    def note(self, notes: ReadNotes) -> None:
        self.blocks_unreadable = notes.blocks_unreadable
        self.unreadable_reasons = {k: dict(v) for k, v in notes.unreadable_reasons.items()}
        self.byte_cap = notes.byte_cap
        self.stream_error = notes.stream_error
        self.framing_end = notes.framing_end
        self.packets_undecoded = notes.packets_undecoded

    def malformed_dns_name(self, octets: int) -> None:
        if not self.dns_names_malformed:
            self.dns_name_octets_first = octets
        self.dns_names_malformed += 1

    def unwritable(self, exc: BaseException) -> None:
        if not self.values_unwritable:
            self.unwritable_reason = type(exc).__name__
        self.values_unwritable += 1

    @property
    def whole(self) -> bool:
        return (
            self.packets_read >= self.packets_in_capture
            and not self.blocks_unreadable
            and self.byte_cap is None
            and self.stream_error is None
            and self.framing_end is None
        )

    def statement(self) -> str:
        """``"14887 of 14887 packets in the capture read"``, and why fewer when fewer.

        When blocks were skipped, a byte cap stopped the read, a gzip stream
        broke off or the capture's framing ended early, the capture's own count
        is not known, and the statement says
        what was read and why instead: ``"6 packets read, 1 blocks unreadable:
        <reason> (1, the first at byte 72, interface 7)"``.
        """
        partial = (
            self.blocks_unreadable
            or self.byte_cap is not None
            or self.stream_error
            or self.framing_end
        )
        if partial:
            said = f"{self.packets_read} packets read"
        else:
            said = f"{self.packets_read} of {self.packets_in_capture} packets in the capture read"
        if self.packets_read < self.packets_in_capture and self.limit is not None:
            said += f" (the caller asked for {self.limit})"
        if self.blocks_unreadable:
            said += f", {self.blocks_unreadable} blocks unreadable: " + "; ".join(
                f"{reason} ({entry['count']}, the first {entry['first']})"
                for reason, entry in self.unreadable_reasons.items()
            )
        if self.byte_cap is not None:
            said += (
                f", reading stopped at the {self.byte_cap} decompressed bytes the platform "
                "allows a capture"
            )
        if self.stream_error:
            said += f", reading stopped where {self.stream_error}"
        if self.framing_end:
            said += f", reading stopped where {self.framing_end}"
        if self.packets_undecoded:
            said += (
                f", {self.packets_undecoded} of them read only to the headers before "
                "one that could not be decoded"
            )
        if self.dns_names_malformed:
            said += (
                f", {self.dns_names_malformed} DNS question names malformed: longer than "
                f"the 255 octets DNS allows (the first {self.dns_name_octets_first} octets)"
            )
        if self.values_unwritable:
            said += (
                f", {self.values_unwritable} values read but not written ({self.unwritable_reason})"
            )
        return said

    def as_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "packets_read": self.packets_read,
            "packets_in_capture": self.packets_in_capture,
            "packet_limit": self.limit,
        }
        if self.blocks_unreadable:
            fields["blocks_unreadable"] = self.blocks_unreadable
            fields["unreadable_reasons"] = {k: dict(v) for k, v in self.unreadable_reasons.items()}
        if self.byte_cap is not None:
            fields["byte_cap"] = self.byte_cap
        if self.stream_error:
            fields["stream_error"] = self.stream_error
        if self.framing_end:
            fields["framing_end"] = self.framing_end
        if self.packets_undecoded:
            fields["packets_undecoded"] = self.packets_undecoded
        if self.values_unwritable:
            fields["values_unwritable"] = self.values_unwritable
            fields["unwritable_reason"] = self.unwritable_reason
        return fields

    @classmethod
    def from_fields(cls, facts: dict[str, Any]) -> CaptureRead:
        reasons = facts.get("unreadable_reasons")
        return cls(
            packets_read=int(facts.get("packets_read") or 0),
            packets_in_capture=int(facts.get("packets_in_capture") or 0),
            limit=facts.get("packet_limit"),
            blocks_unreadable=int(facts.get("blocks_unreadable") or 0),
            unreadable_reasons=dict(reasons) if isinstance(reasons, dict) else {},
            byte_cap=facts.get("byte_cap"),
            stream_error=facts.get("stream_error"),
            framing_end=facts.get("framing_end"),
            packets_undecoded=int(facts.get("packets_undecoded") or 0),
            values_unwritable=int(facts.get("values_unwritable") or 0),
            unwritable_reason=str(facts.get("unwritable_reason") or ""),
        )


def asked_limit(packet_limit: Any) -> int | None:
    """A caller's packet limit as a positive count, or ``None`` for the whole capture.

    Nothing, zero, a negative number and a value that is not a number all mean
    no limit: a limit applies only when the caller passed one.
    """
    if packet_limit is None or isinstance(packet_limit, bool):
        return None
    try:
        wanted = int(packet_limit)
    except (TypeError, ValueError):
        return None
    return wanted if wanted > 0 else None


def each_packet(
    path: str, visit: Callable[[Packet], None], packet_limit: Any = None
) -> CaptureRead:
    """Call ``visit`` on each packet of the capture at ``path``, in file order.

    A stream: one packet in memory at a time, which is what lets a reader take
    the whole capture instead of a head of it. With a limit the walk stops
    there and the rest are counted without being decoded, so the answer still
    says how many the capture holds. Raises ``CaptureFormatError`` for a file
    that is not a capture.
    """
    limit = asked_limit(packet_limit)
    read = CaptureRead(limit=limit)
    with Capture(path) as capture:
        stream = capture.records()
        rest = 0
        for record in stream:
            if limit is not None and read.packets_read >= limit:
                rest = 1 + sum(1 for _record in stream)
                break
            read.packets_read += 1
            visit(capture.decode(record))
        read.packets_in_capture = read.packets_read + rest
        read.note(capture.notes)
    return read


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_unspecified
    )


def _extract_sni(pkt: Packet) -> bytes | None:
    """Best-effort TLS SNI from a ClientHello, parsed from the raw TCP payload.

    Walks the TLS record -> handshake -> extensions to the server_name and
    answers the name's bytes. Returns None on any shape mismatch — SNI is a
    bonus signal, never a hard dependency.
    """
    try:
        if pkt.tcp is None or not pkt.tcp.data:
            return None
        data: bytes = pkt.tcp.data
        # TLS record: content_type(22=handshake) ver(2) len(2); handshake:
        # type(1=client_hello) len(3) ver(2) random(32) ...
        if len(data) < 45 or data[0] != 0x16 or data[5] != 0x01:
            return None
        idx = 43  # after record(5) + hs header(4) + ver(2) + random(32)
        sid_len = data[idx]
        idx += 1 + sid_len
        cs_len = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2 + cs_len
        comp_len = data[idx]
        idx += 1 + comp_len
        ext_total = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2
        end = min(idx + ext_total, len(data))
        while idx + 4 <= end:
            etype = int.from_bytes(data[idx : idx + 2], "big")
            elen = int.from_bytes(data[idx + 2 : idx + 4], "big")
            idx += 4
            if etype == 0x0000:  # server_name
                # server_name_list(2) + entry: type(1) + name_len(2) + name
                name_len = int.from_bytes(data[idx + 3 : idx + 5], "big")
                name = data[idx + 5 : idx + 5 + name_len]
                return name or None
            idx += elen
    except Exception:
        return None
    return None


def _server_name(name: bytes) -> str:
    """A TLS server name as the sender's text.

    A host name is ASCII (RFC 6066, an A-label for an IDN); a byte outside it
    is written as an escape, not dropped, and the name is written as the
    triage pack writes a sample's strings: control characters escaped.
    """
    return pack_escaped(name.decode("ascii", "backslashreplace"))


def _is_capture_time(value: Any) -> bool:
    """True for a packet time that can be placed: a finite, positive number.

    A corrupt record header can carry NaN, infinity or a negative time; one of
    them would stretch the duration to nonsense and put a gap into every
    beacon interval, so such a packet is counted but never timed.
    """
    return isinstance(value, (int, float)) and math.isfinite(value) and value > 0


class _Span:
    """The capture's earliest and latest packet time: two numbers however long it is."""

    def __init__(self) -> None:
        self.low = 0.0
        self.high = 0.0
        self.timed = 0

    def add(self, t: float) -> None:
        if self.timed == 0:
            self.low = self.high = t
        else:
            self.low = min(self.low, t)
            self.high = max(self.high, t)
        self.timed += 1

    def duration(self) -> float:
        return self.high - self.low if self.timed >= 2 else 0.0


class _Intervals:
    """One conversation's times, read sorted: a capture need not be in time order.

    Linear in the input, as it always was. A multi-interface capture
    interleaves its interfaces, so the times are sorted before the gaps are
    taken; a gap of zero (equal times) is not an interval.
    """

    def __init__(self) -> None:
        self.times: list[float] = []

    def add(self, t: float) -> None:
        self.times.append(t)

    def beacon(self) -> tuple[int, float] | None:
        """``(callbacks, mean interval)`` when the times are a regular callback, else ``None``.

        Regular: at least ``_BEACON_MIN_HITS`` times whose gaps average at least
        ``_BEACON_MIN_INTERVAL_S`` with a coefficient of variation at most
        ``_BEACON_MAX_CV``.
        """
        ts = sorted(self.times)
        if len(ts) < _BEACON_MIN_HITS:
            return None
        deltas = [b - a for a, b in zip(ts, ts[1:], strict=False) if (b - a) > 0]
        if len(deltas) < _BEACON_MIN_HITS - 1:
            return None
        mean = sum(deltas) / len(deltas)
        if mean < _BEACON_MIN_INTERVAL_S:
            return None
        variance = sum((x - mean) ** 2 for x in deltas) / len(deltas)
        if (variance**0.5) / mean <= _BEACON_MAX_CV:
            return len(ts), mean
        return None


def capture_facts(pcap_path: str, packet_limit: Any = None) -> dict[str, Any] | None:
    """The capture's facts as data, or ``None`` when it could not be read.

    Keys: ``packets_read``, ``packets_in_capture``, ``packet_limit`` (the
    caller's, or ``None``), ``bytes``, ``duration_s``, ``protocols`` (count per
    ``tcp``/``udp``/``other`` of the IP packets read), ``conversations`` (every
    external peer and port as ``{dst, dport, proto, packets, bytes}``, both
    directions counted, the heaviest first; ``internal``, the addresses of the
    other end that are not public; ``packets_to_peer``/``bytes_to_peer``, what
    those sent to the peer; ``packets_from_peer``/``bytes_from_peer``, what the
    peer sent them; ``internal_to_peer`` and ``internal_from_peer``, the ones
    that sent to the peer and the ones it sent to, when both directions carried
    packets and those are not the same addresses; ``public_senders`` with
    ``packets_public_to_peer``/``bytes_public_to_peer`` when a public address
    sent to the peer too; and ``inbound_only`` when the peer sent every packet),
    ``sni`` (``{name: ClientHello count}``) and ``beacons`` (``{dst, dport,
    proto, callbacks, interval_s}``, measured on the packets toward the peer;
    when those are not regular, on the TCP connections the other side opened
    toward it, one per SYN source address and port, and then marked ``unit:
    "connection"``).
    """
    span = _Span()
    proto_counts: dict[str, int] = defaultdict(int)
    # (dst, dport, proto) -> {pkts, bytes, times}
    convs: dict[tuple[str, int, str], dict[str, Any]] = {}
    snis: dict[str, int] = defaultdict(int)
    unwritten: list[BaseException] = []
    total_bytes = 0

    def _visit(pkt: Packet) -> None:
        nonlocal total_bytes
        try:
            plen = pkt.length
            total_bytes += plen
            t = pkt.time if _is_capture_time(pkt.time) else 0.0
            if t:
                span.add(t)
            if pkt.ip_dst is None and not pkt.ipv6:
                return
            dst = pkt.ip_dst
            sport = 0
            if pkt.tcp is not None:
                proto = "tcp"
                sport, dport = pkt.tcp.sport, pkt.tcp.dport
                # A ClientHello is recognised by its bytes, not its port: TLS
                # on 8443, 993 or a C2 port names its server the same way.
                name = _extract_sni(pkt)
                if name:
                    try:
                        snis[_server_name(name)] += 1
                    except Exception as exc:  # noqa: BLE001 - one value, counted
                        unwritten.append(exc)
            elif pkt.udp is not None:
                proto = "udp"
                sport, dport = pkt.udp.sport, pkt.udp.dport
            else:
                proto = "other"
                dport = 0
            proto_counts[proto] += 1
            # An IPv6 datagram is counted by its next header; its addresses are
            # not read, so it names no conversation.
            if dst is None:
                return
            # The summary is about the external (C2) surface: a conversation is
            # an external peer and its port, and holds the packets both ways.
            # A packet to an external address is toward it, as it always was;
            # one from an external address to an internal one is from it. The
            # other end is the packet's other address: internal by the same
            # rule, or a public sender when the capture gives no internal one.
            if _is_external(dst):
                key, from_peer, end = (dst, dport, proto), False, pkt.ip_src
            elif pkt.ip_src is not None and _is_external(pkt.ip_src):
                key, from_peer, end = (pkt.ip_src, sport, proto), True, dst
            else:
                return
            c = convs.setdefault(key, _conversation())
            c["pkts"] += 1
            c["bytes"] += plen
            if from_peer:
                c["receivers"].add(end)
                c["pkts_from"] += 1
                c["bytes_from"] += plen
                return
            if end is not None and not _is_external(end):
                c["senders"].add(end)
                c["pkts_to"] += 1
                c["bytes_to"] += plen
            else:
                if end is not None:
                    c["public"].add(end)
                c["pkts_public"] += 1
                c["bytes_public"] += plen
            # The beacon is measured on the packets toward the peer, as before,
            # and on the connections the sandbox's side opened toward it: one
            # per source address and port, so a retransmitted SYN is one.
            if t:
                c["times"].add(t)
                if pkt.tcp is not None and pkt.tcp.opens:
                    opener = (pkt.ip_src, sport)
                    if opener not in c["openers"]:
                        c["openers"].add(opener)
                        c["opens"].add(t)
        except Exception:  # noqa: BLE001 — one malformed packet is not a lost capture
            return

    try:
        read = each_packet(pcap_path, _visit, packet_limit)
    except Exception as exc:
        logger.warning("pcap_summary: the capture could not be read (%s).", type(exc).__name__)
        return None
    for failure in unwritten:
        read.unwritable(failure)

    logger.info("pcap_summary: %s", read.statement())

    beacons: list[dict[str, Any]] = []
    for (dst, dport, proto), c in convs.items():
        beacon = c["times"].beacon()
        unit: dict[str, str] = {}
        if beacon is None:
            beacon = c["opens"].beacon()
            unit = {"unit": "connection"}
        if beacon is not None:
            callbacks, interval = beacon
            beacons.append(
                {
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "callbacks": callbacks,
                    "interval_s": round(interval, 1),
                    **unit,
                }
            )

    ranked = sorted(convs.items(), key=lambda kv: kv[1]["bytes"], reverse=True)
    return {
        **read.as_fields(),
        "bytes": total_bytes,
        "duration_s": round(span.duration(), 1),
        "protocols": dict(sorted(proto_counts.items())),
        "conversations": [_conversation_row(key, c) for key, c in ranked],
        "sni": dict(sorted(snis.items())),
        "beacons": beacons,
    }


def _conversation() -> dict[str, Any]:
    return {
        "pkts": 0,
        "bytes": 0,
        "pkts_to": 0,
        "bytes_to": 0,
        "pkts_from": 0,
        "bytes_from": 0,
        "pkts_public": 0,
        "bytes_public": 0,
        "senders": set(),
        "receivers": set(),
        "public": set(),
        "times": _Intervals(),
        "opens": _Intervals(),
        "openers": set(),
    }


def _address_order(ip: str) -> tuple[int, int, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (7, 0, ip)
    return (addr.version, int(addr), ip)


def _addresses(found: set[str]) -> list[str]:
    """The addresses of one end, in address order."""
    return sorted(found, key=_address_order)


def _conversation_row(key: tuple[str, int, str], c: dict[str, Any]) -> dict[str, Any]:
    """One conversation's row: its two ends, and the packets and bytes each sent."""
    dst, dport, proto = key
    row: dict[str, Any] = {
        "dst": dst,
        "dport": dport,
        "proto": proto,
        "packets": c["pkts"],
        "bytes": c["bytes"],
        "internal": _addresses(c["senders"] | c["receivers"]),
    }
    if c["senders"] and c["receivers"] and c["senders"] != c["receivers"]:
        # Each direction is named by its own addresses: one internal end that
        # only asked, or only got, is never said to have done both.
        row["internal_to_peer"] = _addresses(c["senders"])
        row["internal_from_peer"] = _addresses(c["receivers"])
    row.update(
        packets_to_peer=c["pkts_to"],
        bytes_to_peer=c["bytes_to"],
        packets_from_peer=c["pkts_from"],
        bytes_from_peer=c["bytes_from"],
    )
    if c["pkts_public"]:
        row["public_senders"] = _addresses(c["public"])
        row["packets_public_to_peer"] = c["pkts_public"]
        row["bytes_public_to_peer"] = c["bytes_public"]
    if c["pkts_from"] == c["pkts"]:
        # Every packet came from the external peer: the sandbox never sent to
        # it, so it is no peer the sample contacted.
        row["inbound_only"] = True
    return row


def _sent(packets: Any, size: Any) -> str:
    return f"{packets} pkts, {size} bytes" if packets else "none"


def _ends(addresses: Any) -> str:
    return " and ".join(str(ip) for ip in addresses or ())


def conversation_line(row: dict[str, Any]) -> str:
    """One conversation as every surface writes it: its two ends and what each sent.

    ``"<peer>:<port>/<proto> — N pkts, M bytes: <internal> sent K pkts, B
    bytes; <peer> sent K pkts, B bytes"``. Each direction names only the
    addresses that sent in it: the peer's names the internal ends it sent to
    (``to <internal>``) wherever they are not exactly the ones that sent to it,
    and a direction that carried nothing is ``none`` (an internal end that
    sent nothing beside the peer's packets: ``(inbound only)``, or ``(none
    back)`` where a public address sent to the peer). Several addresses are
    joined with ``and``; a public address that sent to the peer is named with
    what it sent, and a conversation with no internal end says so. A row
    recorded before the ends were named (``packets_from_host``, the peer's
    share) says what the peer was sent and sent and that the other end is not
    recorded; one recorded without the peer's share, when only the packets
    toward the peer were counted, says what the peer sent is not recorded.
    """
    peer = row.get("dst")
    line = (
        f"{peer}:{row.get('dport')}/{row.get('proto')} — "
        f"{row.get('packets')} pkts, {row.get('bytes')} bytes: "
    )
    inbound = " (inbound only)" if row.get("inbound_only") else ""
    if "internal" not in row:
        if "packets_from_host" not in row:
            # Counted toward the peer alone, or both ways with nothing from
            # the peer: the totals are what was sent to it either way.
            return line + (
                f"{peer} was sent {_sent(row.get('packets'), row.get('bytes'))}; what it "
                "sent and the other end are not recorded"
            )
        got_p = int(row.get("packets_from_host") or 0)
        got_b = int(row.get("bytes_from_host") or 0)
        sent_p = int(row.get("packets") or 0) - got_p
        sent_b = int(row.get("bytes") or 0) - got_b
        return line + (
            f"{peer} was sent {_sent(sent_p, sent_b)} and sent {_sent(got_p, got_b)}"
            f"{inbound}; the other end is not recorded"
        )
    internal = list(row.get("internal") or ())
    senders = row.get("internal_to_peer", internal if row.get("packets_to_peer") else [])
    receivers = row.get("internal_from_peer", internal if row.get("packets_from_peer") else [])
    public = row.get("packets_public_to_peer")
    parts: list[str] = []
    if senders:
        parts.append(
            f"{_ends(senders)} sent " + _sent(row.get("packets_to_peer"), row.get("bytes_to_peer"))
        )
    if not internal:
        parts.append("no internal end in the capture")
    elif row.get("packets_from_peer"):
        named = f" to {_ends(receivers)}" if receivers != senders or public else ""
        back = "" if senders or inbound else " (none back)"
        parts.append(
            f"{peer} sent "
            + _sent(row.get("packets_from_peer"), row.get("bytes_from_peer"))
            + f"{named}{inbound}{back}"
        )
    else:
        parts.append(f"{peer} sent none" + (f" to {_ends(senders)}" if public else ""))
    if public:
        parts.append(
            f"{_ends(row.get('public_senders')) or 'an address the capture does not give'} "
            f"sent {_sent(public, row.get('bytes_public_to_peer'))}"
        )
    return line + "; ".join(parts)


def summary_text(
    facts: dict[str, Any],
    shown: int | None = None,
    left_out: str = "",
    names_shown: int | None = None,
    names_left_out: str = "",
    beacons_left_out: str = "",
) -> str:
    """The facts as the markdown block the network analyst and the report read.

    The protocols and the TLS names in the writer's order, whatever order a
    stored record keeps its keys in. ``shown`` lists the heaviest ``shown``
    conversations and ends the list with ``left_out``, the sentence saying how
    many are not and where they are; ``names_shown`` and ``names_left_out`` do
    the same for the TLS names. ``beacons_left_out`` ends the beacon list, the
    beacons the facts hold being those it shows. ``None`` lists them all.
    """
    read = CaptureRead.from_fields(facts)
    heading = "#### Packet Capture Analysis (deterministic, whole capture):"
    if not read.whole:
        heading = "#### Packet Capture Analysis (deterministic, part of the capture):"
    protocols = facts.get("protocols") or {}
    overview = (
        f"{read.statement()}: {facts.get('bytes', 0)} bytes over "
        f"{float(facts.get('duration_s') or 0.0):.1f}s. Protocols: "
        + (", ".join(f"{k}={v}" for k, v in sorted(protocols.items())) or "no IP packets")
    )
    conversations = facts.get("conversations") or []
    if not conversations:
        return (
            f"{heading}\n{overview}\nNo external (public) endpoints contacted — traffic "
            "stayed internal to the sandbox."
        )
    listed = conversations if shown is None else conversations[: max(0, shown)]
    counted = (
        f"all {len(conversations)}"
        if len(listed) == len(conversations)
        else f"{len(listed)} of {len(conversations)}"
    )
    out = [
        heading,
        overview,
        "",
        f"External conversations ({counted}, by volume; each names its two ends and the "
        "bytes each sent):",
        *[f"- {conversation_line(row)}" for row in listed],
    ]
    if len(listed) < len(conversations):
        out.append(left_out)
    sni = facts.get("sni") or {}
    if sni:
        out += [
            "",
            "TLS SNI (encrypted destinations):",
            *[
                f"- {name} ({n} ClientHello)"
                for name, n in sorted(sni.items())[
                    : names_shown if names_shown is not None else None
                ]
            ],
        ]
        if names_shown is not None and names_shown < len(sni):
            out.append(names_left_out)
    beacons = facts.get("beacons") or []
    if beacons or beacons_left_out:
        out += [
            "",
            "Beaconing detected (periodic callbacks — strong C2 signal):",
            *[
                f"- {b['dst']}:{b['dport']}/{b['proto']} — {b['callbacks']} "
                + ("connections opened" if b.get("unit") == "connection" else "callbacks")
                + f", ~{b['interval_s']:.1f}s interval (regular; likely C2 beacon)"
                for b in beacons
            ],
        ]
        if beacons_left_out:
            out.append(beacons_left_out)
    else:
        out += ["", "No regular beaconing interval detected in the packets read."]
    return "\n".join(out)


def summarize_pcap(pcap_path: str, packet_limit: Any = None) -> str | None:
    """The whole capture as a markdown block, or ``None`` when it holds no packet."""
    facts = capture_facts(pcap_path, packet_limit)
    if not facts or not facts.get("packets_read"):
        return None
    return summary_text(facts)
