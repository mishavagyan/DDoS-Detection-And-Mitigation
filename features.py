# features.py
import math
import heapq
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Tuple, Any, Optional

from capture import PacketEvent


def _entropy_from_counts(counts: Dict[Any, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0

    ent = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


@dataclass
class FeatureSnapshot:
    ts: float
    window_seconds: int

    packets_per_second: float
    connections_per_second: float
    syn_packet_rate: float
    ack_packet_rate: float
    syn_ack_ratio: float
    unique_ip_count: int

    per_ip_rps: Dict[str, float]
    top_ips: List[Tuple[str, float]]
    max_ip_rps: float

    tcp_ratio: float
    udp_ratio: float
    icmp_ratio: float
    syn_ratio: float
    src_ip_entropy: float
    top_dst_port_share: float
    small_pkt_ratio: float

    tcp_packet_rate: float
    syn_connections_per_second: float


class FeatureExtractor:
    """
    Sliding window features using event timestamps.
    Works for both live capture and replay mode.
    """
    def __init__(
        self,
        window_seconds: int,
        top_n_ips: int = 10,
        advance_with_wall_clock: bool = False,
    ):
        self.window_seconds = window_seconds
        self.top_n_ips = max(1, top_n_ips)
        self.advance_with_wall_clock = advance_with_wall_clock
        self.events: Deque[PacketEvent] = deque()
        self._last_ts: Optional[float] = None

    def add_events(self, batch: List[PacketEvent]) -> None:
        if not batch:
            return

        for ev in batch:
            self.events.append(ev)
            self._last_ts = ev.ts if self._last_ts is None else max(self._last_ts, ev.ts)

        self._prune(self._now_ts())

    def _now_ts(self) -> float:
        event_ts = self._last_ts if self._last_ts is not None else 0.0
        if self.advance_with_wall_clock:
            # In live capture mode, keep the window moving even when traffic pauses.
            return max(event_ts, time.time())
        return event_ts

    def _prune(self, now_ts: float) -> None:
        cutoff = now_ts - self.window_seconds
        while self.events and self.events[0].ts < cutoff:
            self.events.popleft()

    def compute(self) -> FeatureSnapshot:
        now_ts = self._now_ts()
        self._prune(now_ts)

        n = len(self.events)
        w = max(1, self.window_seconds)

        pps = n / w

        per_ip_counts: Dict[str, int] = defaultdict(int)
        proto_counts: Dict[str, int] = defaultdict(int)
        src_ip_counts: Dict[str, int] = defaultdict(int)
        dst_port_counts: Dict[int, int] = defaultdict(int)

        syn_count = 0
        ack_count = 0
        tcp_count = 0
        conn_count = 0
        small_count = 0

        for e in self.events:
            per_ip_counts[e.src_ip] += 1
            src_ip_counts[e.src_ip] += 1
            proto_counts[e.proto] += 1

            if e.dst_port is not None:
                dst_port_counts[e.dst_port] += 1

            if e.length is not None and e.length < 120:
                small_count += 1

            if e.proto == "TCP":
                tcp_count += 1

                # SYN without ACK ~= new connection attempt
                if "S" in e.tcp_flags and "A" not in e.tcp_flags:
                    syn_count += 1
                    conn_count += 1

                if "A" in e.tcp_flags:
                    ack_count += 1

        tcp_packet_rate = tcp_count / w
        syn_cps = conn_count / w
        cps = conn_count / w

        unique_ip_count = len(src_ip_counts)

        syn_rate = syn_count / w
        ack_rate = ack_count / w

        # Keep the full per_ip_rps for detection compatibility,
        # but only compute/store top-N separately for logging/reporting.
        per_ip_rps = {ip: cnt / w for ip, cnt in per_ip_counts.items()}

        # More efficient than sorting the whole dict when only top-N is needed.
        top_ips = heapq.nlargest(self.top_n_ips, per_ip_rps.items(), key=lambda x: x[1])
        max_ip_rps = top_ips[0][1] if top_ips else 0.0

        tcp_ratio = (proto_counts["TCP"] / n) if n else 0.0
        udp_ratio = (proto_counts["UDP"] / n) if n else 0.0
        icmp_ratio = (proto_counts["ICMP"] / n) if n else 0.0

        syn_ratio = (syn_count / tcp_count) if tcp_count else 0.0
        syn_ack_ratio = (syn_count / max(ack_count, 1)) if tcp_count else 0.0

        # Entropy is measured in bits (log2-based Shannon entropy).
        src_ip_entropy = _entropy_from_counts(src_ip_counts)

        top_dst_port_share = 0.0
        if n and dst_port_counts:
            top_dst_port_share = max(dst_port_counts.values()) / n

        small_pkt_ratio = (small_count / n) if n else 0.0

        return FeatureSnapshot(
            ts=now_ts,
            window_seconds=self.window_seconds,
            packets_per_second=pps,
            connections_per_second=cps,
            syn_packet_rate=syn_rate,
            ack_packet_rate=ack_rate,
            syn_ack_ratio=syn_ack_ratio,
            unique_ip_count=unique_ip_count,
            per_ip_rps=per_ip_rps,
            top_ips=top_ips,
            max_ip_rps=max_ip_rps,
            tcp_ratio=tcp_ratio,
            udp_ratio=udp_ratio,
            icmp_ratio=icmp_ratio,
            syn_ratio=syn_ratio,
            src_ip_entropy=src_ip_entropy,
            top_dst_port_share=top_dst_port_share,
            small_pkt_ratio=small_pkt_ratio,
            tcp_packet_rate=tcp_packet_rate,
            syn_connections_per_second=syn_cps,
        )

    def to_dict(self, snap: FeatureSnapshot) -> Dict[str, Any]:
        return {
            "ts": snap.ts,
            "window_seconds": snap.window_seconds,
            "packets_per_second": snap.packets_per_second,
            "connections_per_second": snap.connections_per_second,
            "syn_packet_rate": snap.syn_packet_rate,
            "ack_packet_rate": snap.ack_packet_rate,
            "syn_ack_ratio": snap.syn_ack_ratio,
            "unique_ip_count": snap.unique_ip_count,
            "tcp_packet_rate": snap.tcp_packet_rate,
            "syn_connections_per_second": snap.syn_connections_per_second,
            "top_ips": snap.top_ips,
            "max_ip_rps": snap.max_ip_rps,
            "tcp_ratio": snap.tcp_ratio,
            "udp_ratio": snap.udp_ratio,
            "icmp_ratio": snap.icmp_ratio,
            "syn_ratio": snap.syn_ratio,
            "src_ip_entropy": snap.src_ip_entropy,
            "top_dst_port_share": snap.top_dst_port_share,
            "small_pkt_ratio": snap.small_pkt_ratio,
        }