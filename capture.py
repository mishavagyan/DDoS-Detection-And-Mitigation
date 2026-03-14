# capture.py
import threading
import time
import queue
from dataclasses import dataclass
from queue import Queue
from typing import Optional, Iterator

try:
    from scapy.all import sniff, TCP, UDP, ICMP, IP
except Exception:
    sniff = None
    TCP = None
    UDP = None
    ICMP = None
    IP = None


@dataclass
class PacketEvent:
    ts: float
    src_ip: str
    dst_ip: str
    proto: str
    tcp_flags: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: Optional[int] = None


class TrafficCapture:
    def __init__(
        self,
        mode: str,
        out_queue: Queue,
        interface: str = "eth0",
        bpf_filter: str = "ip",
        log_source_path: Optional[str] = None,
    ):
        self.mode = mode
        self.q = out_queue
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.log_source_path = log_source_path
        self._stop = threading.Event()
        self._finished = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Diagnostics / observability counters
        self.dropped_packets = 0
        self.parse_errors = 0
        self.packet_errors = 0

    def start(self) -> None:
        self._stop.clear()
        self._finished.clear()

        if self.mode == "scapy":
            if sniff is None:
                raise RuntimeError("Scapy is not available. Install scapy or use log mode.")
            self._thread = threading.Thread(target=self._run_scapy, daemon=True)
        elif self.mode == "log":
            if not self.log_source_path:
                raise ValueError("log_source_path is required for log mode.")
            self._thread = threading.Thread(target=self._run_log, daemon=True)
        else:
            raise ValueError(f"Unknown capture mode: {self.mode}")

        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def is_finished(self) -> bool:
        return self._finished.is_set()

    def _enqueue_event(self, ev: PacketEvent) -> None:
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            self.dropped_packets += 1

    def _on_packet(self, pkt) -> None:
        try:
            if IP is None or IP not in pkt:
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            proto = "IP"
            flags = ""
            sp = None
            dp = None

            if TCP and TCP in pkt:
                proto = "TCP"
                flags = str(pkt[TCP].flags)
                sp = int(pkt[TCP].sport)
                dp = int(pkt[TCP].dport)
            elif UDP and UDP in pkt:
                proto = "UDP"
                sp = int(pkt[UDP].sport)
                dp = int(pkt[UDP].dport)
            elif ICMP and ICMP in pkt:
                proto = "ICMP"

            ev = PacketEvent(
                ts=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                proto=proto,
                tcp_flags=flags,
                src_port=sp,
                dst_port=dp,
                length=len(pkt) if pkt is not None else None,
            )
            self._enqueue_event(ev)
        except Exception:
            self.packet_errors += 1

    def _run_scapy(self) -> None:
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        finally:
            self._finished.set()

    def _parse_log_line(self, line: str) -> Optional[PacketEvent]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split()
        if len(parts) < 5:
            self.parse_errors += 1
            return None

        try:
            ts = float(parts[0])
            src_ip = parts[1]
            dst_ip = parts[2]
            proto = parts[3]
            flags = parts[4]

            sp = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None
            dp = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else None
            length = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else None
        except Exception:
            self.parse_errors += 1
            return None

        return PacketEvent(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
            tcp_flags=flags,
            src_port=sp,
            dst_port=dp,
            length=length,
        )

    def _iter_log_events(self) -> Iterator[PacketEvent]:
        with open(self.log_source_path, "r", encoding="utf-8") as f:
            for line in f:
                ev = self._parse_log_line(line)
                if ev is not None:
                    yield ev

    def _run_log(self) -> None:
        start_real = time.time()
        first_ts = None

        try:
            for ev in self._iter_log_events():
                if self._stop.is_set():
                    break

                if first_ts is None:
                    first_ts = ev.ts

                target_elapsed = ev.ts - first_ts
                while not self._stop.is_set():
                    elapsed = time.time() - start_real
                    if elapsed >= target_elapsed:
                        break
                    time.sleep(0.001)

                self._enqueue_event(ev)
        finally:
            self._finished.set()