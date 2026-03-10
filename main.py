# main.py
import time
from queue import Queue, Empty
from typing import List

from config import Config
from capture import TrafficCapture, PacketEvent
from features import FeatureExtractor
from detection import HybridDetector
from mitigation import Mitigator
from logger import EventLogger


def drain_queue(q: Queue, max_items: int = 100000) -> List[PacketEvent]:
    items = []
    for _ in range(max_items):
        try:
            items.append(q.get_nowait())
        except Empty:
            break
    return items


def main():
    cfg = Config()
    q: Queue = Queue(maxsize=500000)

    capture = TrafficCapture(
        mode=cfg.capture_mode,
        out_queue=q,
        interface=cfg.interface,
        bpf_filter=cfg.bpf_filter,
        log_source_path=cfg.log_source_path,
    )

    extractor = FeatureExtractor(window_seconds=cfg.feature_window_seconds)

    detector = HybridDetector(
        pps_threshold=cfg.pps_threshold,
        cps_threshold=cfg.cps_threshold,
        syn_rate_threshold=cfg.syn_rate_threshold,
        unique_ip_threshold=cfg.unique_ip_threshold,
        per_ip_rps_threshold=cfg.per_ip_rps_threshold,
        anomaly_z=cfg.anomaly_zscore_threshold,
        min_ticks_before_anomaly=cfg.min_ticks_before_anomaly,
        attack_on_score=cfg.attack_on_score,
        attack_off_score=cfg.attack_off_score,
        attack_on_windows=cfg.attack_on_windows,
        attack_off_windows=cfg.attack_off_windows,
        baseline_alpha=cfg.baseline_alpha,
        baseline_k=cfg.baseline_k,
        baseline_warmup_ticks=cfg.baseline_warmup_ticks,
        legit_ack_rate_min=cfg.legit_ack_rate_min,
        legit_syn_ack_ratio_max=cfg.legit_syn_ack_ratio_max,
        legit_penalty=cfg.legit_penalty,
        use_ml=False,
    )

    mitigator = Mitigator(
        backend=cfg.mitigation_backend,
        block_seconds=cfg.block_seconds,
        allowlist_cidrs=getattr(cfg, "allowlist_cidrs", [])
    )

    logger = EventLogger(events_path=cfg.events_log_path, blocked_path=cfg.blocked_log_path)

    print("[*] Starting capture...")
    capture.start()

    print("[*] Running main loop. Press Ctrl+C to stop.")
    try:
        while True:
            tick_start = time.time()

            batch = drain_queue(q)
            if batch:
                extractor.add_events(batch)
            elif cfg.capture_mode == "log" and capture.is_finished():
                print("[*] Log replay finished. Exiting.")
                break

            snap = extractor.compute()
            decision = detector.detect(snap)

            expired = mitigator.cleanup_expired()
            for ip in expired:
                print(f"[+] UNBLOCK (TTL expired): {ip}", flush=True)

            features_dict = extractor.to_dict(snap)
            decision_dict = detector.to_dict(decision)

            if decision.is_attack and decision.risk_score >= 40:
                logger.log_detection(features_dict, decision_dict)

                candidates = decision.suspicious_ips[:]
                if not candidates and decision.risk_score >= 80:
                    candidates = snap.top_ips[:]

                blocks = 0
                for ip, metric in candidates:
                    if blocks >= cfg.max_blocks_per_tick:
                        break
                    if ip.startswith("127.") or ip == "0.0.0.0":
                        continue

                    res = mitigator.block_ip(ip)
                    logger.log_block(
                        ip=ip,
                        reason=f"attack:{decision.attack_type}:{decision.severity}:score={decision.risk_score:.0f}",
                        backend=cfg.mitigation_backend,
                        ok=res.ok,
                        detail=res.detail,
                    )
                    if res.ok:
                        blocks += 1

                active = sum(
                    1 for _, until in mitigator._blocked_until.items()
                    if until > time.time()
                ) if hasattr(mitigator, "_blocked_until") else 0

                print(
                    f"[!] ATTACK type={decision.attack_type} sev={decision.severity} score={decision.risk_score:.0f} "
                    f"blocked={blocks} active_blocks={active} "
                    f"pps={snap.packets_per_second:.1f} syn={snap.syn_packet_rate:.1f} "
                    f"uniq={snap.unique_ip_count} syn_ratio={snap.syn_ratio:.2f} udp={snap.udp_ratio:.2f} "
                    f"H={snap.src_ip_entropy:.2f} top_port_share={snap.top_dst_port_share:.2f}"
                )
            else:
                print(
                    f"[-] normal type={decision.attack_type} score={decision.risk_score:.0f} "
                    f"pps={snap.packets_per_second:.1f} cps={snap.connections_per_second:.1f} "
                    f"syn={snap.syn_packet_rate:.1f} uniq={snap.unique_ip_count} "
                    f"syn_ratio={snap.syn_ratio:.2f} udp={snap.udp_ratio:.2f} "
                    f"H={snap.src_ip_entropy:.2f} top_port_share={snap.top_dst_port_share:.2f} "
                    f"top={snap.top_ips[:3]}"
                )

            elapsed = time.time() - tick_start
            time.sleep(max(0.0, cfg.tick_seconds - elapsed))

    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        capture.stop()


if __name__ == "__main__":
    main()