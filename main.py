# main.py
import time
import logging
from queue import Queue, Empty
from typing import List

from config import Config
from capture import TrafficCapture, PacketEvent
from features import FeatureExtractor
from detection import HybridDetector
from mitigation import Mitigator
from logger import EventLogger, setup_logging


def drain_queue(q: Queue, max_items: int = 100000) -> List[PacketEvent]:
    items: List[PacketEvent] = []
    for _ in range(max_items):
        try:
            items.append(q.get_nowait())
        except Empty:
            break
    return items


def main() -> None:
    setup_logging()
    log = logging.getLogger("ddos")

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
        allowlist_cidrs=cfg.allowlist_cidrs,
        redis_host=cfg.redis_host,
        redis_port=cfg.redis_port,
        redis_db=cfg.redis_db,
    )

    if cfg.mitigation_backend == "redis":
        if mitigator.redis_store is None or not mitigator.redis_store.ping():
            raise RuntimeError(
                f"Redis backend selected, but Redis is unavailable at "
                f"{cfg.redis_host}:{cfg.redis_port}/{cfg.redis_db}"
            )
        log.info(
            "Redis backend connected at %s:%s/%s",
            cfg.redis_host,
            cfg.redis_port,
            cfg.redis_db,
        )

    logger = EventLogger(events_path=cfg.events_log_path, blocked_path=cfg.blocked_log_path)

    log.info("Starting capture")
    capture.start()

    log.info("Running main loop (Ctrl+C to stop)")
    try:
        while True:
            tick_start = time.time()

            batch = drain_queue(q, max_items=100000)
            if batch:
                extractor.add_events(batch)
            elif cfg.capture_mode == "log" and capture.is_finished():
                log.info("Log replay finished. Exiting")
                break

            try:
                snap = extractor.compute()
                decision = detector.detect(snap)
            except Exception as e:
                log.exception("Failed to compute features or detection decision: %s", e)
                elapsed = time.time() - tick_start
                time.sleep(max(0.0, cfg.tick_seconds - elapsed))
                continue

            expired = mitigator.cleanup_expired()
            for ip in expired:
                log.info("UNBLOCK (TTL expired): %s", ip)

            features_dict = extractor.to_dict(snap)
            decision_dict = detector.to_dict(decision)

            if decision.is_attack and decision.risk_score >= 40:
                logger.log_detection(features_dict, decision_dict)

                candidates = decision.suspicious_ips[:]
                if not candidates and decision.risk_score >= 80:
                    candidates = snap.top_ips[:]

                blocks = 0
                reason = f"attack:{decision.attack_type}:{decision.severity}:score={decision.risk_score:.0f}"

                for ip, metric in candidates:
                    if blocks >= cfg.max_blocks_per_tick:
                        break

                    if mitigator.is_blocked(ip):
                        continue

                    res = mitigator.block_ip(ip, reason=reason)

                    logger.log_block(
                        ip=ip,
                        reason=reason,
                        backend=cfg.mitigation_backend,
                        ok=res.ok,
                        detail=res.detail,
                    )

                    if res.ok:
                        blocks += 1

                active = mitigator.active_block_count()

                log.warning(
                    "ATTACK type=%s sev=%s score=%s blocked=%s active_blocks=%s "
                    "pps=%.1f syn=%.1f uniq=%s syn_ratio=%.2f udp=%.2f icmp=%.2f "
                    "H=%.2f top_port_share=%.2f dropped=%s parse_errors=%s packet_errors=%s",
                    decision.attack_type,
                    decision.severity,
                    int(decision.risk_score),
                    blocks,
                    active,
                    snap.packets_per_second,
                    snap.syn_packet_rate,
                    snap.unique_ip_count,
                    snap.syn_ratio,
                    snap.udp_ratio,
                    snap.icmp_ratio,
                    snap.src_ip_entropy,
                    snap.top_dst_port_share,
                    capture.dropped_packets,
                    capture.parse_errors,
                    capture.packet_errors,
                )
            else:
                log.debug(
                    "normal type=%s score=%s pps=%.1f cps=%.1f syn=%.1f uniq=%s "
                    "syn_ratio=%.2f udp=%.2f icmp=%.2f H=%.2f top_port_share=%.2f "
                    "top=%s dropped=%s parse_errors=%s packet_errors=%s",
                    decision.attack_type,
                    int(decision.risk_score),
                    snap.packets_per_second,
                    snap.connections_per_second,
                    snap.syn_packet_rate,
                    snap.unique_ip_count,
                    snap.syn_ratio,
                    snap.udp_ratio,
                    snap.icmp_ratio,
                    snap.src_ip_entropy,
                    snap.top_dst_port_share,
                    snap.top_ips[:3],
                    capture.dropped_packets,
                    capture.parse_errors,
                    capture.packet_errors,
                )

            elapsed = time.time() - tick_start
            time.sleep(max(0.0, cfg.tick_seconds - elapsed))

    except KeyboardInterrupt:
        log.info("Stopping system")
    finally:
        capture.stop()
        try:
            logger.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()