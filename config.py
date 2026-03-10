# config.py
from dataclasses import dataclass

@dataclass
class Config:
    # Capture
    interface: str = "en0"
    bpf_filter: str = "ip"
    capture_mode: str = "log"        # "scapy" or "log"
    log_source_path: str = "sample_traffic.log"

    # Timing
    tick_seconds: float = 1.0
    feature_window_seconds: int = 5

    # Thresholds (base)
    pps_threshold: int = 600
    cps_threshold: int = 150
    syn_rate_threshold: int = 150
    unique_ip_threshold: int = 200
    per_ip_rps_threshold: int = 100

    # Anomaly (z-score)
    anomaly_zscore_threshold: float = 3.0
    min_ticks_before_anomaly: int = 15

    # NEW: Adaptive baseline (EWMA)
    baseline_alpha: float = 0.15          # 0.05..0.3 (higher adapts faster)
    baseline_k: float = 4.0               # how many std dev above baseline is suspicious
    baseline_warmup_ticks: int = 10       # don't use baseline until we have some history

    # NEW: Legitimate surge rules
    # If ACK is high and SYN/ACK ratio looks normal, reduce risk (flash crowd)
    legit_ack_rate_min: float = 100.0     # ACK packets/sec considered "real traffic"
    legit_syn_ack_ratio_max: float = 1.6  # SYN/ACK near 1.0 is normal; floods are much higher
    legit_penalty: float = 25.0           # risk score reduction when legit evidence exists

    # Hysteresis (attack state)
    attack_on_score: float = 45
    attack_off_score: float = 30
    attack_on_windows: int = 2
    attack_off_windows: int = 3

    # Mitigation
    mitigation_backend: str = "sim"  # "sim", "none", "iptables", "nft", "ipset"
    block_seconds: int = 10
    max_blocks_per_tick: int = 50
    allowlist_cidrs = ["127.0.0.0/8", "192.168.0.0/16"]

    # Logging
    logs_dir: str = "logs"
    events_log_path: str = "logs/events.log"
    blocked_log_path: str = "logs/blocked_ips.log"