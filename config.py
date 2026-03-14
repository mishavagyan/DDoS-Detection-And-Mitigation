# config.py
from dataclasses import dataclass, field
from typing import List


@dataclass
class Config:
    # Capture
    interface: str = "en0"
    bpf_filter: str = "ip"
    capture_mode: str = "log"   # "scapy" or "log"
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

    # Adaptive baseline (EWMA)
    baseline_alpha: float = 0.15
    baseline_k: float = 4.0
    baseline_warmup_ticks: int = 10

    # Legitimate surge rules
    legit_ack_rate_min: float = 100.0
    legit_syn_ack_ratio_max: float = 1.6
    legit_penalty: float = 25.0

    # Hysteresis (attack state)
    attack_on_score: float = 45
    attack_off_score: float = 30
    attack_on_windows: int = 2
    attack_off_windows: int = 3

    # Mitigation
    mitigation_backend: str = "redis"  # "sim", "none", "iptables", "nft", "ipset", "redis"
    block_seconds: int = 10
    max_blocks_per_tick: int = 50
    allowlist_cidrs: List[str] = field(default_factory=lambda: [
        "127.0.0.0/8",
        "192.168.0.0/16",
    ])

    # Logging
    logs_dir: str = "logs"
    events_log_path: str = "logs/events.log"
    blocked_log_path: str = "logs/blocked_ips.log"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_enabled: bool = True

    def __post_init__(self) -> None:
        valid_capture_modes = {"scapy", "log"}
        valid_backends = {"sim", "none", "iptables", "nft", "ipset", "redis"}

        if self.capture_mode not in valid_capture_modes:
            raise ValueError(f"capture_mode must be one of {sorted(valid_capture_modes)}, got {self.capture_mode!r}")

        if self.mitigation_backend not in valid_backends:
            raise ValueError(f"mitigation_backend must be one of {sorted(valid_backends)}, got {self.mitigation_backend!r}")

        if self.tick_seconds <= 0:
            raise ValueError("tick_seconds must be positive")

        if self.feature_window_seconds <= 0:
            raise ValueError("feature_window_seconds must be positive")

        if self.pps_threshold <= 0:
            raise ValueError("pps_threshold must be positive")

        if self.cps_threshold <= 0:
            raise ValueError("cps_threshold must be positive")

        if self.syn_rate_threshold <= 0:
            raise ValueError("syn_rate_threshold must be positive")

        if self.unique_ip_threshold <= 0:
            raise ValueError("unique_ip_threshold must be positive")

        if self.per_ip_rps_threshold <= 0:
            raise ValueError("per_ip_rps_threshold must be positive")

        if self.anomaly_zscore_threshold <= 0:
            raise ValueError("anomaly_zscore_threshold must be positive")

        if self.min_ticks_before_anomaly < 1:
            raise ValueError("min_ticks_before_anomaly must be at least 1")

        if not (0 < self.baseline_alpha < 1):
            raise ValueError("baseline_alpha must be in the range (0, 1)")

        if self.baseline_k <= 0:
            raise ValueError("baseline_k must be positive")

        if self.baseline_warmup_ticks < 1:
            raise ValueError("baseline_warmup_ticks must be at least 1")

        if self.legit_ack_rate_min < 0:
            raise ValueError("legit_ack_rate_min must be non-negative")

        if self.legit_syn_ack_ratio_max <= 0:
            raise ValueError("legit_syn_ack_ratio_max must be positive")

        if self.legit_penalty < 0:
            raise ValueError("legit_penalty must be non-negative")

        if self.attack_on_score < 0 or self.attack_on_score > 100:
            raise ValueError("attack_on_score must be in [0, 100]")

        if self.attack_off_score < 0 or self.attack_off_score > 100:
            raise ValueError("attack_off_score must be in [0, 100]")

        if self.attack_off_score > self.attack_on_score:
            raise ValueError("attack_off_score should not be greater than attack_on_score")

        if self.attack_on_windows < 1:
            raise ValueError("attack_on_windows must be at least 1")

        if self.attack_off_windows < 1:
            raise ValueError("attack_off_windows must be at least 1")

        if self.block_seconds <= 0:
            raise ValueError("block_seconds must be positive")

        if self.max_blocks_per_tick < 1:
            raise ValueError("max_blocks_per_tick must be at least 1")

        if self.redis_port <= 0 or self.redis_port > 65535:
            raise ValueError("redis_port must be in the range 1..65535")

        if self.redis_db < 0:
            raise ValueError("redis_db must be non-negative")

        if self.capture_mode == "log" and not self.log_source_path:
            raise ValueError("log_source_path is required when capture_mode='log'")