# detection.py
import math
from collections import deque
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple

from features import FeatureSnapshot


@dataclass
class DetectionDecision:
    is_attack: bool
    reasons: List[str]
    suspicious_ips: List[Tuple[str, float]]
    severity: str
    attack_type: str
    risk_score: float


class Hysteresis:
    def __init__(self, on_score: float, off_score: float, on_windows: int, off_windows: int):
        self.on_score = on_score
        self.off_score = off_score
        self.on_windows = max(1, on_windows)
        self.off_windows = max(1, off_windows)
        self._in_attack = False
        self._above = 0
        self._below = 0

    def update(self, score: float) -> bool:
        if not self._in_attack:
            self._above = self._above + 1 if score >= self.on_score else 0
            if self._above >= self.on_windows:
                self._in_attack = True
                self._below = 0
        else:
            self._below = self._below + 1 if score <= self.off_score else 0
            if self._below >= self.off_windows:
                self._in_attack = False
                self._above = 0
        return self._in_attack


class EWMABaseline:
    """
    Online baseline mean+variance via EWMA.
    Used to avoid false alerts during expected surges.
    """
    def __init__(self, alpha: float):
        self.alpha = max(0.001, min(0.9, alpha))
        self.mean = None
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> None:
        if self.mean is None:
            self.mean = x
            self.var = 0.0
            self.n = 1
            return
        a = self.alpha
        prev_mean = self.mean
        self.mean = (1 - a) * self.mean + a * x
        # EWMA variance update (approx)
        self.var = (1 - a) * (self.var + a * (x - prev_mean) ** 2)
        self.n += 1

    def std(self) -> float:
        return math.sqrt(self.var) if self.var > 1e-12 else 0.0


class HybridDetector:
    def __init__(
        self,
        pps_threshold: int,
        cps_threshold: int,
        syn_rate_threshold: int,
        unique_ip_threshold: int,
        per_ip_rps_threshold: int,
        anomaly_z: float,
        min_ticks_before_anomaly: int,

        attack_on_score: float,
        attack_off_score: float,
        attack_on_windows: int,
        attack_off_windows: int,

        baseline_alpha: float,
        baseline_k: float,
        baseline_warmup_ticks: int,

        legit_ack_rate_min: float,
        legit_syn_ack_ratio_max: float,
        legit_penalty: float,

        use_ml: bool = False,
    ):
        self.pps_threshold = pps_threshold
        self.cps_threshold = cps_threshold
        self.syn_rate_threshold = syn_rate_threshold
        self.unique_ip_threshold = unique_ip_threshold
        self.per_ip_rps_threshold = per_ip_rps_threshold

        self.anomaly_z = anomaly_z
        self.min_ticks_before_anomaly = min_ticks_before_anomaly
        self.hist_pps = deque(maxlen=300)
        self.hist_syn = deque(maxlen=300)

        self.hyst = Hysteresis(attack_on_score, attack_off_score, attack_on_windows, attack_off_windows)

        self.base_pps = EWMABaseline(alpha=baseline_alpha)
        self.base_syn = EWMABaseline(alpha=baseline_alpha)
        self.base_k = baseline_k
        self.base_warmup = baseline_warmup_ticks

        self.legit_ack_rate_min = legit_ack_rate_min
        self.legit_syn_ack_ratio_max = legit_syn_ack_ratio_max
        self.legit_penalty = legit_penalty

        self.use_ml = False

    def _zscore(self, x: float, history: deque) -> float:
        if len(history) < 2:
            return 0.0
        mean = sum(history) / len(history)
        var = sum((v - mean) ** 2 for v in history) / (len(history) - 1)
        std = math.sqrt(var) if var > 1e-9 else 0.0
        return 0.0 if std == 0.0 else (x - mean) / std

    
    def _classify(self, snap: FeatureSnapshot) -> str:
        # SYN flood
        if snap.tcp_ratio >= 0.6 and snap.syn_ratio >= 0.6 and snap.syn_ack_ratio >= 3.0:
            return "syn_flood"

        # ----------------------------------------------------
        # TCP ACK flood (single IP abusing ACK packets)
        # ----------------------------------------------------
        ack_ratio = (
            snap.ack_packet_rate / snap.packets_per_second
            if snap.packets_per_second > 0
            else 0.0
        )

        if (
            snap.tcp_ratio >= 0.7
            and ack_ratio >= 0.7
            and snap.packets_per_second >= self.pps_threshold
            and snap.max_ip_rps >= self.per_ip_rps_threshold
        ):
            return "tcp_ack_flood"

        # UDP flood
        if snap.udp_ratio >= 0.6 and snap.packets_per_second >= self.pps_threshold * 0.6:
            return "udp_flood"

        # Flash crowd (legitimate surge)
        if (
            snap.packets_per_second >= self.pps_threshold * 0.9
            and snap.ack_packet_rate >= self.legit_ack_rate_min
            and snap.syn_ack_ratio <= self.legit_syn_ack_ratio_max
            and snap.max_ip_rps < (self.per_ip_rps_threshold * 0.7)
        ):
            return "flash_crowd"

        # Distributed flood (botnet-like)
        if (
            snap.unique_ip_count >= self.unique_ip_threshold * 0.7
            and snap.src_ip_entropy >= 6.0
            and (snap.syn_ack_ratio >= 3.0 or snap.udp_ratio >= 0.6)
        ):
            return "distributed_flood"

        return "unknown"
        

    def detect(self, snap: FeatureSnapshot) -> DetectionDecision:
        reasons: List[str] = []

        # Candidates to block: only truly high per-IP talkers
        suspicious_ips = [(ip, rps) for ip, rps in snap.top_ips if rps >= self.per_ip_rps_threshold]

        # z-scores
        z_pps = self._zscore(snap.packets_per_second, self.hist_pps)
        z_syn = self._zscore(snap.syn_packet_rate, self.hist_syn)

        score = 0.0

        # ----------- Fixed threshold contributions -----------
        if snap.packets_per_second >= self.pps_threshold:
            score += 20
            reasons.append(f"PPS high: {snap.packets_per_second:.1f} >= {self.pps_threshold}")

        if snap.connections_per_second >= self.cps_threshold:
            score += 10
            reasons.append(f"CPS high: {snap.connections_per_second:.1f} >= {self.cps_threshold}")

        if snap.syn_packet_rate >= self.syn_rate_threshold:
            score += 20
            reasons.append(f"SYN rate high: {snap.syn_packet_rate:.1f} >= {self.syn_rate_threshold}")

        if snap.unique_ip_count >= self.unique_ip_threshold:
            score += 10
            reasons.append(f"Unique src IPs high: {snap.unique_ip_count} >= {self.unique_ip_threshold}")

        if suspicious_ips:
            score += 10
            reasons.append(f"Per-IP RPS high (top talker): max_ip_rps={snap.max_ip_rps:.1f}")

        # SYN flood fingerprint
        if snap.syn_ack_ratio >= 3.0 and snap.syn_packet_rate >= self.syn_rate_threshold * 0.6:
            score += 20
            reasons.append(f"SYN/ACK imbalance: syn_ack_ratio={snap.syn_ack_ratio:.2f}")

        # ----------------------------------------------------
        # TCP ACK flood fingerprint (many ACKs, one talker dominating)
        # ----------------------------------------------------
        ack_ratio = (
            snap.ack_packet_rate / snap.packets_per_second
            if snap.packets_per_second > 0
            else 0.0
        )

        if (
            snap.tcp_ratio >= 0.7
            and ack_ratio >= 0.7
            and snap.max_ip_rps >= self.per_ip_rps_threshold
            and snap.packets_per_second >= self.pps_threshold * 0.8
        ):
            score += 25
            reasons.append(
                f"ACK flood fingerprint: ack_ratio={ack_ratio:.2f}, max_ip_rps={snap.max_ip_rps:.1f}"
            )

        # Port concentration (typical for floods)
        if snap.top_dst_port_share >= 0.7 and snap.packets_per_second >= self.pps_threshold * 0.5:
            score += 6
            reasons.append(f"Port concentration: top_dst_port_share={snap.top_dst_port_share:.2f}")

        # ----------- Adaptive baseline contributions -----------
        # Compare to baseline when warmed up
        if self.base_pps.n >= self.base_warmup:
            thr_pps = (self.base_pps.mean or 0.0) + self.base_k * self.base_pps.std()
            if snap.packets_per_second > thr_pps and thr_pps > 0:
                score += 10
                reasons.append(f"Baseline PPS anomaly: {snap.packets_per_second:.1f} > {thr_pps:.1f}")

        if self.base_syn.n >= self.base_warmup:
            thr_syn = (self.base_syn.mean or 0.0) + self.base_k * self.base_syn.std()
            if snap.syn_packet_rate > thr_syn and thr_syn > 0:
                score += 8
                reasons.append(f"Baseline SYN anomaly: {snap.syn_packet_rate:.1f} > {thr_syn:.1f}")

        # z-score (optional extra)
        if len(self.hist_pps) >= self.min_ticks_before_anomaly and z_pps >= self.anomaly_z:
            score += 6
            reasons.append(f"z(PPS)={z_pps:.2f} >= {self.anomaly_z}")
        if len(self.hist_syn) >= self.min_ticks_before_anomaly and z_syn >= self.anomaly_z:
            score += 6
            reasons.append(f"z(SYN)={z_syn:.2f} >= {self.anomaly_z}")

        # ----------- Legitimate surge evidence (Black Friday protection) -----------
        # If ACK is high and SYN/ACK ratio looks normal-ish, reduce risk.
        # This indicates completed traffic, not half-open flood.
        legit_evidence = (
            snap.ack_packet_rate >= self.legit_ack_rate_min and
            snap.syn_ack_ratio <= self.legit_syn_ack_ratio_max and
            snap.max_ip_rps < (self.per_ip_rps_threshold * 0.7)  # no single super-spammer
        )
        if legit_evidence:
            score -= self.legit_penalty
            reasons.append(
                f"Legit surge evidence: ack_rate={snap.ack_packet_rate:.1f}, syn_ack_ratio={snap.syn_ack_ratio:.2f}, max_ip_rps={snap.max_ip_rps:.1f}"
            )

        score = max(0.0, min(100.0, score))

        # Update histories
        self.hist_pps.append(snap.packets_per_second)
        self.hist_syn.append(snap.syn_packet_rate)

        # Update baseline ONLY when score is low (assume normal)
        # This prevents poisoning baseline during attacks.
        if score < 25:
            self.base_pps.update(snap.packets_per_second)
            self.base_syn.update(snap.syn_packet_rate)

        is_attack = self.hyst.update(score)
        attack_type = self._classify(snap)

        # if is_attack and attack_type == "unknown":
        #     attack_type = "generic_flood"

        # Severity by score
        if score >= 85:
            severity = "high"
        elif score >= 65:
            severity = "medium"
        elif score >= 40:
            severity = "low"
        else:
            severity = "low"

        return DetectionDecision(
            is_attack=is_attack,
            reasons=reasons,
            suspicious_ips=suspicious_ips,
            severity=severity,
            attack_type=attack_type,
            risk_score=score,
        )

    def to_dict(self, d: DetectionDecision) -> Dict[str, Any]:
        return {
            "is_attack": d.is_attack,
            "reasons": d.reasons,
            "suspicious_ips": d.suspicious_ips,
            "severity": d.severity,
            "attack_type": d.attack_type,
            "risk_score": d.risk_score,
        }