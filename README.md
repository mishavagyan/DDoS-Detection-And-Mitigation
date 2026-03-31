# DDoS Protection (Host-Level)

This project is a Python control plane for host-level DDoS detection and mitigation.

## What it does

- Captures live traffic (`scapy`) or replays logs.
- Computes sliding-window traffic features.
- Scores attack risk with threshold + anomaly + hysteresis logic.
- Applies mitigation in kernel datapath (`nftables`) with dynamic attack levels.
- Optionally applies targeted source-IP blocks with TTL for high-confidence offenders.
- Logs detections and block actions for tuning and incident review.

## Key design choices

- Aggregate kernel controls are primary (spoof-resistant).
- Per-IP blocking is secondary (fallback for non-spoofed repeat offenders).
- Policy modes:
  - `observe`: detect/log only, no direct IP blocks.
  - `soft`: aggregate controls + strict gate for direct IP blocks.
  - `enforce`: full mitigation behavior.

## Quick start

1. Install dependencies:
   - `python3 -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install -r requirements.txt`
2. Configure `config.py` for your interface and policy mode.
3. Run as root on Linux for live packet capture and nftables actions:
   - `sudo .venv/bin/python main.py`

## Safety notes

- This project cannot protect against upstream link saturation alone.
- For large volumetric attacks, combine with ISP/CDN/scrubbing provider controls.
- Start in `observe`, tune thresholds, then move to `soft`, then `enforce`.
