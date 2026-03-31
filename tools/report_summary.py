# report_summary.py
import json

EVENTS_PATH = "logs/events.log"
BLOCKS_PATH = "logs/blocked_ips.log"

detections = []
blocks = []

with open(EVENTS_PATH, "r", encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("type") == "detection":
            detections.append(obj)

with open(BLOCKS_PATH, "r", encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("type") == "block" and obj.get("ok"):
            blocks.append(obj)

if not detections:
    print("No detection events found.")
    raise SystemExit(0)

# compute stats
peak_pps = 0.0
attack_ts = []
attack_types = {}

for d in detections:
    features = d.get("features", {})
    decision = d.get("decision", {})
    pps = float(features.get("packets_per_second", 0))
    peak_pps = max(peak_pps, pps)

    if decision.get("is_attack"):
        attack_ts.append(d.get("ts", 0))
        at = decision.get("attack_type", "unknown")
        attack_types[at] = attack_types.get(at, 0) + 1

unique_blocked = sorted({b.get("ip") for b in blocks if b.get("ip")})

if attack_ts:
    start = min(attack_ts)
    end = max(attack_ts)
    duration = end - start
else:
    start = end = duration = 0

print("=== DDoS Detection Summary ===")
print(f"Detections logged: {len(detections)}")
print(f"Peak PPS: {peak_pps:.1f}")

if attack_ts:
    print(f"Attack detected: YES")
    print(f"Attack window (log time): start={start:.2f}, end={end:.2f}, duration={duration:.2f}s")
    print(f"Most common attack type: {max(attack_types, key=attack_types.get)}")
else:
    print("Attack detected: NO")

print(f"Unique blocked IPs: {len(unique_blocked)}")
if unique_blocked:
    print("Blocked list:", ", ".join(unique_blocked))