# report_plot.py
import json
import matplotlib.pyplot as plt

EVENTS_PATH = "logs/events.log"

ts = []
pps = []
score = []

with open(EVENTS_PATH, "r", encoding="utf-8") as f:
    for line in f:
        obj = json.loads(line)
        if obj.get("type") != "detection":
            continue
        features = obj.get("features", {})
        decision = obj.get("decision", {})
        ts.append(obj.get("ts", 0))
        pps.append(features.get("packets_per_second", 0))
        score.append(decision.get("risk_score", 0))

if not ts:
    print("No detection events found. Run main.py first.")
    raise SystemExit(0)

# Normalize time to start at 0 for plot
t0 = ts[0]
t = [x - t0 for x in ts]

plt.figure()
plt.plot(t, pps)
plt.xlabel("time (s)")
plt.ylabel("packets_per_second")
plt.title("Traffic Volume (PPS)")
plt.show()

plt.figure()
plt.plot(t, score)
plt.xlabel("time (s)")
plt.ylabel("risk_score")
plt.title("Detection Risk Score")
plt.show()