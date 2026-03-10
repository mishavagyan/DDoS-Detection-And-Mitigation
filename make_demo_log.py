# make_demo_log.py
import random
import time

OUT = "sample_traffic.log"

def write_line(f, ts, src, dst, proto, flags, sp, dp, length=None):
    parts = [f"{ts:.6f}", src, dst, proto, flags, str(sp), str(dp)]
    if length is not None:
        parts.append(str(length))
    f.write(" ".join(parts) + "\n")

start = 1771630200.0

with open(OUT, "w", encoding="utf-8") as f:
    ts = start

    # 1) NORMAL: 20 seconds, ~50 pps mixed TCP
    for _ in range(20 * 50):
        src = f"10.0.0.{random.randint(2, 50)}"
        sp = random.randint(20000, 60000)
        write_line(f, ts, src, "192.168.1.20", "TCP", "A", sp, 80, 60)
        ts += 1/50

    # 2) ATTACK: 10 seconds, ~800 pps SYN flood from one IP
    attacker = "10.0.0.77"
    sp = 40000
    for i in range(10 * 800):
        write_line(f, ts, attacker, "192.168.1.20", "TCP", "S", sp + (i % 20000), 80, 60)
        ts += 1/800

    # 3) NORMAL again: 20 seconds, ~50 pps
    for _ in range(20 * 50):
        src = f"10.0.0.{random.randint(2, 50)}"
        sp = random.randint(20000, 60000)
        write_line(f, ts, src, "192.168.1.20", "TCP", "A", sp, 80, 60)
        ts += 1/50

print(f"Wrote demo log: {OUT}")