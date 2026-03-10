# make_flashcrowd_log.py
import random

OUT = "sample_traffic.log"

def write_line(f, ts, src, dst, proto, flags, sp, dp, length=60):
    f.write(f"{ts:.6f} {src} {dst} {proto} {flags} {sp} {dp} {length}\n")

start = 1773000000.0
ts = start

with open(OUT, "w", encoding="utf-8") as f:
    # NORMAL 10s ~50pps (ACK traffic)
    for _ in range(10 * 50):
        src = f"10.0.0.{random.randint(2, 200)}"
        sp = random.randint(20000, 60000)
        write_line(f, ts, src, "192.168.1.20", "TCP", "A", sp, 80, 60)
        ts += 1/50

    # FLASH CROWD 10s ~800pps (still ACK traffic, many users, low per-IP)
    for _ in range(10 * 800):
        src = f"10.0.0.{random.randint(2, 250)}"
        sp = random.randint(20000, 60000)
        write_line(f, ts, src, "192.168.1.20", "TCP", "A", sp, 80, 60)
        ts += 1/800

    # NORMAL 10s
    for _ in range(10 * 50):
        src = f"10.0.0.{random.randint(2, 200)}"
        sp = random.randint(20000, 60000)
        write_line(f, ts, src, "192.168.1.20", "TCP", "A", sp, 80, 60)
        ts += 1/50

print("Wrote flash crowd log to sample_traffic.log")