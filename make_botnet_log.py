import random
import time

OUT = "sample_traffic.log"

DST_IP = "192.168.1.20"
DST_PORT = 80

# Normal traffic
NORMAL_BEFORE_SECONDS = 10
NORMAL_AFTER_SECONDS = 10
NORMAL_PPS = 50

# Botnet attack
ATTACK_SECONDS = 10
BOT_COUNT = 200
BOT_PPS_EACH = 10   # total attack rate = BOT_COUNT * BOT_PPS_EACH = 2000 pps

# Packet size
PKT_LEN = 60


def write_line(f, ts, src, dst, proto, flags, sp, dp, length=60):
    f.write(f"{ts:.6f} {src} {dst} {proto} {flags} {sp} {dp} {length}\n")


def main():
    random.seed(42)
    ts = time.time()

    legit_ips = [f"10.0.1.{i}" for i in range(2, 80)]
    bot_ips = [f"172.16.{i // 254}.{(i % 254) + 1}" for i in range(BOT_COUNT)]

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# ts src_ip dst_ip proto flags src_port dst_port length\n")

        # 1) NORMAL BEFORE
        for _ in range(NORMAL_BEFORE_SECONDS * NORMAL_PPS):
            src = random.choice(legit_ips)
            sp = random.randint(20000, 60000)
            write_line(f, ts, src, DST_IP, "TCP", "A", sp, DST_PORT, PKT_LEN)
            ts += 1 / NORMAL_PPS

        # 2) DISTRIBUTED BOTNET SYN FLOOD
        # Each bot sends BOT_PPS_EACH packets/sec, but spread across the whole botnet.
        total_attack_pps = BOT_COUNT * BOT_PPS_EACH
        total_attack_packets = ATTACK_SECONDS * total_attack_pps

        for _ in range(total_attack_packets):
            src = random.choice(bot_ips)
            sp = random.randint(10000, 65000)
            write_line(f, ts, src, DST_IP, "TCP", "S", sp, DST_PORT, PKT_LEN)
            ts += 1 / total_attack_pps

        # 3) NORMAL AFTER
        for _ in range(NORMAL_AFTER_SECONDS * NORMAL_PPS):
            src = random.choice(legit_ips)
            sp = random.randint(20000, 60000)
            write_line(f, ts, src, DST_IP, "TCP", "A", sp, DST_PORT, PKT_LEN)
            ts += 1 / NORMAL_PPS

    print(
        f"[+] Wrote {OUT} with distributed botnet SYN flood: "
        f"{BOT_COUNT} bots x {BOT_PPS_EACH} pps for {ATTACK_SECONDS}s "
        f"(total ~{BOT_COUNT * BOT_PPS_EACH} pps)."
    )


if __name__ == "__main__":
    main()