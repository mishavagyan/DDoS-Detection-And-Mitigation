# make_ack_flood_log.py
import random
import time

OUT_PATH = "sample_traffic.log"

DST_IP = "192.168.1.20"
DST_PORT = 80

# Normal traffic parameters
NORMAL_SECONDS_BEFORE = 10
NORMAL_SECONDS_AFTER = 10
NORMAL_PPS = 50
NORMAL_UNIQUE_IPS = 150  # many users

# ACK flood parameters (one attacker)
ATTACK_SECONDS = 10
ATTACK_PPS = 900
ATTACKER_IP = "10.0.0.77"


def write_events(f, start_ts: float, seconds: int, pps: int, src_ips, flags: str):
    """
    Write events with stable timestamps increasing at 1/pps steps.
    """
    dt = 1.0 / max(1, pps)
    t = start_ts
    for _ in range(seconds * pps):
        src_ip = random.choice(src_ips)
        # random source port to look more realistic
        sport = random.randint(1024, 65535)
        f.write(f"{t:.6f} {src_ip} {DST_IP} TCP {flags} {sport} {DST_PORT}\n")
        t += dt
    return t


def main():
    random.seed(42)
    now = time.time()

    # pool of legit user IPs
    legit_ips = [f"10.0.0.{i}" for i in range(1, NORMAL_UNIQUE_IPS + 1)]
    attacker_ips = [ATTACKER_IP]  # single attacker

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("# ts src_ip dst_ip proto flags src_port dst_port\n")

        t = now

        # 1) normal BEFORE (mix of ACK + few SYN)
        # (keeps your system seeing some SYN sometimes)
        for sec in range(NORMAL_SECONDS_BEFORE):
            # 80% ACK, 20% SYN
            n_ack = int(NORMAL_PPS * 0.8)
            n_syn = NORMAL_PPS - n_ack

            # ACK chunk
            t = write_events(f, t, 1, n_ack, legit_ips, "A")
            # SYN chunk
            t = write_events(f, t, 1, n_syn, legit_ips, "S")

        # 2) ACK FLOOD (attacker sends only ACK at high PPS)
        t = write_events(f, t, ATTACK_SECONDS, ATTACK_PPS, attacker_ips, "A")

        # 3) normal AFTER
        for sec in range(NORMAL_SECONDS_AFTER):
            n_ack = int(NORMAL_PPS * 0.8)
            n_syn = NORMAL_PPS - n_ack
            t = write_events(f, t, 1, n_ack, legit_ips, "A")
            t = write_events(f, t, 1, n_syn, legit_ips, "S")

    print(f"[+] Wrote {OUT_PATH} with ACK flood from {ATTACKER_IP} (~{ATTACK_PPS} pps for {ATTACK_SECONDS}s).")


if __name__ == "__main__":
    main()