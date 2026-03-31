# ParrotOS Validation Matrix

Use this matrix to validate mitigation quality and false-positive safety.

## Test Scenarios

| Scenario | Command | Duration | Expected |
|---|---|---:|---|
| SYN flood | `hping3 -S -p <port> --flood <ip>` | 30s | enters `under_attack`, SYN drops increase |
| Spoofed SYN flood | `hping3 -S -p <port> --flood --rand-source <ip>` | 30s | aggregate drops increase, no unbounded IP block churn |
| UDP flood | `hping3 --udp -p <port> --flood <ip>` | 30s | UDP limiter active, service remains reachable |
| ICMP flood | `hping3 --icmp --flood <ip>` | 30s | ICMP limiter active, service remains reachable |
| Flash crowd (legit) | workload generator | 60s | avoid aggressive IP blocks, low false positives |

## SLO Gates

- Availability during attack: `>= 99.0%`
- False-positive deny rate during normal traffic: `< 0.1%`
- Reaction time to elevated protections: `<= 3s`
- Recovery to `normal` after attack stop: `<= 60s`
