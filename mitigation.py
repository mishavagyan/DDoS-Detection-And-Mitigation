# mitigation.py
import ipaddress
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from redis_store import RedisStore


@dataclass
class MitigationResult:
    ok: bool
    detail: Optional[str] = None


class Mitigator:
    def __init__(
        self,
        backend: str = "iptables",
        block_seconds: int = 120,
        policy_mode: str = "soft",
        allowlist_cidrs: Optional[List[str]] = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        self.backend = backend
        self.policy_mode = policy_mode
        self.block_seconds = block_seconds
        self.attack_level = "normal"
        self._blocked_until: Dict[str, float] = {}
        self._last_redis_blocks: Set[str] = set()

        self.allowlist = []
        for c in (allowlist_cidrs or []):
            try:
                self.allowlist.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass

        self.redis_store = None
        if self.backend == "redis":
            self.redis_store = RedisStore(host=redis_host, port=redis_port, db=redis_db)
        elif self.backend == "nft":
            self._ensure_nft_bootstrap()
        elif self.backend == "ipset":
            self._ensure_ipset_bootstrap()

    def _is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.allowlist)
        except Exception:
            return False

    def is_blocked(self, ip: str) -> bool:
        now = time.time()

        if self.backend == "redis" and self.redis_store is not None:
            return self.redis_store.is_blocked(ip)

        return ip in self._blocked_until and self._blocked_until[ip] > now

    def set_attack_level(
        self,
        level: str,
        syn_limit: int,
        udp_limit: int,
        icmp_limit: int,
    ) -> MitigationResult:
        if self.backend != "nft":
            self.attack_level = level
            return MitigationResult(ok=True, detail=f"attack_level_set:{level}")

        if level not in {"normal", "elevated", "under_attack"}:
            return MitigationResult(ok=False, detail=f"invalid_attack_level:{level}")

        if self.attack_level == level:
            return MitigationResult(ok=True, detail=f"attack_level_unchanged:{level}")

        res = self._apply_nft_attack_level(level, syn_limit, udp_limit, icmp_limit)
        if res.ok:
            self.attack_level = level
        return res

    def cleanup_expired(self) -> List[str]:
        if self.backend == "redis":
            if self.redis_store is None:
                return []
            try:
                current = set(self.redis_store.list_blocked_ips())
                expired = sorted(self._last_redis_blocks - current)
                self._last_redis_blocks = current
                return expired
            except Exception:
                return []

        now = time.time()
        expired = [ip for ip, until in self._blocked_until.items() if until <= now]

        for ip in expired:
            if self.backend == "iptables":
                self._unblock_ip_iptables(ip)
            elif self.backend == "nft":
                self._unblock_ip_nft(ip)

            self._blocked_until.pop(ip, None)

        return expired

    def block_ip(self, ip: str, reason: str = "attack") -> MitigationResult:
        if self._is_allowlisted(ip):
            return MitigationResult(ok=True, detail="allowlisted_skip")

        now = time.time()
        until = now + self.block_seconds

        if self.backend == "sim":
            self._blocked_until[ip] = max(self._blocked_until.get(ip, 0), until)
            return MitigationResult(ok=True, detail=f"sim_block_until:{self._blocked_until[ip]:.0f}")

        if self.backend == "none":
            return MitigationResult(ok=True, detail="no_mitigation")

        if self.policy_mode == "observe":
            return MitigationResult(ok=True, detail="observe_only_skip")

        if self.backend == "redis":
            if self.redis_store is None:
                return MitigationResult(ok=False, detail="redis_not_initialized")

            try:
                count = self.redis_store.incr_offender(ip, ttl=300)

                if count >= 3:
                    ttl = 60
                elif count == 2:
                    ttl = 30
                else:
                    ttl = self.block_seconds

                self.redis_store.set_block(ip, reason, ttl)
                return MitigationResult(ok=True, detail=f"redis_block_ttl:{ttl}:offenses={count}")
            except Exception as e:
                return MitigationResult(ok=False, detail=f"redis_exception:{e}")

        if self.backend == "iptables":
            # Avoid duplicate rule insertion if already blocked
            if self.is_blocked(ip):
                self._blocked_until[ip] = max(self._blocked_until.get(ip, 0), until)
                return MitigationResult(ok=True, detail=f"already_blocked_extend_until:{self._blocked_until[ip]:.0f}")

            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            res = self._run(cmd)
            if res.ok:
                self._blocked_until[ip] = until
            return res

        if self.backend == "ipset":
            cmd = ["ipset", "add", "ddos_block", ip, "timeout", str(self.block_seconds), "-exist"]
            res = self._run(cmd)
            if res.ok:
                self._blocked_until[ip] = max(self._blocked_until.get(ip, 0), until)
            return res

        if self.backend == "nft":
            self._ensure_nft_bootstrap()
            cmd = [
                "nft",
                "add",
                "element",
                "inet",
                "ddosprot",
                "blocked_ips",
                "{",
                f"{ip}",
                "timeout",
                f"{self.block_seconds}s",
                "}",
            ]
            res = self._run(cmd, allow_exists=True)
            if res.ok:
                self._blocked_until[ip] = until
            return res

        return MitigationResult(ok=False, detail=f"unknown_backend:{self.backend}")

    def _unblock_ip_iptables(self, ip: str) -> MitigationResult:
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run(cmd)

    def _unblock_ip_nft(self, ip: str) -> MitigationResult:
        cmd = ["nft", "delete", "element", "inet", "ddosprot", "blocked_ips", "{", ip, "}"]
        return self._run(cmd)

    def _ensure_ipset_bootstrap(self) -> MitigationResult:
        create_set = self._run(["ipset", "create", "ddos_block", "hash:ip", "timeout", "0", "-exist"])
        if not create_set.ok:
            return create_set

        # Ensure there is an iptables rule that enforces drop from ipset.
        check_rule = self._run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "ddos_block", "src", "-j", "DROP"])
        if check_rule.ok:
            return MitigationResult(ok=True, detail="ipset_bootstrap_ok")

        add_rule = self._run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "ddos_block", "src", "-j", "DROP"])
        if add_rule.ok:
            return MitigationResult(ok=True, detail="ipset_bootstrap_ok")
        return add_rule

    def _ensure_nft_bootstrap(self) -> MitigationResult:
        commands = [
            ["nft", "add", "table", "inet", "ddosprot"],
            ["nft", "add", "chain", "inet", "ddosprot", "input", "{", "type", "filter", "hook", "input", "priority", "-300", ";", "policy", "accept", ";", "}"],
            ["nft", "add", "chain", "inet", "ddosprot", "ddos_dynamic"],
            ["nft", "add", "set", "inet", "ddosprot", "blocked_ips", "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
            ["nft", "add", "rule", "inet", "ddosprot", "input", "ct", "state", "established,related", "accept"],
            ["nft", "add", "rule", "inet", "ddosprot", "input", "ip", "saddr", "@blocked_ips", "drop"],
            ["nft", "add", "rule", "inet", "ddosprot", "input", "jump", "ddos_dynamic"],
        ]
        final = MitigationResult(ok=True, detail="nft_bootstrap_ok")
        for cmd in commands:
            res = self._run(cmd, allow_exists=True)
            if not res.ok:
                final = res
        return final

    def _apply_nft_attack_level(self, level: str, syn_limit: int, udp_limit: int, icmp_limit: int) -> MitigationResult:
        self._ensure_nft_bootstrap()
        flush = self._run(["nft", "flush", "chain", "inet", "ddosprot", "ddos_dynamic"])
        if not flush.ok:
            return flush

        if level == "normal":
            return MitigationResult(ok=True, detail="nft_attack_level:normal")

        rules: List[List[str]] = []
        if level in {"elevated", "under_attack"}:
            rules.extend([
                [
                    "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                    "ip", "protocol", "tcp", "tcp", "flags", "syn", "limit",
                    "rate", f"{syn_limit}/second", "burst", "80", "packets", "accept",
                ],
                [
                    "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                    "ip", "protocol", "tcp", "tcp", "flags", "syn", "drop",
                ],
                [
                    "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                    "ip", "protocol", "udp", "limit", "rate", f"{udp_limit}/second",
                    "burst", "200", "packets", "accept",
                ],
                [
                    "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                    "ip", "protocol", "icmp", "limit", "rate", f"{icmp_limit}/second",
                    "burst", "50", "packets", "accept",
                ],
            ])

            if level == "under_attack":
                rules.extend([
                    [
                        "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                        "ip", "protocol", "udp", "drop",
                    ],
                    [
                        "nft", "add", "rule", "inet", "ddosprot", "ddos_dynamic",
                        "ip", "protocol", "icmp", "drop",
                    ],
                ])

        for cmd in rules:
            res = self._run(cmd, allow_exists=True)
            if not res.ok:
                return res
        return MitigationResult(ok=True, detail=f"nft_attack_level:{level}")

    def _run(self, cmd: List[str], allow_exists: bool = False) -> MitigationResult:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if p.returncode == 0:
                return MitigationResult(ok=True, detail=p.stdout.strip() or "ok")
            if allow_exists:
                err = (p.stderr or p.stdout or "").lower()
                if "file exists" in err or "exists" in err:
                    return MitigationResult(ok=True, detail="already_exists")
            return MitigationResult(
                ok=False,
                detail=(p.stderr.strip() or p.stdout.strip() or f"rc={p.returncode}")
            )
        except FileNotFoundError:
            return MitigationResult(ok=False, detail=f"command_not_found:{cmd[0]}")
        except Exception as e:
            return MitigationResult(ok=False, detail=f"exception:{e}")

    def active_block_count(self) -> int:
        if self.backend == "redis" and self.redis_store is not None:
            return self.redis_store.count_blocked()

        now = time.time()
        return sum(1 for until in self._blocked_until.values() if until > now)