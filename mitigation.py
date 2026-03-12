import time
import subprocess
import ipaddress
from dataclasses import dataclass
from typing import Dict, Optional, List

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
        allowlist_cidrs: Optional[List[str]] = None,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
    ):
        self.backend = backend
        self.block_seconds = block_seconds
        self._blocked_until: Dict[str, float] = {}

        self.allowlist = []
        for c in (allowlist_cidrs or []):
            try:
                self.allowlist.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass

        self.redis_store = None
        if self.backend == "redis":
            self.redis_store = RedisStore(host=redis_host, port=redis_port, db=redis_db)

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

    def cleanup_expired(self) -> List[str]:
        if self.backend == "redis":
            return []

        now = time.time()
        expired = [ip for ip, until in self._blocked_until.items() if until <= now]
        for ip in expired:
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
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
            res = self._run(cmd)
            if res.ok:
                self._blocked_until[ip] = until
            return res

        if self.backend == "ipset":
            cmd = ["ipset", "add", "ddos_block", ip, "timeout", str(self.block_seconds), "-exist"]
            return self._run(cmd)

        if self.backend == "nft":
            cmd = ["nft", "add", "rule", "inet", "ddosprot", "input", "ip", "saddr", ip, "drop"]
            res = self._run(cmd)
            if res.ok:
                self._blocked_until[ip] = until
            return res

        return MitigationResult(ok=False, detail=f"unknown_backend:{self.backend}")

    def _run(self, cmd) -> MitigationResult:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if p.returncode == 0:
                return MitigationResult(ok=True, detail=p.stdout.strip() or "ok")
            return MitigationResult(ok=False, detail=(p.stderr.strip() or p.stdout.strip() or f"rc={p.returncode}"))
        except FileNotFoundError:
            return MitigationResult(ok=False, detail=f"command_not_found:{cmd[0]}")
        except Exception as e:
            return MitigationResult(ok=False, detail=f"exception:{e}")
        
    def active_block_count(self) -> int:
        if self.backend == "redis" and self.redis_store is not None:
            return self.redis_store.count_blocked()
        now = time.time()
        return sum(1 for _, until in self._blocked_until.items() if until > now)