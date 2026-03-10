# mitigation.py
import time
import subprocess
import ipaddress
from dataclasses import dataclass
from typing import Dict, Optional, List


@dataclass
class MitigationResult:
    ok: bool
    detail: Optional[str] = None


class Mitigator:
    def __init__(self, backend: str = "iptables", block_seconds: int = 120, allowlist_cidrs: Optional[List[str]] = None):
        self.backend = backend
        self.block_seconds = block_seconds
        self._blocked_until: Dict[str, float] = {}

        self.allowlist = []
        for c in (allowlist_cidrs or []):
            try:
                self.allowlist.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass

    def _is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.allowlist)
        except Exception:
            return False

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        return ip in self._blocked_until and self._blocked_until[ip] > now

    def cleanup_expired(self) -> List[str]:
        now = time.time()
        expired = [ip for ip, until in self._blocked_until.items() if until <= now]
        for ip in expired:
            self._blocked_until.pop(ip, None)
        return expired

    def block_ip(self, ip: str) -> MitigationResult:
        if self._is_allowlisted(ip):
            return MitigationResult(ok=True, detail="allowlisted_skip")

        now = time.time()
        until = now + self.block_seconds

        # SIM backend
        if self.backend == "sim":
            self._blocked_until[ip] = max(self._blocked_until.get(ip, 0), until)
            return MitigationResult(ok=True, detail=f"sim_block_until:{self._blocked_until[ip]:.0f}")

        # NONE backend
        if self.backend == "none":
            return MitigationResult(ok=True, detail="no_mitigation")

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