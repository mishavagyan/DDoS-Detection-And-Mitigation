# logger.py
import json
import os
import time
import logging
from typing import Any, Dict, Optional

def setup_logging(level=logging.INFO, log_file="logs/system.log") -> None:
    os.makedirs("logs", exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # allow all logs internally

    if root.handlers:
        root.handlers.clear()

    # console handler (INFO+ only)
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # file handler (DEBUG+)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

class EventLogger:
    def __init__(self, events_path: str, blocked_path: str):
        self.events_path = events_path
        self.blocked_path = blocked_path
        os.makedirs(os.path.dirname(events_path), exist_ok=True)

    def _write_jsonl(self, path: str, payload: Dict[str, Any]) -> None:
        payload = dict(payload)
        payload["ts"] = payload.get("ts", time.time())
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def log_detection(self, features: Dict[str, Any], decision: Dict[str, Any]) -> None:
        self._write_jsonl(self.events_path, {
            "type": "detection",
            "features": features,
            "decision": decision,
        })

    def log_block(self, ip: str, reason: str, backend: str, ok: bool, detail: Optional[str] = None) -> None:
        self._write_jsonl(self.blocked_path, {
            "type": "block",
            "ip": ip,
            "reason": reason,
            "backend": backend,
            "ok": ok,
            "detail": detail,
        })