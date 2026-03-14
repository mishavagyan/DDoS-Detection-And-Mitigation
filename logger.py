# logger.py
import json
import os
import time
import logging
from typing import Any, Dict, Optional, TextIO


def setup_logging(level: int = logging.INFO, log_file: str = "logs/system.log") -> None:
    log_dir = os.path.dirname(log_file) or "."
    os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    if root.handlers:
        root.handlers.clear()

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


class EventLogger:
    def __init__(self, events_path: str, blocked_path: str):
        self.events_path = events_path
        self.blocked_path = blocked_path

        events_dir = os.path.dirname(events_path) or "."
        blocked_dir = os.path.dirname(blocked_path) or "."

        os.makedirs(events_dir, exist_ok=True)
        os.makedirs(blocked_dir, exist_ok=True)

        self._events_f: TextIO = open(events_path, "a", encoding="utf-8", buffering=1)
        self._blocked_f: TextIO = open(blocked_path, "a", encoding="utf-8", buffering=1)
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return

        try:
            self._events_f.close()
        finally:
            self._blocked_f.close()

        self._closed = True

    def _write_jsonl(self, fh: TextIO, payload: Dict[str, Any]) -> None:
        record = dict(payload)
        record["ts"] = record.get("ts", time.time())
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def log_detection(self, features: Dict[str, Any], decision: Dict[str, Any]) -> None:
        self._write_jsonl(
            self._events_f,
            {
                "type": "detection",
                "features": features,
                "decision": decision,
            },
        )

    def log_block(
        self,
        ip: str,
        reason: str,
        backend: str,
        ok: bool,
        detail: Optional[str] = None,
    ) -> None:
        self._write_jsonl(
            self._blocked_f,
            {
                "type": "block",
                "ip": ip,
                "reason": reason,
                "backend": backend,
                "ok": ok,
                "detail": detail,
            },
        )