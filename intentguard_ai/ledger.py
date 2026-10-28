"""Append-only audit ledger.

Every tool call through the proxy gets logged: allowed or denied, with the
full validation result, timestamp, and session context. This feeds the
measurement layer (RAV input).

Format: JSONL (one JSON object per line). Each entry is a complete record.
The ledger file is append-only by convention; the proxy never reads back
or modifies existing entries.
"""

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional, TextIO

from .envelope import ValidationResult
from .delta import DriftAlert


class AuditLedger:
    def __init__(self, path: str | Path | None = None, stream: TextIO | None = None):
        self._path = Path(path) if path else None
        self._stream = stream
        self._file: Optional[TextIO] = None

        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self._path, "a")

    def log_validation(self, result: ValidationResult, request_id: Optional[str] = None,
                       params_summary: Optional[dict] = None) -> None:
        entry = {
            "type": "validation",
            "timestamp": time.time(),
            "request_id": request_id,
            "tool": result.tool_name,
            "purpose": result.purpose,
            "allowed": result.allowed,
            "reason": result.reason,
            "params_keys": list(params_summary.keys()) if params_summary else [],
        }
        self._write(entry)

    def log_drift_alert(self, alert: DriftAlert) -> None:
        entry = {
            "type": "drift_alert",
            "timestamp": time.time(),
            "tool": alert.tool_name,
            "purpose": alert.purpose,
            "reason": alert.reason,
            "distribution": alert.session_distribution,
        }
        self._write(entry)

    def log_scare_scan(self, direction: str, verdict: str, tells: list,
                       tool_name: str, purpose: str, action: str,
                       source: Optional[str] = None) -> None:
        entry = {
            "type": "scare_scan",
            "timestamp": time.time(),
            "direction": direction,
            "verdict": verdict,
            "tells": tells,
            "tool": tool_name,
            "purpose": purpose,
            "action": action,
        }
        if source:
            entry["source"] = source
        self._write(entry)

    def log_session_event(self, event: str, details: Optional[dict] = None) -> None:
        entry = {
            "type": "session",
            "timestamp": time.time(),
            "event": event,
            "details": details or {},
        }
        self._write(entry)

    def _write(self, entry: dict) -> None:
        line = json.dumps(entry, default=str)
        if self._file:
            self._file.write(line + "\n")
            self._file.flush()
        if self._stream:
            self._stream.write(line + "\n")
            self._stream.flush()

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
