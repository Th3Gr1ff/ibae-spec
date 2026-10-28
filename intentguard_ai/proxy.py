"""IntentGuard MCP Proxy -- purpose-enforcement gateway for AI agent tool calls.

Sits between an MCP client (Claude Code, or any agent) and an MCP server (the
real tool). Speaks MCP (JSON-RPC 2.0 over stdio) on both sides. The agent
thinks it's talking to the tool. It's talking to IntentGuard.

Architecture:
    Agent  <--stdio-->  IntentGuard Proxy  <--stdio-->  Real MCP Server

The proxy:
1. Forwards initialize/tools/list transparently
2. Intercepts tools/call -- validates against the purpose envelope
3. Scans outbound params via SCARE-Context (after envelope passes)
4. Scans inbound responses via SCARE-Context (before forwarding to agent)
5. Blocks calls outside the envelope (returns JSON-RPC error, never reaches server)
6. Quarantines RED and AMBER-inbound content (fail-closed)
7. Logs everything to the append-only ledger
8. Runs the delta detector across the session

FAIL-CLOSED CONTRACT: if the SCARE scanner raises an exception, the content
is quarantined. If content exceeds the hard ceiling, it is quarantined.
There is no path where unscanned content reaches the agent.

Usage:
    python -m intentguard_ai.proxy --policy policy.yaml --purpose read-invoices -- node server.js
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from .delta import DeltaDetector
from .envelope import EnvelopeValidator
from .ledger import AuditLedger
from .policy import Policy
from .scare_context import SCAREContext

logger = logging.getLogger("intentguard")

DENIED_ERROR_CODE = -32001
SCARE_QUARANTINE_CODE = -32002
PURPOSE_HEADER = "X-IntentGuard-Purpose"


def _read_jsonrpc_message(stream) -> Optional[dict]:
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            logger.warning("non-JSON line from stream: %s", line[:200])
            continue


def _write_jsonrpc_message(stream, msg: dict) -> None:
    stream.write(json.dumps(msg) + "\n")
    stream.flush()


def _make_error_response(request_id, code: int, message: str, data: Optional[dict] = None) -> dict:
    resp = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if data:
        resp["error"]["data"] = data
    return resp


def _make_success_response(request_id, result: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


class IntentGuardProxy:
    def __init__(self, policy: Policy, purpose: str, ledger: AuditLedger,
                 server_cmd: list[str], deny_action: str = "block"):
        self._policy = policy
        self._purpose = purpose
        self._validator = EnvelopeValidator(policy)
        self._delta = DeltaDetector()
        self._ledger = ledger
        self._server_cmd = server_cmd
        self._deny_action = deny_action
        self._server_proc: Optional[subprocess.Popen] = None
        self._running = False
        self._scare = SCAREContext()
        self._pending_tool_calls: dict[str, str] = {}
        self._pending_lock = threading.Lock()

        if not self._validator.set_purpose(purpose):
            raise ValueError(f"purpose '{purpose}' not found in policy")
        self._delta.set_purpose(purpose)

    def run(self) -> int:
        self._ledger.log_session_event("proxy_start", {
            "purpose": self._purpose,
            "server_cmd": self._server_cmd,
            "scare_enabled": self._policy.scare.context_scan,
        })

        self._server_proc = subprocess.Popen(
            self._server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        self._running = True

        server_reader = threading.Thread(
            target=self._relay_server_to_client,
            daemon=True,
        )
        server_reader.start()

        try:
            self._relay_client_to_server()
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            self._running = False
            self._shutdown()

        return 0

    def _relay_client_to_server(self) -> None:
        while self._running:
            msg = _read_jsonrpc_message(sys.stdin)
            if msg is None:
                break

            method = msg.get("method", "")

            if method == "tools/call":
                self._handle_tool_call(msg)
            elif method == "intentguard/set_purpose":
                self._handle_set_purpose(msg)
            elif method == "intentguard/status":
                self._handle_status(msg)
            else:
                self._forward_to_server(msg)

    def _relay_server_to_client(self) -> None:
        while self._running and self._server_proc:
            msg = _read_jsonrpc_message(self._server_proc.stdout)
            if msg is None:
                break

            request_id = str(msg.get("id", ""))
            tool_name = None
            with self._pending_lock:
                tool_name = self._pending_tool_calls.pop(request_id, None)

            if tool_name and "result" in msg:
                scanned = self._scan_inbound(msg, tool_name, request_id)
                if scanned is not None:
                    _write_jsonrpc_message(sys.stdout, scanned)
                    continue

            _write_jsonrpc_message(sys.stdout, msg)

    def _handle_tool_call(self, msg: dict) -> None:
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        request_id = msg.get("id")

        result = self._validator.validate(tool_name, tool_args)

        self._ledger.log_validation(
            result,
            request_id=str(request_id),
            params_summary=tool_args,
        )

        if not result.allowed:
            logger.info("DENIED: tool=%s purpose=%s reason=%s", tool_name, self._purpose, result.reason)
            error_resp = _make_error_response(
                request_id,
                DENIED_ERROR_CODE,
                f"IntentGuard: tool call denied -- {result.reason}",
                data={
                    "tool": tool_name,
                    "purpose": self._purpose,
                    "intentguard": True,
                },
            )
            _write_jsonrpc_message(sys.stdout, error_resp)
            return

        quarantine = self._scan_outbound(tool_name, tool_args, request_id)
        if quarantine:
            _write_jsonrpc_message(sys.stdout, quarantine)
            return

        drift_alert = self._delta.record(tool_name)
        if drift_alert:
            self._ledger.log_drift_alert(drift_alert)
            logger.warning("DRIFT: %s", drift_alert.reason)

        with self._pending_lock:
            self._pending_tool_calls[str(request_id)] = tool_name

        logger.info("ALLOWED: tool=%s purpose=%s", tool_name, self._purpose)
        self._forward_to_server(msg)

    def _scan_outbound(self, tool_name: str, tool_args: dict, request_id) -> Optional[dict]:
        cfg = self._policy.get_scare_config(self._purpose)
        if not cfg.context_scan or not cfg.outbound_scan:
            return None

        text = json.dumps(tool_args, default=str)
        text_bytes = len(text.encode("utf-8", errors="replace"))

        if text_bytes > cfg.hard_ceiling_bytes:
            self._ledger.log_scare_scan(
                direction="outbound", verdict="QUARANTINE",
                tells=[], tool_name=tool_name, purpose=self._purpose,
                action="quarantined", source=f"params:{tool_name}",
            )
            logger.warning("SCARE QUARANTINE (outbound): tool=%s reason=exceeds_hard_ceiling (%d bytes)", tool_name, text_bytes)
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                f"IntentGuard SCARE: outbound params quarantined (exceeds size ceiling)",
                data={"tool": tool_name, "purpose": self._purpose, "intentguard": True, "scare_verdict": "QUARANTINE"},
            )

        try:
            report = self._scare.scan_text(text, source=f"params:{tool_name}")
        except Exception as exc:
            self._ledger.log_scare_scan(
                direction="outbound", verdict="ERROR",
                tells=[{"type": "scanner_error", "subtype": "exception", "severity": "high", "line": 0, "match": str(exc)[:200]}],
                tool_name=tool_name, purpose=self._purpose,
                action="quarantined", source=f"params:{tool_name}",
            )
            logger.error("SCARE QUARANTINE (outbound): tool=%s reason=scanner_exception", tool_name)
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                "IntentGuard SCARE: outbound params quarantined (scanner error, fail-closed)",
                data={"tool": tool_name, "purpose": self._purpose, "intentguard": True, "scare_verdict": "ERROR"},
            )

        verdict = report["verdict"]
        self._ledger.log_scare_scan(
            direction="outbound", verdict=verdict, tells=report["tells"],
            tool_name=tool_name, purpose=self._purpose,
            action="quarantined" if verdict == "RED" else ("logged" if verdict == "AMBER" else "passed"),
            source=f"params:{tool_name}",
        )

        if verdict == "RED" and cfg.quarantine_on_red:
            logger.warning("SCARE QUARANTINE (outbound RED): tool=%s tells=%d", tool_name, len(report["tells"]))
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                "IntentGuard SCARE: outbound params quarantined (RED verdict)",
                data={
                    "tool": tool_name, "purpose": self._purpose,
                    "intentguard": True, "scare_verdict": "RED",
                    "tell_count": len(report["tells"]),
                },
            )

        if verdict == "AMBER" and cfg.alert_on_amber:
            logger.warning("SCARE AMBER (outbound): tool=%s tells=%d", tool_name, len(report["tells"]))

        return None

    def _scan_inbound(self, msg: dict, tool_name: str, request_id: str) -> Optional[dict]:
        cfg = self._policy.get_scare_config(self._purpose)
        if not cfg.context_scan or not cfg.inbound_scan:
            return None

        result_obj = msg.get("result", {})
        content_items = result_obj.get("content", [])
        text_parts = []
        for item in content_items:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    text_parts.append(item.get("text", ""))
                elif "data" in item:
                    text_parts.append(item["data"])

        if not text_parts:
            return None

        text = "\n".join(text_parts)
        text_bytes = len(text.encode("utf-8", errors="replace"))

        if text_bytes > cfg.hard_ceiling_bytes:
            self._ledger.log_scare_scan(
                direction="inbound", verdict="QUARANTINE",
                tells=[], tool_name=tool_name, purpose=self._purpose,
                action="quarantined", source=f"response:{tool_name}",
            )
            logger.warning("SCARE QUARANTINE (inbound): tool=%s reason=exceeds_hard_ceiling (%d bytes)", tool_name, text_bytes)
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                "IntentGuard SCARE: inbound response quarantined (exceeds size ceiling)",
                data={"tool": tool_name, "purpose": self._purpose, "intentguard": True, "scare_verdict": "QUARANTINE"},
            )

        try:
            report = self._scare.scan_text(text, source=f"response:{tool_name}")
        except Exception as exc:
            self._ledger.log_scare_scan(
                direction="inbound", verdict="ERROR",
                tells=[{"type": "scanner_error", "subtype": "exception", "severity": "high", "line": 0, "match": str(exc)[:200]}],
                tool_name=tool_name, purpose=self._purpose,
                action="quarantined", source=f"response:{tool_name}",
            )
            logger.error("SCARE QUARANTINE (inbound): tool=%s reason=scanner_exception", tool_name)
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                "IntentGuard SCARE: inbound response quarantined (scanner error, fail-closed)",
                data={"tool": tool_name, "purpose": self._purpose, "intentguard": True, "scare_verdict": "ERROR"},
            )

        verdict = report["verdict"]

        if verdict == "RED" and cfg.quarantine_on_red:
            self._ledger.log_scare_scan(
                direction="inbound", verdict=verdict, tells=report["tells"],
                tool_name=tool_name, purpose=self._purpose,
                action="quarantined", source=f"response:{tool_name}",
            )
            logger.warning("SCARE QUARANTINE (inbound RED): tool=%s tells=%d", tool_name, len(report["tells"]))
            return _make_error_response(
                request_id, SCARE_QUARANTINE_CODE,
                "IntentGuard SCARE: inbound response quarantined (RED -- prompt injection or exfil detected)",
                data={
                    "tool": tool_name, "purpose": self._purpose,
                    "intentguard": True, "scare_verdict": "RED",
                    "tell_count": len(report["tells"]),
                    "tell_types": list({t["subtype"] for t in report["tells"]}),
                },
            )

        if verdict == "AMBER":
            if cfg.quarantine_on_amber_inbound:
                self._ledger.log_scare_scan(
                    direction="inbound", verdict=verdict, tells=report["tells"],
                    tool_name=tool_name, purpose=self._purpose,
                    action="quarantined", source=f"response:{tool_name}",
                )
                logger.warning("SCARE QUARANTINE (inbound AMBER): tool=%s tells=%d", tool_name, len(report["tells"]))
                return _make_error_response(
                    request_id, SCARE_QUARANTINE_CODE,
                    "IntentGuard SCARE: inbound response quarantined (AMBER -- suspicious content detected)",
                    data={
                        "tool": tool_name, "purpose": self._purpose,
                        "intentguard": True, "scare_verdict": "AMBER",
                        "tell_count": len(report["tells"]),
                        "tell_types": list({t["subtype"] for t in report["tells"]}),
                    },
                )
            else:
                self._ledger.log_scare_scan(
                    direction="inbound", verdict=verdict, tells=report["tells"],
                    tool_name=tool_name, purpose=self._purpose,
                    action="forwarded_with_warning", source=f"response:{tool_name}",
                )
                logger.warning("SCARE AMBER (inbound, forwarding with warning): tool=%s tells=%d", tool_name, len(report["tells"]))
                if content_items:
                    warning_item = {
                        "type": "text",
                        "text": json.dumps({
                            "intentguard_warning": "SCARE-Context AMBER verdict on this response",
                            "tell_count": len(report["tells"]),
                            "tell_types": list({t["subtype"] for t in report["tells"]}),
                        }),
                    }
                    result_obj["content"] = [warning_item] + content_items
                    msg["result"] = result_obj
                return None

        self._ledger.log_scare_scan(
            direction="inbound", verdict=verdict, tells=report["tells"],
            tool_name=tool_name, purpose=self._purpose,
            action="passed", source=f"response:{tool_name}",
        )
        return None

    def _handle_set_purpose(self, msg: dict) -> None:
        request_id = msg.get("id")
        new_purpose = msg.get("params", {}).get("purpose", "")

        if self._validator.set_purpose(new_purpose):
            self._purpose = new_purpose
            self._delta.reset()
            self._delta.set_purpose(new_purpose)
            self._ledger.log_session_event("purpose_changed", {"new_purpose": new_purpose})
            resp = _make_success_response(request_id, {
                "purpose": new_purpose,
                "status": "active",
            })
        else:
            resp = _make_error_response(
                request_id, DENIED_ERROR_CODE,
                f"purpose '{new_purpose}' not found in policy",
            )
        _write_jsonrpc_message(sys.stdout, resp)

    def _handle_status(self, msg: dict) -> None:
        request_id = msg.get("id")
        scare_cfg = self._policy.get_scare_config(self._purpose)
        resp = _make_success_response(request_id, {
            "purpose": self._purpose,
            "active": self._running,
            "drift_alerts": len(self._delta.alerts),
            "validator_purpose": self._validator.active_purpose,
            "scare": {
                "context_scan": scare_cfg.context_scan,
                "outbound_scan": scare_cfg.outbound_scan,
                "inbound_scan": scare_cfg.inbound_scan,
                "quarantine_on_red": scare_cfg.quarantine_on_red,
                "quarantine_on_amber_inbound": scare_cfg.quarantine_on_amber_inbound,
            },
        })
        _write_jsonrpc_message(sys.stdout, resp)

    def _forward_to_server(self, msg: dict) -> None:
        if self._server_proc and self._server_proc.stdin:
            _write_jsonrpc_message(self._server_proc.stdin, msg)

    def _shutdown(self) -> None:
        self._ledger.log_session_event("proxy_stop", {
            "purpose": self._purpose,
            "drift_alerts": len(self._delta.alerts),
        })
        self._ledger.close()

        if self._server_proc:
            self._server_proc.stdin.close()
            try:
                self._server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server_proc.terminate()
                self._server_proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(
        description="IntentGuard MCP Proxy -- purpose-enforcement gateway for AI tool calls",
    )
    parser.add_argument("--policy", required=True, help="Path to policy YAML file")
    parser.add_argument("--purpose", required=True, help="Declared purpose for this session")
    parser.add_argument("--ledger", default=None, help="Path to audit ledger file (default: ./intentguard_audit.jsonl)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging to stderr")
    parser.add_argument("server_cmd", nargs="+", help="MCP server command to proxy (after --)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[IntentGuard] %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    policy = Policy.from_file(args.policy)
    ledger_path = args.ledger or "intentguard_audit.jsonl"
    ledger = AuditLedger(path=ledger_path)

    proxy = IntentGuardProxy(
        policy=policy,
        purpose=args.purpose,
        ledger=ledger,
        server_cmd=args.server_cmd,
    )

    sys.exit(proxy.run())


if __name__ == "__main__":
    main()
