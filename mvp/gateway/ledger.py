"""
OCSF Ledger emission.
Phase 1-2: NDJSON to stdout (captured by docker log driver).
Phase 3: pluggable SIEM emitter (Sentinel Log Analytics via HTTP Data
Collector API, with mock Sentinel receiver for testable e2e).
Phase 3.1 (2026-09-17): Splunk HEC emitter added. Same emitter serves
Cribl (Cribl accepts Splunk HEC natively as a source).

SIEM_CONNECTOR env var accepts a comma-separated list, e.g.:
  "stdout"                 -> NDJSON to stdout only (default)
  "sentinel"               -> Sentinel only
  "splunk_hec"             -> Splunk HEC only (also works for Cribl HEC listener)
  "stdout,sentinel"        -> both
  "stdout,splunk_hec"      -> stdout + Splunk HEC
  "both"                   -> back-compat alias for "stdout,sentinel"
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from typing import Any
from datetime import datetime, timezone

import httpx


SIEM_CONNECTOR = os.environ.get("SIEM_CONNECTOR", "stdout")


def _sentinel_signature(
    workspace_id: str,
    shared_key: str,
    body_length: int,
    date_header: str,
    method: str = "POST",
    content_type: str = "application/json",
    resource: str = "/api/logs",
) -> str:
    """RFC 2616 signature for Azure Log Analytics HTTP Data Collector API."""
    string_to_hash = (
        f"{method}\n{body_length}\n{content_type}\n"
        f"x-ms-date:{date_header}\n{resource}"
    )
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _emit_sentinel(event: dict[str, Any]) -> None:
    """Push single OCSF event to Sentinel Log Analytics."""
    workspace_id = os.environ.get("SENTINEL_WORKSPACE_ID", "")
    shared_key = os.environ.get(
        "SENTINEL_SHARED_KEY",
        base64.b64encode(b"mock-key-for-lab-use-only-not-a-real-secret").decode(),
    )
    log_type = os.environ.get("SENTINEL_LOG_TYPE", "IntentGuardOCSF")
    endpoint = os.environ.get(
        "SENTINEL_ENDPOINT",
        f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
    )
    body = json.dumps([event])
    date_header = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = _sentinel_signature(
        workspace_id or "mock-workspace",
        shared_key,
        len(body.encode("utf-8")),
        date_header,
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": date_header,
        "time-generated-field": "TimeGenerated",
    }
    try:
        with httpx.Client(timeout=5.0, verify=False) as c:
            r = c.post(endpoint, headers=headers, content=body)
        if r.status_code >= 400:
            print(
                f"sentinel_emit_failed status={r.status_code} body={r.text[:200]}",
                file=sys.stderr, flush=True,
            )
    except Exception as ex:
        print(f"sentinel_emit_exception:{ex}", file=sys.stderr, flush=True)


def _emit_splunk_hec(event: dict[str, Any]) -> None:
    """
    Push a single OCSF event to a Splunk HTTP Event Collector endpoint.
    Same emitter serves Cribl (Cribl accepts Splunk HEC natively as an input).

    Env vars:
      SPLUNK_HEC_ENDPOINT   - base URL, e.g. https://splunk.example.com:8088
                              (path /services/collector/event is appended)
      SPLUNK_HEC_TOKEN      - HEC token (required)
      SPLUNK_HEC_SOURCETYPE - sourcetype label (default: "intenttrace:ocsf")
      SPLUNK_HEC_INDEX      - optional index name (omit to use HEC default)
      SPLUNK_HEC_HOST       - host label (default: "intenttrace-gateway")
      SPLUNK_HEC_VERIFY_TLS - "true" to verify TLS (default: false, matches
                              Sentinel MVP pattern; flip to true in prod)
    """
    endpoint_base = os.environ.get("SPLUNK_HEC_ENDPOINT", "")
    token = os.environ.get("SPLUNK_HEC_TOKEN", "")
    if not endpoint_base or not token:
        print(
            "splunk_hec_emit_skipped: SPLUNK_HEC_ENDPOINT or SPLUNK_HEC_TOKEN unset",
            file=sys.stderr, flush=True,
        )
        return
    sourcetype = os.environ.get("SPLUNK_HEC_SOURCETYPE", "intenttrace:ocsf")
    host = os.environ.get("SPLUNK_HEC_HOST", "intenttrace-gateway")
    index = os.environ.get("SPLUNK_HEC_INDEX", "")
    verify_tls = os.environ.get("SPLUNK_HEC_VERIFY_TLS", "false").lower() == "true"
    url = endpoint_base.rstrip("/") + "/services/collector/event"
    # OCSF event.time is milliseconds since epoch; Splunk HEC wants seconds (float ok).
    event_time_seconds = (event.get("time", int(time.time() * 1000))) / 1000.0
    hec_envelope: dict[str, Any] = {
        "time": event_time_seconds,
        "host": host,
        "sourcetype": sourcetype,
        "event": event,
    }
    if index:
        hec_envelope["index"] = index
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(timeout=5.0, verify=verify_tls) as c:
            r = c.post(url, headers=headers, json=hec_envelope)
        if r.status_code >= 400:
            print(
                f"splunk_hec_emit_failed status={r.status_code} body={r.text[:200]}",
                file=sys.stderr, flush=True,
            )
    except Exception as ex:
        print(f"splunk_hec_emit_exception:{ex}", file=sys.stderr, flush=True)


def _connector_set(raw: str) -> set[str]:
    """Parse SIEM_CONNECTOR env into a normalized set of destinations."""
    parts = {p.strip().lower() for p in raw.split(",") if p.strip()}
    # Back-compat: "both" was an alias for stdout + sentinel.
    if "both" in parts:
        parts.discard("both")
        parts.update({"stdout", "sentinel"})
    return parts


def emit_ocsf(ctx: dict[str, Any], admitted: bool) -> None:
    """
    OCSF Authentication activity_id, minimally shaped for MVP.
    Real OCSF schema: class_uid 3002 (Authentication), activity_id 1 (Logon).
    Dispatches to SIEM connectors per SIEM_CONNECTOR env
    (comma-separated: stdout, sentinel, splunk_hec; "both" = stdout+sentinel).
    """
    event = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "IntentGuard Gateway MVP", "version": "0.1.0"},
            "correlation_uid": ctx.get("correlation_id"),
        },
        "time": int(time.time() * 1000),
        "class_uid": 3002,
        "class_name": "Authentication",
        "activity_id": 1,
        "activity_name": "Logon",
        "type_uid": 300201,
        "severity_id": 1 if admitted else 3,
        "status_id": 1 if admitted else 2,
        "status": "Success" if admitted else "Failure",
        "actor": {
            "user": {
                "name": ctx.get("token_claims", {}).get("sub"),
                "role": ctx.get("token_claims", {}).get("role"),
            },
        },
        "src_endpoint": {
            "ip": ctx.get("request_headers", {}).get("x-forwarded-for"),
        },
        "http_request": {
            "http_method": ctx.get("request_method"),
            "url": {"path": ctx.get("request_path")},
        },
        "unmapped": {
            "purpose": ctx.get("purpose"),
            "dpop_jkt": ctx.get("dpop_jwk_thumbprint"),
            "admitted": admitted,
            "deny_step": ctx.get("deny_step"),
            "deny_reason": ctx.get("deny_reason"),
            "latency_ms": int((time.time() - ctx.get("started_at", time.time())) * 1000),
        },
    }
    # Dispatch to configured connector(s).
    connectors = _connector_set(SIEM_CONNECTOR)
    if "stdout" in connectors:
        print(json.dumps(event), file=sys.stdout, flush=True)
    if "sentinel" in connectors:
        _emit_sentinel(event)
    if "splunk_hec" in connectors:
        _emit_splunk_hec(event)
    # Phase 4: fan out to Behavioral Delta Detector if wired.
    # Fire-and-forget in a thread so a downstream Sidecar->/_admin/revoke
    # callback into this same gateway process can't deadlock the event loop.
    bdd_endpoint = os.environ.get("BDD_ENDPOINT")
    if bdd_endpoint:
        threading.Thread(
            target=_emit_bdd_sync, args=(bdd_endpoint, event), daemon=True
        ).start()


def _emit_bdd_sync(endpoint: str, event: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5.0) as c:
            c.post(endpoint, json=event)
    except Exception as ex:
        print(f"bdd_emit_exception:{ex}", file=sys.stderr, flush=True)
