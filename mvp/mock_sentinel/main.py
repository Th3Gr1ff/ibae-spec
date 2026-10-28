"""
Mock Sentinel Log Analytics HTTP Data Collector API receiver.
Pretends to be https://<workspace>.ods.opinsights.azure.com/api/logs
so Phase 3 SIEM-connector code can be tested end-to-end without
real Azure credentials.

Verification: GET /_received returns all events the mock has seen,
so the phase3_test.sh script can assert every gateway ledger event
reached the SIEM connector.
"""
import json
from typing import Any
from fastapi import FastAPI, Request, Header

app = FastAPI(title="IntentGuard MVP Mock Sentinel")
RECEIVED: list[dict[str, Any]] = []


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock_sentinel"}


@app.get("/_received")
def received() -> dict[str, Any]:
    """Test-harness endpoint: dump everything the mock has seen."""
    return {"count": len(RECEIVED), "events": RECEIVED}


@app.post("/_received/reset")
def reset_received() -> dict[str, int]:
    RECEIVED.clear()
    return {"count": 0}


@app.post("/api/logs")
async def logs(
    request: Request,
    log_type: str = Header(default="", alias="Log-Type"),
    x_ms_date: str = Header(default="", alias="x-ms-date"),
    authorization: str = Header(default="", alias="Authorization"),
) -> dict[str, str]:
    """
    Log Analytics HTTP Data Collector API endpoint (mock).
    Accepts POST with JSON array body + Log-Type header.
    Real Sentinel returns 200 OK on success.
    We just record the events for later verification.
    """
    body = await request.body()
    try:
        events = json.loads(body.decode())
        if isinstance(events, list):
            for e in events:
                RECEIVED.append({
                    "log_type": log_type,
                    "x_ms_date": x_ms_date,
                    "auth_prefix": authorization[:24] if authorization else None,
                    "event": e,
                })
    except Exception as ex:
        return {"status": "error", "reason": str(ex)}
    return {"status": "ok"}
