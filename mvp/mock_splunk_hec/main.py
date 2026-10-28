"""
Mock Splunk HTTP Event Collector receiver.

Pretends to be a real Splunk HEC at https://splunk.example.com:8088/services/collector/event
so Phase 3.1 SIEM-connector code (also serves Cribl HEC listeners) can be
tested end-to-end without a real Splunk deployment.

Verification: GET /_received returns all events the mock has seen,
so the phase3_test.sh script can assert every gateway ledger event
reached the HEC endpoint.

Auth: accepts any "Authorization: Splunk <token>" for MVP. Real HEC
would validate the token against a per-token index/sourcetype policy.
"""
import json
from typing import Any
from fastapi import FastAPI, Request, Header, HTTPException

app = FastAPI(title="IntentTrace MVP Mock Splunk HEC")
RECEIVED: list[dict[str, Any]] = []


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock_splunk_hec"}


@app.get("/_received")
def received() -> dict[str, Any]:
    """Test-harness endpoint: dump everything the mock has seen."""
    return {"count": len(RECEIVED), "events": RECEIVED}


@app.post("/_received/reset")
def reset_received() -> dict[str, int]:
    RECEIVED.clear()
    return {"count": 0}


@app.post("/services/collector/event")
async def collector_event(
    request: Request,
    authorization: str = Header(default="", alias="Authorization"),
) -> dict[str, Any]:
    """
    Splunk HEC event endpoint (mock).
    Real HEC returns: {"text":"Success","code":0} on 200.
    Rejects with 401 if no token supplied.
    """
    if not authorization.startswith("Splunk "):
        raise HTTPException(status_code=401, detail="No Splunk HEC token")
    body = await request.body()
    try:
        envelope = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(envelope, dict) or "event" not in envelope:
        raise HTTPException(status_code=400, detail="HEC envelope missing 'event'")
    RECEIVED.append(envelope)
    return {"text": "Success", "code": 0}
