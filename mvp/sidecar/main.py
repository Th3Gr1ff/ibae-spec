"""
Sidecar approval channel.

IBAE v1.1 §7 role: human-in-the-loop review queue for BDD proposals.
BDD flags a suspected behavioral abuse (e.g. subject exceeding rate),
Sidecar decides whether to enact revocation, then calls the gateway's
runtime revocation endpoint.

Phase 4 MVP: two policy modes:
- auto (default): auto-approve every proposal, log the decision.
  Proves the closed loop end-to-end.
- manual: hold proposals in a queue for /decisions/{id}/approve or /deny
  calls from a human console. Real deployments run in this mode.
"""
import os
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="IntentGuard Sidecar", version="0.1.0")

POLICY_MODE = os.environ.get("SIDECAR_POLICY_MODE", "auto")
GATEWAY_ADMIN_URL = os.environ.get(
    "GATEWAY_ADMIN_URL", "http://gateway:8443/_admin/revoke"
)
ADMIN_SHARED_SECRET = os.environ.get("ADMIN_SHARED_SECRET", "dev-admin-key")

QUEUE: list[dict[str, Any]] = []
DECISIONS: list[dict[str, Any]] = []


def _enact_revocation(proposal: dict[str, Any]) -> dict[str, Any]:
    """Fire the runtime revocation against the gateway admin endpoint."""
    payload = {"kind": proposal["kind"], "value": proposal["value"]}
    try:
        with httpx.Client(timeout=5.0) as c:
            r = c.post(
                GATEWAY_ADMIN_URL,
                json=payload,
                headers={"X-Admin-Key": ADMIN_SHARED_SECRET},
            )
        return {
            "gateway_status": r.status_code,
            "gateway_body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200],
        }
    except Exception as ex:
        return {"gateway_status": "error", "error": str(ex)}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sidecar", "policy_mode": POLICY_MODE}


@app.get("/_queue")
def show_queue() -> dict[str, Any]:
    return {"pending": QUEUE, "decided": DECISIONS}


@app.post("/_reset")
def reset() -> dict[str, str]:
    QUEUE.clear()
    DECISIONS.clear()
    return {"status": "reset"}


@app.post("/review")
async def review(request: Request) -> dict[str, Any]:
    """BDD posts a revocation proposal here."""
    proposal = await request.json()
    proposal_id = uuid.uuid4().hex[:12]
    record = {
        "id": proposal_id,
        "received_at": time.time(),
        "proposal": proposal,
    }
    if POLICY_MODE == "auto":
        # Fire immediately + log
        enact_result = _enact_revocation(proposal)
        DECISIONS.append({
            **record,
            "decision": "approved",
            "decided_at": time.time(),
            "auto": True,
            "enact_result": enact_result,
        })
        return {
            "status": "auto_approved",
            "id": proposal_id,
            "enact_result": enact_result,
        }
    # manual: queue for human
    QUEUE.append(record)
    return {"status": "queued", "id": proposal_id}


@app.post("/decisions/{proposal_id}/approve")
def approve(proposal_id: str) -> dict[str, Any]:
    for i, rec in enumerate(QUEUE):
        if rec["id"] == proposal_id:
            enact_result = _enact_revocation(rec["proposal"])
            DECISIONS.append({
                **rec,
                "decision": "approved",
                "decided_at": time.time(),
                "auto": False,
                "enact_result": enact_result,
            })
            QUEUE.pop(i)
            return {"status": "approved", "id": proposal_id, "enact_result": enact_result}
    raise HTTPException(status_code=404, detail="proposal_not_found")


@app.post("/decisions/{proposal_id}/deny")
def deny(proposal_id: str) -> dict[str, Any]:
    for i, rec in enumerate(QUEUE):
        if rec["id"] == proposal_id:
            DECISIONS.append({
                **rec,
                "decision": "denied",
                "decided_at": time.time(),
                "auto": False,
            })
            QUEUE.pop(i)
            return {"status": "denied", "id": proposal_id}
    raise HTTPException(status_code=404, detail="proposal_not_found")
