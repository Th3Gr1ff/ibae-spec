"""
Behavioral Delta Detector (BDD).

IBAE v1.1 §7 role: the semantic watcher that catches abuse patterns
the structural gate at step 4 admits by design. Alpha's A2 attack tree
finding: an admitted purpose ("read-invoices") lets an enumeration sweep
through unless something aggregates over time.

Phase 4 MVP detector: rolling-window request-rate per subject.
If a subject exceeds RATE_THRESHOLD admitted requests inside
RATE_WINDOW_SECONDS, BDD proposes a subject revocation to Sidecar.
"""
import os
import time
from collections import defaultdict, deque
from typing import Any

import httpx
from fastapi import FastAPI, Request

app = FastAPI(title="IntentGuard BDD", version="0.1.0")

RATE_THRESHOLD = int(os.environ.get("BDD_RATE_THRESHOLD", "10"))
RATE_WINDOW_SECONDS = int(os.environ.get("BDD_RATE_WINDOW_SECONDS", "60"))
SIDECAR_ENDPOINT = os.environ.get(
    "SIDECAR_ENDPOINT", "http://sidecar:8090/review"
)

# subject -> deque of monotonic timestamps of admitted requests
WINDOWS: dict[str, deque[float]] = defaultdict(deque)
# subjects already proposed to Sidecar this run (don't spam)
ALREADY_PROPOSED: set[str] = set()
EVENTS_SEEN = 0
PROPOSALS_SENT = 0


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "bdd"}


@app.get("/_status")
def status() -> dict[str, Any]:
    return {
        "events_seen": EVENTS_SEEN,
        "proposals_sent": PROPOSALS_SENT,
        "tracked_subjects": len(WINDOWS),
        "already_proposed": sorted(ALREADY_PROPOSED),
        "config": {
            "rate_threshold": RATE_THRESHOLD,
            "rate_window_seconds": RATE_WINDOW_SECONDS,
        },
    }


@app.post("/_reset")
def reset() -> dict[str, str]:
    global EVENTS_SEEN, PROPOSALS_SENT
    WINDOWS.clear()
    ALREADY_PROPOSED.clear()
    EVENTS_SEEN = 0
    PROPOSALS_SENT = 0
    return {"status": "reset"}


@app.post("/events")
async def events(request: Request) -> dict[str, Any]:
    """Ingest a single OCSF event from the gateway ledger."""
    global EVENTS_SEEN, PROPOSALS_SENT
    ev = await request.json()
    EVENTS_SEEN += 1

    # Only rate-track admitted requests. Denies don't need aggregate
    # detection since they're already stopped by the structural gate.
    if ev.get("status") != "Success":
        return {"status": "ignored", "reason": "not_admit"}

    subject = ev.get("actor", {}).get("user", {}).get("name")
    if not subject:
        return {"status": "ignored", "reason": "no_subject"}

    now = time.monotonic()
    q = WINDOWS[subject]
    q.append(now)
    # trim outside window
    cutoff = now - RATE_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.popleft()

    if len(q) >= RATE_THRESHOLD and subject not in ALREADY_PROPOSED:
        # Fire proposal to sidecar
        proposal = {
            "kind": "subject",
            "value": subject,
            "detector": "rate_window",
            "evidence": {
                "count_in_window": len(q),
                "window_seconds": RATE_WINDOW_SECONDS,
                "threshold": RATE_THRESHOLD,
            },
            "correlation_uid": ev.get("metadata", {}).get("correlation_uid"),
        }
        try:
            with httpx.Client(timeout=5.0) as c:
                r = c.post(SIDECAR_ENDPOINT, json=proposal)
            ALREADY_PROPOSED.add(subject)
            PROPOSALS_SENT += 1
            return {
                "status": "proposal_sent",
                "subject": subject,
                "sidecar_status": r.status_code,
            }
        except Exception as ex:
            return {"status": "proposal_failed", "error": str(ex)}

    return {"status": "tracked", "subject": subject, "count_in_window": len(q)}
