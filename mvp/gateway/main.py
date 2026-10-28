"""
IntentGuard Gateway MVP - FastAPI reverse proxy running 6-step admission chain
per IBAE v1.1 §6.

Phase 1: happy path admits + basic deny paths.
Phase 2-4: added incrementally.
"""
import os
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response

from admission import (
    step1_jwks,
    step2_dpop,
    step3_envelope,
    step4_structural,
    step5_gust,
    step6_decision,
)
from ledger import emit_ocsf


app = FastAPI(title="IntentGuard Gateway MVP", version="0.1.0")

ADFS_JWKS_URL = os.environ.get(
    "ADFS_JWKS_URL", "https://fs.ibae.lab/adfs/discovery/keys"
)
MOCK_BACKEND_URL = os.environ.get(
    "MOCK_BACKEND_URL", "http://mock_backend:8080"
)
JWKS_CACHE: dict[str, Any] = {"keys": None, "fetched_at": 0}
JWKS_TTL_SECONDS = 3600


async def get_jwks() -> dict[str, Any]:
    """
    Fetch and cache AD FS JWKS.
    In scaffold-smoke-test mode, also load /tmp/synthetic_jwks.json
    (mounted from host) and merge its keys into the returned set,
    so the test client's ephemeral signing key is recognized by step 1
    without waiting on the AD FS Purpose Issuer plugin (task #51).
    """
    now = time.time()
    if JWKS_CACHE["keys"] and now - JWKS_CACHE["fetched_at"] < JWKS_TTL_SECONDS:
        return JWKS_CACHE["keys"]
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        r = await client.get(ADFS_JWKS_URL)
        r.raise_for_status()
        jwks = r.json()

    # Scaffold-mode: pick up locally-generated synthetic public JWK if present.
    import json
    import os as _os
    synthetic_path = _os.environ.get(
        "SYNTHETIC_JWKS_PATH", "/synthetic_jwks/synthetic_jwks.json"
    )
    if _os.path.exists(synthetic_path):
        try:
            with open(synthetic_path) as f:
                extra = json.load(f)
            jwks["keys"] = list(jwks.get("keys", [])) + list(extra.get("keys", []))
        except Exception:
            pass  # Best-effort scaffold mode

    JWKS_CACHE["keys"] = jwks
    JWKS_CACHE["fetched_at"] = now
    return JWKS_CACHE["keys"]


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/jwks-preview")
async def jwks_preview():
    """Debug endpoint: verify JWKS reachability."""
    jwks = await get_jwks()
    return {
        "keys_count": len(jwks.get("keys", [])),
        "kids": [k.get("kid") for k in jwks.get("keys", [])],
    }


ADMIN_SHARED_SECRET = os.environ.get("ADMIN_SHARED_SECRET", "dev-admin-key")


@app.post("/_admin/revoke")
async def admin_revoke(request: Request):
    """
    Runtime revocation endpoint. Phase 4 loop-closer:
    BDD detects, Sidecar approves, calls this to mutate the negation store
    without a redeploy. Auth is a shared secret in the header; in prod
    this would be mTLS between gateway and sidecar.
    """
    if request.headers.get("X-Admin-Key") != ADMIN_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="admin_auth_failed")
    body = await request.json()
    kind = body.get("kind")
    value = body.get("value")
    if kind not in ("subject", "purpose", "tenant") or not value:
        raise HTTPException(status_code=400, detail="bad_revocation_shape")
    key = {"subject": "revoked_subjects",
           "purpose": "revoked_purposes",
           "tenant": "locked_tenants"}[kind]
    step5_gust.NEGATION_STORE[key].add(value)
    return {
        "status": "revoked",
        "kind": kind,
        "value": value,
        "current_store": {k: sorted(v) for k, v in step5_gust.NEGATION_STORE.items()},
    }


@app.get("/_admin/negation_store")
async def admin_show_store():
    """Read-only view of the current negation store, for tests + ops."""
    return {k: sorted(v) for k, v in step5_gust.NEGATION_STORE.items()}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def gateway(path: str, request: Request):
    """
    Main admission chain: run 6 steps per v1.1 §6.
    On admit: forward to backend, relay response.
    On deny: return 401 or 403, emit OCSF deny event.
    """
    correlation_id = os.urandom(8).hex()
    started_at = time.time()

    ctx: dict[str, Any] = {
        "correlation_id": correlation_id,
        "started_at": started_at,
        "request_method": request.method,
        "request_path": "/" + path,
        "request_headers": dict(request.headers),
    }

    try:
        # Step 1: Access Token / JWKS Validation
        jwks = await get_jwks()
        step1_result = step1_jwks.validate(ctx, jwks)
        ctx.update(step1_result)

        # Step 2: DPoP Proof Verification
        step2_result = step2_dpop.validate(ctx)
        ctx.update(step2_result)

        # Step 3: Purpose Envelope Decoding
        step3_result = step3_envelope.decode(ctx)
        ctx.update(step3_result)

        # Step 4: Structural Envelope Match (the intent gate)
        step4_result = step4_structural.match(ctx)
        ctx.update(step4_result)

        # Step 5: GUST-Negative Cross-Check
        step5_result = step5_gust.check(ctx)
        ctx.update(step5_result)

        # Step 6: Admit / Deny + OCSF Ledger Emission
        decision = step6_decision.decide(ctx)

    except HTTPException as e:
        ctx["deny_reason"] = e.detail
        ctx["deny_step"] = getattr(e, "step", "unknown")
        emit_ocsf(ctx, admitted=False)
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.detail, "correlation_id": correlation_id},
        )

    if decision["admit"]:
        # Forward to backend
        body = await request.body()
        async with httpx.AsyncClient(timeout=30.0) as client:
            backend_response = await client.request(
                request.method,
                f"{MOCK_BACKEND_URL}/{path}",
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ("host", "authorization", "dpop")
                },
                content=body,
                params=request.query_params,
            )
        emit_ocsf(ctx, admitted=True)
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )
    else:
        # Attribute the deny to whichever admission step raised the veto.
        # Step 4 sets structural_match=False; step 5 sets gust_negative=True.
        if ctx.get("gust_negative"):
            ctx["deny_step"] = "step5_gust"
            ctx["deny_reason"] = ctx.get("gust_reason", "gust_negative")
        elif not ctx.get("structural_match"):
            ctx["deny_step"] = "step4_structural"
            ctx["deny_reason"] = decision.get("reason", "structural_fail")
        emit_ocsf(ctx, admitted=False)
        return JSONResponse(
            status_code=403,
            content={
                "error": "denied",
                "reason": decision.get("reason", "policy"),
                "correlation_id": correlation_id,
            },
        )
