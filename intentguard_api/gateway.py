"""IntentGuard API Gateway - 6-step admission chain protecting any REST API.

Sits as a reverse proxy between clients and the backend API. Every request
must carry a purpose-bound DPoP token. The gateway checks:
  1. Token signature (JWKS)
  2. DPoP proof-of-possession (RFC 9449)
  3. Purpose envelope lookup
  4. Structural match (method + path vs envelope)
  5. GUST-negative cross-check (runtime revocation)
  6. Admit/Deny decision
"""

import os
import sys
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, Response

sys.path.insert(0, os.path.dirname(__file__))

from admission import (
    step1_jwks,
    step2_dpop,
    step3_envelope,
    step4_structural,
    step5_gust,
    step6_decision,
)

app = FastAPI(title="IntentGuard API Gateway", version="0.1.0")

ISSUER_JWKS_URL = os.environ.get("ISSUER_JWKS_URL", "http://127.0.0.1:8710/jwks")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8720")
JWKS_CACHE: dict[str, Any] = {"keys": None, "fetched_at": 0}
JWKS_TTL_SECONDS = 300


async def get_jwks() -> dict[str, Any]:
    now = time.time()
    if JWKS_CACHE["keys"] and now - JWKS_CACHE["fetched_at"] < JWKS_TTL_SECONDS:
        return JWKS_CACHE["keys"]
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(ISSUER_JWKS_URL)
        r.raise_for_status()
        jwks = r.json()
    JWKS_CACHE["keys"] = jwks
    JWKS_CACHE["fetched_at"] = now
    return JWKS_CACHE["keys"]


@app.get("/health")
async def health():
    return {"status": "ok", "service": "intentguard-api-gateway"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def gateway(path: str, request: Request):
    correlation_id = os.urandom(8).hex()
    ctx: dict[str, Any] = {
        "correlation_id": correlation_id,
        "started_at": time.time(),
        "request_method": request.method,
        "request_path": "/" + path,
        "request_headers": dict(request.headers),
    }
    try:
        jwks = await get_jwks()
        ctx.update(step1_jwks.validate(ctx, jwks))
        ctx.update(step2_dpop.validate(ctx))
        ctx.update(step3_envelope.decode(ctx))
        ctx.update(step4_structural.match(ctx))
        ctx.update(step5_gust.check(ctx))
        decision = step6_decision.decide(ctx)
    except HTTPException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "error": e.detail,
                "correlation_id": correlation_id,
                "gateway": "IntentGuard",
            },
        )
    if decision["admit"]:
        body = await request.body()
        async with httpx.AsyncClient(timeout=30.0) as client:
            backend_response = await client.request(
                request.method,
                f"{BACKEND_URL}/{path}",
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ("host", "authorization", "dpop")
                },
                content=body,
                params=request.query_params,
            )
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )
    else:
        return JSONResponse(
            status_code=403,
            content={
                "error": "PURPOSE_MISMATCH",
                "reason": decision.get("reason", "policy"),
                "action": "BLOCKED",
                "correlation_id": correlation_id,
                "gateway": "IntentGuard",
            },
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("GATEWAY_PORT", "8730"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
