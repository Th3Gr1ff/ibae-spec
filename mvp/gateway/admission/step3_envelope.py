"""
Step 3 (v1.1 §6.5): Purpose Envelope Decoding.
Look up the envelope for the token's purpose claim.

The `purpose` claim is server-set at token issuance (per §3.1),
so we trust it as authoritative. This step resolves the purpose
name to a concrete envelope definition (allowed methods, routes,
schema, object-scope) that step 4 will structural-match against.
"""
from typing import Any
from fastapi import HTTPException


# MVP envelope catalog. In production this comes from a policy store.
# Structure per envelope:
#   allowed_methods: list of HTTP verbs
#   allowed_paths: list of path prefixes (Phase 1: prefix-match only)
ENVELOPE_CATALOG: dict[str, dict[str, Any]] = {
    "read-invoices": {
        "allowed_methods": ["GET"],
        "allowed_paths": ["/invoices"],
    },
    "read-own-ticket": {
        "allowed_methods": ["GET"],
        "allowed_paths": ["/tickets/mine"],
    },
    "admin-full": {
        "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"],
        "allowed_paths": ["/"],
    },
}


def decode(ctx: dict[str, Any]) -> dict[str, Any]:
    """Resolve token's purpose to an envelope."""
    purpose = ctx["token_claims"].get("purpose")
    if not purpose:
        e = HTTPException(
            status_code=403,
            detail="token_missing_purpose_claim",
        )
        e.step = "step3_envelope"
        raise e

    envelope = ENVELOPE_CATALOG.get(purpose)
    if envelope is None:
        e = HTTPException(
            status_code=403,
            detail=f"unknown_purpose:{purpose}",
        )
        e.step = "step3_envelope"
        raise e

    return {"purpose": purpose, "envelope": envelope}
