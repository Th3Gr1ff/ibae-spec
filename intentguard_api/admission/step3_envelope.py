"""Step 3: Purpose Envelope Decoding.
Resolve the token's purpose claim to a concrete envelope definition.
"""
from typing import Any
from fastapi import HTTPException
from policy import ENVELOPE_CATALOG


def decode(ctx: dict[str, Any]) -> dict[str, Any]:
    purpose = ctx["token_claims"].get("purpose")
    if not purpose:
        e = HTTPException(status_code=403, detail="token_missing_purpose_claim")
        e.step = "step3_envelope"
        raise e
    envelope = ENVELOPE_CATALOG.get(purpose)
    if envelope is None:
        e = HTTPException(status_code=403, detail=f"unknown_purpose:{purpose}")
        e.step = "step3_envelope"
        raise e
    return {"purpose": purpose, "envelope": envelope}
