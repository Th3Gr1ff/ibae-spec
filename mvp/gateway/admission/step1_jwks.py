"""
Step 1 (v1.1 §6.1): Access Token / JWKS Validation.
Verify the JWT access token signature against AD FS's published JWKS.
"""
from typing import Any

import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException


def validate(ctx: dict[str, Any], jwks: dict[str, Any]) -> dict[str, Any]:
    """
    Extract Bearer token from Authorization header, verify signature via JWKS,
    return the decoded claims.
    """
    auth = ctx["request_headers"].get("authorization", "")
    if not auth.lower().startswith("bearer "):
        e = HTTPException(status_code=401, detail="missing_bearer_token")
        e.step = "step1_jwks"
        raise e
    token = auth.split(" ", 1)[1].strip()

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as ex:
        e = HTTPException(status_code=401, detail=f"malformed_token:{ex}")
        e.step = "step1_jwks"
        raise e

    kid = unverified_header.get("kid")
    matching_key = None
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            matching_key = key
            break
    if matching_key is None:
        e = HTTPException(
            status_code=401,
            detail=f"unknown_kid:{kid}",
        )
        e.step = "step1_jwks"
        raise e

    public_key = RSAAlgorithm.from_jwk(matching_key)
    try:
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=[matching_key.get("alg", "RS256")],
            options={"verify_aud": False, "verify_iss": False},
        )
    except jwt.ExpiredSignatureError:
        e = HTTPException(status_code=401, detail="token_expired")
        e.step = "step1_jwks"
        raise e
    except jwt.InvalidTokenError as ex:
        e = HTTPException(status_code=401, detail=f"invalid_signature:{ex}")
        e.step = "step1_jwks"
        raise e

    return {"token_claims": claims, "token_kid": kid}
