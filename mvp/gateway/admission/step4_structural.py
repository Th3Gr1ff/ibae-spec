"""
Step 4 (v1.1 §6.6): Structural Envelope Match — THE INTENT GATE.
Compare the request's method/route/schema/object-scope against
the envelope's allowed set. Admit only if the request shape
falls within the declared purpose envelope.

Per Alpha's A2 finding (spec-verified): this is a STRUCTURAL
check, not semantic. Enumeration and value-abuse pass by design;
that class of attack lives in the delta-detector (step 5 + BDD),
not here.
"""
from typing import Any
from fastapi import HTTPException


def match(ctx: dict[str, Any]) -> dict[str, Any]:
    """Structural match: method + path prefix."""
    envelope = ctx["envelope"]
    method = ctx["request_method"]
    path = ctx["request_path"]

    if method not in envelope["allowed_methods"]:
        e = HTTPException(
            status_code=403,
            detail=f"method_not_in_envelope:{method}",
        )
        e.step = "step4_structural"
        raise e

    path_ok = any(
        path == allowed or path.startswith(allowed.rstrip("/") + "/")
        or allowed == "/"
        for allowed in envelope["allowed_paths"]
    )
    if not path_ok:
        e = HTTPException(
            status_code=403,
            detail=f"path_not_in_envelope:{path}",
        )
        e.step = "step4_structural"
        raise e

    return {"structural_match": True}
