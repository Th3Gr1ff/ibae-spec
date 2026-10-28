"""Step 4: Structural Envelope Match - THE INTENT GATE.
Compare request method/path against the envelope's allowed set.
"""
from typing import Any
from fastapi import HTTPException


def match(ctx: dict[str, Any]) -> dict[str, Any]:
    envelope = ctx["envelope"]
    method = ctx["request_method"]
    path = ctx["request_path"]
    if method not in envelope["allowed_methods"]:
        e = HTTPException(
            status_code=403,
            detail=f"PURPOSE_MISMATCH:method={method},purpose={ctx['purpose']}",
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
            detail=f"PURPOSE_MISMATCH:path={path},purpose={ctx['purpose']}",
        )
        e.step = "step4_structural"
        raise e
    return {"structural_match": True}
