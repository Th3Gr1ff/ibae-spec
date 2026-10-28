"""Step 6: Admit / Deny decision."""
from typing import Any


def decide(ctx: dict[str, Any]) -> dict[str, Any]:
    if not ctx.get("structural_match"):
        return {"admit": False, "reason": "step4_structural_fail"}
    if ctx.get("gust_negative"):
        return {"admit": False, "reason": ctx.get("gust_reason", "gust_negative")}
    return {"admit": True, "reason": "envelope_match"}
