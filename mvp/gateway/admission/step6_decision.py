"""
Step 6 (v1.1 §6.8): Admit / Deny + OCSF Ledger Emission.
Terminal decision node. Admit iff steps 4 passed AND step 5 non-negative.
The ledger emission happens in the caller (main.py) so the same event
shape covers both admit and deny outcomes.
"""
from typing import Any


def decide(ctx: dict[str, Any]) -> dict[str, Any]:
    """Compute admit or deny from the accumulated context."""
    if not ctx.get("structural_match"):
        return {"admit": False, "reason": "step4_structural_fail"}
    if ctx.get("gust_negative"):
        return {"admit": False, "reason": ctx.get("gust_reason", "gust_negative")}
    return {"admit": True, "reason": "envelope_match"}
