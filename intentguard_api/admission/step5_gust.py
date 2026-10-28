"""Step 5: GUST-Negative Cross-Check.
Runtime negation store for revoked subjects, purposes, or tenants.
"""
import os
from typing import Any


def _from_env(var: str) -> set[str]:
    return {x.strip() for x in os.environ.get(var, "").split(",") if x.strip()}


NEGATION_STORE: dict[str, set[str]] = {
    "revoked_subjects": _from_env("REVOKED_SUBJECTS"),
    "revoked_purposes": _from_env("REVOKED_PURPOSES"),
    "locked_tenants": _from_env("LOCKED_TENANTS"),
}


def check(ctx: dict[str, Any]) -> dict[str, Any]:
    subject = ctx["token_claims"].get("sub")
    purpose = ctx["purpose"]
    if subject in NEGATION_STORE["revoked_subjects"]:
        return {"gust_negative": True, "gust_reason": f"subject_revoked:{subject}"}
    if purpose in NEGATION_STORE["revoked_purposes"]:
        return {"gust_negative": True, "gust_reason": f"purpose_revoked:{purpose}"}
    return {"gust_negative": False}
