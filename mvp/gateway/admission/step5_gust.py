"""
Step 5 (v1.1 §6.7): GUST-Negative Cross-Check.
GUST = Grant Under Structural Trust. This step confirms nothing
in the ambient session state contradicts the admission decision
step 4 just made. In v1.1, this is a lookup against a
session-scoped negation store (e.g., subject revoked, tenancy
locked, envelope revoked mid-session).

Phase 1 MVP: stubbed to always return non-negative.
Phase 2+: populate the negation store from Behavioral Delta
Detector alerts + human policy updates via Sidecar.
"""
import os
from typing import Any


def _from_env(var: str) -> set[str]:
    return {x.strip() for x in os.environ.get(var, "").split(",") if x.strip()}


NEGATION_STORE: dict[str, set[str]] = {
    # Populated from env vars at import time so docker-compose can
    # inject test-persona revocations without code changes.
    "revoked_subjects": _from_env("REVOKED_SUBJECTS"),
    "revoked_purposes": _from_env("REVOKED_PURPOSES"),
    "locked_tenants": _from_env("LOCKED_TENANTS"),
}


def check(ctx: dict[str, Any]) -> dict[str, Any]:
    """Phase 2: env-populated negation store. Phase 4 wires this to BDD."""
    subject = ctx["token_claims"].get("sub")
    purpose = ctx["purpose"]

    if subject in NEGATION_STORE["revoked_subjects"]:
        return {"gust_negative": True, "gust_reason": f"subject_revoked:{subject}"}
    if purpose in NEGATION_STORE["revoked_purposes"]:
        return {"gust_negative": True, "gust_reason": f"purpose_revoked:{purpose}"}

    return {"gust_negative": False}
