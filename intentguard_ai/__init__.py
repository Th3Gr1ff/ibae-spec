"""IntentGuard for AI — MCP purpose-enforcement proxy.

Same architecture as IntentGuard for AD, different integration surface.
Core engine: purpose envelope + deny-on-delta, applied to MCP tool calls
instead of AD service-account actions.
"""

__all__ = ["proxy", "envelope", "ledger", "policy", "delta"]
