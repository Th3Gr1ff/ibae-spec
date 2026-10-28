"""Envelope validation — structural gateway check.

This is the first of the two independent checks. It validates each tool call
against the declared purpose's envelope. The agent cannot see or influence this
check. If the tool call falls outside the envelope, it's denied before reaching
the real MCP server.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

from .policy import Policy, PurposeEnvelope


@dataclass
class ValidationResult:
    allowed: bool
    tool_name: str
    purpose: str
    reason: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class EnvelopeValidator:
    def __init__(self, policy: Policy):
        self._policy = policy
        self._active_purpose: Optional[str] = None
        self._envelope: Optional[PurposeEnvelope] = None

    @property
    def active_purpose(self) -> Optional[str]:
        return self._active_purpose

    def set_purpose(self, purpose: str) -> bool:
        envelope = self._policy.get_envelope(purpose)
        if envelope is None:
            return False
        self._active_purpose = purpose
        self._envelope = envelope
        return True

    def validate(self, tool_name: str, params: dict) -> ValidationResult:
        if self._envelope is None:
            if self._policy.default_purpose:
                self.set_purpose(self._policy.default_purpose)
            if self._envelope is None:
                return ValidationResult(
                    allowed=False,
                    tool_name=tool_name,
                    purpose="<none>",
                    reason="no active purpose declared",
                )

        allowed, reason = self._envelope.check(tool_name, params)
        return ValidationResult(
            allowed=allowed,
            tool_name=tool_name,
            purpose=self._active_purpose,
            reason=reason,
        )
