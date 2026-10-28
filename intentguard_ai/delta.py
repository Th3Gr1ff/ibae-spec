"""Session delta detector — behavioral drift check.

This is the second of the two independent checks. It tracks tool call patterns
across the session and flags when the pattern drifts from what agents with this
purpose typically do. Each individual call may pass the structural envelope
check, but the session as a whole may be doing something the purpose didn't
intend.

MVP: frequency-based drift detection. Track tool call distribution per purpose
and flag when the current session's distribution diverges beyond a threshold
from the baseline. The baseline is built from observed sessions over time.

For the initial build, we use a simpler heuristic: flag when a single tool
dominates the session beyond a concentration threshold, or when a tool that's
rarely used for this purpose starts appearing frequently.
"""

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DriftAlert:
    tool_name: str
    purpose: str
    reason: str
    session_distribution: dict[str, int]
    timestamp: float = field(default_factory=time.time)


class DeltaDetector:
    def __init__(self, concentration_threshold: float = 0.95, min_calls_before_check: int = 10):
        self._threshold = concentration_threshold
        self._min_calls = min_calls_before_check
        self._session_counts: Counter = Counter()
        self._total_calls: int = 0
        self._alerts: list[DriftAlert] = []
        self._purpose: Optional[str] = None

    @property
    def alerts(self) -> list[DriftAlert]:
        return list(self._alerts)

    def set_purpose(self, purpose: str) -> None:
        self._purpose = purpose

    def record(self, tool_name: str) -> Optional[DriftAlert]:
        self._session_counts[tool_name] += 1
        self._total_calls += 1

        if self._total_calls < self._min_calls:
            return None

        tool_count = self._session_counts[tool_name]
        concentration = tool_count / self._total_calls

        if concentration >= self._threshold and len(self._session_counts) > 1:
            alert = DriftAlert(
                tool_name=tool_name,
                purpose=self._purpose or "<none>",
                reason=(
                    f"tool '{tool_name}' concentration {concentration:.0%} "
                    f"exceeds threshold {self._threshold:.0%} "
                    f"({tool_count}/{self._total_calls} calls)"
                ),
                session_distribution=dict(self._session_counts),
            )
            self._alerts.append(alert)
            return alert

        return None

    def reset(self) -> None:
        self._session_counts.clear()
        self._total_calls = 0
        self._alerts.clear()
