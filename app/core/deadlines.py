"""End-to-end deadlines.

Every outbound call gets its remaining budget from one ``Deadline`` created when
the request arrives. Per-call timeouts alone are not enough: three sequential
20-second calls each "within timeout" still blow a 30-second budget, and the
guide requires the request to be cancelled and 504 returned instead (§8.3, §15.1).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .errors import RequestDeadlineExceeded


@dataclass(frozen=True, slots=True)
class Deadline:
    """Monotonic deadline. Never built from wall-clock time — clock steps would
    silently extend or truncate a request budget."""

    expires_at_monotonic: float

    @classmethod
    def after(cls, seconds: float) -> "Deadline":
        return cls(time.monotonic() + seconds)

    @property
    def remaining(self) -> float:
        return max(0.0, self.expires_at_monotonic - time.monotonic())

    @property
    def expired(self) -> bool:
        return self.remaining <= 0.0

    def check(self, stage: str) -> None:
        if self.expired:
            raise RequestDeadlineExceeded(
                f"deadline exceeded during {stage}",
                public_detail="request deadline exceeded",
            )

    def budget_for(self, requested: float, *, reserve: float = 0.0) -> float:
        """Timeout for one downstream call.

        ``reserve`` keeps time for the work that must still happen afterwards
        (restoration, vault writes) so the request can fail cleanly instead of
        being cut off mid-way.
        """
        available = self.remaining - reserve
        if available <= 0:
            raise RequestDeadlineExceeded(
                "no time budget left for downstream call",
                public_detail="request deadline exceeded",
            )
        return min(requested, available)
