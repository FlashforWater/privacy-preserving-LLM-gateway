"""Bounded retry for the external provider.

Only *safe transient* failures are retried: connection errors, timeouts, 429 and
5xx. A 4xx is a request-shaped problem and retrying it just burns the deadline.

Every attempt reuses the same idempotency key so a provider that supports it does
not bill or process the request twice, and the total time is capped by the
request deadline rather than by the attempt count alone.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

import httpx

from app.core.deadlines import Deadline
from app.core.errors import ExternalProviderError

T = TypeVar("T")

RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 4.0

    def delay_for(self, attempt: int) -> float:
        # Full jitter: prevents a fleet of gateways from retrying in lockstep.
        ceiling = min(self.max_delay_seconds, self.base_delay_seconds * (2**attempt))
        return random.uniform(0.0, ceiling)  # noqa: S311 - jitter, not cryptography


def is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.ConnectError | httpx.ReadError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in RETRYABLE_STATUS
    return False


async def with_retry(
    operation: Callable[[int], Awaitable[T]],
    *,
    policy: RetryPolicy,
    deadline: Deadline,
) -> T:
    last: BaseException | None = None
    for attempt in range(policy.max_attempts):
        deadline.check("external provider call")
        try:
            return await operation(attempt)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            if not is_retryable(exc) or attempt == policy.max_attempts - 1:
                raise
            last = exc
            delay = policy.delay_for(attempt)
            if delay >= deadline.remaining:
                raise
            await asyncio.sleep(delay)
    raise ExternalProviderError(  # pragma: no cover - loop always returns or raises
        f"provider retries exhausted: {type(last).__name__ if last else 'unknown'}",
        public_detail="external provider unavailable",
    )
