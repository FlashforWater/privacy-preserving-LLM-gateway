"""Tracing hooks.

Deliberately minimal in the MVP. Spans carry the same allow-listed attributes the
logs do; a tracing backend is one more place payload content could end up, so
attributes go through the same filter rather than being passed straight through.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator
from dataclasses import dataclass, field

from app.core.logging import ALLOWED_LOG_FIELDS


@dataclass(slots=True)
class Span:
    name: str
    started_at: float = field(default_factory=time.monotonic)
    attributes: dict[str, object] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000

    def set(self, key: str, value: object) -> None:
        if key in ALLOWED_LOG_FIELDS:
            self.attributes[key] = value


@contextlib.contextmanager
def span(name: str) -> Iterator[Span]:
    current = Span(name=name)
    try:
        yield current
    finally:
        pass
