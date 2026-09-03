"""Pipeline tracing for local inspection.

**Development only.** A trace holds exactly what the rest of this service exists
to keep from leaving: original text, matched finding values, and the token
mapping table. Nothing in ``app/`` constructs one — the only caller is
``scripts/trace_ui.py``, which refuses to run outside a development environment.

The recorder exists so that the inspection UI shows what the pipeline *actually*
did rather than what a parallel reimplementation would do. A debugging view that
drifts from the real code is worse than none: it builds confidence in behaviour
that is not there.

``Orchestrator.process`` takes ``trace=None`` by default, so the production path
allocates nothing and behaves identically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Stage:
    name: str
    started_at: float
    duration_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TraceRecorder:
    """Collects per-stage detail for one request."""

    stages: list[Stage] = field(default_factory=list)
    _open: Stage | None = None

    def begin(self, name: str) -> None:
        self._open = Stage(name=name, started_at=time.monotonic())
        self.stages.append(self._open)

    def record(self, **data: Any) -> None:
        if self._open is None:
            self.begin("unnamed")
        assert self._open is not None
        self._open.data.update(data)
        self._open.duration_ms = (time.monotonic() - self._open.started_at) * 1000

    def end(self) -> None:
        if self._open is not None:
            self._open.duration_ms = (time.monotonic() - self._open.started_at) * 1000
            self._open = None

    def to_json_obj(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "duration_ms": round(s.duration_ms, 2), "data": s.data}
            for s in self.stages
        ]
