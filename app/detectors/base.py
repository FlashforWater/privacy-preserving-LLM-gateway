"""Detector protocol.

Detectors produce evidence, never actions (guide §3.1). Two consequences are
enforced by ``tests/security/test_layer_isolation.py``:

* no detector module may import the policy engine;
* no detector module may import the external adapter.

A detector that cannot complete raises :class:`DetectorUnavailable`. It must not
return an empty result to mean "nothing found" — those two states have opposite
safety meanings and the policy engine distinguishes them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.core.deadlines import Deadline
from app.core.errors import InspectionFailedClosed
from app.domain.content import ContentItem, ParsedItem
from app.domain.findings import Finding


class DetectorUnavailable(InspectionFailedClosed):
    """The detector could not run or returned output that failed validation."""


@runtime_checkable
class TextDetector(Protocol):
    name: str

    def detect(self, item: ContentItem, parsed: ParsedItem) -> list[Finding]: ...


@runtime_checkable
class AsyncTextDetector(Protocol):
    name: str

    async def detect(
        self, item: ContentItem, parsed: ParsedItem, deadline: Deadline
    ) -> list[Finding]: ...


def clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))
