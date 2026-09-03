"""OCR protocol.

OCR is an inspection stage, not a convenience. When policy or the classifier
requires textual inspection of an image and OCR is unavailable, the item is
withheld — it is never treated as "no text found" (guide §15.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.core.errors import InspectionFailedClosed


class OcrUnavailable(InspectionFailedClosed):
    """OCR could not run, timed out, or crashed."""


@dataclass(frozen=True, slots=True)
class OcrLine:
    text: str
    confidence: float


@dataclass(frozen=True, slots=True)
class OcrResult:
    lines: tuple[OcrLine, ...]
    engine: str
    #: False when the engine returned partial output (page limit, timeout budget).
    complete: bool = True

    @property
    def text(self) -> str:
        return "\n".join(line.text for line in self.lines)

    @property
    def mean_confidence(self) -> float:
        if not self.lines:
            return 0.0
        return sum(line.confidence for line in self.lines) / len(self.lines)


class OcrEngine(Protocol):
    name: str

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult: ...
