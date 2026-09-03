"""Span rewriting.

Two rules from guide §10.4 are implemented here and nowhere else:

* **Never rewrite the same character range twice.** Overlapping decisions are
  resolved into a disjoint set first; applying two replacements to one range
  produces corrupted text and, worse, can leave half of an identifier behind.
* **Replace from the end of the string toward the beginning**, so that earlier
  offsets stay valid as later ones are consumed.

Overlap resolution keeps the finding with stronger evidence, prefers the longest
correct direct-identifier span, and — when types conflict and their actions
differ — takes the stricter action.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import PolicyAction, action_rank
from app.core.errors import InspectionFailedClosed
from app.domain.findings import Finding

REDACTION_PLACEHOLDER = "[REDACTED]"


@dataclass(frozen=True, slots=True)
class SpanEdit:
    start: int
    end: int
    replacement: str
    action: PolicyAction
    finding: Finding

    @property
    def length(self) -> int:
        return self.end - self.start


class SpanConflict(InspectionFailedClosed):
    """Unresolvable overlap. Guide §15.1: do not call the external provider."""


def resolve_overlaps(edits: list[SpanEdit]) -> list[SpanEdit]:
    """Reduce ``edits`` to a disjoint, deterministic set.

    Ordering key, applied in turn:

    1. stricter action wins (a BLOCK-worthy span is not downgraded by a PASS one);
    2. stronger evidence wins (checksum > regex > keyword > local model);
    3. longer span wins (prefer the full identifier over a fragment);
    4. lower start offset, then finding id — purely to make the result stable.
    """
    if not edits:
        return []

    ordered = sorted(
        edits,
        key=lambda e: (
            -action_rank(e.action),
            e.finding.evidence_rank,
            -e.length,
            e.start,
            str(e.finding.finding_id),
        ),
    )

    kept: list[SpanEdit] = []
    for edit in ordered:
        if any(_overlaps(edit, existing) for existing in kept):
            continue
        kept.append(edit)

    kept.sort(key=lambda e: e.start)
    for previous, current in zip(kept, kept[1:], strict=False):
        if current.start < previous.end:  # pragma: no cover - guarded above
            raise SpanConflict(
                "overlapping span edits survived resolution",
                public_detail="content could not be sanitized safely",
            )
    return kept


def _overlaps(a: SpanEdit, b: SpanEdit) -> bool:
    return a.start < b.end and b.start < a.end


def apply_edits(text: str, edits: list[SpanEdit]) -> str:
    """Apply disjoint edits back to front."""
    if not edits:
        return text
    for edit in edits:
        if edit.start < 0 or edit.end > len(text) or edit.start >= edit.end:
            raise SpanConflict(
                f"edit [{edit.start}, {edit.end}) is outside the text",
                public_detail="content could not be sanitized safely",
            )
    result = text
    for edit in sorted(edits, key=lambda e: e.start, reverse=True):
        result = result[: edit.start] + edit.replacement + result[edit.end :]
    return result
