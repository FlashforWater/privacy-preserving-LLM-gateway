"""Findings — evidence produced by detectors.

A finding is *evidence*, never an action (guide §3.1). Detectors may not import
the policy engine and must not express intent such as "redact this".

The raw matched text is needed during processing (to tokenize the exact span) but
must never be serialized. :meth:`Finding.to_audit_dict` therefore emits a keyed
fingerprint instead, and ``raw_text`` is excluded from the model dump.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.enums import EntityType, FindingSource, source_rank


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    item_id: str
    entity_type: EntityType
    source: FindingSource
    start: int | None = None
    end: int | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    rule_id: str | None = None
    #: Keyed fingerprint of the matched value; filled in by the detector pipeline.
    text_hash: str | None = None
    #: In-process only. Excluded from every dump; see ``to_audit_dict``.
    raw_text: str | None = Field(default=None, exclude=True, repr=False)
    metadata: dict[str, Any] = Field(default_factory=dict)
    #: Source ids that contributed after merging (guide §10.4).
    contributing_sources: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _spans_are_coherent(self) -> "Finding":
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must be provided together")
        if self.start is not None and self.end is not None:
            if self.start < 0 or self.end <= self.start:
                raise ValueError(f"invalid span [{self.start}, {self.end})")
        return self

    @property
    def has_span(self) -> bool:
        return self.start is not None and self.end is not None

    @property
    def span(self) -> tuple[int, int]:
        if self.start is None or self.end is None:
            raise ValueError("finding has no span")
        return self.start, self.end

    @property
    def length(self) -> int:
        return 0 if not self.has_span else self.end - self.start  # type: ignore[operator]

    def overlaps(self, other: "Finding") -> bool:
        if not (self.has_span and other.has_span) or self.item_id != other.item_id:
            return False
        a_start, a_end = self.span
        b_start, b_end = other.span
        return a_start < b_end and b_start < a_end

    @property
    def evidence_rank(self) -> int:
        """Lower is stronger. Checksum-validated evidence beats a bare regex,
        which beats a keyword, which beats a local-model-only finding."""
        return source_rank(self.source)

    def to_audit_dict(self) -> dict[str, Any]:
        """Serialization for audit records — carries no matched text."""
        return {
            "finding_id": str(self.finding_id),
            "item_id": self.item_id,
            "entity_type": self.entity_type.value,
            "source": self.source.value,
            "rule_id": self.rule_id,
            "confidence": round(self.confidence, 3),
            "text_hash": self.text_hash,
            "span_length": self.length,
            "contributing_sources": list(self.contributing_sources),
        }


class InspectionResult(BaseModel):
    """Everything learned about one item locally."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    item_id: str
    findings: list[Finding] = Field(default_factory=list)
    #: False whenever any required inspection stage did not complete. The fast
    #: path guard reads this directly; absence of findings is not evidence of
    #: safety when inspection itself failed (guide §3.2).
    inspection_complete: bool = False
    failure_reason: str | None = None
    stages_completed: tuple[str, ...] = ()

    @property
    def protected_findings(self) -> list[Finding]:
        return list(self.findings)
