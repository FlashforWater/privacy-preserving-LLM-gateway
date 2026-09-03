"""Strict policy schema.

``extra="forbid"`` everywhere is the point of this module: a policy with a
misspelled key must fail at startup, not quietly fall back to a default that
nobody chose. Guide §9.3.1–9.3.2.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import EntityType, ImageClass, PolicyAction


class EntityRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PolicyAction
    minimum_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ContentClassRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: PolicyAction


class PolicyDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    unknown_entity: PolicyAction = PolicyAction.BLOCK
    unsupported_content: PolicyAction = PolicyAction.BLOCK
    detector_error: PolicyAction = PolicyAction.BLOCK
    low_confidence: PolicyAction = PolicyAction.REDACT

    @field_validator("unknown_entity", "unsupported_content", "detector_error")
    @classmethod
    def _must_not_be_permissive(cls, value: PolicyAction) -> PolicyAction:
        """A default of PASS would turn every gap in the policy into an
        unreviewed exemption. Uncertainty defaults are not a tuning knob."""
        if value is PolicyAction.PASS:
            raise ValueError("uncertainty defaults may not be PASS")
        return value


class PolicyLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_request_bytes: int = Field(gt=0)
    max_file_bytes: int = Field(gt=0)
    max_scope_bytes: int = Field(gt=0)
    max_scope_turns: int = Field(gt=0)
    max_scope_files: int = Field(gt=0)
    max_scope_pages: int = Field(gt=0)
    max_scope_mappings: int = Field(gt=0)
    max_ocr_pixels: int = Field(gt=0)


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1, max_length=64)
    defaults: PolicyDefaults
    entities: dict[EntityType, EntityRule]
    content_classes: dict[ImageClass, ContentClassRule]
    purpose_overrides: dict[str, dict[EntityType, EntityRule]] = Field(default_factory=dict)
    limits: PolicyLimits

    @field_validator("entities")
    @classmethod
    def _every_entity_type_is_covered(
        cls, value: dict[EntityType, EntityRule]
    ) -> dict[EntityType, EntityRule]:
        """Force the policy to say something about every entity type the code can
        produce. Otherwise adding an EntityType silently routes it to the unknown
        default and nobody notices until an incident."""
        missing = {
            entity
            for entity in EntityType
            if entity not in value
            and entity not in (EntityType.ID_DOCUMENT_IMAGE, EntityType.ORDINARY_IMAGE)
        }
        if missing:
            raise ValueError(
                "policy is missing rules for entity types: "
                + ", ".join(sorted(e.value for e in missing))
            )
        return value

    @field_validator("content_classes")
    @classmethod
    def _every_image_class_is_covered(
        cls, value: dict[ImageClass, ContentClassRule]
    ) -> dict[ImageClass, ContentClassRule]:
        missing = {c for c in ImageClass if c not in value}
        if missing:
            raise ValueError(
                "policy is missing rules for content classes: "
                + ", ".join(sorted(c.value for c in missing))
            )
        return value
