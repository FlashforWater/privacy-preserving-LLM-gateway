"""External-model responses and the public API response.

The provider's reply is untrusted input. It is validated for shape and size
before anything is scanned for tokens, and only fields explicitly declared as
text are ever restored (guide §13.4.1).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ForwardPath, PrivacyMode


class ExternalTextField(BaseModel):
    """A provider response field that the restorer is allowed to touch."""

    model_config = ConfigDict(extra="forbid")

    path: str
    text: str


class ExternalModelResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str
    text_fields: list[ExternalTextField] = Field(default_factory=list)
    finish_reason: str | None = None
    #: Token accounting only; never provider payload bodies.
    usage: dict[str, int] = Field(default_factory=dict)

    def total_text_length(self) -> int:
        return sum(len(field.text) for field in self.text_fields)


class RestorationStats(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tokens_seen: int = 0
    tokens_restored: int = 0
    unknown_tokens: int = 0
    substitutions: int = 0

    @property
    def had_unknown(self) -> bool:
        return self.unknown_tokens > 0


class PrivacySummary(BaseModel):
    """The ``privacy`` block of the public response (guide §8.2).

    Carries counts and ids only. No finding values, token mappings, OCR text, or
    sensitive reason details.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: ForwardPath
    scope_privacy_mode: PrivacyMode
    policy_version: str
    actions: dict[str, int] = Field(default_factory=dict)
    withheld_item_ids: list[str] = Field(default_factory=list)


class GatewayResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope_id: str
    request_id: str
    status: str
    output: dict[str, object]
    privacy: PrivacySummary
