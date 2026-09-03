"""Request context and the two typed outbound shapes.

The adapter accepts :class:`OriginalApprovedRequest` or
:class:`SanitizedModelRequest` and nothing else (guide §14). Keeping them as
separate types is the mechanism that makes a bypass hard: there is no way to hand
the provider a raw internal request object, because the adapter's signature will
not take one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import Principal
from app.core.deadlines import Deadline
from app.core.enums import ContentItemType, ForwardPath, RequestState
from app.domain.content import ContentItem, Manifest
from app.domain.scopes import ScopeRecord, new_request_id, utcnow


@dataclass(slots=True)
class RequestContext:
    request_id: str
    principal: Principal
    scope: ScopeRecord
    manifest: Manifest
    deadline: Deadline
    policy_version: str
    started_at: datetime = field(default_factory=utcnow)
    state: RequestState = RequestState.RECEIVED
    idempotency_key: str | None = None

    @classmethod
    def create(
        cls,
        *,
        principal: Principal,
        scope: ScopeRecord,
        manifest: Manifest,
        deadline: Deadline,
        idempotency_key: str | None = None,
    ) -> "RequestContext":
        return cls(
            request_id=new_request_id(),
            principal=principal,
            scope=scope,
            manifest=manifest,
            deadline=deadline,
            # Pinned when the scope was created, not re-read per request, so the
            # whole conversation is evaluated under one policy (guide §9.3.3).
            policy_version=scope.policy_version,
            idempotency_key=idempotency_key,
        )

    @property
    def tenant_id(self) -> str:
        return self.principal.tenant_id

    def advance(self, state: RequestState) -> None:
        self.state = state


class OutboundTextPart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ContentItemType = ContentItemType.TEXT
    item_id: str
    text: str


class OutboundBinaryPart(BaseModel):
    """An approved attachment forwarded byte-for-byte.

    Only produced for items whose decision is PASS after complete inspection. The
    MVP never re-encodes, crops or strips metadata (guide §12.2): the choice is
    the exact original bytes or nothing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    kind: ContentItemType
    item_id: str
    data: bytes
    mime_type: str
    filename: str | None = None


OutboundPart = OutboundTextPart | OutboundBinaryPart


class OutboundMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str
    parts: tuple[OutboundPart, ...]


class _BaseOutboundRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    model: str
    purpose: str
    messages: tuple[OutboundMessage, ...]
    temperature: float
    max_output_tokens: int

    def item_ids(self) -> tuple[str, ...]:
        return tuple(part.item_id for message in self.messages for part in message.parts)

    def binary_parts(self) -> tuple[OutboundBinaryPart, ...]:
        return tuple(
            part
            for message in self.messages
            for part in message.parts
            if isinstance(part, OutboundBinaryPart)
        )

    def text_parts(self) -> tuple[OutboundTextPart, ...]:
        return tuple(
            part
            for message in self.messages
            for part in message.parts
            if isinstance(part, OutboundTextPart)
        )


class OriginalApprovedRequest(_BaseOutboundRequest):
    """Fast path. Semantics, ordering and bytes are the user's originals."""

    path: ForwardPath = ForwardPath.FAST


class SanitizedModelRequest(_BaseOutboundRequest):
    """Privacy path. Contains tokens and locally reconstructed sanitized text."""

    path: ForwardPath = ForwardPath.SANITIZED
    #: Tokens present in this payload; the restorer will only accept these back.
    issued_tokens: frozenset[str] = frozenset()


@dataclass(slots=True)
class NormalizedRequest:
    """Manifest plus resolved items, in stable processing order."""

    manifest: Manifest
    items: list[ContentItem]

    @property
    def total_bytes(self) -> int:
        return sum(item.byte_size for item in self.items)

    @property
    def file_count(self) -> int:
        return sum(1 for item in self.items if item.is_attachment)

    def by_id(self, item_id: str) -> ContentItem:
        for item in self.items:
            if item.item_id == item_id:
                return item
        raise KeyError(item_id)
