"""Item-level routing and sanitization.

Turns decisions into the external representation of each item (guide §5.2):

===============================  ==========================================
Effective action                 What leaves the gateway
===============================  ==========================================
PASS (text)                      the original text
PASS (attachment)                the original bytes, byte-for-byte
TOKENIZE / REDACT                sanitized text with tokens or [REDACTED]
LOCAL_ANALYZE_TO_SANITIZED_TEXT  locally extracted, sanitized text only
LOCAL_ONLY / BLOCK               nothing
===============================  ==========================================

The rule that does the most work is this one, from guide §11.1:

    Once protected information is found, never forward the original file after
    merely sanitizing extracted text.

Identifiers survive in metadata, comments, hidden sheets, embedded files,
annotations and layers that the text extraction never touched. So a document with
any protected finding is replaced by a newly constructed text representation —
the file itself does not go.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.enums import ContentItemType, EntityType, PolicyAction
from app.core.errors import InspectionFailedClosed
from app.domain.content import ContentItem, ParsedItem
from app.domain.decisions import ItemDecision
from app.domain.findings import Finding
from app.domain.requests import OutboundBinaryPart, OutboundPart, OutboundTextPart
from app.vault.base import PendingMapping

from .span_rewriter import (
    REDACTION_PLACEHOLDER,
    SpanConflict,
    SpanEdit,
    apply_edits,
    resolve_overlaps,
)
from .tokenizer import TokenRequest, build_token_request, escape_token_like

#: Item types whose original bytes may ever be forwarded. Text is forwarded as
#: text; complex documents are excluded on purpose (see module docstring).
_BYTE_FORWARDABLE = (ContentItemType.IMAGE,)


@dataclass(slots=True)
class SanitizedItem:
    item_id: str
    part: OutboundPart | None
    action: PolicyAction
    tokens_used: list[str] = field(default_factory=list)
    escaped_token_like: int = 0


@dataclass(slots=True)
class SanitizationResult:
    items: list[SanitizedItem] = field(default_factory=list)
    pending_mappings: list[PendingMapping] = field(default_factory=list)
    withheld_item_ids: list[str] = field(default_factory=list)

    @property
    def issued_tokens(self) -> frozenset[str]:
        return frozenset(token for item in self.items for token in item.tokens_used)

    def parts_by_item(self) -> dict[str, OutboundPart]:
        return {item.item_id: item.part for item in self.items if item.part is not None}


class TokenAllocator:
    """Resolves values to tokens, reusing existing mappings within the scope.

    Reuse is what makes multi-turn conversations coherent: the same person keeps
    the same token across turns, so the external model can follow the thread.
    Lookups go through the vault's keyed digest, never through the plaintext.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        scope_id: str,
        hmac_key: bytes,
        existing: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._scope_id = scope_id
        self._key = hmac_key
        # (entity_type, digest) -> token, seeded from the vault before sanitizing.
        self._known: dict[tuple[str, str], str] = dict(existing or {})
        self._pending: list[PendingMapping] = []

    @property
    def pending(self) -> list[PendingMapping]:
        return list(self._pending)

    def seed(self, entity_type: EntityType, digest: str, token: str) -> None:
        """Register a token this scope already issued for the same canonical value.

        Seeded entries are not added to ``pending``: they already exist in the
        vault, and re-inserting them would double-count the scope's mapping quota.
        """
        self._known.setdefault((entity_type.value, digest), token)

    def request_for(self, value: str, entity_type: EntityType) -> TokenRequest:
        return build_token_request(
            value, entity_type,
            tenant_id=self._tenant_id, scope_id=self._scope_id, key=self._key,
        )

    def allocate(self, value: str, entity_type: EntityType, *, mint: object) -> str:
        request = self.request_for(value, entity_type)
        key = (entity_type.value, request.lookup_hmac)
        existing = self._known.get(key)
        if existing is not None:
            return existing
        token = mint(entity_type)  # type: ignore[operator]
        self._known[key] = token
        self._pending.append(
            PendingMapping(
                token=token,
                entity_type=entity_type,
                original_value=request.original_value,
                canonical_value_hmac=request.lookup_hmac,
            )
        )
        return token


class ItemRouter:
    def __init__(self, allocator: TokenAllocator, *, mint: object) -> None:
        self._allocator = allocator
        self._mint = mint

    def route(
        self,
        *,
        item: ContentItem,
        parsed: ParsedItem | None,
        decision: ItemDecision,
        findings: list[Finding],
    ) -> SanitizedItem:
        action = decision.effective_action

        if action in (PolicyAction.BLOCK, PolicyAction.LOCAL_ONLY):
            return SanitizedItem(item_id=item.item_id, part=None, action=action)

        if action is PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT:
            return self._local_analysis_part(item, parsed, decision, findings)

        if action is PolicyAction.PASS:
            return self._pass_through(item, parsed, action)

        # TOKENIZE / REDACT
        return self._sanitized_text(item, parsed, decision, findings, action)

    # ---- branches --------------------------------------------------------

    def _pass_through(
        self, item: ContentItem, parsed: ParsedItem | None, action: PolicyAction
    ) -> SanitizedItem:
        if item.item_type is ContentItemType.TEXT:
            text, escaped = escape_token_like(item.text or "")
            return SanitizedItem(
                item_id=item.item_id,
                part=OutboundTextPart(item_id=item.item_id, text=text),
                action=action,
                escaped_token_like=escaped,
            )

        if item.item_type in _BYTE_FORWARDABLE:
            if parsed is None or not parsed.original_bytes_forwardable or item.data is None:
                # Inspection said the bytes are not clean enough to forward as-is.
                # There is no re-encode/strip path in the MVP, so withhold.
                raise InspectionFailedClosed(
                    f"item {item.item_id} was marked PASS but its bytes are not forwardable",
                    public_detail="attachment could not be forwarded safely",
                )
            return SanitizedItem(
                item_id=item.item_id,
                part=OutboundBinaryPart(
                    kind=item.item_type,
                    item_id=item.item_id,
                    data=item.data,
                    mime_type=item.detected_mime or "application/octet-stream",
                    filename=item.filename,
                ),
                action=action,
            )

        # Complex documents (PDF/DOCX/XLSX) are never forwarded as original bytes
        # unless every component was inspected and nothing protected was found.
        if parsed is not None and parsed.fully_inspected and item.data is not None:
            if not parsed.inspection_notes.get("blocks_original_forward", False):
                return SanitizedItem(
                    item_id=item.item_id,
                    part=OutboundBinaryPart(
                        kind=item.item_type,
                        item_id=item.item_id,
                        data=item.data,
                        mime_type=item.detected_mime or "application/octet-stream",
                        filename=item.filename,
                    ),
                    action=action,
                )
        # Fall back to the reconstructed text representation.
        return self._sanitized_text(item, parsed, None, [], action)

    def _local_analysis_part(
        self,
        item: ContentItem,
        parsed: ParsedItem | None,
        decision: ItemDecision,
        findings: list[Finding],
    ) -> SanitizedItem:
        """Original bytes stay local; only validated extracted text goes out."""
        sanitized = self._sanitized_text(
            item, parsed, decision, findings, PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT
        )
        if sanitized.part is None or not isinstance(sanitized.part, OutboundTextPart):
            return sanitized
        if not sanitized.part.text.strip():
            # Nothing usable was extracted. Sending an empty part would imply the
            # attachment was considered; withholding it is the honest outcome.
            return SanitizedItem(
                item_id=item.item_id,
                part=None,
                action=PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT,
            )
        return sanitized

    def _sanitized_text(
        self,
        item: ContentItem,
        parsed: ParsedItem | None,
        decision: ItemDecision | None,
        findings: list[Finding],
        action: PolicyAction,
    ) -> SanitizedItem:
        source = parsed.normalized_text if parsed is not None else (item.text or "")
        source, escaped = escape_token_like(source)

        edits: list[SpanEdit] = []
        tokens_used: list[str] = []
        by_id = {str(f.finding_id): f for f in findings}

        for span_decision in decision.span_decisions if decision else ():
            finding = by_id.get(str(span_decision.finding_id))
            if finding is None or not finding.has_span or finding.raw_text is None:
                continue
            start, end = finding.span
            if end > len(source):
                # Escaping is length-preserving, so this cannot happen unless the
                # text changed between detection and sanitization. Never drop the
                # edit quietly: a dropped edit leaves the identifier in the
                # payload. Fail closed instead (guide §15.1).
                raise SpanConflict(
                    f"finding span [{start}, {end}) exceeds the sanitization source",
                    public_detail="content could not be sanitized safely",
                )
            if span_decision.action is PolicyAction.TOKENIZE:
                token = self._allocator.allocate(
                    finding.raw_text, finding.entity_type, mint=self._mint
                )
                tokens_used.append(token)
                replacement = token
            else:
                replacement = REDACTION_PLACEHOLDER
            edits.append(
                SpanEdit(
                    start=start, end=end, replacement=replacement,
                    action=span_decision.action, finding=finding,
                )
            )

        text = apply_edits(source, resolve_overlaps(edits))
        return SanitizedItem(
            item_id=item.item_id,
            part=OutboundTextPart(item_id=item.item_id, text=text),
            action=action,
            tokens_used=tokens_used,
            escaped_token_like=escaped,
        )
