"""Outbound request assembly and the no-bypass fast-path guard.

Guide §14.1 asks for *a single* guard method, tested aggressively, with the
logic not reproduced in any route. That is
:func:`assert_original_forward_allowed`. Every fast-path decision in the system
goes through it; there is no second implementation to drift out of sync.

The guard's six conditions are checked independently and all failures are
collected, so an operator debugging "why did this not take the fast path" gets
the whole answer at once instead of one reason per retry.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import ContentItemType, ForwardPath, PolicyAction, PrivacyMode
from app.core.errors import ContentBlocked, InspectionFailedClosed
from app.domain.content import ContentItem, ParsedItem
from app.domain.decisions import DecisionBundle
from app.domain.findings import InspectionResult
from app.domain.requests import (
    NormalizedRequest,
    OriginalApprovedRequest,
    OutboundBinaryPart,
    OutboundMessage,
    OutboundPart,
    OutboundTextPart,
    RequestContext,
    SanitizedModelRequest,
)
from app.domain.scopes import ScopeRecord
from app.sanitization.item_router import SanitizationResult


@dataclass(frozen=True, slots=True)
class FastPathVerdict:
    allowed: bool
    blockers: tuple[str, ...] = ()

    def require(self) -> None:
        if not self.allowed:
            raise InspectionFailedClosed(
                "fast path requested but not permitted: " + ", ".join(self.blockers),
                public_detail="request could not be forwarded unmodified",
            )


def assert_original_forward_allowed(
    *,
    scope: ScopeRecord,
    items: list[ContentItem],
    parsed: dict[str, ParsedItem],
    inspections: dict[str, InspectionResult],
    decisions: DecisionBundle,
    model: str,
    purpose: str,
    allowed_models: frozenset[str],
    allowed_purposes: frozenset[str],
) -> FastPathVerdict:
    """The one place that decides whether original content may be forwarded.

    All six conditions from guide §14.1 must hold:

    1. every item completed all required inspection stages;
    2. the policy engine returned PASS for every item and finding;
    3. no detector reported protected or unknown-sensitive content;
    4. the scope privacy mode is CLEAN, not SANITIZED_LOCKED;
    5. there was no parser, OCR, detector, classifier, policy or vault error;
    6. the external destination, model and purpose are allow-listed.

    Conditions 1, 3 and 5 overlap deliberately. They are checked separately
    because they fail in different ways: an inspection that never ran, a detector
    that ran and found something, and a detector that crashed are three distinct
    states, and only the middle one is a normal outcome.
    """
    blockers: list[str] = []

    # (4) Scope state. Checked first because it is the cheapest and the most
    # commonly hit: one tokenized turn locks the conversation for good.
    if scope.privacy_mode is not PrivacyMode.CLEAN:
        blockers.append("scope_sanitized_locked")
    if not scope.is_usable():
        blockers.append("scope_not_usable")

    for item in items:
        item_id = item.item_id

        # (1) and (5): inspection must have completed for every item.
        inspection = inspections.get(item_id)
        if inspection is None:
            blockers.append(f"missing_inspection:{item_id}")
            continue
        if not inspection.inspection_complete:
            blockers.append(f"incomplete_inspection:{item_id}")
        if inspection.failure_reason:
            blockers.append(f"inspection_error:{item_id}")

        parsed_item = parsed.get(item_id)
        if parsed_item is None:
            blockers.append(f"missing_parse:{item_id}")
            continue
        if not parsed_item.fully_inspected:
            blockers.append(f"partial_parse:{item_id}")

        # (3) Any finding at all disqualifies the fast path. Not "any finding
        # above a threshold" — a finding the policy chose to PASS is still
        # protected content that was detected, and the fast path is for requests
        # where nothing was found at all.
        if inspection.findings:
            blockers.append(f"findings_present:{item_id}")

        # (2) Every decision must be PASS.
        if not decisions.has_decision_for(item_id):
            blockers.append(f"missing_decision:{item_id}")
            continue
        decision = decisions.by_item(item_id)
        if decision.effective_action is not PolicyAction.PASS:
            blockers.append(f"non_pass_action:{item_id}")

        # Attachments additionally need their bytes cleared for forwarding.
        if item.is_attachment:
            if item.item_type is ContentItemType.IMAGE and not parsed_item.original_bytes_forwardable:
                blockers.append(f"bytes_not_forwardable:{item_id}")
            if parsed_item.inspection_notes.get("blocks_original_forward", False):
                blockers.append(f"bytes_not_forwardable:{item_id}")

    # (6) Destination allow-lists.
    if model not in allowed_models:
        blockers.append("model_not_allowed")
    if purpose not in allowed_purposes:
        blockers.append("purpose_not_allowed")

    return FastPathVerdict(allowed=not blockers, blockers=tuple(dict.fromkeys(blockers)))


def build_original_request(
    context: RequestContext, normalized: NormalizedRequest
) -> OriginalApprovedRequest:
    """Fast path: the user's own text and bytes, in their own order."""
    messages: list[OutboundMessage] = []
    for index, message in enumerate(context.manifest.messages):
        parts: list[OutboundPart] = []
        for item in normalized.items:
            if item.message_index != index:
                continue
            if item.item_type is ContentItemType.TEXT:
                parts.append(OutboundTextPart(item_id=item.item_id, text=item.text or ""))
            elif item.data is not None:
                parts.append(
                    OutboundBinaryPart(
                        kind=item.item_type,
                        item_id=item.item_id,
                        data=item.data,
                        mime_type=item.detected_mime or "application/octet-stream",
                        filename=item.filename,
                    )
                )
        messages.append(OutboundMessage(role=message.role, parts=tuple(parts)))

    return OriginalApprovedRequest(
        request_id=context.request_id,
        model=context.manifest.model,
        purpose=context.manifest.purpose,
        messages=tuple(messages),
        temperature=context.manifest.options.temperature,
        max_output_tokens=context.manifest.options.max_output_tokens,
        path=ForwardPath.FAST,
    )


def build_sanitized_request(
    context: RequestContext,
    normalized: NormalizedRequest,
    sanitization: SanitizationResult,
) -> SanitizedModelRequest:
    parts_by_item = sanitization.parts_by_item()
    messages: list[OutboundMessage] = []
    for index, message in enumerate(context.manifest.messages):
        parts: list[OutboundPart] = []
        for item in normalized.items:
            if item.message_index != index:
                continue
            part = parts_by_item.get(item.item_id)
            if part is not None:
                parts.append(part)
        messages.append(OutboundMessage(role=message.role, parts=tuple(parts)))

    return SanitizedModelRequest(
        request_id=context.request_id,
        model=context.manifest.model,
        purpose=context.manifest.purpose,
        messages=tuple(messages),
        temperature=context.manifest.options.temperature,
        max_output_tokens=context.manifest.options.max_output_tokens,
        path=ForwardPath.SANITIZED,
        issued_tokens=sanitization.issued_tokens,
    )


def assert_no_withheld_or_blocked_content(
    outbound: OriginalApprovedRequest | SanitizedModelRequest, decisions: DecisionBundle
) -> None:
    """Final invariant before the provider call (guide §15.2.5).

    Cheap, and it catches the class of bug that matters most: an assembly change
    that accidentally re-includes an item policy decided to withhold.
    """
    withheld = set(decisions.withheld_item_ids())
    present = set(outbound.item_ids())
    leaked = withheld & present
    if leaked:
        raise ContentBlocked(
            f"withheld items present in outbound payload: {sorted(leaked)}",
            public_detail="request could not be forwarded safely",
        )
    for item_id in present:
        if not decisions.has_decision_for(item_id):
            raise InspectionFailedClosed(
                f"outbound item {item_id} has no policy decision",
                public_detail="request could not be forwarded safely",
            )
