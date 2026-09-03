"""Request orchestration (guide §16).

Order of operations, and why it is this order:

1. resolve and validate the scope, then enforce limits — before any bytes are parsed;
2. normalize into items;
3. parse and inspect every item locally;
4. merge evidence;
5. evaluate policy and assert complete decision coverage;
6. block if required content is blocked;
7. fast path *only* through the single guard, otherwise sanitize;
8. persist token mappings and lock the scope **before** the external call;
9. run the final no-withheld-content invariant;
10. call the provider;
11. validate the response, then restore exact tokens.

There is no ``except Exception: pass`` and no fallback-to-forward branch anywhere
in this module. Every failure path ends in an error response, and every error
path leaves the provider uncalled.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from app.core.deadlines import Deadline
from app.core.enums import ForwardPath, PolicyAction, RequestState
from app.core.errors import ContentBlocked, GatewayError, InspectionFailedClosed
from app.core.logging import content_fingerprint, pseudonymous_id, safe_extra
from app.detectors.base import DetectorUnavailable
from app.detectors.keyword_detector import KeywordDetector
from app.detectors.local_model_detector import LocalModelDetector
from app.detectors.regex_detector import RegexDetector
from app.domain.content import ContentItem, ParsedItem
from app.domain.decisions import DecisionBundle
from app.domain.findings import Finding, InspectionResult
from app.domain.requests import (
    NormalizedRequest,
    OriginalApprovedRequest,
    RequestContext,
    SanitizedModelRequest,
)
from app.domain.responses import GatewayResponse, PrivacySummary
from app.domain.scopes import ScopeLimits
from app.external.base import ExternalModelAdapter
from app.observability import metrics
from app.observability.audit import AuditRecord
from app.parsers.base import ParserLimits, ParserRegistry
from app.policy.engine import PolicyEngine, assert_complete_decision_coverage
from app.restore.restorer import Restorer
from app.sanitization.item_router import ItemRouter, SanitizationResult, TokenAllocator
from app.sanitization.tokenizer import new_token
from app.vault.base import Vault

from .evidence_merger import merge
from .request_builder import (
    assert_no_withheld_or_blocked_content,
    assert_original_forward_allowed,
    build_original_request,
    build_sanitized_request,
)

logger = logging.getLogger("gateway.orchestrator")


@dataclass(slots=True)
class OrchestratorDependencies:
    policy: PolicyEngine
    parsers: ParserRegistry
    regex_detector: RegexDetector
    keyword_detector: KeywordDetector
    local_model_detector: LocalModelDetector | None
    adapter: ExternalModelAdapter
    vault: Vault
    restorer: Restorer
    hmac_key: bytes
    mapping_ttl_seconds: int
    parser_limits: ParserLimits
    scope_limits: ScopeLimits
    allowed_models: frozenset[str]


class Orchestrator:
    def __init__(self, deps: OrchestratorDependencies) -> None:
        self._deps = deps

    @property
    def deps(self) -> OrchestratorDependencies:
        """Wired dependencies. Exposed so tests can substitute a broken component
        and assert the fail-closed behaviour."""
        return self._deps

    async def process(
        self, context: RequestContext, normalized: NormalizedRequest
    ) -> GatewayResponse:
        started = time.monotonic()
        audit = AuditRecord(
            request_id=context.request_id,
            scope_id=context.scope.scope_id,
            tenant_hash=pseudonymous_id(context.tenant_id, self._deps.hmac_key),
            principal_hash=pseudonymous_id(
                context.principal.principal_id, self._deps.hmac_key
            ),
            policy_version=context.policy_version,
            item_count=len(normalized.items),
        )
        path = ForwardPath.SANITIZED
        try:
            response = await self._process_inner(context, normalized, audit)
            path = response.privacy.path
            audit.outcome = "completed"
            return response
        except GatewayError as exc:
            audit.outcome = "failed"
            audit.error_code = exc.code
            audit.stage = context.state.value
            if isinstance(exc, InspectionFailedClosed):
                metrics.fail_closed_total.labels(stage=context.state.value).inc()
            raise
        finally:
            audit.emit()
            metrics.observe_outcome(
                path.value, audit.outcome or "failed", time.monotonic() - started
            )

    # ------------------------------------------------------------------

    async def _process_inner(
        self,
        context: RequestContext,
        normalized: NormalizedRequest,
        audit: AuditRecord,
    ) -> GatewayResponse:
        deps = self._deps

        # --- inspect ---------------------------------------------------
        context.advance(RequestState.INSPECTING)
        parsed: dict[str, ParsedItem] = {}
        inspections: dict[str, InspectionResult] = {}
        findings_by_item: dict[str, list[Finding]] = {}

        for item in normalized.items:
            context.deadline.check("inspection")
            parsed_item, inspection, findings = await self._inspect_item(item, context)
            parsed[item.item_id] = parsed_item
            inspections[item.item_id] = inspection
            findings_by_item[item.item_id] = findings
            audit.add_findings(findings)
            for finding in findings:
                metrics.findings_total.labels(
                    entity_type=finding.entity_type.value, source=finding.source.value
                ).inc()

        # --- policy ----------------------------------------------------
        context.advance(RequestState.POLICY_EVALUATED)
        decisions = deps.policy.evaluate(
            purpose=context.manifest.purpose,
            items=normalized.items,
            parsed=parsed,
            inspections=inspections,
        )
        assert_complete_decision_coverage(normalized.items, decisions)
        audit.add_decisions(decisions)
        for item in decisions.items:
            for decision in item.decisions:
                metrics.policy_actions_total.labels(
                    action=decision.action.value, reason_code=decision.reason_code
                ).inc()

        if decisions.blocks_required_request_content():
            context.advance(RequestState.BLOCKED)
            raise ContentBlocked(
                "policy blocked required content",
                public_detail="request contains content that policy does not permit",
                meta={"reason_codes": list(decisions.strictest_reason_codes())},
            )

        # --- route -----------------------------------------------------
        verdict = assert_original_forward_allowed(
            scope=context.scope,
            items=normalized.items,
            parsed=parsed,
            inspections=inspections,
            decisions=decisions,
            model=context.manifest.model,
            purpose=context.manifest.purpose,
            allowed_models=deps.allowed_models,
            allowed_purposes=context.principal.allowed_purposes,
        )

        outbound: OriginalApprovedRequest | SanitizedModelRequest
        if verdict.allowed:
            outbound = build_original_request(context, normalized)
            path = ForwardPath.FAST
        else:
            context.advance(RequestState.SANITIZING)
            sanitization = await self._sanitize(
                context, normalized, parsed, decisions, findings_by_item
            )
            outbound = build_sanitized_request(context, normalized, sanitization)
            path = ForwardPath.SANITIZED
            for item in decisions.items:
                if item.is_withheld:
                    metrics.withheld_items_total.labels(
                        action=item.effective_action.value
                    ).inc()

        assert_no_withheld_or_blocked_content(outbound, decisions)
        audit.path = path.value

        # --- forward ---------------------------------------------------
        context.advance(RequestState.FORWARDING)
        context.deadline.check("external call")
        try:
            provider_response = await deps.adapter.complete(outbound, context.deadline)
            metrics.provider_requests_total.labels(status_category="2xx").inc()
        except GatewayError:
            metrics.provider_requests_total.labels(status_category="error").inc()
            context.advance(RequestState.EXTERNAL_FAILED)
            raise

        # --- restore ---------------------------------------------------
        context.advance(RequestState.RESTORING)
        outcome = await deps.restorer.restore_text_fields(provider_response, context)
        metrics.tokens_restored_total.inc(outcome.stats.tokens_restored)
        metrics.unknown_tokens_total.inc(outcome.stats.unknown_tokens)
        if outcome.stats.had_unknown:
            logger.warning(
                "gateway.restore.unknown_tokens",
                extra=safe_extra(
                    request_id=context.request_id,
                    scope_id=context.scope.scope_id,
                    unknown_token_count=outcome.stats.unknown_tokens,
                    restored_count=outcome.stats.tokens_restored,
                ),
            )

        context.advance(RequestState.COMPLETED)
        return GatewayResponse(
            scope_id=context.scope.scope_id,
            request_id=context.request_id,
            status="completed",
            output={
                "role": "assistant",
                "content": [
                    {"type": "text", "text": field.text}
                    for field in outcome.response.text_fields
                ],
            },
            privacy=PrivacySummary(
                path=path,
                scope_privacy_mode=context.scope.privacy_mode,
                policy_version=decisions.policy_version,
                actions=decisions.action_counts(),
                withheld_item_ids=list(decisions.withheld_item_ids()),
            ),
        )

    # ------------------------------------------------------------------

    async def _inspect_item(
        self, item: ContentItem, context: RequestContext
    ) -> tuple[ParsedItem, InspectionResult, list[Finding]]:
        deps = self._deps
        stages: list[str] = []
        try:
            parsed_item = deps.parsers.parse(item, deps.parser_limits)
            stages.append("parse")
        except GatewayError as exc:
            metrics.component_errors_total.labels(
                component="parser", result_code=exc.code
            ).inc()
            raise

        findings: list[Finding] = []
        findings.extend(deps.regex_detector.detect(item, parsed_item))
        stages.append("regex")
        findings.extend(deps.keyword_detector.detect(item, parsed_item))
        stages.append("keyword")

        # The local model only sees text, and only when there is text to see.
        if deps.local_model_detector is not None and parsed_item.normalized_text.strip():
            try:
                findings.extend(
                    await deps.local_model_detector.detect(
                        item, parsed_item, context.deadline
                    )
                )
                stages.append("local_model")
            except DetectorUnavailable as exc:
                # Fail closed for the content that depends on this detector; do
                # not degrade to "deterministic rules only" silently.
                metrics.component_errors_total.labels(
                    component="local_model", result_code=exc.code
                ).inc()
                raise

        # Attach the keyed fingerprint now so that anything serialized downstream
        # carries it instead of the matched text. Findings are frozen, so this
        # builds new instances rather than mutating in place.
        merged = [
            finding.model_copy(
                update={"text_hash": content_fingerprint(finding.raw_text, deps.hmac_key)}
            )
            if finding.raw_text
            else finding
            for finding in merge(findings, parsed_item)
        ]

        inspection = InspectionResult(
            item_id=item.item_id,
            findings=merged,
            inspection_complete=parsed_item.fully_inspected,
            failure_reason=None if parsed_item.fully_inspected else "partial_inspection",
            stages_completed=tuple(stages),
        )
        return parsed_item, inspection, merged

    async def _sanitize(
        self,
        context: RequestContext,
        normalized: NormalizedRequest,
        parsed: dict[str, ParsedItem],
        decisions: DecisionBundle,
        findings_by_item: dict[str, list[Finding]],
    ) -> SanitizationResult:
        deps = self._deps

        # Seed the allocator with tokens this scope already issued for the same
        # canonical values, so references stay stable across turns.
        allocator = TokenAllocator(
            tenant_id=context.tenant_id,
            scope_id=context.scope.scope_id,
            hmac_key=deps.hmac_key,
        )
        await self._seed_existing_tokens(
            allocator, context, normalized, decisions, findings_by_item
        )

        router = ItemRouter(allocator, mint=new_token)
        result = SanitizationResult()
        for item in normalized.items:
            decision = decisions.by_item(item.item_id)
            sanitized = router.route(
                item=item,
                parsed=parsed.get(item.item_id),
                decision=decision,
                findings=findings_by_item.get(item.item_id, []),
            )
            result.items.append(sanitized)
            if sanitized.part is None:
                result.withheld_item_ids.append(item.item_id)
            if sanitized.escaped_token_like:
                metrics.escaped_token_like_total.inc(sanitized.escaped_token_like)

        result.pending_mappings = allocator.pending

        # Capacity is checked before writing so a scope cannot exceed its mapping
        # budget mid-transaction.
        context.scope.check_mapping_capacity(
            deps.scope_limits, len(result.pending_mappings)
        )

        if result.pending_mappings:
            written = await deps.vault.put_all_and_lock_scope(
                tenant_id=context.tenant_id,
                scope_id=context.scope.scope_id,
                request_id=context.request_id,
                policy_version=context.policy_version,
                mappings=result.pending_mappings,
                ttl_seconds=deps.mapping_ttl_seconds,
            )
            context.scope.lock_sanitized()
            for mapping in result.pending_mappings:
                metrics.tokens_issued_total.labels(
                    entity_type=mapping.entity_type.value
                ).inc()
            logger.info(
                "gateway.vault.mappings_written",
                extra=safe_extra(
                    request_id=context.request_id,
                    scope_id=context.scope.scope_id,
                    token_count=written,
                ),
            )
        return result

    async def _seed_existing_tokens(
        self,
        allocator: TokenAllocator,
        context: RequestContext,
        normalized: NormalizedRequest,
        decisions: DecisionBundle,
        findings_by_item: dict[str, list[Finding]],
    ) -> None:
        for item in normalized.items:
            decision = decisions.by_item(item.item_id)
            span_ids = {str(d.finding_id) for d in decision.span_decisions
                        if d.action is PolicyAction.TOKENIZE}
            for finding in findings_by_item.get(item.item_id, []):
                if str(finding.finding_id) not in span_ids or not finding.raw_text:
                    continue
                request = allocator.request_for(finding.raw_text, finding.entity_type)
                existing = await self._deps.vault.find_token_by_digest(
                    tenant_id=context.tenant_id,
                    scope_id=context.scope.scope_id,
                    entity_type=finding.entity_type,
                    digest=request.lookup_hmac,
                )
                if existing is not None:
                    allocator.seed(finding.entity_type, request.lookup_hmac, existing)
