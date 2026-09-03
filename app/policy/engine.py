"""The authoritative policy engine.

Contract (guide §9.1): it takes normalized request context plus findings and
returns deterministic decisions. It must not call an LLM, and nothing else in the
system is allowed to decide an action.

Precedence, applied in order (guide §9.3.4):

1. purpose override for the entity,
2. content-class rule for the item,
3. entity rule,
4. defaults.

When several rules apply to one item the *most restrictive* effective action wins
(§9.3.5). Low-confidence and unknown findings follow an explicit uncertainty rule
and are never silently dropped (§9.3.8).
"""

from __future__ import annotations

from app.core.enums import (
    EntityType,
    ImageClass,
    PolicyAction,
    strictest,
)
from app.domain.content import ContentItem, ParsedItem
from app.domain.decisions import DecisionBundle, ItemDecision, PolicyDecision
from app.domain.findings import Finding, InspectionResult

from .schema import EntityRule, PolicyDocument

# Reason codes are part of the public contract (they appear in metrics and audit
# records) and must never contain payload-derived text.
REASON_ENTITY_RULE = "entity_rule"
REASON_PURPOSE_OVERRIDE = "purpose_override"
REASON_CONTENT_CLASS = "content_class"
REASON_LOW_CONFIDENCE = "low_confidence"
REASON_UNKNOWN_ENTITY = "unknown_entity"
REASON_INSPECTION_INCOMPLETE = "inspection_incomplete"
REASON_UNSUPPORTED_CONTENT = "unsupported_content"
REASON_NO_FINDINGS = "no_protected_content"


class PolicyEngine:
    def __init__(self, policy: PolicyDocument) -> None:
        self._policy = policy

    @property
    def version(self) -> str:
        return self._policy.version

    @property
    def document(self) -> PolicyDocument:
        return self._policy

    # ---- rule resolution -------------------------------------------------

    def _entity_rule(self, entity_type: EntityType, purpose: str) -> tuple[EntityRule, str]:
        override = self._policy.purpose_overrides.get(purpose, {}).get(entity_type)
        if override is not None:
            return override, REASON_PURPOSE_OVERRIDE
        rule = self._policy.entities.get(entity_type)
        if rule is not None:
            return rule, REASON_ENTITY_RULE
        return (
            EntityRule(action=self._policy.defaults.unknown_entity),
            REASON_UNKNOWN_ENTITY,
        )

    def _content_class_action(self, image_class: ImageClass) -> PolicyAction:
        rule = self._policy.content_classes.get(image_class)
        if rule is None:
            return self._policy.defaults.unsupported_content
        return rule.action

    # ---- evaluation ------------------------------------------------------

    def evaluate(
        self,
        *,
        purpose: str,
        items: list[ContentItem],
        parsed: dict[str, ParsedItem],
        inspections: dict[str, InspectionResult],
        required_item_ids: frozenset[str] | None = None,
    ) -> DecisionBundle:
        item_decisions: list[ItemDecision] = []
        for item in items:
            item_decisions.append(
                self._evaluate_item(
                    purpose=purpose,
                    item=item,
                    parsed=parsed.get(item.item_id),
                    inspection=inspections.get(item.item_id),
                )
            )
        return DecisionBundle(
            policy_version=self._policy.version,
            items=tuple(item_decisions),
            required_item_ids=required_item_ids or frozenset(),
        )

    def _evaluate_item(
        self,
        *,
        purpose: str,
        item: ContentItem,
        parsed: ParsedItem | None,
        inspection: InspectionResult | None,
    ) -> ItemDecision:
        version = self._policy.version
        decisions: list[PolicyDecision] = []
        span_decisions: list[PolicyDecision] = []

        # 1. Incomplete inspection outranks everything. Absence of findings is not
        #    evidence of safety (guide §3.2), so a failed or missing inspection
        #    resolves through the detector_error default rather than to PASS.
        if inspection is None or not inspection.inspection_complete or parsed is None:
            decisions.append(
                PolicyDecision(
                    item_id=item.item_id,
                    action=self._policy.defaults.detector_error,
                    policy_rule_id="defaults.detector_error",
                    reason_code=REASON_INSPECTION_INCOMPLETE,
                    policy_version=version,
                )
            )
            return ItemDecision(
                item_id=item.item_id,
                effective_action=decisions[0].action,
                decisions=tuple(decisions),
            )

        # 2. Content-class rule for images.
        if parsed.image_class is not None:
            action = self._content_class_action(parsed.image_class)
            decisions.append(
                PolicyDecision(
                    item_id=item.item_id,
                    action=action,
                    policy_rule_id=f"content_classes.{parsed.image_class.value}",
                    reason_code=REASON_CONTENT_CLASS,
                    policy_version=version,
                    entity_type=_content_class_entity(parsed.image_class),
                )
            )

        # 3. One decision per finding.
        for finding in inspection.findings:
            decision = self._evaluate_finding(purpose, finding, version)
            decisions.append(decision)
            if finding.has_span and decision.action in (
                PolicyAction.TOKENIZE,
                PolicyAction.REDACT,
            ):
                span_decisions.append(decision)

        # 4. Nothing said anything: the item is clean, and it was fully inspected.
        if not decisions:
            decisions.append(
                PolicyDecision(
                    item_id=item.item_id,
                    action=PolicyAction.PASS,
                    policy_rule_id="defaults.no_findings",
                    reason_code=REASON_NO_FINDINGS,
                    policy_version=version,
                )
            )

        return ItemDecision(
            item_id=item.item_id,
            effective_action=strictest([d.action for d in decisions]),
            decisions=tuple(decisions),
            span_decisions=tuple(span_decisions),
        )

    def _evaluate_finding(
        self, purpose: str, finding: Finding, version: str
    ) -> PolicyDecision:
        rule, reason = self._entity_rule(finding.entity_type, purpose)

        if finding.confidence < rule.minimum_confidence:
            # Explicit uncertainty rule. Never a silent drop.
            return PolicyDecision(
                item_id=finding.item_id,
                action=self._policy.defaults.low_confidence,
                policy_rule_id="defaults.low_confidence",
                reason_code=REASON_LOW_CONFIDENCE,
                policy_version=version,
                finding_id=finding.finding_id,
                entity_type=finding.entity_type,
            )

        rule_id = (
            f"purpose_overrides.{purpose}.{finding.entity_type.value}"
            if reason == REASON_PURPOSE_OVERRIDE
            else f"entities.{finding.entity_type.value}"
        )
        return PolicyDecision(
            item_id=finding.item_id,
            action=rule.action,
            policy_rule_id=rule_id,
            reason_code=reason,
            policy_version=version,
            finding_id=finding.finding_id,
            entity_type=finding.entity_type,
        )


def _content_class_entity(image_class: ImageClass) -> EntityType | None:
    return {
        ImageClass.ORDINARY_IMAGE: EntityType.ORDINARY_IMAGE,
        ImageClass.ID_DOCUMENT_IMAGE: EntityType.ID_DOCUMENT_IMAGE,
    }.get(image_class)


def assert_complete_decision_coverage(
    items: list[ContentItem], bundle: DecisionBundle
) -> None:
    """Guide §7.4: a missing decision means do not forward.

    Called by the orchestrator between policy evaluation and any outbound
    assembly, so a new item type that slips past the evaluator cannot ride along
    undecided.
    """
    missing = [item.item_id for item in items if not bundle.has_decision_for(item.item_id)]
    if missing:
        from app.core.errors import InspectionFailedClosed

        raise InspectionFailedClosed(
            f"no policy decision for items: {missing}",
            public_detail="inspection did not complete for all content",
        )
