"""Policy decisions and the decision bundle.

The bundle is what the fast-path guard and the outbound builder read. It is built
once by the policy engine and never mutated afterwards, so "which items may leave"
has exactly one answer per request.
"""

from __future__ import annotations

import uuid
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    FORWARDABLE_ACTIONS,
    WITHHOLDING_ACTIONS,
    EntityType,
    PolicyAction,
    action_rank,
    strictest,
)


class PolicyDecision(BaseModel):
    """Guide §7.4. Every externally forwarded item must have a traceable decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str
    action: PolicyAction
    policy_rule_id: str
    reason_code: str
    policy_version: str
    finding_id: uuid.UUID | None = None
    entity_type: EntityType | None = None


class ItemDecision(BaseModel):
    """The effective outcome for one content item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str
    effective_action: PolicyAction
    decisions: tuple[PolicyDecision, ...]
    #: Span-level decisions that must be applied inside the item's text.
    span_decisions: tuple[PolicyDecision, ...] = ()

    @property
    def is_forwardable(self) -> bool:
        return self.effective_action in FORWARDABLE_ACTIONS

    @property
    def is_withheld(self) -> bool:
        return self.effective_action in WITHHOLDING_ACTIONS

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(sorted({d.reason_code for d in self.decisions}))


class DecisionBundle(BaseModel):
    """All decisions for one request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str
    items: tuple[ItemDecision, ...]
    #: Item ids that are required for the request to make sense. Blocking one of
    #: these blocks the whole request; blocking a separable attachment does not.
    required_item_ids: frozenset[str] = frozenset()

    def by_item(self, item_id: str) -> ItemDecision:
        for item in self.items:
            if item.item_id == item_id:
                return item
        raise KeyError(f"no decision for item {item_id!r}")

    def has_decision_for(self, item_id: str) -> bool:
        return any(i.item_id == item_id for i in self.items)

    @property
    def effective_action(self) -> PolicyAction:
        return strictest([i.effective_action for i in self.items])

    def blocks_required_request_content(self) -> bool:
        """True when a BLOCK lands on required content, or when *any* item is
        blocked outright — a blocked attachment is never silently dropped."""
        for item in self.items:
            if item.effective_action is PolicyAction.BLOCK:
                return True
        return False

    def withheld_item_ids(self) -> tuple[str, ...]:
        return tuple(sorted(i.item_id for i in self.items if i.is_withheld))

    def forwardable_item_ids(self) -> tuple[str, ...]:
        return tuple(i.item_id for i in self.items if i.is_forwardable)

    def original_forward_candidate(self) -> bool:
        """Necessary (not sufficient) condition for the fast path.

        Sufficiency is decided only by
        :func:`app.gateway.request_builder.assert_original_forward_allowed`,
        which also checks inspection completeness and scope state.
        """
        return all(i.effective_action is PolicyAction.PASS for i in self.items)

    def action_counts(self) -> dict[str, int]:
        counter: Counter[str] = Counter()
        for item in self.items:
            for decision in item.decisions:
                counter[decision.action.value] += 1
        return dict(sorted(counter.items()))

    def public_summary(self) -> dict[str, object]:
        """Non-sensitive summary for API responses and logs (guide §8.2)."""
        return {
            "policy_version": self.policy_version,
            "actions": self.action_counts(),
            "withheld_item_ids": list(self.withheld_item_ids()),
        }

    def strictest_reason_codes(self) -> tuple[str, ...]:
        worst = self.effective_action
        codes = {
            d.reason_code
            for i in self.items
            for d in i.decisions
            if action_rank(d.action) == action_rank(worst)
        }
        return tuple(sorted(codes))
