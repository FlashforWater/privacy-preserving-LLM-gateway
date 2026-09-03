"""Contract tests on the closed vocabularies.

Guide §7.1: "Do not add a new entity type without adding policy, test fixtures,
metrics labels, and expected failure behavior for it." These tests turn that
sentence into something a CI run enforces — adding an ``EntityType`` member
without a policy rule fails here, not in production.
"""

from __future__ import annotations

from pathlib import Path

from app.core.enums import (
    ACTION_PRECEDENCE,
    FORWARDABLE_ACTIONS,
    LOCAL_MODEL_ENTITIES,
    SOURCE_PRECEDENCE,
    WITHHOLDING_ACTIONS,
    EntityType,
    FindingSource,
    ImageClass,
    PolicyAction,
    action_rank,
    strictest,
)
from app.policy.loader import load_policy_document

POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.default.yaml"


class TestPrecedence:
    def test_precedence_covers_every_action(self) -> None:
        assert set(ACTION_PRECEDENCE) == set(PolicyAction)

    def test_precedence_is_ordered_least_to_most_restrictive(self) -> None:
        assert ACTION_PRECEDENCE[0] is PolicyAction.PASS
        assert ACTION_PRECEDENCE[-1] is PolicyAction.BLOCK
        assert action_rank(PolicyAction.TOKENIZE) < action_rank(PolicyAction.REDACT)
        assert action_rank(PolicyAction.REDACT) < action_rank(
            PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT
        )
        assert action_rank(PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT) < action_rank(
            PolicyAction.LOCAL_ONLY
        )

    def test_strictest_picks_the_most_restrictive(self) -> None:
        assert strictest([PolicyAction.PASS, PolicyAction.BLOCK]) is PolicyAction.BLOCK
        assert strictest([PolicyAction.TOKENIZE, PolicyAction.PASS]) is PolicyAction.TOKENIZE

    def test_every_action_is_either_forwardable_or_withholding(self) -> None:
        assert FORWARDABLE_ACTIONS | WITHHOLDING_ACTIONS == set(PolicyAction)
        assert not (FORWARDABLE_ACTIONS & WITHHOLDING_ACTIONS)

    def test_source_precedence_covers_every_source(self) -> None:
        assert set(SOURCE_PRECEDENCE) == set(FindingSource)

    def test_checksum_is_the_strongest_evidence(self) -> None:
        assert SOURCE_PRECEDENCE[0] is FindingSource.CHECKSUM
        assert SOURCE_PRECEDENCE[-1] is FindingSource.LOCAL_MODEL


class TestPolicyCoversTheVocabulary:
    def test_every_entity_type_has_a_rule_or_is_a_content_class(self) -> None:
        policy = load_policy_document(POLICY)
        content_class_entities = {EntityType.ID_DOCUMENT_IMAGE, EntityType.ORDINARY_IMAGE}
        for entity in EntityType:
            if entity in content_class_entities:
                continue
            assert entity in policy.entities, f"policy has no rule for {entity.value}"

    def test_every_image_class_has_a_rule(self) -> None:
        policy = load_policy_document(POLICY)
        for image_class in ImageClass:
            assert image_class in policy.content_classes

    def test_local_model_entities_are_a_subset_of_the_taxonomy(self) -> None:
        assert LOCAL_MODEL_ENTITIES <= set(EntityType)

    def test_local_model_cannot_claim_deterministic_entities(self) -> None:
        """The model is not allowed to assert ID_CARD, BANK_CARD or PHONE.

        Those have checksums and structure; a model claim there would be weaker
        evidence competing with a rule that can actually be verified.
        """
        for entity in (EntityType.ID_CARD, EntityType.BANK_CARD, EntityType.PHONE,
                       EntityType.EMAIL, EntityType.VEHICLE_PLATE):
            assert entity not in LOCAL_MODEL_ENTITIES


class TestMetricsLabels:
    def test_every_entity_type_can_be_a_metric_label(self) -> None:
        from app.observability import metrics

        for entity in EntityType:
            metrics.findings_total.labels(entity_type=entity.value, source="regex")

    def test_every_action_can_be_a_metric_label(self) -> None:
        from app.observability import metrics

        for action in PolicyAction:
            metrics.policy_actions_total.labels(action=action.value, reason_code="test")
