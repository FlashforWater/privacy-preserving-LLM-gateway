"""Policy schema validation and evaluation precedence (guide §19.1)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from app.core.enums import ContentItemType, EntityType, FindingSource, ImageClass, PolicyAction
from app.core.errors import ConfigurationError
from app.domain.content import ContentItem, ParsedItem
from app.domain.findings import Finding, InspectionResult
from app.policy.engine import (
    REASON_INSPECTION_INCOMPLETE,
    REASON_LOW_CONFIDENCE,
    REASON_PURPOSE_OVERRIDE,
    PolicyEngine,
    assert_complete_decision_coverage,
)
from app.policy.loader import load_policy_document

POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.default.yaml"


def item(item_id: str = "i1", item_type: ContentItemType = ContentItemType.TEXT) -> ContentItem:
    return ContentItem(
        item_id=item_id, item_type=item_type, message_index=0, position=0,
        role="user", text="x", detected_mime="text/plain",
    )


def finding(entity: EntityType, confidence: float = 0.95, item_id: str = "i1") -> Finding:
    return Finding(
        item_id=item_id, entity_type=entity, source=FindingSource.REGEX,
        start=0, end=3, confidence=confidence, rule_id="test", raw_text="abc",
    )


def evaluate(engine: PolicyEngine, findings: list[Finding], *, purpose: str = "general",
             image_class: ImageClass | None = None, complete: bool = True):
    content = item()
    parsed = ParsedItem(item_id="i1", normalized_text="abc", fully_inspected=True,
                        image_class=image_class)
    inspection = InspectionResult(item_id="i1", findings=findings, inspection_complete=complete)
    return engine.evaluate(
        purpose=purpose, items=[content], parsed={"i1": parsed}, inspections={"i1": inspection}
    )


class TestSchemaValidation:
    def test_default_policy_loads(self) -> None:
        document = load_policy_document(POLICY)
        assert document.version
        assert document.entities

    def test_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "policy.yaml"
        bad.write_text(
            POLICY.read_text(encoding="utf-8") + "\nunexpected_section:\n  foo: bar\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigurationError):
            load_policy_document(bad)

    def test_missing_entity_rule_is_rejected(self, tmp_path: Path) -> None:
        text = POLICY.read_text(encoding="utf-8").replace(
            "  ID_CARD:\n    action: TOKENIZE\n    minimum_confidence: 0.50\n", ""
        )
        bad = tmp_path / "policy.yaml"
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigurationError) as exc:
            load_policy_document(bad)
        assert "ID_CARD" in str(exc.value)

    def test_permissive_uncertainty_default_is_rejected(self, tmp_path: Path) -> None:
        text = POLICY.read_text(encoding="utf-8").replace(
            "  unknown_entity: BLOCK", "  unknown_entity: PASS"
        )
        bad = tmp_path / "policy.yaml"
        bad.write_text(text, encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_policy_document(bad)

    def test_invalid_yaml_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "policy.yaml"
        bad.write_text(textwrap.dedent("version: [unclosed\n"), encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_policy_document(bad)


class TestEvaluation:
    def test_direct_identifier_is_tokenized(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.ID_CARD)])
        assert bundle.by_item("i1").effective_action is PolicyAction.TOKENIZE

    def test_no_findings_passes(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [])
        assert bundle.by_item("i1").effective_action is PolicyAction.PASS

    def test_medical_data_blocks_by_default(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.MEDICAL_DATA)])
        assert bundle.by_item("i1").effective_action is PolicyAction.BLOCK
        assert bundle.blocks_required_request_content()

    def test_purpose_override_permits_medical_data(self, policy: PolicyEngine) -> None:
        bundle = evaluate(
            policy, [finding(EntityType.MEDICAL_DATA)], purpose="medical_report_analysis"
        )
        decision = bundle.by_item("i1")
        assert decision.effective_action is PolicyAction.PASS
        assert REASON_PURPOSE_OVERRIDE in decision.reason_codes

    def test_override_does_not_relax_direct_identifiers(self, policy: PolicyEngine) -> None:
        """The medical override permits the analytical content, not the names.

        This is the property that makes the override safe to grant.
        """
        bundle = evaluate(
            policy,
            [finding(EntityType.MEDICAL_DATA), finding(EntityType.ID_CARD)],
            purpose="medical_report_analysis",
        )
        assert bundle.by_item("i1").effective_action is PolicyAction.TOKENIZE

    def test_strictest_action_wins(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.PERSON), finding(EntityType.MEDICAL_DATA)])
        assert bundle.by_item("i1").effective_action is PolicyAction.BLOCK

    def test_low_confidence_uses_the_uncertainty_rule(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.PERSON, confidence=0.10)])
        decision = bundle.by_item("i1")
        assert decision.effective_action is PolicyAction.REDACT
        assert REASON_LOW_CONFIDENCE in decision.reason_codes

    def test_low_confidence_is_never_silently_dropped(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.PERSON, confidence=0.01)])
        assert bundle.by_item("i1").decisions

    def test_unknown_sensitive_blocks(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [finding(EntityType.UNKNOWN_SENSITIVE)])
        assert bundle.by_item("i1").effective_action is PolicyAction.BLOCK

    def test_incomplete_inspection_uses_detector_error_default(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [], complete=False)
        decision = bundle.by_item("i1")
        assert decision.effective_action is PolicyAction.BLOCK
        assert REASON_INSPECTION_INCOMPLETE in decision.reason_codes

    def test_unknown_image_blocks(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [], image_class=ImageClass.UNKNOWN_IMAGE)
        assert bundle.by_item("i1").effective_action is PolicyAction.BLOCK

    def test_id_document_image_routes_to_local_analysis(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [], image_class=ImageClass.ID_DOCUMENT_IMAGE)
        assert (
            bundle.by_item("i1").effective_action
            is PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT
        )

    def test_ordinary_image_passes(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [], image_class=ImageClass.ORDINARY_IMAGE)
        assert bundle.by_item("i1").effective_action is PolicyAction.PASS

    def test_missing_decision_coverage_raises(self, policy: PolicyEngine) -> None:
        bundle = evaluate(policy, [])
        with pytest.raises(Exception):
            assert_complete_decision_coverage([item("i1"), item("i2")], bundle)

    def test_engine_never_calls_a_model(self) -> None:
        """Source-level check: the policy engine must not import a model client."""
        import ast

        source = (
            Path(__file__).resolve().parents[2] / "app" / "policy" / "engine.py"
        ).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom):
                names = [(node.module or "")]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            for name in names:
                assert "local_model" not in name
                assert "external" not in name
