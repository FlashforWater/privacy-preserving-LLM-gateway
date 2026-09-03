"""The no-bypass guard (guide §14.1).

"Test it aggressively" — every condition gets a test that flips exactly that
condition and asserts the fast path closes. If any of these ever starts passing
with the fast path open, original user content is leaving the gateway without
complete inspection.
"""

from __future__ import annotations

import pytest

from app.core.enums import ContentItemType, EntityType, FindingSource, PolicyAction, PrivacyMode
from app.domain.content import ContentItem, ParsedItem
from app.domain.decisions import DecisionBundle, ItemDecision, PolicyDecision
from app.domain.findings import Finding, InspectionResult
from app.domain.scopes import ScopeRecord
from app.gateway.request_builder import assert_original_forward_allowed

ALLOWED_MODELS = frozenset({"model-a"})
ALLOWED_PURPOSES = frozenset({"general"})


def scope(**overrides: object) -> ScopeRecord:
    record = ScopeRecord.create(
        tenant_id="tenant-a", policy_version="v1",
        idle_ttl_seconds=7200, absolute_ttl_seconds=86400,
    )
    for key, value in overrides.items():
        setattr(record, key, value)
    return record


def text_item(item_id: str = "i1") -> ContentItem:
    return ContentItem(
        item_id=item_id, item_type=ContentItemType.TEXT, message_index=0, position=0,
        role="user", text="hello", detected_mime="text/plain",
    )


def image_item(item_id: str = "img1") -> ContentItem:
    return ContentItem(
        item_id=item_id, item_type=ContentItemType.IMAGE, message_index=0, position=1,
        role="user", data=b"\x89PNG", detected_mime="image/png",
    )


def parsed_ok(item_id: str = "i1", **overrides: object) -> ParsedItem:
    parsed = ParsedItem(
        item_id=item_id, normalized_text="hello", fully_inspected=True,
        parser_name="plain_text", original_bytes_forwardable=True,
    )
    for key, value in overrides.items():
        setattr(parsed, key, value)
    return parsed


def inspection_ok(item_id: str = "i1", **overrides: object) -> InspectionResult:
    data = {
        "item_id": item_id, "findings": [], "inspection_complete": True,
        "stages_completed": ("parse", "regex", "keyword"),
    }
    data.update(overrides)
    return InspectionResult(**data)  # type: ignore[arg-type]


def pass_bundle(item_id: str = "i1", action: PolicyAction = PolicyAction.PASS) -> DecisionBundle:
    decision = PolicyDecision(
        item_id=item_id, action=action, policy_rule_id="defaults.no_findings",
        reason_code="no_protected_content", policy_version="v1",
    )
    return DecisionBundle(
        policy_version="v1",
        items=(ItemDecision(item_id=item_id, effective_action=action, decisions=(decision,)),),
    )


def verdict(**overrides: object):
    kwargs = {
        "scope": scope(),
        "items": [text_item()],
        "parsed": {"i1": parsed_ok()},
        "inspections": {"i1": inspection_ok()},
        "decisions": pass_bundle(),
        "model": "model-a",
        "purpose": "general",
        "allowed_models": ALLOWED_MODELS,
        "allowed_purposes": ALLOWED_PURPOSES,
    }
    kwargs.update(overrides)
    return assert_original_forward_allowed(**kwargs)  # type: ignore[arg-type]


class TestGuardOpensOnlyWhenEverythingIsClean:
    def test_clean_request_is_allowed(self) -> None:
        result = verdict()
        assert result.allowed, result.blockers

    def test_all_conditions_are_reported_together(self) -> None:
        """One call should explain everything that is wrong, not just the first."""
        result = verdict(
            scope=scope(privacy_mode=PrivacyMode.SANITIZED_LOCKED),
            model="model-z",
            purpose="unlisted",
        )
        assert not result.allowed
        assert len(result.blockers) >= 3


class TestEachConditionClosesTheFastPath:
    def test_scope_sanitized_locked(self) -> None:
        result = verdict(scope=scope(privacy_mode=PrivacyMode.SANITIZED_LOCKED))
        assert not result.allowed
        assert "scope_sanitized_locked" in result.blockers

    def test_incomplete_inspection(self) -> None:
        result = verdict(inspections={"i1": inspection_ok(inspection_complete=False)})
        assert not result.allowed
        assert "incomplete_inspection:i1" in result.blockers

    def test_inspection_error(self) -> None:
        result = verdict(
            inspections={"i1": inspection_ok(failure_reason="ocr_timeout")}
        )
        assert not result.allowed
        assert "inspection_error:i1" in result.blockers

    def test_missing_inspection(self) -> None:
        result = verdict(inspections={})
        assert not result.allowed
        assert "missing_inspection:i1" in result.blockers

    def test_partial_parse(self) -> None:
        result = verdict(parsed={"i1": parsed_ok(fully_inspected=False)})
        assert not result.allowed
        assert "partial_parse:i1" in result.blockers

    def test_any_finding_closes_the_path(self) -> None:
        """Even a finding policy chose to PASS disqualifies the fast path.

        The fast path is for requests where nothing was detected at all; a
        detected-but-permitted entity still means protected content was present.
        """
        found = Finding(
            item_id="i1", entity_type=EntityType.ORGANIZATION, source=FindingSource.REGEX,
            start=0, end=3, confidence=0.9, rule_id="r", raw_text="abc",
        )
        result = verdict(inspections={"i1": inspection_ok(findings=[found])})
        assert not result.allowed
        assert "findings_present:i1" in result.blockers

    def test_non_pass_action(self) -> None:
        result = verdict(decisions=pass_bundle(action=PolicyAction.TOKENIZE))
        assert not result.allowed
        assert "non_pass_action:i1" in result.blockers

    def test_missing_decision(self) -> None:
        result = verdict(decisions=DecisionBundle(policy_version="v1", items=()))
        assert not result.allowed
        assert "missing_decision:i1" in result.blockers

    def test_model_not_allowed(self) -> None:
        result = verdict(model="model-z")
        assert not result.allowed
        assert "model_not_allowed" in result.blockers

    def test_purpose_not_allowed(self) -> None:
        result = verdict(purpose="unlisted")
        assert not result.allowed
        assert "purpose_not_allowed" in result.blockers

    def test_image_bytes_not_forwardable(self) -> None:
        result = verdict(
            items=[image_item()],
            parsed={"img1": parsed_ok("img1", original_bytes_forwardable=False)},
            inspections={"img1": inspection_ok("img1")},
            decisions=pass_bundle("img1"),
        )
        assert not result.allowed
        assert "bytes_not_forwardable:img1" in result.blockers

    def test_document_marked_unforwardable(self) -> None:
        parsed = parsed_ok("img1")
        parsed.inspection_notes["blocks_original_forward"] = True
        result = verdict(
            items=[image_item()],
            parsed={"img1": parsed},
            inspections={"img1": inspection_ok("img1")},
            decisions=pass_bundle("img1"),
        )
        assert not result.allowed

    def test_expired_scope(self) -> None:
        from datetime import UTC, datetime, timedelta

        stale = scope()
        stale.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        result = verdict(scope=stale)
        assert not result.allowed
        assert "scope_not_usable" in result.blockers


class TestGuardIsTheOnlyImplementation:
    def test_no_route_reimplements_the_guard(self) -> None:
        """Guide §14.1: do not reproduce the guard logic in multiple routes."""
        from pathlib import Path

        api_dir = Path(__file__).resolve().parents[2] / "app" / "api"
        for source_file in api_dir.glob("*.py"):
            text = source_file.read_text(encoding="utf-8")
            assert "PrivacyMode.CLEAN" not in text, source_file.name
            assert "original_forward" not in text, source_file.name

    def test_require_raises_when_not_allowed(self) -> None:
        from app.core.errors import InspectionFailedClosed

        with pytest.raises(InspectionFailedClosed):
            verdict(model="model-z").require()
