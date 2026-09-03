"""Closed vocabularies shared by every layer.

Adding a member here is never a local change: §7.1 of the design guide requires a
new entity type to arrive together with policy, fixtures, metrics labels, and an
expected failure behaviour. The tests in ``tests/unit/test_enums_contract.py``
enforce that.
"""

from __future__ import annotations

from enum import Enum


class EntityType(str, Enum):
    """Deliberately small taxonomy (guide §7.1)."""

    PERSON = "PERSON"
    ID_CARD = "ID_CARD"
    PHONE = "PHONE"
    BANK_CARD = "BANK_CARD"
    EMAIL = "EMAIL"
    ADDRESS_DETAILED = "ADDRESS_DETAILED"
    ORGANIZATION = "ORGANIZATION"
    VEHICLE_PLATE = "VEHICLE_PLATE"
    MEDICAL_DATA = "MEDICAL_DATA"
    FACE = "FACE"
    ID_DOCUMENT_IMAGE = "ID_DOCUMENT_IMAGE"
    ORDINARY_IMAGE = "ORDINARY_IMAGE"
    UNKNOWN_SENSITIVE = "UNKNOWN_SENSITIVE"


#: Entity types that describe a whole content item rather than a span inside it.
CONTENT_CLASS_ENTITIES: frozenset[EntityType] = frozenset(
    {
        EntityType.FACE,
        EntityType.ID_DOCUMENT_IMAGE,
        EntityType.ORDINARY_IMAGE,
    }
)

#: Entity types the local model is allowed to return. Anything else is rejected
#: before it can reach the evidence merger (guide §10.3).
LOCAL_MODEL_ENTITIES: frozenset[EntityType] = frozenset(
    {
        EntityType.PERSON,
        EntityType.ADDRESS_DETAILED,
        EntityType.ORGANIZATION,
        EntityType.MEDICAL_DATA,
        EntityType.UNKNOWN_SENSITIVE,
    }
)


class PolicyAction(str, Enum):
    """Guide §7.2."""

    PASS = "PASS"
    TOKENIZE = "TOKENIZE"
    REDACT = "REDACT"
    LOCAL_ANALYZE_TO_SANITIZED_TEXT = "LOCAL_ANALYZE_TO_SANITIZED_TEXT"
    LOCAL_ONLY = "LOCAL_ONLY"
    BLOCK = "BLOCK"


#: Least → most restrictive. When several actions apply to one item the most
#: restrictive one wins; there is no averaging and no "closest match".
ACTION_PRECEDENCE: tuple[PolicyAction, ...] = (
    PolicyAction.PASS,
    PolicyAction.TOKENIZE,
    PolicyAction.REDACT,
    PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT,
    PolicyAction.LOCAL_ONLY,
    PolicyAction.BLOCK,
)

_ACTION_RANK: dict[PolicyAction, int] = {a: i for i, a in enumerate(ACTION_PRECEDENCE)}


def action_rank(action: PolicyAction) -> int:
    return _ACTION_RANK[action]


def strictest(actions: object) -> PolicyAction:
    """Return the most restrictive action in ``actions``.

    An empty collection is a programming error, not "nothing to do": an item with
    no decision must never be forwarded (guide §7.4), so callers assert coverage
    before asking for an effective action.
    """
    ranked = sorted((a for a in actions), key=action_rank)  # type: ignore[union-attr]
    if not ranked:
        raise ValueError("no actions supplied; an item without a decision cannot be forwarded")
    return ranked[-1]


#: Actions whose item may still appear in the outbound request in some form.
FORWARDABLE_ACTIONS: frozenset[PolicyAction] = frozenset(
    {
        PolicyAction.PASS,
        PolicyAction.TOKENIZE,
        PolicyAction.REDACT,
        PolicyAction.LOCAL_ANALYZE_TO_SANITIZED_TEXT,
    }
)

#: Actions that keep the item entirely inside the trusted zone.
WITHHOLDING_ACTIONS: frozenset[PolicyAction] = frozenset(
    {PolicyAction.LOCAL_ONLY, PolicyAction.BLOCK}
)


class ContentItemType(str, Enum):
    TEXT = "text"
    FILE = "file"
    IMAGE = "image"


class ImageClass(str, Enum):
    """Local classifier output (guide §12.1)."""

    ORDINARY_IMAGE = "ORDINARY_IMAGE"
    ID_DOCUMENT_IMAGE = "ID_DOCUMENT_IMAGE"
    SENSITIVE_IMAGE = "SENSITIVE_IMAGE"
    UNKNOWN_IMAGE = "UNKNOWN_IMAGE"


class FindingSource(str, Enum):
    REGEX = "regex"
    CHECKSUM = "checksum"
    KEYWORD = "keyword"
    LOCAL_MODEL = "local_model"
    OCR = "ocr"
    IMAGE_CLASSIFIER = "image_classifier"


#: Evidence precedence for overlap resolution (guide §10.4), strongest first.
SOURCE_PRECEDENCE: tuple[FindingSource, ...] = (
    FindingSource.CHECKSUM,
    FindingSource.REGEX,
    FindingSource.KEYWORD,
    FindingSource.IMAGE_CLASSIFIER,
    FindingSource.OCR,
    FindingSource.LOCAL_MODEL,
)

_SOURCE_RANK: dict[FindingSource, int] = {s: i for i, s in enumerate(SOURCE_PRECEDENCE)}


def source_rank(source: FindingSource) -> int:
    """Lower is stronger evidence."""
    return _SOURCE_RANK[source]


class ScopeStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    EXPIRED = "EXPIRED"


class PrivacyMode(str, Enum):
    CLEAN = "CLEAN"
    SANITIZED_LOCKED = "SANITIZED_LOCKED"


class RequestState(str, Enum):
    """Guide §5.4."""

    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    INSPECTING = "INSPECTING"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    SANITIZING = "SANITIZING"
    FORWARDING = "FORWARDING"
    RESTORING = "RESTORING"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED_CLOSED = "FAILED_CLOSED"
    EXTERNAL_FAILED = "EXTERNAL_FAILED"


class ForwardPath(str, Enum):
    FAST = "fast"
    SANITIZED = "sanitized"
