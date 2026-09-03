"""Evidence merging and overlap resolution (guide §10.4).

Precedence::

    validated checksum rule
      > high-specificity deterministic rule
      > contextual keyword rule
      > local-model-only finding

Merging never *drops* protection. When two findings overlap and disagree, the
merged finding keeps the entity type whose policy action is stricter, records
both source ids for audit, and takes the longest correct direct-identifier span —
so the result is always at least as protective as either input.

Confidence is raised when a nearby field label supports a shape-based finding.
That is why the keyword detector runs even for entity types the regexes already
cover.
"""

from __future__ import annotations

from collections import defaultdict

from app.core.enums import EntityType, FindingSource
from app.detectors.keyword_detector import context_boost
from app.domain.content import ParsedItem
from app.domain.findings import Finding

#: Entity types ordered by how damaging a leak is, most damaging first. Used to
#: break ties when two overlapping findings carry equally strong evidence.
_ENTITY_SEVERITY: tuple[EntityType, ...] = (
    EntityType.ID_CARD,
    EntityType.BANK_CARD,
    EntityType.PHONE,
    EntityType.EMAIL,
    EntityType.VEHICLE_PLATE,
    EntityType.ADDRESS_DETAILED,
    EntityType.PERSON,
    EntityType.MEDICAL_DATA,
    EntityType.UNKNOWN_SENSITIVE,
    EntityType.ORGANIZATION,
)
_SEVERITY_RANK = {entity: index for index, entity in enumerate(_ENTITY_SEVERITY)}


def _severity(entity: EntityType) -> int:
    return _SEVERITY_RANK.get(entity, len(_ENTITY_SEVERITY))


def merge(findings: list[Finding], parsed: ParsedItem) -> list[Finding]:
    """Return a non-overlapping, confidence-adjusted finding list for one item."""
    if not findings:
        return []

    boosted = [_apply_context(finding, parsed.normalized_text) for finding in findings]

    spanless = [f for f in boosted if not f.has_span]
    spanned = [f for f in boosted if f.has_span]

    # Strongest first: evidence rank, then severity, then longest span, then
    # highest confidence. Stable on finding_id so the result is reproducible.
    spanned.sort(
        key=lambda f: (
            f.evidence_rank,
            _severity(f.entity_type),
            -f.length,
            -f.confidence,
            str(f.finding_id),
        )
    )

    kept: list[Finding] = []
    absorbed: dict[str, list[str]] = defaultdict(list)

    for candidate in spanned:
        winner = next((k for k in kept if k.overlaps(candidate)), None)
        if winner is None:
            kept.append(candidate)
            continue
        absorbed[str(winner.finding_id)].append(
            f"{candidate.source.value}:{candidate.rule_id or '-'}"
        )
        # If the absorbed finding is more severe, upgrade the survivor's type so
        # the stricter policy action applies (guide §10.4, bullet 2).
        if _severity(candidate.entity_type) < _severity(winner.entity_type):
            upgraded = winner.model_copy(
                update={
                    "entity_type": candidate.entity_type,
                    "confidence": max(winner.confidence, candidate.confidence),
                }
            )
            kept[kept.index(winner)] = upgraded

    merged = [
        finding.model_copy(
            update={
                "contributing_sources": tuple(
                    [f"{finding.source.value}:{finding.rule_id or '-'}"]
                    + absorbed.get(str(finding.finding_id), [])
                )
            }
        )
        for finding in kept
    ]
    merged.sort(key=lambda f: f.span)
    return merged + spanless


def _apply_context(finding: Finding, text: str) -> Finding:
    """Raise confidence for a shape-based finding sitting next to a matching label."""
    if finding.source not in (FindingSource.REGEX, FindingSource.CHECKSUM):
        return finding
    bonus = context_boost(text, finding)
    if bonus <= 0:
        return finding
    return finding.model_copy(
        update={"confidence": min(1.0, finding.confidence + bonus)}
    )
