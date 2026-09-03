"""Span rewriting, overlap resolution and evidence merging (guide §19.1)."""

from __future__ import annotations

from app.core.enums import EntityType, FindingSource, PolicyAction
from app.domain.content import ParsedItem
from app.domain.findings import Finding
from app.gateway.evidence_merger import merge
from app.sanitization.span_rewriter import SpanEdit, apply_edits, resolve_overlaps


def finding(
    start: int, end: int, entity: EntityType, source: FindingSource,
    confidence: float = 0.9, text: str = "", rule: str = "r",
) -> Finding:
    return Finding(
        item_id="i1", entity_type=entity, source=source, start=start, end=end,
        confidence=confidence, rule_id=rule, raw_text=text,
    )


def parsed(text: str) -> ParsedItem:
    return ParsedItem(item_id="i1", normalized_text=text, fully_inspected=True)


class TestSpanRewriting:
    def test_edits_apply_back_to_front(self) -> None:
        text = "AAA BBB CCC"
        edits = [
            SpanEdit(0, 3, "[1]", PolicyAction.REDACT, finding(0, 3, EntityType.PERSON, FindingSource.REGEX)),
            SpanEdit(8, 11, "[22222]", PolicyAction.REDACT, finding(8, 11, EntityType.PERSON, FindingSource.REGEX)),
        ]
        assert apply_edits(text, resolve_overlaps(edits)) == "[1] BBB [22222]"

    def test_same_range_is_never_rewritten_twice(self) -> None:
        text = "identifier here"
        edits = [
            SpanEdit(0, 10, "[A]", PolicyAction.REDACT, finding(0, 10, EntityType.PERSON, FindingSource.REGEX)),
            SpanEdit(0, 10, "[B]", PolicyAction.REDACT, finding(0, 10, EntityType.PERSON, FindingSource.KEYWORD)),
        ]
        kept = resolve_overlaps(edits)
        assert len(kept) == 1

    def test_stricter_action_wins_an_overlap(self) -> None:
        edits = [
            SpanEdit(0, 5, "[TOK]", PolicyAction.TOKENIZE,
                     finding(0, 5, EntityType.PERSON, FindingSource.CHECKSUM)),
            SpanEdit(0, 5, "[RED]", PolicyAction.REDACT,
                     finding(0, 5, EntityType.PERSON, FindingSource.LOCAL_MODEL)),
        ]
        assert resolve_overlaps(edits)[0].replacement == "[RED]"

    def test_stronger_evidence_wins_at_equal_strictness(self) -> None:
        edits = [
            SpanEdit(0, 5, "[weak]", PolicyAction.TOKENIZE,
                     finding(0, 5, EntityType.PERSON, FindingSource.LOCAL_MODEL)),
            SpanEdit(0, 5, "[strong]", PolicyAction.TOKENIZE,
                     finding(0, 5, EntityType.ID_CARD, FindingSource.CHECKSUM)),
        ]
        assert resolve_overlaps(edits)[0].replacement == "[strong]"

    def test_longer_span_preferred_at_equal_evidence(self) -> None:
        edits = [
            SpanEdit(0, 4, "[short]", PolicyAction.TOKENIZE,
                     finding(0, 4, EntityType.ID_CARD, FindingSource.REGEX)),
            SpanEdit(0, 18, "[long]", PolicyAction.TOKENIZE,
                     finding(0, 18, EntityType.ID_CARD, FindingSource.REGEX)),
        ]
        assert resolve_overlaps(edits)[0].replacement == "[long]"

    def test_result_is_disjoint_and_ordered(self) -> None:
        edits = [
            SpanEdit(10, 20, "[b]", PolicyAction.REDACT, finding(10, 20, EntityType.PERSON, FindingSource.REGEX)),
            SpanEdit(0, 5, "[a]", PolicyAction.REDACT, finding(0, 5, EntityType.PERSON, FindingSource.REGEX)),
            SpanEdit(15, 25, "[c]", PolicyAction.REDACT, finding(15, 25, EntityType.PERSON, FindingSource.REGEX)),
        ]
        kept = resolve_overlaps(edits)
        starts = [edit.start for edit in kept]
        assert starts == sorted(starts)
        for previous, current in zip(kept, kept[1:], strict=False):
            assert previous.end <= current.start

    def test_resolution_is_deterministic(self) -> None:
        edits = [
            SpanEdit(0, 5, "[a]", PolicyAction.TOKENIZE,
                     finding(0, 5, EntityType.PERSON, FindingSource.REGEX)),
            SpanEdit(2, 7, "[b]", PolicyAction.TOKENIZE,
                     finding(2, 7, EntityType.PERSON, FindingSource.REGEX)),
        ]
        first = [e.replacement for e in resolve_overlaps(list(edits))]
        second = [e.replacement for e in resolve_overlaps(list(reversed(edits)))]
        assert first == second


class TestEvidenceMerging:
    def test_overlapping_findings_collapse_to_one(self) -> None:
        text = "身份证号 110101199003079999"
        merged = merge(
            [
                finding(5, 23, EntityType.ID_CARD, FindingSource.CHECKSUM, 0.99),
                finding(5, 23, EntityType.PHONE, FindingSource.LOCAL_MODEL, 0.4),
            ],
            parsed(text),
        )
        assert len(merged) == 1
        assert merged[0].source is FindingSource.CHECKSUM

    def test_contributing_sources_are_recorded(self) -> None:
        merged = merge(
            [
                finding(0, 10, EntityType.ID_CARD, FindingSource.CHECKSUM, rule="a"),
                finding(0, 10, EntityType.PERSON, FindingSource.KEYWORD, rule="b"),
            ],
            parsed("x" * 20),
        )
        assert len(merged[0].contributing_sources) == 2

    def test_more_severe_type_wins_when_absorbed(self) -> None:
        """A weaker-evidence but more severe overlap upgrades the survivor.

        Merging must never lower protection: if one detector says ORGANIZATION
        and another says ID_CARD over the same characters, the stricter policy
        action has to apply.
        """
        merged = merge(
            [
                finding(0, 10, EntityType.ORGANIZATION, FindingSource.REGEX, 0.8),
                finding(0, 10, EntityType.ID_CARD, FindingSource.LOCAL_MODEL, 0.5),
            ],
            parsed("x" * 20),
        )
        assert merged[0].entity_type is EntityType.ID_CARD

    def test_non_overlapping_findings_are_all_kept(self) -> None:
        merged = merge(
            [
                finding(0, 5, EntityType.PERSON, FindingSource.KEYWORD),
                finding(10, 20, EntityType.PHONE, FindingSource.REGEX),
            ],
            parsed("x" * 30),
        )
        assert len(merged) == 2

    def test_context_label_raises_confidence(self) -> None:
        text = "电话: 13812345678"
        merged = merge(
            [finding(5, 16, EntityType.PHONE, FindingSource.REGEX, 0.85, text="13812345678")],
            parsed(text),
        )
        assert merged[0].confidence > 0.85

    def test_merging_is_stable(self) -> None:
        findings = [
            finding(0, 5, EntityType.PERSON, FindingSource.KEYWORD),
            finding(3, 9, EntityType.PERSON, FindingSource.LOCAL_MODEL),
            finding(20, 30, EntityType.PHONE, FindingSource.REGEX),
        ]
        first = [f.span for f in merge(list(findings), parsed("x" * 40))]
        second = [f.span for f in merge(list(reversed(findings)), parsed("x" * 40))]
        assert first == second
