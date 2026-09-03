"""Local-model output validation (guide §10.3).

The model is a detection assistant whose output is untrusted. These tests pin the
acceptance conditions; loosening any of them lets a hallucinated span rewrite an
unrelated part of the document.
"""

from __future__ import annotations

import pytest

from app.detectors.base import DetectorUnavailable
from app.detectors.local_model_detector import (
    RawEntity,
    parse_entity_payload,
    verify_spans,
)

TEXT = "Patient: Wei Zhang, phone 13812345678."


class TestPayloadParsing:
    def test_valid_payload(self) -> None:
        entities = parse_entity_payload(
            '{"entities": [{"start": 9, "end": 18, "text": "Wei Zhang", '
            '"type": "PERSON", "confidence": 0.9}]}'
        )
        assert entities[0].type == "PERSON"

    def test_code_fence_is_tolerated(self) -> None:
        assert parse_entity_payload('```json\n{"entities": []}\n```') == []

    def test_prose_is_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload("Sure! Here are the entities I found: none.")

    def test_extra_top_level_fields_are_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload('{"entities": [], "note": "hi"}')

    def test_extra_entity_fields_are_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload(
                '{"entities": [{"start": 0, "end": 1, "text": "a", "type": "PERSON",'
                ' "confidence": 0.5, "action": "BLOCK"}]}'
            )

    def test_missing_entity_field_is_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload('{"entities": [{"start": 0, "end": 1, "text": "a"}]}')

    def test_too_many_entities_is_rejected(self) -> None:
        entity = '{"start": 0, "end": 1, "text": "a", "type": "PERSON", "confidence": 0.5}'
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload('{"entities": [' + ",".join([entity] * 201) + "]}")

    def test_malformed_json_is_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload('{"entities": [')


class TestSpanVerification:
    def test_exact_span_is_accepted(self) -> None:
        result = verify_spans(TEXT, [RawEntity(9, 18, "Wei Zhang", "PERSON", 0.9)])
        assert len(result.accepted) == 1
        assert result.rejected == 0

    def test_mismatched_text_is_rejected(self) -> None:
        """The single most important check: offsets must reproduce the input."""
        result = verify_spans(TEXT, [RawEntity(9, 18, "Someone Else", "PERSON", 0.9)])
        assert result.accepted == []
        assert result.rejected == 1

    def test_out_of_bounds_span_is_rejected(self) -> None:
        result = verify_spans(TEXT, [RawEntity(0, 9999, "x", "PERSON", 0.9)])
        assert result.accepted == []

    def test_inverted_span_is_rejected(self) -> None:
        result = verify_spans(TEXT, [RawEntity(18, 9, "Wei Zhang", "PERSON", 0.9)])
        assert result.accepted == []

    def test_entity_type_outside_the_allow_list_is_rejected(self) -> None:
        result = verify_spans(TEXT, [RawEntity(9, 18, "Wei Zhang", "ID_CARD", 0.9)])
        assert result.accepted == []

    def test_oversized_span_is_rejected(self) -> None:
        long_text = "x" * 2000
        result = verify_spans(long_text, [RawEntity(0, 1000, long_text[:1000], "PERSON", 0.9)])
        assert result.accepted == []

    def test_partial_acceptance_counts_rejections(self) -> None:
        result = verify_spans(
            TEXT,
            [
                RawEntity(9, 18, "Wei Zhang", "PERSON", 0.9),
                RawEntity(0, 5, "WRONG", "PERSON", 0.9),
            ],
        )
        assert len(result.accepted) == 1
        assert result.rejected == 1
