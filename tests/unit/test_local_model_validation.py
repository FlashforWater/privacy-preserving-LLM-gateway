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
    """The model's ``text`` is a claim; the offsets are only a hint.

    Measured against a live vLLM-served Qwen3.8: it identified six of six
    entities correctly and got five of six character offsets wrong, the drift
    growing with position. So the gateway locates the claimed string itself and
    never acts on the model's arithmetic.
    """

    def test_correct_offsets_are_used_directly(self) -> None:
        result = verify_spans(TEXT, [RawEntity(9, 18, "Wei Zhang", "PERSON", 0.9)])
        assert len(result.accepted) == 1
        assert result.accepted[0].relocated is False
        assert TEXT[result.accepted[0].start : result.accepted[0].end] == "Wei Zhang"

    def test_wrong_offsets_are_recovered_not_discarded(self) -> None:
        """The regression this class exists for.

        Under a strict offset rule this entity was thrown away, and a real name
        then travelled to the external model untouched — while the audit trail
        said the detector found nothing.
        """
        result = verify_spans(TEXT, [RawEntity(999, 1008, "Wei Zhang", "PERSON", 0.9)])
        assert len(result.accepted) == 1
        assert result.accepted[0].relocated is True
        span = result.accepted[0]
        assert TEXT[span.start : span.end] == "Wei Zhang"

    def test_every_accepted_span_slices_back_to_its_claim(self) -> None:
        """The invariant that replaces the offset check."""
        entities = [
            RawEntity(0, 1, "Wei Zhang", "PERSON", 0.9),
            RawEntity(0, 1, "13812345678", "UNKNOWN_SENSITIVE", 0.9),
        ]
        for span in verify_spans(TEXT, entities).accepted:
            assert TEXT[span.start : span.end] == span.text

    def test_invented_text_is_rejected(self) -> None:
        """A claim that does not occur in the document is a hallucination."""
        result = verify_spans(TEXT, [RawEntity(9, 18, "Chen Xiaoming", "PERSON", 0.9)])
        assert result.accepted == []
        assert result.rejected == 1

    def test_every_occurrence_is_marked(self) -> None:
        """Over-marking costs utility; under-marking discloses data."""
        text = "Wei Zhang paid. Contact Wei Zhang again."
        result = verify_spans(text, [RawEntity(0, 9, "Wei Zhang", "PERSON", 0.9)])
        assert [(s.start, s.end) for s in result.accepted] == [(0, 9), (24, 33)]

    def test_very_short_claims_are_rejected(self) -> None:
        """A one-character claim matches almost everywhere and is never an
        identifier on its own; accepting it would redact the document to noise."""
        result = verify_spans(TEXT, [RawEntity(0, 1, "a", "PERSON", 0.9)])
        assert result.accepted == []

    def test_entity_type_outside_the_allow_list_is_rejected(self) -> None:
        result = verify_spans(TEXT, [RawEntity(9, 18, "Wei Zhang", "ID_CARD", 0.9)])
        assert result.accepted == []

    def test_oversized_claim_is_rejected(self) -> None:
        result = verify_spans(TEXT + "x" * 2000, [RawEntity(0, 1, "x" * 600, "PERSON", 0.9)])
        assert result.accepted == []

    def test_duplicate_claims_do_not_duplicate_spans(self) -> None:
        result = verify_spans(
            TEXT,
            [
                RawEntity(9, 18, "Wei Zhang", "PERSON", 0.9),
                RawEntity(500, 509, "Wei Zhang", "PERSON", 0.8),
            ],
        )
        assert len(result.accepted) == 1

    def test_partial_acceptance_counts_rejections(self) -> None:
        result = verify_spans(
            TEXT,
            [
                RawEntity(9, 18, "Wei Zhang", "PERSON", 0.9),
                RawEntity(0, 5, "Nobody Here", "PERSON", 0.9),
            ],
        )
        assert len(result.accepted) == 1
        assert result.rejected == 1


class TestReasoningModelHandling:
    """Findings from probing a live vLLM-served reasoning model.

    ``content`` is null while the model is thinking, and a truncated answer means
    the entity list is incomplete. Accepting either as "no entities found" would
    silently under-detect — the one failure mode this service exists to prevent.
    """

    def test_null_content_is_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload(None)  # type: ignore[arg-type]

    def test_truncated_json_is_rejected(self) -> None:
        with pytest.raises(DetectorUnavailable):
            parse_entity_payload('{"entities": [{"start": 0, "end": 3, "text": "abc"')

    def test_thinking_switch_is_sent_only_when_enabled(self) -> None:
        from app.detectors.local_model_detector import OpenAICompatibleLocalModel

        on = OpenAICompatibleLocalModel(
            base_url="http://local.test/v1", model="m", disable_thinking=True
        )
        off = OpenAICompatibleLocalModel(
            base_url="http://local.test/v1", model="m", disable_thinking=False
        )
        assert on._thinking_kwargs() == {"chat_template_kwargs": {"enable_thinking": False}}
        assert off._thinking_kwargs() == {}
