"""Deterministic rules: positive, negative, boundary, Unicode and adversarial
cases (guide §19.1, first bullet).

The variant cases matter more than the clean ones. Real documents contain
``110101 19900307 9999`` and full-width digits; a rule that only matches the
compact ASCII form has excellent unit-test numbers and terrible recall.
"""

from __future__ import annotations

import pytest

from app.core.enums import EntityType, FindingSource
from app.detectors.checksum import cn_id_checksum_ok, cn_id_date_plausible, luhn_ok
from app.detectors.keyword_detector import KeywordDetector, context_boost
from app.detectors.regex_detector import RegexDetector
from app.domain.content import ContentItem, ParsedItem
from app.core.enums import ContentItemType
from tests.fixtures import synthetic


def parsed(text: str) -> tuple[ContentItem, ParsedItem]:
    item = ContentItem(
        item_id="i1", item_type=ContentItemType.TEXT, message_index=0, position=0,
        role="user", text=text, detected_mime="text/plain",
    )
    return item, ParsedItem(item_id="i1", normalized_text=text, fully_inspected=True)


def types_found(text: str) -> set[EntityType]:
    item, parsed_item = parsed(text)
    return {f.entity_type for f in RegexDetector().detect(item, parsed_item)}


def full_width(value: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else c for c in value)


class TestChecksums:
    def test_valid_ids(self) -> None:
        assert cn_id_checksum_ok(synthetic.ID_CARD)
        assert cn_id_checksum_ok(synthetic.ID_CARD_SECOND)

    def test_wrong_check_digit(self) -> None:
        bad = synthetic.ID_CARD[:17] + ("0" if synthetic.ID_CARD[17] != "0" else "1")
        assert not cn_id_checksum_ok(bad)

    def test_transposed_digits_are_caught(self) -> None:
        card = synthetic.ID_CARD
        swapped = card[:6] + card[7] + card[6] + card[8:]
        assert not cn_id_checksum_ok(swapped)

    def test_separators_ignored(self) -> None:
        card = synthetic.ID_CARD
        assert cn_id_checksum_ok(f"{card[:6]} {card[6:14]} {card[14:]}")
        assert cn_id_checksum_ok(f"{card[:6]}-{card[6:14]}-{card[14:]}")

    def test_luhn(self) -> None:
        assert luhn_ok(synthetic.BANK_CARD)
        assert luhn_ok("4539 5787 6362 1486")
        assert not luhn_ok(synthetic.BANK_CARD[:-1] + "7")

    def test_date_plausibility_rejects_serial_numbers(self) -> None:
        assert cn_id_date_plausible(synthetic.ID_CARD)
        assert not cn_id_date_plausible("110101199913079999")  # month 99


class TestRegexRules:
    @pytest.mark.parametrize(
        "text",
        [
            f"身份证号 {synthetic.ID_CARD}",
            f"身份证号 {synthetic.ID_CARD[:6]} {synthetic.ID_CARD[6:14]} {synthetic.ID_CARD[14:]}",
            f"ID {synthetic.ID_CARD[:6]}-{synthetic.ID_CARD[6:14]}-{synthetic.ID_CARD[14:]}",
            f"证件 {full_width(synthetic.ID_CARD)}",
        ],
    )
    def test_id_card_variants(self, text: str) -> None:
        assert EntityType.ID_CARD in types_found(text)

    @pytest.mark.parametrize(
        "text",
        ["电话 13812345678", "电话 138-1234-5678", "tel 138 1234 5678",
         f"手机 {full_width('13812345678')}"],
    )
    def test_phone_variants(self, text: str) -> None:
        assert EntityType.PHONE in types_found(text)

    def test_bank_card_variants(self) -> None:
        assert EntityType.BANK_CARD in types_found("卡号 4539 5787 6362 1486")
        assert EntityType.BANK_CARD in types_found(f"card {synthetic.BANK_CARD}")

    def test_email_and_plate(self) -> None:
        assert EntityType.EMAIL in types_found(f"mail {synthetic.EMAIL}")
        assert EntityType.VEHICLE_PLATE in types_found(f"车牌 {synthetic.PLATE}")

    def test_checksum_promotes_source_and_confidence(self) -> None:
        item, parsed_item = parsed(f"身份证号 {synthetic.ID_CARD}")
        finding = next(
            f for f in RegexDetector().detect(item, parsed_item)
            if f.entity_type is EntityType.ID_CARD
        )
        assert finding.source is FindingSource.CHECKSUM
        assert finding.confidence >= 0.99

    def test_invalid_date_is_not_an_id_card(self) -> None:
        assert EntityType.ID_CARD not in types_found("流水号 110101199913079999")

    def test_failed_luhn_still_reports_a_finding(self) -> None:
        """A mistyped card number is still a card number.

        Confidence drops (and policy then routes it through the low-confidence
        rule) but the finding is not discarded — a failed checksum is weak
        evidence, not counter-evidence.
        """
        item, parsed_item = parsed("卡号 4539578763621487")
        findings = [
            f for f in RegexDetector().detect(item, parsed_item)
            if f.entity_type is EntityType.BANK_CARD
        ]
        assert findings
        assert findings[0].confidence < 0.99

    def test_short_number_is_not_a_phone(self) -> None:
        assert EntityType.PHONE not in types_found("measurement 1381234567")

    def test_reported_span_matches_the_original_text(self) -> None:
        """Spans are reported against the original string, not the folded copy.

        The tokenizer replaces exactly this range, so an offset computed on a
        normalized variant would rewrite the wrong characters.
        """
        text = f"证件 {full_width(synthetic.ID_CARD)} 完"
        item, parsed_item = parsed(text)
        finding = next(
            f for f in RegexDetector().detect(item, parsed_item)
            if f.entity_type is EntityType.ID_CARD
        )
        start, end = finding.span
        assert text[start:end] == full_width(synthetic.ID_CARD)


class TestKeywordRules:
    def test_labelled_person_is_detected(self) -> None:
        item, parsed_item = parsed("患者: 张伟\n主诉: 左臂疼痛")
        findings = KeywordDetector().detect(item, parsed_item)
        person = [f for f in findings if f.entity_type is EntityType.PERSON]
        assert person and person[0].raw_text == "张伟"

    def test_value_capture_stops_at_delimiters(self) -> None:
        item, parsed_item = parsed("Name: John Doe | Age: 40")
        finding = next(
            f for f in KeywordDetector().detect(item, parsed_item)
            if f.entity_type is EntityType.PERSON
        )
        assert finding.raw_text == "John Doe"

    def test_label_itself_is_not_part_of_the_span(self) -> None:
        item, parsed_item = parsed("姓名：张伟")
        finding = KeywordDetector().detect(item, parsed_item)[0]
        start, end = finding.span
        assert parsed_item.normalized_text[start:end] == "张伟"

    def test_context_boost_requires_a_matching_label(self) -> None:
        item, parsed_item = parsed(f"电话: {synthetic.PHONE}")
        phone = next(
            f for f in RegexDetector().detect(item, parsed_item)
            if f.entity_type is EntityType.PHONE
        )
        assert context_boost(parsed_item.normalized_text, phone) > 0

        item2, parsed2 = parsed(f"reading {synthetic.PHONE}")
        bare = next(
            f for f in RegexDetector().detect(item2, parsed2)
            if f.entity_type is EntityType.PHONE
        )
        assert context_boost(parsed2.normalized_text, bare) == 0
