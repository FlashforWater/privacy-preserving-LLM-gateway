"""Chinese-language adaptation.

The corpus is Chinese insurance and medical paperwork. That changes several
things that are invisible when the fixtures are English:

* offsets returned by the model are wrong essentially always, not merely often;
* forms align fields with spaces instead of delimiting them with colons;
* OCR inserts spaces inside names, and Chinese has no word spacing to distinguish
  those from real ones;
* the identifier set is different — 15-digit legacy IDs, 统一社会信用代码,
  港澳通行证, and landlines written with an area-code separator.

Each test below corresponds to something measured against real Chinese text.
"""

from __future__ import annotations

import pytest

from app.core.enums import ContentItemType, EntityType
from app.detectors.checksum import uscc_checksum_ok
from app.detectors.keyword_detector import KeywordDetector
from app.detectors.regex_detector import RegexDetector
from app.domain.content import ContentItem, ParsedItem
from app.sanitization.tokenizer import canonicalize

VALID_USCC = "91350100M000100Y43"


def parsed(text: str) -> tuple[ContentItem, ParsedItem]:
    item = ContentItem(
        item_id="i1", item_type=ContentItemType.TEXT, message_index=0, position=0,
        role="user", text=text, detected_mime="text/plain",
    )
    return item, ParsedItem(item_id="i1", normalized_text=text, fully_inspected=True)


def regex_types(text: str) -> set[EntityType]:
    item, p = parsed(text)
    return {f.entity_type for f in RegexDetector().detect(item, p)}


def labelled(text: str) -> dict[str, str]:
    item, p = parsed(text)
    return {f.rule_id or "": f.raw_text or "" for f in KeywordDetector().detect(item, p)}


class TestChineseIdentifiers:
    def test_uscc_checksum(self) -> None:
        assert uscc_checksum_ok(VALID_USCC)
        assert not uscc_checksum_ok(VALID_USCC[:-1] + "4")
        assert not uscc_checksum_ok("9135010OM000100Y43")  # O is not in the alphabet

    def test_uscc_is_detected_as_an_org_identifier(self) -> None:
        assert EntityType.ORG_ID in regex_types(f"统一社会信用代码 {VALID_USCC}")

    def test_legacy_15_digit_id(self) -> None:
        """Pre-2000 IDs have no check digit but fill archived claim files."""
        assert EntityType.ID_CARD in regex_types("证件号 320502900307999")

    def test_legacy_id_rejects_an_impossible_date(self) -> None:
        assert EntityType.ID_CARD not in regex_types("流水号 320502991307999")

    @pytest.mark.parametrize(
        "text",
        ["护照 E12345678", "港澳通行证 C12345678", "台胞证 H1234567890", "公务护照 P1234567"],
    )
    def test_travel_documents(self, text: str) -> None:
        assert EntityType.ID_CARD in regex_types(text)

    def test_landline_requires_a_separator(self) -> None:
        """Without the separator the pattern would match timestamps and amounts,
        and every one of those would be redacted."""
        assert EntityType.PHONE in regex_types("座机 0512-87654321")
        assert EntityType.PHONE in regex_types("总机 (010) 88886666")
        assert EntityType.PHONE not in regex_types("金额 051287654321")

    def test_plate_with_full_width_separator(self) -> None:
        assert EntityType.VEHICLE_PLATE in regex_types("号牌号码 苏E·12345")


class TestChineseAddress:
    def test_street_level_address_is_detected(self) -> None:
        assert EntityType.ADDRESS_DETAILED in regex_types(
            "住址：江苏省苏州市工业园区星海街88号3幢501室"
        )

    def test_city_alone_is_not_detailed_enough(self) -> None:
        """A bare city identifies nobody; matching it would redact useful context."""
        assert EntityType.ADDRESS_DETAILED not in regex_types("事故发生在苏州市")

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("在苏州工业园区星海街88号路口", "苏州工业园区星海街88号"),
            ("家住北京市朝阳区某某路12号", "北京市朝阳区某某路12号"),
            ("地址为上海市浦东新区世纪大道100号", "上海市浦东新区世纪大道100号"),
        ],
    )
    def test_leading_particles_are_trimmed(self, text: str, expected: str) -> None:
        """Chinese runs words together, so a pattern anchored on 路/号 picks up the
        preposition in front of it. The span is trimmed and the offset advanced."""
        item, p = parsed(text)
        finding = next(
            f for f in RegexDetector().detect(item, p)
            if f.entity_type is EntityType.ADDRESS_DETAILED
        )
        start, end = finding.span
        assert text[start:end] == expected

    def test_road_name_starting_with_a_trimmed_character_is_not_eaten(self) -> None:
        """Trimming is left-anchored and stops at the first character that is not
        a particle, so a road whose name begins with one survives intact."""
        text = "南京西路1266号"
        item, p = parsed(text)
        finding = next(
            f for f in RegexDetector().detect(item, p)
            if f.entity_type is EntityType.ADDRESS_DETAILED
        )
        start, end = finding.span
        assert text[start:end] == text


class TestSpaceAlignedForms:
    """Chinese forms align fields with spaces rather than delimiting them."""

    def test_colon_less_label(self) -> None:
        assert labelled("姓名  张伟").get("label_person") == "张伟"

    def test_full_width_space_separator(self) -> None:
        assert labelled("被保险人　张伟").get("label_person") == "张伟"

    def test_value_stops_at_a_column_gap(self) -> None:
        """The regression this guard exists for.

        Without a column-gap terminator the capture ran into the next field. The
        oversized span then overlapped the identifier beside it, evidence merging
        kept the stronger identifier, and the name it had swallowed ended up with
        no finding at all — the label rule would have quietly stopped protecting
        names in exactly the layout where names appear most.
        """
        captured = labelled("被保险人  张伟          身份证号 320502199003079999")
        assert captured.get("label_person") == "张伟"

    def test_single_space_inside_a_value_is_kept(self) -> None:
        assert labelled("姓名 Wei Zhang").get("label_person") == "Wei Zhang"

    def test_chinese_medical_record_labels(self) -> None:
        assert labelled("病历号 ZY-2026-0038172").get("label_medical_record") == "ZY-2026-0038172"


class TestCjkCanonicalization:
    def test_ocr_spacing_inside_a_name_does_not_split_the_token(self) -> None:
        """Chinese has no word spacing, so a space inside 张 伟 is layout noise.

        Left in, it would give the same person two tokens and break coreference
        across materials in one scope — the external model would see two people
        where the file has one.
        """
        for variant in ("张 伟", "张　伟", "张  伟"):
            assert canonicalize(variant, EntityType.PERSON) == canonicalize(
                "张伟", EntityType.PERSON
            )

    def test_distinct_names_stay_distinct(self) -> None:
        assert canonicalize("张伟", EntityType.PERSON) != canonicalize("张威", EntityType.PERSON)

    def test_no_alias_merging(self) -> None:
        assert canonicalize("张伟", EntityType.PERSON) != canonicalize("张先生", EntityType.PERSON)

    def test_latin_word_spacing_is_preserved(self) -> None:
        """The rule is scoped to CJK-flanked whitespace; English keeps its spaces."""
        assert canonicalize("Wei Zhang", EntityType.PERSON) != canonicalize(
            "WeiZhang", EntityType.PERSON
        )


class TestChinesePromptIsDefault:
    def test_default_prompt_is_the_chinese_one(self) -> None:
        from app.detectors.local_model_detector import DEFAULT_PROMPT, load_prompt

        assert DEFAULT_PROMPT.endswith("zh_v1")
        prompt = load_prompt(DEFAULT_PROMPT)
        assert "不可信数据" in prompt
        assert "{{normalized_text}}" in prompt

    def test_prompt_tells_the_model_offsets_are_only_a_hint(self) -> None:
        """The model cannot count Chinese characters — measured 0/13 correct
        offsets on a claims note. Asking it to try wastes tokens and invites it
        to alter the text to fit."""
        from app.detectors.local_model_detector import DEFAULT_PROMPT, load_prompt

        prompt = load_prompt(DEFAULT_PROMPT)
        assert "仅作参考" in prompt
        assert "逐字符抄自原文" in prompt

    def test_unknown_prompt_fails_closed(self) -> None:
        from app.detectors.base import DetectorUnavailable
        from app.detectors.local_model_detector import load_prompt

        with pytest.raises(DetectorUnavailable):
            load_prompt("no_such_prompt")
