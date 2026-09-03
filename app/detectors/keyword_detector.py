"""Field-label rules (guide §10.2, last bullet).

Two jobs:

1. **Detect labelled values that have no intrinsic shape.** ``Patient: 张伟`` and
   ``Name: Wei Zhang`` are direct identifiers that no regex over the value alone
   could recognise. The label is the evidence.
2. **Supply context to shape-based rules.** A 16-digit number next to ``Card No.``
   is much more likely to be a bank card than the same digits in a table of
   measurements. :func:`context_boost` exposes that as a confidence adjustment
   the evidence merger applies.

The value capture is deliberately short and stops at structural delimiters. A
greedy capture would swallow a whole paragraph and tokenize analytical content
that policy never asked to remove (guide §3.3, minimum necessary transformation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.enums import EntityType, FindingSource
from app.domain.content import ContentItem, ParsedItem
from app.domain.findings import Finding

#: Where a labelled value ends. Newlines, pipes (table cells), and CJK/ASCII
#: sentence punctuation all terminate a value.
_VALUE_STOP = r"[\n\r|、,，;；。]"
_VALUE = rf"([^\n\r|、,，;；。]{{1,64}}?)(?={_VALUE_STOP}|$)"
_SEPARATOR = r"\s*[:：=]\s*"


@dataclass(frozen=True, slots=True)
class KeywordRule:
    rule_id: str
    entity_type: EntityType
    labels: tuple[str, ...]
    confidence: float
    #: Extra confidence granted to a shape-based finding that sits next to this label.
    context_bonus: float = 0.10


KEYWORD_RULES: tuple[KeywordRule, ...] = (
    KeywordRule(
        rule_id="label_person",
        entity_type=EntityType.PERSON,
        labels=("姓名", "患者", "被保险人", "投保人", "驾驶人", "联系人", "受检人",
                "name", "patient", "insured", "policyholder", "driver", "contact person"),
        confidence=0.82,
    ),
    KeywordRule(
        rule_id="label_id_card",
        entity_type=EntityType.ID_CARD,
        labels=("身份证号", "身份证", "证件号码", "证件号",
                "id number", "id no", "identity card", "national id"),
        confidence=0.85,
    ),
    KeywordRule(
        rule_id="label_phone",
        entity_type=EntityType.PHONE,
        labels=("电话", "手机", "手机号", "联系电话", "联系方式",
                "phone", "mobile", "tel", "telephone"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_address",
        entity_type=EntityType.ADDRESS_DETAILED,
        labels=("地址", "住址", "家庭住址", "详细地址",
                "address", "home address", "residence"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_bank_card",
        entity_type=EntityType.BANK_CARD,
        labels=("银行卡号", "卡号", "账号", "card number", "card no", "account number"),
        confidence=0.78,
    ),
    KeywordRule(
        rule_id="label_email",
        entity_type=EntityType.EMAIL,
        labels=("邮箱", "电子邮箱", "email", "e-mail"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_plate",
        entity_type=EntityType.VEHICLE_PLATE,
        labels=("车牌号", "车牌", "号牌号码", "plate number", "license plate"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_organization",
        entity_type=EntityType.ORGANIZATION,
        labels=("单位", "工作单位", "医院", "机构名称", "employer", "hospital", "organization"),
        confidence=0.72,
    ),
)

#: How far from a label a shape-based finding may sit and still count as labelled.
CONTEXT_WINDOW = 24


def _compile(rule: KeywordRule) -> re.Pattern[str]:
    # Longest label first so "身份证号" wins over "身份证".
    alternatives = "|".join(re.escape(label) for label in sorted(rule.labels, key=len, reverse=True))
    return re.compile(rf"(?i)(?P<label>{alternatives}){_SEPARATOR}{_VALUE}")


_COMPILED: tuple[tuple[KeywordRule, re.Pattern[str]], ...] = tuple(
    (rule, _compile(rule)) for rule in KEYWORD_RULES
)


class KeywordDetector:
    name = "keyword_detector"

    def __init__(self, rules: tuple[tuple[KeywordRule, re.Pattern[str]], ...] = _COMPILED) -> None:
        self._rules = rules

    def detect(self, item: ContentItem, parsed: ParsedItem) -> list[Finding]:
        text = parsed.normalized_text
        if not text:
            return []
        findings: list[Finding] = []
        for rule, pattern in self._rules:
            for match in pattern.finditer(text):
                value = match.group(2)
                if value is None:
                    continue
                stripped = value.strip()
                if not stripped:
                    continue
                # Span of the value only. Tokenizing the label as well would
                # destroy the document structure the external model reasons over.
                offset = match.start(2) + (len(value) - len(value.lstrip()))
                findings.append(
                    Finding(
                        item_id=item.item_id,
                        entity_type=rule.entity_type,
                        source=FindingSource.KEYWORD,
                        start=offset,
                        end=offset + len(stripped),
                        confidence=rule.confidence,
                        rule_id=rule.rule_id,
                        raw_text=stripped,
                        metadata={"label": match.group("label").lower()},
                    )
                )
        return findings


def context_boost(text: str, finding: Finding) -> float:
    """Extra confidence for a shape-based finding sitting next to a matching label.

    Returns 0.0 when no supporting label is nearby, so a bare number in a table of
    measurements is not promoted on the strength of its shape alone.
    """
    if not finding.has_span:
        return 0.0
    start, _ = finding.span
    window = text[max(0, start - CONTEXT_WINDOW) : start].lower()
    for rule in KEYWORD_RULES:
        if rule.entity_type is not finding.entity_type:
            continue
        if any(label.lower() in window for label in rule.labels):
            return rule.context_bonus
    return 0.0
