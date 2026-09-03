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
#: sentence punctuation all terminate a value. Full-width brackets and the
#: enumeration comma are included because Chinese forms use them as field
#: separators far more often than the ASCII set does.
_STOP_CHARS = "\n\r|、,，;；。！？（）()【】《》\t"
_VALUE_STOP = rf"[{_STOP_CHARS}]"
#: A run of two or more spaces is a column boundary, not part of the value.
#: Chinese forms are routinely laid out by alignment rather than by delimiters
#: ("被保险人  张伟          身份证号 3205…"), and without this terminator the
#: capture runs straight into the next field. That is not merely untidy: the
#: oversized span overlaps the identifier finding beside it, evidence merging
#: keeps the stronger identifier, and the name it swallowed ends up with no
#: finding of its own — the label rule would silently stop protecting names.
_COLUMN_GAP = r"[ \t\u3000]{2,}"
_VALUE = rf"([^{_STOP_CHARS}]{{1,64}}?)(?={_COLUMN_GAP}|{_VALUE_STOP}|$)"

#: Label/value separator. Chinese forms very often have no punctuation at all —
#: the value is aligned with spaces or a full-width space in a table cell
#: ("姓名　张伟", "被保险人  张伟"). Requiring a colon loses those entirely, so
#: whitespace alone is accepted as a separator.
_SEPARATOR = r"(?:\s*[:：=]\s*|[ \t\u3000]{1,8})"


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
        labels=("姓名", "患者姓名", "患者", "被保险人", "投保人", "受益人", "驾驶人",
                "驾驶员", "当事人", "联系人", "受检人", "报案人", "申请人", "户名",
                "接诊医师", "接诊医生", "主治医师", "主治医生", "医师", "医生",
                "name", "patient", "insured", "policyholder", "driver", "contact person"),
        confidence=0.82,
    ),
    KeywordRule(
        rule_id="label_id_card",
        entity_type=EntityType.ID_CARD,
        labels=("公民身份号码", "身份证号码", "身份证号", "身份证", "证件号码", "证件号",
                "护照号", "港澳通行证", "台胞证", "驾驶证号", "驾照号",
                "id number", "id no", "identity card", "national id", "passport"),
        confidence=0.85,
    ),
    KeywordRule(
        rule_id="label_phone",
        entity_type=EntityType.PHONE,
        labels=("联系电话", "手机号码", "移动电话", "电话号码", "联系方式",
                "手机号", "手机", "电话", "座机", "传真",
                "phone", "mobile", "tel", "telephone"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_address",
        entity_type=EntityType.ADDRESS_DETAILED,
        labels=("详细地址", "家庭住址", "现住址", "户籍地址", "通讯地址", "住所地",
                "地址", "住址", "住所",
                "address", "home address", "residence"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_bank_card",
        entity_type=EntityType.BANK_CARD,
        labels=("银行卡号", "开户账号", "收款账号", "卡号", "账号", "账户",
                "card number", "card no", "account number"),
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
        labels=("号牌号码", "车牌号码", "车牌号", "车牌",
                "plate number", "license plate"),
        confidence=0.80,
    ),
    KeywordRule(
        rule_id="label_organization",
        entity_type=EntityType.ORGANIZATION,
        labels=("投保单位", "工作单位", "就诊医院", "医疗机构", "机构名称", "单位名称",
                "单位", "医院", "employer", "hospital", "organization"),
        confidence=0.72,
    ),
    KeywordRule(
        rule_id="label_org_id",
        entity_type=EntityType.ORG_ID,
        labels=("统一社会信用代码", "社会信用代码", "纳税人识别号", "组织机构代码",
                "营业执照号", "unified social credit"),
        confidence=0.85,
    ),
    KeywordRule(
        rule_id="label_medical_record",
        entity_type=EntityType.UNKNOWN_SENSITIVE,
        # Hospital record identifiers have no national format, so the label is
        # the only reliable evidence. UNKNOWN_SENSITIVE routes them through the
        # policy's uncertainty rule rather than guessing a category.
        labels=("病案号", "病历号", "住院号", "门诊号", "就诊卡号", "诊疗卡号",
                "社保卡号", "医保卡号", "报告编号", "检验单号"),
        confidence=0.80,
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
