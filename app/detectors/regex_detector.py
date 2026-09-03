"""Deterministic pattern rules (guide §10.2).

Design notes that matter for recall:

* **One rule per identifier, not one giant regex.** Each rule carries an id, an
  entity type, a confidence and an evidence category, and is tested on its own.
* **Separators are matched, not assumed away.** Real documents contain
  ``110101 19900307 9999`` and ``138-1234-5678``; a pattern that only accepts the
  compact form misses most of the corpus. Each rule therefore allows an explicit
  separator class inside the number.
* **Full-width digits are normalized before matching.** CJK documents routinely
  contain ``１３８…``; without folding, every such identifier is invisible.
* Confidence is raised when a checksum validates, and when a nearby field label
  supports the interpretation (context is supplied by the keyword detector via
  :func:`context_boost`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from app.core.enums import EntityType, FindingSource
from app.domain.content import ContentItem, ParsedItem
from app.domain.findings import Finding

from .checksum import cn_id_checksum_ok, cn_id_date_plausible, luhn_ok, uscc_checksum_ok

#: Characters that may appear *inside* an identifier without breaking it.
_SEP = r"[ \t 　\-‐-―－.]{0,2}"


def _fold(text: str) -> str:
    """Full-width → ASCII for digits and Latin letters, preserving length.

    Length preservation is essential: spans computed on the folded string are
    reported against the original, so a one-to-one mapping is required.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 0xFF10 <= code <= 0xFF19 or 0xFF21 <= code <= 0xFF3A or 0xFF41 <= code <= 0xFF5A:
            out.append(chr(code - 0xFEE0))
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True, slots=True)
class RegexRule:
    rule_id: str
    entity_type: EntityType
    pattern: re.Pattern[str]
    base_confidence: float
    #: Optional validator. Returning True raises confidence to ``validated_confidence``;
    #: returning False leaves the finding in place at ``base_confidence``.
    validator: Callable[[str], bool] | None = None
    validated_confidence: float = 0.99
    #: A validator that rejects rather than merely down-weights. Used only where a
    #: failed check means "this is definitely not that identifier".
    hard_filter: Callable[[str], bool] | None = None
    #: Characters stripped from the left of a match, with the offset advanced to
    #: match. Chinese prose runs words together, so a pattern anchored on a road
    #: suffix picks up the preposition in front of it ("在苏州…", "家住北京…").
    #: Over-capture is safe but destroys the surrounding label the downstream
    #: model reads, so the particles come off.
    trim_leading: str = ""
    evidence: str = "pattern"


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


_CN_PROVINCE = "京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新"
_PLATE_LETTER = "A-HJ-NP-Z"
_CJK = "一-龥"
#: Prepositions and framing words that Chinese prose glues to the front of an
#: address. Trimmed from the left of an address match.
_ADDRESS_LEAD = "住址地为是从往赴到于在家公司的了"

RULES: tuple[RegexRule, ...] = (
    RegexRule(
        rule_id="cn_id_card_18",
        entity_type=EntityType.ID_CARD,
        pattern=_c(rf"(?<!\d)\d{{6}}{_SEP}\d{{8}}{_SEP}\d{{3}}[\dXx](?!\d)"),
        base_confidence=0.80,
        validator=cn_id_checksum_ok,
        hard_filter=cn_id_date_plausible,
        evidence="structure+date",
    ),
    RegexRule(
        rule_id="cn_id_card_15",
        entity_type=EntityType.ID_CARD,
        # The pre-2000 format. No check digit exists, so the embedded birth date
        # is the only structural evidence — but archived claim files are full of
        # them and a missed one is a disclosed identity.
        pattern=_c(r"(?<!\d)[1-9]\d{5}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?!\d)"),
        base_confidence=0.70,
        evidence="structure+date",
    ),
    RegexRule(
        rule_id="cn_travel_document",
        entity_type=EntityType.ID_CARD,
        # 护照 E/G, 公务护照 D/S/P, 港澳通行证 C/W, 台胞证 H/M.
        pattern=_c(r"(?<![A-Za-z0-9])(?:[EG]\d{8}|[DSP]\d{7}|[CW]\d{8}|[HM]\d{8,10})(?![A-Za-z0-9])"),
        base_confidence=0.60,
        evidence="structure",
    ),
    RegexRule(
        rule_id="cn_uscc",
        entity_type=EntityType.ORG_ID,
        pattern=_c(r"(?<![A-Za-z0-9])[0-9A-HJ-NPQRTUWXY]{18}(?![A-Za-z0-9])"),
        base_confidence=0.55,
        validator=uscc_checksum_ok,
        evidence="structure+check_character",
    ),
    RegexRule(
        rule_id="cn_landline",
        entity_type=EntityType.PHONE,
        # An explicit separator is required. Without it the pattern matches any
        # eleven-digit run beginning with zero, and claim documents are full of
        # amounts, timestamps and policy numbers that would then be redacted.
        pattern=_c(r"(?<![\d-])(?:0\d{2,3}[-\s]\d{7,8}|\(0\d{2,3}\)\s?\d{7,8})(?![\d-])"),
        base_confidence=0.65,
        evidence="structure+separator",
    ),
    RegexRule(
        rule_id="cn_detailed_address",
        entity_type=EntityType.ADDRESS_DETAILED,
        # Anchored on a road/lane suffix followed by a number. A bare
        # province or city is not detailed enough to identify anyone and is
        # deliberately not matched.
        pattern=_c(
            rf"(?:[{_CJK}]{{2,8}}(?:省|自治区))?(?:[{_CJK}]{{2,8}}(?:市|区|县|旗))*"
            rf"[{_CJK}A-Za-z0-9]{{2,20}}(?:路|街|大道|巷|弄|村|镇)"
            rf"[{_CJK}A-Za-z0-9]{{0,12}}(?:号|弄|栋|幢|单元|室|层)"
        ),
        base_confidence=0.80,
        trim_leading=_ADDRESS_LEAD,
        evidence="administrative_structure",
    ),
    RegexRule(
        rule_id="cn_phone_mobile",
        entity_type=EntityType.PHONE,
        pattern=_c(rf"(?<!\d)(?:\+?86{_SEP})?1[3-9]\d{{1}}{_SEP}\d{{4}}{_SEP}\d{{4}}(?!\d)"),
        base_confidence=0.85,
        evidence="structure",
    ),
    RegexRule(
        rule_id="e164_phone",
        entity_type=EntityType.PHONE,
        pattern=_c(r"(?<![\d+])\+\d{1,3}[ \-]?\d{6,12}(?!\d)"),
        base_confidence=0.70,
        evidence="structure",
    ),
    RegexRule(
        rule_id="bank_card_luhn",
        entity_type=EntityType.BANK_CARD,
        pattern=_c(rf"(?<!\d)\d{{4}}{_SEP}\d{{4}}{_SEP}\d{{4}}{_SEP}\d{{1,7}}(?!\d)"),
        base_confidence=0.55,
        validator=luhn_ok,
        evidence="structure+luhn",
    ),
    RegexRule(
        rule_id="email_address",
        entity_type=EntityType.EMAIL,
        # Conservative syntax (guide §10.2): no quoted local parts, no IP literals.
        pattern=_c(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"),
        base_confidence=0.92,
        evidence="syntax",
    ),
    RegexRule(
        rule_id="cn_vehicle_plate",
        entity_type=EntityType.VEHICLE_PLATE,
        pattern=_c(
            rf"(?<![A-Z0-9])[{_CN_PROVINCE}][{_PLATE_LETTER}][ ·\-]?"
            rf"[{_PLATE_LETTER}0-9]{{4,5}}[{_PLATE_LETTER}0-9挂学警港澳](?![A-Z0-9])"
        ),
        base_confidence=0.85,
        evidence="jurisdiction_pattern",
    ),
)


class RegexDetector:
    """Runs every rule over the normalized text of one item."""

    name = "regex_detector"

    def __init__(self, rules: tuple[RegexRule, ...] = RULES) -> None:
        self._rules = rules

    def detect(self, item: ContentItem, parsed: ParsedItem) -> list[Finding]:
        text = parsed.normalized_text
        if not text:
            return []
        folded = _fold(text)
        findings: list[Finding] = []
        for rule in self._rules:
            for match in rule.pattern.finditer(folded):
                start, end = match.start(), match.end()
                if rule.trim_leading:
                    while start < end and folded[start] in rule.trim_leading:
                        start += 1
                    if start >= end:
                        continue
                # Report the ORIGINAL substring: the folded copy is a matching aid,
                # and the tokenizer must replace exactly what the document contains.
                raw = text[start:end]
                candidate = folded[start:end]
                if rule.hard_filter is not None and not rule.hard_filter(candidate):
                    continue
                confidence = rule.base_confidence
                source = FindingSource.REGEX
                if rule.validator is not None and rule.validator(candidate):
                    confidence = rule.validated_confidence
                    source = FindingSource.CHECKSUM
                findings.append(
                    Finding(
                        item_id=item.item_id,
                        entity_type=rule.entity_type,
                        source=source,
                        start=start,
                        end=end,
                        confidence=confidence,
                        rule_id=rule.rule_id,
                        raw_text=raw,
                        metadata={"evidence": rule.evidence},
                    )
                )
        return findings
