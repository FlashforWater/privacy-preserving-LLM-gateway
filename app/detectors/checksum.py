"""Checksum validators.

These turn "a string that looks like an identifier" into "a validated
identifier". They exist as standalone, individually tested units (guide §10.2)
rather than being folded into the regexes, because they are also the strongest
evidence class in overlap resolution (§10.4).

Note the asymmetry: a passing checksum *raises* confidence, but a failing one
does not veto the finding. A mistyped national ID is still that person's ID, and
the recall cost of vetoing far outweighs the precision gain.
"""

from __future__ import annotations

# GB 11643-1999 weights and check characters for the 18-digit PRC national ID.
_CN_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_ID_CHECK = "10X98765432"


def luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def cn_id_checksum_ok(value: str) -> bool:
    compact = "".join(c for c in value if not c.isspace() and c not in "-_")
    if len(compact) != 18 or not compact[:17].isdigit():
        return False
    total = sum(int(c) * w for c, w in zip(compact[:17], _CN_ID_WEIGHTS, strict=True))
    return compact[17].upper() == _CN_ID_CHECK[total % 11]


# 统一社会信用代码 (GB 32100-2015). The alphabet excludes I, O, S, V and Z so
# that no character can be confused with a digit.
_USCC_ALPHABET = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)


def uscc_checksum_ok(value: str) -> bool:
    """Unified Social Credit Identifier check character.

    An 18-character identifier for a legal entity. It appears throughout claims
    paperwork (投保单位, 维修厂, 医疗机构) and identifies the organisation
    unambiguously, which for a 个体工商户 means it identifies a person.
    """
    text = value.strip().upper()
    if len(text) != 18 or any(c not in _USCC_ALPHABET for c in text):
        return False
    total = sum(
        _USCC_ALPHABET.index(c) * w
        for c, w in zip(text[:17], _USCC_WEIGHTS, strict=True)
    )
    remainder = 31 - total % 31
    expected = _USCC_ALPHABET[0 if remainder == 31 else remainder]
    return text[17] == expected


def cn_id_date_plausible(value: str) -> bool:
    """Cheap sanity check on the embedded birth date.

    Rejects the large class of 18-digit numbers that are merely serial numbers,
    which keeps the false-positive rate down without touching recall on real IDs.
    """
    compact = "".join(c for c in value if c.isdigit() or c.upper() == "X")
    if len(compact) < 14:
        return False
    year, month, day = compact[6:10], compact[10:12], compact[12:14]
    if not (year.isdigit() and month.isdigit() and day.isdigit()):
        return False
    return 1900 <= int(year) <= 2100 and 1 <= int(month) <= 12 and 1 <= int(day) <= 31
