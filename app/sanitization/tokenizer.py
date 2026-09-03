"""Scope-scoped tokenization (guide §13.1).

Token shape::

    [[PGW_V1_PERSON_K7M4Q2Z9F8N3]]

Properties that matter:

* **High entropy, cryptographically random suffix.** The suffix carries no part
  of the original value — not a hash of it, not a prefix, nothing. A token is a
  pure lookup key.
* **Coarse entity type only.** ``PERSON`` tells the external model that two
  different tokens are two different people, which is what makes the reply
  useful. It does not narrow down who they are.
* **Unique per tenant and scope**, and meaningless outside them.
* **Consistent within a scope**: the same deterministically canonicalized value
  maps to the same token across turns, so the model can reason about "the same
  person" without ever seeing a name.

Canonicalization is *deterministic only* (guide §10.5). ``Zhang San``,
``Mr. Zhang``, ``the patient`` and ``the driver`` stay separate. Merging two
people by accident is far more dangerous than issuing two tokens for one person,
so no alias or coreference inference happens here.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import unicodedata
from dataclasses import dataclass

from app.core.enums import EntityType

TOKEN_PREFIX = "PGW_V1"
_SUFFIX_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 look-alikes
_SUFFIX_LENGTH = 12

#: The exact grammar the restorer accepts. Deliberately strict: a token the
#: gateway did not mint must not match, whatever the external model invents.
TOKEN_RE = re.compile(
    rf"\[\[{TOKEN_PREFIX}_(?P<entity>[A-Z_]{{1,32}})_(?P<suffix>[{_SUFFIX_ALPHABET}]{{{_SUFFIX_LENGTH}}})\]\]"
)

#: Anything token-shaped in *user* content is neutralised before sanitization so
#: a caller cannot smuggle a look-alike that the restorer might later expand.
TOKEN_LIKE_RE = re.compile(r"\[\[\s*PGW[_A-Za-z0-9]*\s*\]\]|\[\[[A-Z_]+_[A-Z0-9]{8,}\]\]")


def new_token(entity_type: EntityType) -> str:
    suffix = "".join(secrets.choice(_SUFFIX_ALPHABET) for _ in range(_SUFFIX_LENGTH))
    return f"[[{TOKEN_PREFIX}_{entity_type.value}_{suffix}]]"


def is_token(value: str) -> bool:
    return bool(TOKEN_RE.fullmatch(value))


def find_tokens(text: str) -> list[str]:
    return [match.group(0) for match in TOKEN_RE.finditer(text)]


def escape_token_like(text: str) -> tuple[str, int]:
    """Neutralise token-shaped strings supplied by the caller.

    **The rewrite is length-preserving**: only the outer delimiters change, so
    ``[[PGW_V1_PERSON_ABCDEFGHJKLM]]`` becomes
    ``((PGW_V1_PERSON_ABCDEFGHJKLM))``. That matters more than it looks. Detector
    spans are computed against the pre-escape text; an escape that changed the
    string length would shift every offset after it, and the sanitizer would then
    either rewrite the wrong range or drop the edit — and a dropped edit is an
    identifier left in the outbound payload.

    Returns the text and how many strings were neutralised, so the count can be
    surfaced as a security metric: a spike means someone is probing the grammar.
    """
    count = 0

    def _replace(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        inner = match.group(0)[2:-2]
        return f"(({inner}))"

    escaped = TOKEN_LIKE_RE.sub(_replace, text)
    assert len(escaped) == len(text), "token escaping must preserve length"
    return escaped, count


def canonicalize(value: str, entity_type: EntityType) -> str:
    """Deterministic canonical form used for same-scope token reuse.

    Rules are fixed per entity type and documented here because they define what
    "the same value" means:

    * Unicode NFKC and surrounding whitespace are normalised for everything.
    * Phone and card numbers drop separators, since ``138-1234-5678`` and
      ``13812345678`` are unambiguously the same number.
    * Emails are lower-cased.
    * Names and addresses are **not** aggressively folded: internal spacing is
      collapsed, but nothing else. Two spellings stay two values.
    """
    text = unicodedata.normalize("NFKC", value).strip()
    if entity_type in (EntityType.PHONE, EntityType.BANK_CARD, EntityType.ID_CARD):
        compact = re.sub(r"[\s\-‐-―().]", "", text)
        return compact.upper()
    if entity_type is EntityType.EMAIL:
        return text.lower()
    if entity_type is EntityType.VEHICLE_PLATE:
        return re.sub(r"[\s·\-]", "", text).upper()
    return re.sub(r"\s+", " ", text)


def canonical_hmac(
    canonical_value: str, entity_type: EntityType, *, tenant_id: str, scope_id: str, key: bytes
) -> str:
    """Keyed lookup digest for same-scope deduplication (guide §13.2).

    Keyed rather than a plain hash: an unsalted SHA-256 of a phone number is
    reversible by enumeration in seconds, which would make the mappings table a
    lookup service for anyone who could read it. Scoping the digest to tenant and
    scope additionally prevents cross-scope correlation of identical values.
    """
    message = "\x1f".join((tenant_id, scope_id, entity_type.value, canonical_value))
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """A value that needs a token, resolved against the vault by the caller."""

    entity_type: EntityType
    original_value: str
    canonical_value: str
    lookup_hmac: str


def build_token_request(
    value: str, entity_type: EntityType, *, tenant_id: str, scope_id: str, key: bytes
) -> TokenRequest:
    canonical = canonicalize(value, entity_type)
    return TokenRequest(
        entity_type=entity_type,
        original_value=value,
        canonical_value=canonical,
        lookup_hmac=canonical_hmac(
            canonical, entity_type, tenant_id=tenant_id, scope_id=scope_id, key=key
        ),
    )
