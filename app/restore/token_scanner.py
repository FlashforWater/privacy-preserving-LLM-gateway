"""Token scanning over provider text.

Scans for the exact gateway token grammar and nothing else. An external model can
emit any string it likes; the only ones that mean anything here are the ones this
gateway minted, and the grammar is strict enough that near-misses (wrong version
prefix, wrong suffix length, wrong alphabet) simply do not match.

Substitution counts are bounded so that a response consisting of one token
repeated a million times cannot turn restoration into an amplification attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.sanitization.tokenizer import TOKEN_RE

MAX_SUBSTITUTIONS = 5000
MAX_OUTPUT_CHARS = 500_000


@dataclass(frozen=True, slots=True)
class TokenOccurrence:
    token: str
    start: int
    end: int


def scan(text: str) -> list[TokenOccurrence]:
    return [
        TokenOccurrence(token=match.group(0), start=match.start(), end=match.end())
        for match in TOKEN_RE.finditer(text)
    ]


def unique_tokens(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for occurrence in scan(text):
        seen.setdefault(occurrence.token, None)
    return list(seen)
