"""Vault protocol and record types.

The vault is the only component that holds original values. Its API is
deliberately narrow (guide §13.3): fetch by exact token, or reuse by keyed
digest. There is no list, no search-by-plaintext, and no way for a caller — or an
external model — to enumerate a scope's mappings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from app.core.enums import EntityType


@dataclass(frozen=True, slots=True)
class TokenMapping:
    tenant_id: str
    scope_id: str
    created_by_request_id: str
    token: str
    entity_type: EntityType
    encrypted_original: bytes
    canonical_value_hmac: str
    policy_version: str
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PendingMapping:
    """A mapping the sanitizer wants to persist before the external call."""

    token: str
    entity_type: EntityType
    original_value: str
    canonical_value_hmac: str


class Vault(Protocol):
    async def find_token_by_digest(
        self, *, tenant_id: str, scope_id: str, entity_type: EntityType, digest: str
    ) -> str | None:
        """Existing token for this canonical value in this scope, if any."""

    async def put_all_and_lock_scope(
        self,
        *,
        tenant_id: str,
        scope_id: str,
        request_id: str,
        policy_version: str,
        mappings: list[PendingMapping],
        ttl_seconds: int,
    ) -> int:
        """Persist mappings and flip the scope to SANITIZED_LOCKED atomically.

        Guide §13.2: counters, inserts and the privacy-mode change happen in one
        transaction *before* the external call, so a crash can never leave a
        request that was sent with tokens the vault does not know.
        """

    async def resolve(
        self, *, tenant_id: str, scope_id: str, token: str, at: datetime | None = None
    ) -> str | None:
        """Original value for an exact token, or ``None`` if unknown/expired."""

    async def delete_scope(self, *, tenant_id: str, scope_id: str) -> int: ...

    async def purge_expired(self, *, now: datetime | None = None) -> int: ...
