"""In-memory vault for tests and the docker ``dev`` profile.

Mirrors the Postgres implementation's semantics exactly — same uniqueness rules,
same TTL evaluation at read time, same atomic put-and-lock — so a test that
passes here is meaningful. It is never selected when ``APP_ENV`` is a production
environment; :func:`app.api.dependencies.build_vault` enforces that.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from app.core.enums import EntityType, PrivacyMode
from app.domain.scopes import ScopeRecord

from .base import PendingMapping, TokenMapping
from .crypto import VaultCipher, build_aad


class MemoryVault:
    def __init__(self, cipher: VaultCipher, scopes: dict[str, ScopeRecord]) -> None:
        self._cipher = cipher
        self._scopes = scopes
        self._by_token: dict[tuple[str, str, str], TokenMapping] = {}
        self._by_digest: dict[tuple[str, str, str, str], str] = {}
        self._lock = asyncio.Lock()

    async def find_token_by_digest(
        self, *, tenant_id: str, scope_id: str, entity_type: EntityType, digest: str
    ) -> str | None:
        return self._by_digest.get((tenant_id, scope_id, entity_type.value, digest))

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
        async with self._lock:
            now = datetime.now(UTC)
            expires_at = now + timedelta(seconds=ttl_seconds)
            written = 0
            for pending in mappings:
                key = (tenant_id, scope_id, pending.token)
                if key in self._by_token:
                    continue
                aad = build_aad(
                    tenant_id=tenant_id, scope_id=scope_id, token=pending.token,
                    entity_type=pending.entity_type.value, policy_version=policy_version,
                )
                self._by_token[key] = TokenMapping(
                    tenant_id=tenant_id,
                    scope_id=scope_id,
                    created_by_request_id=request_id,
                    token=pending.token,
                    entity_type=pending.entity_type,
                    encrypted_original=self._cipher.encrypt(pending.original_value, aad=aad),
                    canonical_value_hmac=pending.canonical_value_hmac,
                    policy_version=policy_version,
                    created_at=now,
                    expires_at=expires_at,
                )
                self._by_digest[
                    (tenant_id, scope_id, pending.entity_type.value, pending.canonical_value_hmac)
                ] = pending.token
                written += 1

            scope = self._scopes.get(scope_id)
            if scope is not None:
                scope.privacy_mode = PrivacyMode.SANITIZED_LOCKED
                scope.mapping_count += written
            return written

    async def resolve(
        self, *, tenant_id: str, scope_id: str, token: str, at: datetime | None = None
    ) -> str | None:
        mapping = self._by_token.get((tenant_id, scope_id, token))
        if mapping is None:
            return None
        now = at or datetime.now(UTC)
        if now >= mapping.expires_at:
            return None
        scope = self._scopes.get(scope_id)
        if scope is not None and not scope.is_usable(now):
            # A closed or expired scope cannot restore (guide §5.3).
            return None
        aad = build_aad(
            tenant_id=tenant_id, scope_id=scope_id, token=token,
            entity_type=mapping.entity_type.value, policy_version=mapping.policy_version,
        )
        return self._cipher.decrypt(mapping.encrypted_original, aad=aad)

    async def delete_scope(self, *, tenant_id: str, scope_id: str) -> int:
        removed = [key for key in self._by_token if key[0] == tenant_id and key[1] == scope_id]
        for key in removed:
            del self._by_token[key]
        for key in [k for k in self._by_digest if k[0] == tenant_id and k[1] == scope_id]:
            del self._by_digest[key]
        return len(removed)

    async def purge_expired(self, *, now: datetime | None = None) -> int:
        moment = now or datetime.now(UTC)
        expired = [key for key, m in self._by_token.items() if moment >= m.expires_at]
        for key in expired:
            del self._by_token[key]
        return len(expired)
