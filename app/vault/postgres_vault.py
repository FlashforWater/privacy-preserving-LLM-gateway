"""PostgreSQL vault.

Guide §13.2: uniqueness on ``(tenant_id, scope_id, token)`` and on
``(tenant_id, scope_id, entity_type, canonical_value_hmac)``; counter updates,
inserts and the ``SANITIZED_LOCKED`` transition in a single transaction that
commits *before* the external call.

Values are encrypted by the gateway before insertion, so the database and its
backups contain ciphertext only (§22.1).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.enums import EntityType
from app.core.errors import VaultError

from .base import PendingMapping
from .crypto import VaultCipher, build_aad

_FIND_BY_DIGEST = text(
    """
    SELECT token
      FROM token_mappings
     WHERE tenant_id = :tenant_id
       AND scope_id = :scope_id
       AND entity_type = :entity_type
       AND canonical_value_hmac = :digest
       AND expires_at > now()
     LIMIT 1
    """
)

_INSERT_MAPPING = text(
    """
    INSERT INTO token_mappings (
        tenant_id, scope_id, created_by_request_id, token, entity_type,
        encrypted_original, canonical_value_hmac, policy_version, created_at, expires_at
    ) VALUES (
        :tenant_id, :scope_id, :request_id, :token, :entity_type,
        :encrypted_original, :digest, :policy_version, :created_at, :expires_at
    )
    ON CONFLICT (tenant_id, scope_id, entity_type, canonical_value_hmac) DO NOTHING
    """
)

_LOCK_SCOPE = text(
    """
    UPDATE scopes
       SET privacy_mode = 'SANITIZED_LOCKED',
           mapping_count = mapping_count + :written,
           last_active_at = now()
     WHERE tenant_id = :tenant_id AND scope_id = :scope_id
    RETURNING mapping_count
    """
)

_RESOLVE = text(
    """
    SELECT m.encrypted_original, m.entity_type, m.policy_version
      FROM token_mappings m
      JOIN scopes s ON s.tenant_id = m.tenant_id AND s.scope_id = m.scope_id
     WHERE m.tenant_id = :tenant_id
       AND m.scope_id = :scope_id
       AND m.token = :token
       AND m.expires_at > now()
       AND s.status = 'ACTIVE'
       AND s.idle_expires_at > now()
       AND s.absolute_expires_at > now()
     LIMIT 1
    """
)

_DELETE_SCOPE = text(
    "DELETE FROM token_mappings WHERE tenant_id = :tenant_id AND scope_id = :scope_id"
)

_PURGE = text("DELETE FROM token_mappings WHERE expires_at <= now()")


class PostgresVault:
    def __init__(self, engine: AsyncEngine, cipher: VaultCipher) -> None:
        self._engine = engine
        self._cipher = cipher

    async def find_token_by_digest(
        self, *, tenant_id: str, scope_id: str, entity_type: EntityType, digest: str
    ) -> str | None:
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(
                    _FIND_BY_DIGEST,
                    {
                        "tenant_id": tenant_id,
                        "scope_id": scope_id,
                        "entity_type": entity_type.value,
                        "digest": digest,
                    },
                )
            ).first()
        return None if row is None else str(row[0])

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
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        try:
            async with self._engine.begin() as connection:
                written = 0
                for pending in mappings:
                    aad = build_aad(
                        tenant_id=tenant_id, scope_id=scope_id, token=pending.token,
                        entity_type=pending.entity_type.value, policy_version=policy_version,
                    )
                    result = await connection.execute(
                        _INSERT_MAPPING,
                        {
                            "tenant_id": tenant_id,
                            "scope_id": scope_id,
                            "request_id": request_id,
                            "token": pending.token,
                            "entity_type": pending.entity_type.value,
                            "encrypted_original": self._cipher.encrypt(
                                pending.original_value, aad=aad
                            ),
                            "digest": pending.canonical_value_hmac,
                            "policy_version": policy_version,
                            "created_at": now,
                            "expires_at": expires_at,
                        },
                    )
                    written += result.rowcount or 0

                locked = (
                    await connection.execute(
                        _LOCK_SCOPE,
                        {"tenant_id": tenant_id, "scope_id": scope_id, "written": written},
                    )
                ).first()
                if locked is None:
                    raise VaultError(
                        "scope row disappeared during tokenization",
                        public_detail="request could not be completed safely",
                    )
                return written
        except VaultError:
            raise
        except Exception as exc:  # noqa: BLE001 - any vault failure blocks the call
            raise VaultError(
                f"vault write failed: {type(exc).__name__}",
                public_detail="request could not be completed safely",
            ) from exc

    async def resolve(
        self, *, tenant_id: str, scope_id: str, token: str, at: datetime | None = None
    ) -> str | None:
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(
                    _RESOLVE,
                    {"tenant_id": tenant_id, "scope_id": scope_id, "token": token},
                )
            ).first()
        if row is None:
            return None
        encrypted, entity_type, policy_version = row
        aad = build_aad(
            tenant_id=tenant_id, scope_id=scope_id, token=token,
            entity_type=str(entity_type), policy_version=str(policy_version),
        )
        return self._cipher.decrypt(bytes(encrypted), aad=aad)

    async def delete_scope(self, *, tenant_id: str, scope_id: str) -> int:
        async with self._engine.begin() as connection:
            result = await connection.execute(
                _DELETE_SCOPE, {"tenant_id": tenant_id, "scope_id": scope_id}
            )
        return result.rowcount or 0

    async def purge_expired(self, *, now: datetime | None = None) -> int:
        async with self._engine.begin() as connection:
            result = await connection.execute(_PURGE)
        return result.rowcount or 0
