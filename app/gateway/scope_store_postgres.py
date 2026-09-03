"""PostgreSQL-backed scope store.

Kept separate from the vault so the two can be reviewed independently: this file
holds no encrypted material and never touches original values. It stores scope
state, counters and the privacy mode.

``UPDATE ... WHERE`` clauses always carry ``tenant_id``. Tenant isolation is
enforced by every query, not by the caller remembering to filter.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.enums import PrivacyMode, ScopeStatus
from app.domain.scopes import ScopeRecord

_SELECT = text(
    """
    SELECT tenant_id, scope_id, status, privacy_mode, policy_version,
           client_conversation_id, turn_count, file_count, cumulative_bytes,
           cumulative_pages, mapping_count, created_at, last_active_at,
           idle_expires_at, absolute_expires_at
      FROM scopes
     WHERE tenant_id = :tenant_id AND scope_id = :scope_id
    """
)

_UPSERT = text(
    """
    INSERT INTO scopes (
        tenant_id, scope_id, status, privacy_mode, policy_version,
        client_conversation_id, turn_count, file_count, cumulative_bytes,
        cumulative_pages, mapping_count, created_at, last_active_at,
        idle_expires_at, absolute_expires_at
    ) VALUES (
        :tenant_id, :scope_id, :status, :privacy_mode, :policy_version,
        :client_conversation_id, :turn_count, :file_count, :cumulative_bytes,
        :cumulative_pages, :mapping_count, :created_at, :last_active_at,
        :idle_expires_at, :absolute_expires_at
    )
    ON CONFLICT (tenant_id, scope_id) DO UPDATE SET
        status = EXCLUDED.status,
        privacy_mode = EXCLUDED.privacy_mode,
        turn_count = EXCLUDED.turn_count,
        file_count = EXCLUDED.file_count,
        cumulative_bytes = EXCLUDED.cumulative_bytes,
        cumulative_pages = EXCLUDED.cumulative_pages,
        mapping_count = EXCLUDED.mapping_count,
        last_active_at = EXCLUDED.last_active_at,
        idle_expires_at = EXCLUDED.idle_expires_at
    """
)

_DELETE = text("DELETE FROM scopes WHERE tenant_id = :tenant_id AND scope_id = :scope_id")

_EXPIRE_DUE = text(
    """
    UPDATE scopes
       SET status = 'EXPIRED'
     WHERE status = 'ACTIVE'
       AND (idle_expires_at <= :now OR absolute_expires_at <= :now)
    """
)


class PostgresScopeStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def get(self, *, tenant_id: str, scope_id: str) -> ScopeRecord | None:
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(
                    _SELECT, {"tenant_id": tenant_id, "scope_id": scope_id}
                )
            ).mappings().first()
        if row is None:
            return None
        return ScopeRecord(
            tenant_id=row["tenant_id"],
            scope_id=row["scope_id"],
            status=ScopeStatus(row["status"]),
            privacy_mode=PrivacyMode(row["privacy_mode"]),
            policy_version=row["policy_version"],
            client_conversation_id=row["client_conversation_id"],
            turn_count=row["turn_count"],
            file_count=row["file_count"],
            cumulative_bytes=row["cumulative_bytes"],
            cumulative_pages=row["cumulative_pages"],
            mapping_count=row["mapping_count"],
            created_at=row["created_at"],
            last_active_at=row["last_active_at"],
            idle_expires_at=row["idle_expires_at"],
            absolute_expires_at=row["absolute_expires_at"],
        )

    async def put(self, record: ScopeRecord) -> None:
        async with self._engine.begin() as connection:
            await connection.execute(
                _UPSERT,
                {
                    "tenant_id": record.tenant_id,
                    "scope_id": record.scope_id,
                    "status": record.status.value,
                    "privacy_mode": record.privacy_mode.value,
                    "policy_version": record.policy_version,
                    "client_conversation_id": record.client_conversation_id,
                    "turn_count": record.turn_count,
                    "file_count": record.file_count,
                    "cumulative_bytes": record.cumulative_bytes,
                    "cumulative_pages": record.cumulative_pages,
                    "mapping_count": record.mapping_count,
                    "created_at": record.created_at,
                    "last_active_at": record.last_active_at,
                    "idle_expires_at": record.idle_expires_at,
                    "absolute_expires_at": record.absolute_expires_at,
                },
            )

    async def delete(self, *, tenant_id: str, scope_id: str) -> None:
        async with self._engine.begin() as connection:
            await connection.execute(_DELETE, {"tenant_id": tenant_id, "scope_id": scope_id})

    async def expire_due(self, *, now: datetime) -> int:
        async with self._engine.begin() as connection:
            result = await connection.execute(_EXPIRE_DUE, {"now": now})
        return result.rowcount or 0
