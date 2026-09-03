"""Scope lifecycle service.

Holds the rules that ``/v1/scopes`` and the message route both need, so neither
route re-implements expiry or limit checking:

* the gateway generates ``scope_id`` — a client-supplied id is stored only as a
  correlation label (guide §5.3);
* expiry is evaluated on read, not only by the sweeper;
* closing is idempotent and deletes the scope's mappings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.core.enums import PrivacyMode, ScopeStatus
from app.core.errors import ScopeClosed, ScopeNotFound
from app.domain.scopes import ScopeLimits, ScopeRecord, utcnow
from app.vault.base import Vault


class ScopeStore(Protocol):
    async def get(self, *, tenant_id: str, scope_id: str) -> ScopeRecord | None: ...
    async def put(self, record: ScopeRecord) -> None: ...
    async def delete(self, *, tenant_id: str, scope_id: str) -> None: ...
    async def expire_due(self, *, now: datetime) -> int: ...


class InMemoryScopeStore:
    """Test/dev store. Production uses the Postgres-backed store."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ScopeRecord] = {}
        # Live view keyed by scope_id, shared with MemoryVault so the vault can
        # check scope status at read time. It is deliberately the *same* dict
        # object, not a copy: a snapshot taken at wiring time would never see a
        # scope created afterwards, and every mapping would resolve against an
        # empty store.
        self._by_scope_id: dict[str, ScopeRecord] = {}

    async def get(self, *, tenant_id: str, scope_id: str) -> ScopeRecord | None:
        return self._records.get((tenant_id, scope_id))

    async def put(self, record: ScopeRecord) -> None:
        self._records[(record.tenant_id, record.scope_id)] = record
        self._by_scope_id[record.scope_id] = record

    async def delete(self, *, tenant_id: str, scope_id: str) -> None:
        self._records.pop((tenant_id, scope_id), None)
        self._by_scope_id.pop(scope_id, None)

    async def expire_due(self, *, now: datetime) -> int:
        expired = 0
        for record in self._records.values():
            if record.status is ScopeStatus.ACTIVE and record.is_expired(now):
                record.status = ScopeStatus.EXPIRED
                expired += 1
        return expired

    def live_scopes(self) -> dict[str, ScopeRecord]:
        """The shared, mutable scope view handed to :class:`MemoryVault`."""
        return self._by_scope_id


class ScopeService:
    def __init__(
        self,
        store: ScopeStore,
        vault: Vault,
        *,
        limits: ScopeLimits,
        idle_ttl_seconds: int,
        absolute_ttl_seconds: int,
        policy_version: str,
    ) -> None:
        self._store = store
        self._vault = vault
        self._limits = limits
        self._idle_ttl = idle_ttl_seconds
        self._absolute_ttl = absolute_ttl_seconds
        self._policy_version = policy_version

    @property
    def limits(self) -> ScopeLimits:
        return self._limits

    async def create(
        self, *, tenant_id: str, client_conversation_id: str | None = None
    ) -> ScopeRecord:
        record = ScopeRecord.create(
            tenant_id=tenant_id,
            # Pinned for the scope's lifetime: every turn of one conversation is
            # evaluated under the same policy (guide §9.3.3).
            policy_version=self._policy_version,
            idle_ttl_seconds=self._idle_ttl,
            absolute_ttl_seconds=self._absolute_ttl,
            client_conversation_id=client_conversation_id,
        )
        await self._store.put(record)
        return record

    async def require_active(self, *, tenant_id: str, scope_id: str) -> ScopeRecord:
        record = await self._store.get(tenant_id=tenant_id, scope_id=scope_id)
        if record is None:
            # Same error whether the scope belongs to another tenant or does not
            # exist: a distinguishable response would leak scope existence.
            raise ScopeNotFound("scope not found", public_detail="scope not found")
        now = utcnow()
        if record.status is not ScopeStatus.ACTIVE:
            raise ScopeClosed("scope is closed", public_detail="scope is closed or expired")
        if record.is_expired(now):
            record.status = ScopeStatus.EXPIRED
            await self._store.put(record)
            await self._vault.delete_scope(tenant_id=tenant_id, scope_id=scope_id)
            raise ScopeClosed("scope expired", public_detail="scope is closed or expired")
        return record

    async def admit_turn(
        self, record: ScopeRecord, *, files: int, byte_count: int, pages: int = 0
    ) -> None:
        record.check_admission(
            self._limits, added_files=files, added_bytes=byte_count, added_pages=pages
        )

    async def complete_turn(
        self, record: ScopeRecord, *, files: int, byte_count: int, pages: int
    ) -> None:
        record.record_turn(files=files, byte_count=byte_count, pages=pages)
        record.touch(self._idle_ttl)
        await self._store.put(record)

    async def close(self, *, tenant_id: str, scope_id: str) -> ScopeRecord | None:
        record = await self._store.get(tenant_id=tenant_id, scope_id=scope_id)
        if record is None:
            return None  # idempotent
        record.status = ScopeStatus.CLOSED
        await self._store.put(record)
        # Mappings become unavailable immediately; deletion is not deferred to
        # the TTL sweeper (guide §5.3).
        await self._vault.delete_scope(tenant_id=tenant_id, scope_id=scope_id)
        return record

    async def mark_sanitized(self, record: ScopeRecord) -> None:
        record.privacy_mode = PrivacyMode.SANITIZED_LOCKED
        await self._store.put(record)
