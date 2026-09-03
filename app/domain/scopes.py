"""Scope records and their lifetime rules (guide §5.3, §13.2).

The gateway owns ``scope_id``; the business system stores and replays it. Two
properties matter for safety:

* ``privacy_mode`` is one-way. Once a scope tokenizes anything it becomes
  ``SANITIZED_LOCKED`` for the rest of its life, because a later "clean" turn in
  the same conversation would otherwise ship the original of something an earlier
  turn deliberately tokenized.
* Expiry is evaluated at read time as well as by the sweeper. A row that says
  ACTIVE but is past its deadline is treated as expired, so a stalled cleanup job
  can never extend a scope's reach.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import PrivacyMode, ScopeStatus
from app.core.errors import ScopeLimitExceeded

SCOPE_ID_PREFIX = "scp_"


def new_scope_id() -> str:
    return SCOPE_ID_PREFIX + secrets.token_hex(16)


def new_request_id() -> str:
    return "req_" + secrets.token_hex(12)


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScopeLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_turns: int = 50
    max_files: int = 20
    max_bytes: int = 209_715_200
    max_pages: int = 200
    max_mappings: int = 5000


class ScopeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    scope_id: str
    status: ScopeStatus = ScopeStatus.ACTIVE
    privacy_mode: PrivacyMode = PrivacyMode.CLEAN
    policy_version: str
    client_conversation_id: str | None = None
    turn_count: int = 0
    file_count: int = 0
    cumulative_bytes: int = 0
    cumulative_pages: int = 0
    mapping_count: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    last_active_at: datetime = Field(default_factory=utcnow)
    idle_expires_at: datetime
    absolute_expires_at: datetime

    @classmethod
    def create(
        cls,
        *,
        tenant_id: str,
        policy_version: str,
        idle_ttl_seconds: int,
        absolute_ttl_seconds: int,
        client_conversation_id: str | None = None,
    ) -> "ScopeRecord":
        now = utcnow()
        return cls(
            tenant_id=tenant_id,
            scope_id=new_scope_id(),
            policy_version=policy_version,
            client_conversation_id=client_conversation_id,
            created_at=now,
            last_active_at=now,
            idle_expires_at=now + timedelta(seconds=idle_ttl_seconds),
            absolute_expires_at=now + timedelta(seconds=absolute_ttl_seconds),
        )

    # ---- lifetime --------------------------------------------------------

    def is_expired(self, at: datetime | None = None) -> bool:
        now = at or utcnow()
        return now >= self.idle_expires_at or now >= self.absolute_expires_at

    def is_usable(self, at: datetime | None = None) -> bool:
        return self.status is ScopeStatus.ACTIVE and not self.is_expired(at)

    def touch(self, idle_ttl_seconds: int, at: datetime | None = None) -> None:
        """Extend the idle window only. The absolute deadline never moves —
        that is the point of having two."""
        now = at or utcnow()
        self.last_active_at = now
        self.idle_expires_at = min(
            now + timedelta(seconds=idle_ttl_seconds), self.absolute_expires_at
        )

    def lock_sanitized(self) -> None:
        self.privacy_mode = PrivacyMode.SANITIZED_LOCKED

    @property
    def fast_path_allowed(self) -> bool:
        return self.privacy_mode is PrivacyMode.CLEAN

    # ---- limits ----------------------------------------------------------

    def check_admission(
        self,
        limits: ScopeLimits,
        *,
        added_files: int,
        added_bytes: int,
        added_pages: int = 0,
    ) -> None:
        """Enforce scope capacity *before* any unsafe forwarding (guide §19.3.15)."""
        checks: tuple[tuple[str, int, int], ...] = (
            ("turns", self.turn_count + 1, limits.max_turns),
            ("files", self.file_count + added_files, limits.max_files),
            ("bytes", self.cumulative_bytes + added_bytes, limits.max_bytes),
            ("pages", self.cumulative_pages + added_pages, limits.max_pages),
        )
        for name, projected, allowed in checks:
            if projected > allowed:
                raise ScopeLimitExceeded(
                    f"scope {name} limit exceeded ({projected} > {allowed})",
                    public_detail=f"scope {name} limit exceeded",
                    meta={"limit": name},
                )

    def check_mapping_capacity(self, limits: ScopeLimits, added: int) -> None:
        if self.mapping_count + added > limits.max_mappings:
            raise ScopeLimitExceeded(
                "scope mapping limit exceeded",
                public_detail="scope mapping limit exceeded",
                meta={"limit": "mappings"},
            )

    def record_turn(self, *, files: int, byte_count: int, pages: int) -> None:
        self.turn_count += 1
        self.file_count += files
        self.cumulative_bytes += byte_count
        self.cumulative_pages += pages

    def public_view(self) -> dict[str, object]:
        return {
            "scope_id": self.scope_id,
            "status": self.status.value.lower(),
            "privacy_mode": self.privacy_mode.value.lower(),
            "idle_expires_at": self.idle_expires_at.isoformat(),
            "absolute_expires_at": self.absolute_expires_at.isoformat(),
        }
