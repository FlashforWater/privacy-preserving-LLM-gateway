"""Scope lifecycle, limits and configuration gates (guide §19.1)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError, ScopeClosed, ScopeLimitExceeded, ScopeNotFound
from app.core.enums import PrivacyMode, ScopeStatus
from app.domain.scopes import ScopeLimits, ScopeRecord
from app.gateway.scope_service import InMemoryScopeStore, ScopeService
from app.vault.crypto import StaticKeyProvider, VaultCipher
from app.vault.memory_vault import MemoryVault

POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.default.yaml"
KEY_B64 = base64.b64encode(b"\x03" * 32).decode()


def make_service(**overrides: object) -> tuple[ScopeService, InMemoryScopeStore, MemoryVault]:
    store = InMemoryScopeStore()
    snapshot = store.live_scopes()
    vault = MemoryVault(
        VaultCipher(StaticKeyProvider(master=b"\x01" * 32, hmac=b"\x02" * 32)), snapshot
    )
    kwargs: dict[str, object] = {
        "limits": ScopeLimits(),
        "idle_ttl_seconds": 7200,
        "absolute_ttl_seconds": 86400,
        "policy_version": "v1",
    }
    kwargs.update(overrides)
    return ScopeService(store, vault, **kwargs), store, vault  # type: ignore[arg-type]


class TestScopeRecord:
    def test_gateway_generates_the_id(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=1, absolute_ttl_seconds=2,
        )
        assert record.scope_id.startswith("scp_")
        assert len(record.scope_id) > 20

    def test_ids_are_unique(self) -> None:
        ids = {
            ScopeRecord.create(
                tenant_id="t", policy_version="v1",
                idle_ttl_seconds=1, absolute_ttl_seconds=2,
            ).scope_id
            for _ in range(200)
        }
        assert len(ids) == 200

    def test_touch_extends_idle_but_not_absolute(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=60, absolute_ttl_seconds=120,
        )
        absolute_before = record.absolute_expires_at
        record.touch(60)
        assert record.absolute_expires_at == absolute_before

    def test_idle_window_never_exceeds_absolute(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=100000, absolute_ttl_seconds=60,
        )
        record.touch(100000)
        assert record.idle_expires_at <= record.absolute_expires_at

    def test_expiry_is_evaluated_on_read(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=7200, absolute_ttl_seconds=86400,
        )
        record.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        assert record.is_expired()
        assert not record.is_usable()

    def test_privacy_mode_is_one_way(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=1, absolute_ttl_seconds=2,
        )
        record.lock_sanitized()
        assert record.privacy_mode is PrivacyMode.SANITIZED_LOCKED
        assert not record.fast_path_allowed

    @pytest.mark.parametrize(
        ("kwargs", "limit"),
        [
            ({"added_files": 21, "added_bytes": 0}, "files"),
            ({"added_files": 0, "added_bytes": 10**12}, "bytes"),
            ({"added_files": 0, "added_bytes": 0, "added_pages": 500}, "pages"),
        ],
    )
    def test_admission_limits(self, kwargs: dict[str, int], limit: str) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=1, absolute_ttl_seconds=2,
        )
        with pytest.raises(ScopeLimitExceeded) as exc:
            record.check_admission(ScopeLimits(), **kwargs)
        assert exc.value.meta["limit"] == limit

    def test_turn_limit(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=1, absolute_ttl_seconds=2,
        )
        record.turn_count = 50
        with pytest.raises(ScopeLimitExceeded):
            record.check_admission(ScopeLimits(), added_files=0, added_bytes=0)

    def test_mapping_limit(self) -> None:
        record = ScopeRecord.create(
            tenant_id="t", policy_version="v1",
            idle_ttl_seconds=1, absolute_ttl_seconds=2,
        )
        record.mapping_count = 4999
        with pytest.raises(ScopeLimitExceeded):
            record.check_mapping_capacity(ScopeLimits(), 2)


class TestScopeService:
    async def test_create_and_require(self) -> None:
        service, _store, _vault = make_service()
        record = await service.create(tenant_id="tenant-a")
        found = await service.require_active(tenant_id="tenant-a", scope_id=record.scope_id)
        assert found.scope_id == record.scope_id

    async def test_unknown_scope(self) -> None:
        service, _store, _vault = make_service()
        with pytest.raises(ScopeNotFound):
            await service.require_active(tenant_id="tenant-a", scope_id="scp_missing")

    async def test_other_tenant_cannot_see_the_scope(self) -> None:
        """Cross-tenant access looks exactly like a missing scope.

        A distinguishable response would confirm that a scope id exists.
        """
        service, _store, _vault = make_service()
        record = await service.create(tenant_id="tenant-a")
        with pytest.raises(ScopeNotFound):
            await service.require_active(tenant_id="tenant-b", scope_id=record.scope_id)

    async def test_closed_scope_rejects(self) -> None:
        service, _store, _vault = make_service()
        record = await service.create(tenant_id="tenant-a")
        await service.close(tenant_id="tenant-a", scope_id=record.scope_id)
        with pytest.raises(ScopeClosed):
            await service.require_active(tenant_id="tenant-a", scope_id=record.scope_id)

    async def test_close_is_idempotent(self) -> None:
        service, _store, _vault = make_service()
        record = await service.create(tenant_id="tenant-a")
        assert await service.close(tenant_id="tenant-a", scope_id=record.scope_id)
        assert await service.close(tenant_id="tenant-a", scope_id=record.scope_id) is not None
        assert await service.close(tenant_id="tenant-a", scope_id="scp_unknown") is None

    async def test_expired_scope_is_marked_and_purged(self) -> None:
        service, store, _vault = make_service()
        record = await service.create(tenant_id="tenant-a")
        record.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await store.put(record)
        with pytest.raises(ScopeClosed):
            await service.require_active(tenant_id="tenant-a", scope_id=record.scope_id)
        assert record.status is ScopeStatus.EXPIRED

    async def test_policy_version_is_pinned_at_creation(self) -> None:
        service, _store, _vault = make_service(policy_version="2026-01-01.1")
        record = await service.create(tenant_id="tenant-a")
        assert record.policy_version == "2026-01-01.1"


class TestSettingsGate:
    def test_development_settings_validate(self) -> None:
        Settings(
            app_env="development", policy_file=POLICY,
            vault_master_key_b64=KEY_B64, vault_hmac_key_b64=KEY_B64,
            external_allowed_models="model-a",
        ).validate_for_environment()

    def test_streaming_cannot_be_enabled(self) -> None:
        with pytest.raises(Exception):
            Settings(enable_streaming=True, policy_file=POLICY)

    def test_production_rejects_placeholder_keys(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            Settings(
                app_env="production", policy_file=POLICY,
                external_allowed_models="model-a",
                external_base_url="https://provider.example/v1",
                storage_backend="postgres",
                database_url="postgresql+asyncpg://u:real@db/x",
                external_api_key="real-key",
            ).validate_for_environment()
        assert "placeholder" in str(exc.value)

    def test_production_rejects_payload_logging(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            Settings(
                app_env="production", policy_file=POLICY,
                vault_master_key_b64=KEY_B64, vault_hmac_key_b64=KEY_B64,
                external_allowed_models="model-a",
                external_base_url="https://provider.example/v1",
                external_api_key="real-key",
                database_url="postgresql+asyncpg://u:real@db/x",
                storage_backend="postgres",
                enable_payload_logging=True,
            ).validate_for_environment()
        assert "ENABLE_PAYLOAD_LOGGING" in str(exc.value)

    def test_production_rejects_dev_tokens_and_memory_storage(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            Settings(
                app_env="production", policy_file=POLICY,
                vault_master_key_b64=KEY_B64, vault_hmac_key_b64=KEY_B64,
                external_allowed_models="model-a",
                external_base_url="https://provider.example/v1",
                external_api_key="real-key",
                database_url="postgresql+asyncpg://u:real@db/x",
                dev_static_tokens="t:a:b:general",
                storage_backend="memory",
            ).validate_for_environment()
        message = str(exc.value)
        assert "DEV_STATIC_TOKENS" in message
        assert "STORAGE_BACKEND" in message

    def test_production_requires_https_provider(self) -> None:
        with pytest.raises(ConfigurationError) as exc:
            Settings(
                app_env="production", policy_file=POLICY,
                vault_master_key_b64=KEY_B64, vault_hmac_key_b64=KEY_B64,
                external_allowed_models="model-a",
                external_base_url="http://provider.example/v1",
                external_api_key="real-key",
                database_url="postgresql+asyncpg://u:real@db/x",
                storage_backend="postgres",
            ).validate_for_environment()
        assert "https" in str(exc.value)

    def test_wildcard_provider_host_is_rejected(self) -> None:
        with pytest.raises(Exception):
            Settings(external_base_url="https://*.example/v1", policy_file=POLICY)

    def test_missing_model_allow_list_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            Settings(
                app_env="development", policy_file=POLICY,
                vault_master_key_b64=KEY_B64, vault_hmac_key_b64=KEY_B64,
                external_allowed_models="",
            ).validate_for_environment()
