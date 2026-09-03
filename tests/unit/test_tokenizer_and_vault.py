"""Token grammar, canonicalization, vault isolation and TTL (guide §19.1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.enums import EntityType, PrivacyMode
from app.core.errors import VaultError
from app.domain.scopes import ScopeRecord
from app.gateway.scope_service import InMemoryScopeStore
from app.sanitization.tokenizer import (
    TOKEN_RE,
    build_token_request,
    canonicalize,
    escape_token_like,
    find_tokens,
    is_token,
    new_token,
)
from app.vault.base import PendingMapping
from app.vault.crypto import StaticKeyProvider, VaultCipher, build_aad
from app.vault.memory_vault import MemoryVault

MASTER = b"\x01" * 32
HMAC = b"\x02" * 32


def make_vault() -> tuple[MemoryVault, InMemoryScopeStore, dict[str, ScopeRecord]]:
    cipher = VaultCipher(StaticKeyProvider(master=MASTER, hmac=HMAC))
    store = InMemoryScopeStore()
    snapshot = store.live_scopes()
    return MemoryVault(cipher, snapshot), store, snapshot


async def seed_scope(store: InMemoryScopeStore, snapshot: dict[str, ScopeRecord],
                     tenant: str = "tenant-a", scope_id: str | None = None) -> ScopeRecord:
    record = ScopeRecord.create(
        tenant_id=tenant, policy_version="v1", idle_ttl_seconds=7200, absolute_ttl_seconds=86400
    )
    if scope_id:
        record.scope_id = scope_id
    await store.put(record)
    snapshot[record.scope_id] = record
    return record


class TestTokenGrammar:
    def test_token_matches_its_own_grammar(self) -> None:
        token = new_token(EntityType.PERSON)
        assert is_token(token)
        assert TOKEN_RE.fullmatch(token)

    def test_token_carries_no_part_of_the_value(self) -> None:
        token = new_token(EntityType.PHONE)
        assert "13812345678" not in token
        assert token.count("_") == 3

    def test_tokens_are_unique(self) -> None:
        tokens = {new_token(EntityType.PERSON) for _ in range(200)}
        assert len(tokens) == 200

    @pytest.mark.parametrize(
        "candidate",
        [
            "[[PGW_V1_PERSON_SHORT]]",
            "[[PGW_V2_PERSON_K7M4Q2Z9F8N3]]",
            "[[PERSON_K7M4Q2Z9F8N3]]",
            "[[PGW_V1_PERSON_k7m4q2z9f8n3]]",
            "[[PGW_V1_PERSON_K7M4Q2Z9F8N30]]",
        ],
    )
    def test_near_miss_tokens_are_rejected(self, candidate: str) -> None:
        assert not is_token(candidate)

    def test_find_tokens_in_text(self) -> None:
        a, b = new_token(EntityType.PERSON), new_token(EntityType.PHONE)
        assert find_tokens(f"{a} called {b} yesterday") == [a, b]

    def test_user_supplied_token_like_strings_are_neutralised(self) -> None:
        """A caller must not be able to plant a string the restorer might expand."""
        original = "see [[PGW_V1_PERSON_ABCDEFGHJKLM]] please"
        text, count = escape_token_like(original)
        assert count == 1
        assert find_tokens(text) == []
        assert "[[PGW_V1_PERSON_ABCDEFGHJKLM]]" not in text

    def test_escaping_preserves_length(self) -> None:
        """Detector spans are computed before escaping; a length change would
        shift every later offset and cause the sanitizer to rewrite the wrong
        range or drop an edit."""
        original = "id [[PGW_V1_PERSON_ABCDEFGHJKLM]] and [[OTHER_TOKEN_AAAAAAAA]] end"
        text, count = escape_token_like(original)
        assert count == 2
        assert len(text) == len(original)


class TestCanonicalization:
    def test_separators_do_not_create_a_second_token(self) -> None:
        assert canonicalize("138-1234-5678", EntityType.PHONE) == canonicalize(
            "13812345678", EntityType.PHONE
        )

    def test_email_is_case_insensitive(self) -> None:
        assert canonicalize("A@B.COM", EntityType.EMAIL) == "a@b.com"

    def test_aliases_are_not_merged(self) -> None:
        """Deterministic normalization only (guide §10.5).

        Merging two people is more dangerous than issuing two tokens for one, so
        ``Zhang San`` and ``Mr. Zhang`` stay distinct.
        """
        assert canonicalize("Zhang San", EntityType.PERSON) != canonicalize(
            "Mr. Zhang", EntityType.PERSON
        )
        assert canonicalize("the patient", EntityType.PERSON) != canonicalize(
            "Zhang San", EntityType.PERSON
        )

    def test_digest_is_scope_specific(self) -> None:
        a = build_token_request("13812345678", EntityType.PHONE,
                                tenant_id="t", scope_id="s1", key=HMAC)
        b = build_token_request("13812345678", EntityType.PHONE,
                                tenant_id="t", scope_id="s2", key=HMAC)
        assert a.lookup_hmac != b.lookup_hmac

    def test_digest_is_tenant_specific(self) -> None:
        a = build_token_request("13812345678", EntityType.PHONE,
                                tenant_id="t1", scope_id="s", key=HMAC)
        b = build_token_request("13812345678", EntityType.PHONE,
                                tenant_id="t2", scope_id="s", key=HMAC)
        assert a.lookup_hmac != b.lookup_hmac


class TestVault:
    async def test_round_trip(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot)
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, request_id="req-1",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "digest-1")],
            ttl_seconds=3600,
        )
        assert await vault.resolve(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, token=token
        ) == "Wei Zhang"

    async def test_put_locks_the_scope(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot)
        assert scope.privacy_mode is PrivacyMode.CLEAN
        await vault.put_all_and_lock_scope(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(new_token(EntityType.PERSON), EntityType.PERSON, "x", "d")],
            ttl_seconds=3600,
        )
        assert scope.privacy_mode is PrivacyMode.SANITIZED_LOCKED

    async def test_same_value_reuses_the_token(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot)
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "digest-1")],
            ttl_seconds=3600,
        )
        found = await vault.find_token_by_digest(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id,
            entity_type=EntityType.PERSON, digest="digest-1",
        )
        assert found == token

    async def test_cross_scope_token_does_not_resolve(self) -> None:
        vault, store, snapshot = make_vault()
        scope_a = await seed_scope(store, snapshot)
        scope_b = await seed_scope(store, snapshot)
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id=scope_a.tenant_id, scope_id=scope_a.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "d")],
            ttl_seconds=3600,
        )
        assert await vault.resolve(
            tenant_id=scope_b.tenant_id, scope_id=scope_b.scope_id, token=token
        ) is None

    async def test_cross_tenant_token_does_not_resolve(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot, tenant="tenant-a")
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id="tenant-a", scope_id=scope.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "d")],
            ttl_seconds=3600,
        )
        assert await vault.resolve(
            tenant_id="tenant-b", scope_id=scope.scope_id, token=token
        ) is None

    async def test_expired_mapping_does_not_resolve(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot)
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "d")],
            ttl_seconds=1,
        )
        later = datetime.now(UTC) + timedelta(seconds=5)
        assert await vault.resolve(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, token=token, at=later
        ) is None

    async def test_deleting_a_scope_removes_mappings(self) -> None:
        vault, store, snapshot = make_vault()
        scope = await seed_scope(store, snapshot)
        token = new_token(EntityType.PERSON)
        await vault.put_all_and_lock_scope(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, request_id="r",
            policy_version="v1",
            mappings=[PendingMapping(token, EntityType.PERSON, "Wei Zhang", "d")],
            ttl_seconds=3600,
        )
        await vault.delete_scope(tenant_id=scope.tenant_id, scope_id=scope.scope_id)
        assert await vault.resolve(
            tenant_id=scope.tenant_id, scope_id=scope.scope_id, token=token
        ) is None


class TestVaultCrypto:
    def test_ciphertext_cannot_be_moved_between_bindings(self) -> None:
        """AAD binding: a row copied to another token or tenant fails to decrypt."""
        cipher = VaultCipher(StaticKeyProvider(master=MASTER, hmac=HMAC))
        aad = build_aad(tenant_id="t1", scope_id="s1", token="tok1",
                        entity_type="PERSON", policy_version="v1")
        blob = cipher.encrypt("Wei Zhang", aad=aad)

        for tampered in (
            build_aad(tenant_id="t2", scope_id="s1", token="tok1",
                      entity_type="PERSON", policy_version="v1"),
            build_aad(tenant_id="t1", scope_id="s2", token="tok1",
                      entity_type="PERSON", policy_version="v1"),
            build_aad(tenant_id="t1", scope_id="s1", token="tok2",
                      entity_type="PERSON", policy_version="v1"),
            build_aad(tenant_id="t1", scope_id="s1", token="tok1",
                      entity_type="PHONE", policy_version="v1"),
        ):
            with pytest.raises(VaultError):
                cipher.decrypt(blob, aad=tampered)

    def test_ciphertext_does_not_contain_the_plaintext(self) -> None:
        cipher = VaultCipher(StaticKeyProvider(master=MASTER, hmac=HMAC))
        aad = build_aad(tenant_id="t", scope_id="s", token="k",
                        entity_type="PERSON", policy_version="v1")
        assert b"Wei Zhang" not in cipher.encrypt("Wei Zhang", aad=aad)

    def test_tampered_ciphertext_is_rejected(self) -> None:
        cipher = VaultCipher(StaticKeyProvider(master=MASTER, hmac=HMAC))
        aad = build_aad(tenant_id="t", scope_id="s", token="k",
                        entity_type="PERSON", policy_version="v1")
        blob = bytearray(cipher.encrypt("Wei Zhang", aad=aad))
        blob[-1] ^= 0xFF
        with pytest.raises(VaultError):
            cipher.decrypt(bytes(blob), aad=aad)
