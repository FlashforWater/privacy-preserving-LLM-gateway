"""Vault encryption (guide §13.3).

AES-256-GCM with the associated data bound to tenant, scope, token, entity type
and policy version. Binding matters as much as the encryption: without it a
ciphertext could be copied from one row to another — moving a value between
tenants or re-labelling it as a different entity type — and would still decrypt.
With it, any such move fails authentication and the read is rejected.

The master key never lives in the database and never in source control. In
production it comes from a KMS or hardware-backed service; :class:`KeyProvider`
is the seam where that swap happens.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from app.core.errors import ConfigurationError, VaultError

NONCE_BYTES = 12


class KeyProvider(Protocol):
    def master_key(self) -> bytes: ...
    def hmac_key(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class StaticKeyProvider:
    """Keys supplied by configuration. Replace with a KMS client in production."""

    master: bytes
    hmac: bytes

    def __post_init__(self) -> None:
        for name, key in (("master", self.master), ("hmac", self.hmac)):
            if len(key) != 32:
                raise ConfigurationError(f"{name} key must be 32 bytes, got {len(key)}")

    def master_key(self) -> bytes:
        return self.master

    def hmac_key(self) -> bytes:
        return self.hmac


def build_aad(
    *, tenant_id: str, scope_id: str, token: str, entity_type: str, policy_version: str
) -> bytes:
    """Associated data. Field separator is a unit separator so no field can be
    crafted to look like another (``a|b`` vs ``a`` + ``|b``)."""
    return "\x1f".join((tenant_id, scope_id, token, entity_type, policy_version)).encode("utf-8")


class VaultCipher:
    def __init__(self, keys: KeyProvider) -> None:
        self._keys = keys
        self._aead: object | None = None

    def _get_aead(self) -> object:
        if self._aead is None:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            except ImportError as exc:  # pragma: no cover - dependency is required
                raise ConfigurationError(
                    "cryptography is required for the vault"
                ) from exc
            self._aead = AESGCM(self._keys.master_key())
        return self._aead

    def encrypt(self, plaintext: str, *, aad: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = self._get_aead().encrypt(  # type: ignore[attr-defined]
            nonce, plaintext.encode("utf-8"), aad
        )
        return nonce + ciphertext

    def decrypt(self, blob: bytes, *, aad: bytes) -> str:
        if len(blob) <= NONCE_BYTES:
            raise VaultError(
                "stored ciphertext is truncated", public_detail="restoration unavailable"
            )
        nonce, ciphertext = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
        try:
            plaintext = self._get_aead().decrypt(nonce, ciphertext, aad)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 - authentication failure is fail-closed
            raise VaultError(
                "vault ciphertext failed authentication",
                public_detail="restoration unavailable",
            ) from exc
        return bytes(plaintext).decode("utf-8")

    def self_test(self) -> None:
        """Readiness probe: prove we can round-trip before accepting traffic."""
        aad = build_aad(
            tenant_id="_probe", scope_id="_probe", token="_probe",
            entity_type="_probe", policy_version="_probe",
        )
        if self.decrypt(self.encrypt("ok", aad=aad), aad=aad) != "ok":  # pragma: no cover
            raise VaultError("vault self-test failed", public_detail="service not ready")
