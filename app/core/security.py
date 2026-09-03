"""Caller authentication and constant-time helpers.

Guide §17.1: tenant is resolved from the authenticated principal, never from a
request body field. The MVP ships a development static-token verifier behind the
same protocol a production mTLS/JWT verifier will implement.
"""

from __future__ import annotations

import hmac
from typing import Protocol

from .config import Principal, Settings
from .errors import Forbidden, Unauthorized


class PrincipalVerifier(Protocol):
    def verify(self, credential: str | None) -> Principal: ...


class StaticTokenVerifier:
    """Development verifier backed by ``DEV_STATIC_TOKENS``.

    Compares in constant time so the endpoint cannot be used as a token oracle.
    """

    def __init__(self, settings: Settings) -> None:
        self._principals = settings.static_principals()

    def verify(self, credential: str | None) -> Principal:
        if not credential:
            raise Unauthorized("missing credential", public_detail="authentication required")
        for token, principal in self._principals.items():
            if hmac.compare_digest(token, credential):
                return principal
        raise Unauthorized("unknown credential", public_detail="authentication required")


def parse_bearer(header_value: str | None) -> str | None:
    if not header_value:
        return None
    prefix, _, token = header_value.partition(" ")
    if prefix.lower() != "bearer" or not token:
        return None
    return token.strip()


def authorize_purpose(principal: Principal, purpose: str) -> None:
    if not principal.may_use_purpose(purpose):
        raise Forbidden(
            f"principal not allowed to use purpose {purpose!r}",
            public_detail="purpose not permitted for this caller",
        )


def authorize_model(model: str, allowed: frozenset[str]) -> None:
    """The provider adapter enforces this too; doing it early gives a clean 403
    before any parsing work happens."""
    if model not in allowed:
        raise Forbidden(
            "model not in allow-list", public_detail="requested model is not permitted"
        )
