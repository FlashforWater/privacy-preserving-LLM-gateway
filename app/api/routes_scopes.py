"""Scope endpoints (guide §8.1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import Principal
from app.core.security import parse_bearer

router = APIRouter(prefix="/v1/scopes", tags=["scopes"])


class CreateScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Correlation label only. The gateway always generates the authoritative id.
    client_conversation_id: str | None = Field(default=None, max_length=128)


def get_principal(request: Request) -> Principal:
    application = request.app.state.application
    return application.verifier.verify(parse_bearer(request.headers.get("authorization")))


@router.post("", status_code=201)
async def create_scope(
    request: Request,
    body: CreateScopeRequest | None = None,
    principal: Principal = Depends(get_principal),
) -> dict[str, object]:
    application = request.app.state.application
    record = await application.scopes.create(
        tenant_id=principal.tenant_id,
        client_conversation_id=body.client_conversation_id if body else None,
    )
    return record.public_view()


@router.post("/{scope_id}/close")
async def close_scope(
    scope_id: str, request: Request, principal: Principal = Depends(get_principal)
) -> dict[str, object]:
    application = request.app.state.application
    record = await application.scopes.close(
        tenant_id=principal.tenant_id, scope_id=scope_id
    )
    # Idempotent: closing an unknown or already-closed scope is a success, and
    # returns nothing that reveals whether it existed.
    if record is None:
        return {"scope_id": scope_id, "status": "closed"}
    return record.public_view()
