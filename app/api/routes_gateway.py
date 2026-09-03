"""The message endpoint (guide §8.2).

Multipart: a ``manifest`` JSON field plus one ``file_<item_id>`` part per
attachment. The route does authentication, purpose/model authorization, scope
admission and limit enforcement, then hands off to the orchestrator. It contains
no policy logic and no fast-path logic — both live behind their single owners, so
this file cannot become a second place where forwarding is decided.
"""

from __future__ import annotations

import json
import logging
import time

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from pydantic import ValidationError

from app.core.config import Principal
from app.core.deadlines import Deadline
from app.core.errors import InvalidRequest, PayloadTooLarge
from app.core.logging import safe_extra
from app.core.security import authorize_model, authorize_purpose
from app.domain.content import Manifest
from app.domain.requests import RequestContext
from app.domain.responses import GatewayResponse

from .routes_scopes import get_principal

logger = logging.getLogger("gateway.api")

router = APIRouter(prefix="/v1/scopes", tags=["gateway"])

MAX_MANIFEST_BYTES = 256 * 1024


@router.post("/{scope_id}/messages")
async def post_message(
    scope_id: str,
    request: Request,
    manifest: str = Form(...),
    principal: Principal = Depends(get_principal),
) -> GatewayResponse:
    application = request.app.state.application
    settings = application.settings
    started = time.monotonic()

    if len(manifest.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise PayloadTooLarge(
            "manifest exceeds the size limit", public_detail="manifest is too large"
        )
    parsed_manifest = _parse_manifest(manifest)

    authorize_purpose(principal, parsed_manifest.purpose)
    authorize_model(parsed_manifest.model, settings.allowed_models)

    scope = await application.scopes.require_active(
        tenant_id=principal.tenant_id, scope_id=scope_id
    )

    files = await _collect_files(request)

    normalized = application.normalizer.normalize(
        parsed_manifest, files, application.parser_limits
    )

    # Capacity is checked before any parsing so an over-limit turn cannot consume
    # OCR or local-model time (guide §19.3.15).
    await application.scopes.admit_turn(
        scope,
        files=normalized.file_count,
        byte_count=normalized.total_bytes,
    )

    context = RequestContext.create(
        principal=principal,
        scope=scope,
        manifest=parsed_manifest,
        deadline=Deadline.after(settings.request_deadline_seconds),
        idempotency_key=request.headers.get("idempotency-key"),
    )

    response = await application.orchestrator.process(context, normalized)

    await application.scopes.complete_turn(
        scope,
        files=normalized.file_count,
        byte_count=normalized.total_bytes,
        pages=0,
    )

    logger.info(
        "gateway.request.completed",
        extra=safe_extra(
            request_id=context.request_id,
            scope_id=scope.scope_id,
            route="/v1/scopes/{scope_id}/messages",
            status=response.status,
            path=response.privacy.path.value,
            policy_version=response.privacy.policy_version,
            item_count=len(normalized.items),
            file_count=normalized.file_count,
            bytes_in=normalized.total_bytes,
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        ),
    )
    return response


def _parse_manifest(raw: str) -> Manifest:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidRequest(
            "manifest is not valid JSON", public_detail="manifest is not valid JSON"
        ) from exc
    try:
        return Manifest.model_validate(payload)
    except ValidationError as exc:
        # Field locations only; pydantic's messages can quote the input.
        locations = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]
        raise InvalidRequest(
            "manifest failed validation",
            public_detail="manifest failed validation",
            meta={"fields": locations[:20]},
        ) from exc


async def _collect_files(request: Request) -> dict[str, bytes]:
    """Read every uploaded part into memory.

    Bytes stay in memory for the life of the request and are never written to a
    shared location (guide §17.4). Per-file and total size limits are enforced by
    the normalizer immediately afterwards.
    """
    form = await request.form()
    files: dict[str, bytes] = {}
    for field_name, value in form.multi_items():
        if isinstance(value, UploadFile):
            files[field_name] = await value.read()
            await value.close()
    return files
