"""Health and metrics endpoints (guide §8.4).

``/health/ready`` fails when policy cannot be loaded, vault encryption is
unavailable, required local inspection is missing, or the deployment is running
a development component in a production environment. Readiness is a gate, not a
status board: if it cannot prove the safety-critical pieces work, it reports not
ready and the load balancer keeps traffic away.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.core.deadlines import Deadline
from app.observability.metrics import REGISTRY

router = APIRouter(tags=["operations"])

READINESS_BUDGET_SECONDS = 3.0


@router.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
async def ready(request: Request, response: Response) -> dict[str, object]:
    application = getattr(request.app.state, "application", None)
    if application is None:
        response.status_code = 503
        return {"status": "not_ready", "reasons": ["application not initialised"]}

    # Short budget: readiness is polled frequently and must not hold a worker
    # open waiting on a dependency that is already known to be slow.
    problems = await application.probe_dependencies(Deadline.after(READINESS_BUDGET_SECONDS))
    if problems:
        response.status_code = 503
        return {"status": "not_ready", "reasons": problems}

    return {
        "status": "ready",
        "policy_version": application.policy.version,
        "streaming_enabled": application.settings.enable_streaming,
        "ocr_backend": application.ocr_backend,
        "storage_backend": application.settings.storage_backend,
    }


@router.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
