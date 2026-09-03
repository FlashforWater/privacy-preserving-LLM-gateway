"""ASGI application factory.

Startup order matters: configuration and policy are validated, the vault proves
it can encrypt and decrypt, and only then is the application object attached to
the app state. A failure at any of those steps leaves ``/health/ready``
reporting not-ready, which is what keeps a misconfigured process out of rotation.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import error_handlers, routes_gateway, routes_health, routes_scopes
from app.api.dependencies import build_application
from app.core.config import get_settings
from app.core.errors import ConfigurationError
from app.core.logging import configure_logging, safe_extra

logger = logging.getLogger("gateway.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.app_env != "development")
    try:
        app.state.application = build_application(settings)
    except ConfigurationError:
        # Do not attach an application object: readiness stays false and the
        # process refuses traffic rather than starting in an unknown state.
        app.state.application = None
        logger.error(
            "gateway.startup.configuration_rejected",
            extra=safe_extra(error_code="CONFIGURATION_ERROR"),
        )
        raise
    logger.info(
        "gateway.startup.ready",
        extra=safe_extra(policy_version=app.state.application.policy.version),
    )
    yield
    app.state.application = None


def create_app() -> FastAPI:
    app = FastAPI(
        title="Privacy-Preserving LLM Gateway",
        version="0.1.0",
        lifespan=lifespan,
        # The schema documents shapes, not content; disabling the interactive
        # docs keeps one fewer surface on an internal service.
        docs_url=None,
        redoc_url=None,
    )
    error_handlers.install(app)
    app.include_router(routes_health.router)
    app.include_router(routes_scopes.router)
    app.include_router(routes_gateway.router)
    return app


app = create_app()
