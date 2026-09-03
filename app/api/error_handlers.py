"""Error serialization.

Guide §8.3: stable machine-readable codes, and errors must not echo original
content. The handler serializes ``GatewayError.to_public_dict`` and nothing else;
an unexpected exception becomes a generic 500 whose message is a constant, so a
stack-trace string containing payload fragments cannot reach the client.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.errors import GatewayError
from app.core.logging import safe_extra

logger = logging.getLogger("gateway.api")


def install(app: FastAPI) -> None:
    @app.exception_handler(GatewayError)
    async def _gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        logger.warning(
            "gateway.request.error",
            extra=safe_extra(
                route=request.url.path,
                method=request.method,
                error_code=exc.code,
                status_code=exc.status_code,
            ),
        )
        return JSONResponse(status_code=exc.status_code, content=exc.to_public_dict())

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Pydantic's error detail can quote the offending input, which for this
        # service may be payload content. Only the field locations are returned.
        locations = [".".join(str(part) for part in error.get("loc", ())) for error in exc.errors()]
        logger.info(
            "gateway.request.invalid",
            extra=safe_extra(route=request.url.path, method=request.method, error_code="INVALID_REQUEST"),
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "INVALID_REQUEST",
                    "detail": "request failed validation",
                    "fields": locations[:20],
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "gateway.request.unexpected_error",
            exc_info=exc,
            extra=safe_extra(
                route=request.url.path, method=request.method, error_code="INTERNAL_ERROR"
            ),
        )
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "detail": "internal error"}},
        )
