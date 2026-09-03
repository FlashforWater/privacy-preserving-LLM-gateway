"""Gateway errors and their stable public codes (guide §8.3).

Two rules hold everywhere in this package:

* **Errors never echo original content.** ``public_detail`` is what the caller
  sees; it is built from codes and counts, never from payload text.
* **An error is never a permission to forward.** There is no exception type here
  that means "continue without inspection". ``InspectionFailedClosed`` exists
  precisely so that a parser/OCR/detector/policy/vault failure has an unambiguous,
  non-forwarding representation.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any


class GatewayError(Exception):
    """Base class. Subclasses fix an HTTP status and a machine-readable code."""

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str, *, public_detail: str | None = None,
                 meta: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        # `message` is for internal logs (still must not contain payload bodies).
        # `public_detail` is what crosses back to the caller.
        self.public_detail = public_detail or self.code
        self.meta = dict(meta or {})

    def to_public_dict(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "detail": self.public_detail, **self.meta}}


class InvalidRequest(GatewayError):
    status_code = HTTPStatus.BAD_REQUEST
    code = "INVALID_REQUEST"


class ScopeNotFound(GatewayError):
    status_code = HTTPStatus.NOT_FOUND
    code = "SCOPE_NOT_FOUND"


class ScopeClosed(GatewayError):
    status_code = HTTPStatus.CONFLICT
    code = "SCOPE_CLOSED"


class Unauthorized(GatewayError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "UNAUTHORIZED"


class Forbidden(GatewayError):
    status_code = HTTPStatus.FORBIDDEN
    code = "UNAUTHORIZED"


class PayloadTooLarge(GatewayError):
    status_code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "PAYLOAD_TOO_LARGE"


class ScopeLimitExceeded(GatewayError):
    status_code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "SCOPE_LIMIT_EXCEEDED"


class UnsupportedMediaType(GatewayError):
    status_code = HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    code = "UNSUPPORTED_MEDIA_TYPE"


class ContentBlocked(GatewayError):
    """Policy intentionally blocked the request or a required item."""

    status_code = HTTPStatus.UNPROCESSABLE_ENTITY
    code = "CONTENT_BLOCKED"


class InspectionFailedClosed(GatewayError):
    """A parser, OCR engine, detector, classifier, policy or vault failed.

    This is the single representation of "we could not complete inspection".
    Nothing in the codebase may catch it and continue to the external provider.
    """

    status_code = HTTPStatus.FAILED_DEPENDENCY
    code = "INSPECTION_FAILED_CLOSED"


class ExternalProviderError(GatewayError):
    status_code = HTTPStatus.BAD_GATEWAY
    code = "EXTERNAL_PROVIDER_ERROR"


class RequestDeadlineExceeded(GatewayError):
    status_code = HTTPStatus.GATEWAY_TIMEOUT
    code = "REQUEST_DEADLINE_EXCEEDED"


class ConfigurationError(GatewayError):
    """Startup-time failure. The process must not become ready (guide §3.10)."""

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    code = "CONFIGURATION_ERROR"


class VaultError(InspectionFailedClosed):
    """Vault problems are fail-closed problems; they must not reach the provider."""

    code = "INSPECTION_FAILED_CLOSED"
