"""External provider adapter protocol (guide §14).

The signature is the security control. ``complete`` accepts only
:class:`OriginalApprovedRequest` or :class:`SanitizedModelRequest` — both of
which can be produced solely by ``request_builder`` after the fast-path guard or
the sanitizer has run. There is no overload that takes a raw internal request, so
"call the provider directly from a detector" does not type-check and does not
work.
"""

from __future__ import annotations

from typing import Protocol

from app.core.deadlines import Deadline
from app.domain.requests import OriginalApprovedRequest, SanitizedModelRequest
from app.domain.responses import ExternalModelResponse

OutboundRequest = OriginalApprovedRequest | SanitizedModelRequest


class ExternalModelAdapter(Protocol):
    name: str

    async def complete(
        self, request: OutboundRequest, deadline: Deadline
    ) -> ExternalModelResponse: ...
