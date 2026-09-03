"""The single external provider adapter (guide §14).

Responsibilities kept here and nowhere else: provider format conversion, message
and attachment ordering, the model allow-list, timeouts, bounded retry, response
validation and error mapping. Nothing in this module logs a request or response
body.

Attachment ordering is preserved exactly as the caller sent it, because a
multimodal prompt whose parts are reordered means something different from what
the user asked.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from app.core.deadlines import Deadline
from app.core.errors import ExternalProviderError, Forbidden
from app.domain.requests import (
    OriginalApprovedRequest,
    OutboundBinaryPart,
    OutboundTextPart,
    SanitizedModelRequest,
)
from app.domain.responses import ExternalModelResponse

from .response_validation import parse_openai_chat_completion
from .retry import RetryPolicy, with_retry

OutboundRequest = OriginalApprovedRequest | SanitizedModelRequest


class OpenAICompatibleAdapter:
    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        allowed_models: frozenset[str],
        timeout_seconds: float = 60.0,
        retry: RetryPolicy | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._allowed_models = allowed_models
        self._timeout = timeout_seconds
        self._retry = retry or RetryPolicy()
        self._client = client

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def complete(
        self, request: OutboundRequest, deadline: Deadline
    ) -> ExternalModelResponse:
        # Enforced again here even though the API layer already checked: this is
        # the last place before bytes leave the process.
        if request.model not in self._allowed_models:
            raise Forbidden(
                "model not in allow-list", public_detail="requested model is not permitted"
            )

        payload = self._to_provider_format(request)
        headers = {"Idempotency-Key": request.request_id}

        async def attempt(_attempt: int) -> ExternalModelResponse:
            response = await self._http().post(
                "/chat/completions",
                json=payload,
                headers=headers,
                timeout=deadline.budget_for(self._timeout, reserve=2.0),
            )
            response.raise_for_status()
            return parse_openai_chat_completion(response.json(), model=request.model)

        try:
            return await with_retry(attempt, policy=self._retry, deadline=deadline)
        except httpx.HTTPStatusError as exc:
            # Status category only. Provider error bodies can echo our input.
            raise ExternalProviderError(
                f"provider returned HTTP {exc.response.status_code}",
                public_detail="external provider error",
                meta={"provider_status": str(exc.response.status_code)},
            ) from exc
        except httpx.HTTPError as exc:
            raise ExternalProviderError(
                f"provider transport failure: {type(exc).__name__}",
                public_detail="external provider unavailable",
            ) from exc

    def _to_provider_format(self, request: OutboundRequest) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        for message in request.messages:
            content: list[dict[str, Any]] = []
            for part in message.parts:
                if isinstance(part, OutboundTextPart):
                    content.append({"type": "text", "text": part.text})
                elif isinstance(part, OutboundBinaryPart):
                    encoded = base64.b64encode(part.data).decode("ascii")
                    content.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{part.mime_type};base64,{encoded}"},
                        }
                    )
            messages.append({"role": message.role, "content": content})

        return {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_output_tokens,
            # Streaming is not implemented in the MVP (guide §13.5): partial,
            # un-restored output has no safe failure mode.
            "stream": False,
        }


class RecordingAdapter:
    """In-process fake that captures exactly what would have been sent.

    Used by the failure-injection and security suites for the central assertion:
    *when inspection or protection is incomplete, the provider receives zero
    unsafe bytes* (guide §19.5). Because it records the typed outbound request,
    tests can assert on both text and raw attachment bytes.
    """

    name = "recording-fake"

    def __init__(self, responses: list[ExternalModelResponse] | None = None) -> None:
        self.requests: list[OutboundRequest] = []
        self._responses = list(responses or [])

    async def complete(
        self, request: OutboundRequest, deadline: Deadline
    ) -> ExternalModelResponse:
        self.requests.append(request)
        if self._responses:
            return self._responses.pop(0)
        return ExternalModelResponse(model=request.model, text_fields=[])

    # -- assertions used by tests -----------------------------------------

    def captured_text(self) -> str:
        return "\n".join(
            part.text
            for request in self.requests
            for part in request.text_parts()
        )

    def captured_bytes(self) -> bytes:
        return b"".join(
            part.data for request in self.requests for part in request.binary_parts()
        )
