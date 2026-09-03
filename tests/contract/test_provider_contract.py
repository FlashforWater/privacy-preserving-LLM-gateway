"""Provider adapter contract (guide §14, §19.3.11).

Checks the mapping in both directions and the retry policy's boundaries, using a
transport stub rather than a network — a contract test that needs the internet is
a contract test that gets skipped.
"""

from __future__ import annotations

import httpx
import pytest

from app.core.deadlines import Deadline
from app.core.enums import ContentItemType, ForwardPath
from app.core.errors import ExternalProviderError, Forbidden
from app.domain.requests import (
    OutboundBinaryPart,
    OutboundMessage,
    OutboundTextPart,
    SanitizedModelRequest,
)
from app.external.openai_compatible import OpenAICompatibleAdapter
from app.external.response_validation import parse_openai_chat_completion
from app.external.retry import RetryPolicy, is_retryable, with_retry

ALLOWED = frozenset({"model-a"})


def sanitized_request(**overrides: object) -> SanitizedModelRequest:
    data: dict[str, object] = {
        "request_id": "req-1",
        "model": "model-a",
        "purpose": "general",
        "messages": (
            OutboundMessage(
                role="user",
                parts=(
                    OutboundTextPart(item_id="t1", text="hello"),
                    OutboundBinaryPart(
                        kind=ContentItemType.IMAGE, item_id="i1",
                        data=b"\x89PNG\r\n\x1a\n", mime_type="image/png",
                    ),
                ),
            ),
        ),
        "temperature": 0.2,
        "max_output_tokens": 100,
        "path": ForwardPath.SANITIZED,
    }
    data.update(overrides)
    return SanitizedModelRequest(**data)  # type: ignore[arg-type]


def stub_transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://provider.test/v1"
    )


class TestRequestMapping:
    async def test_text_and_image_parts_map_in_order(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured.update(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "model": "model-a",
                    "choices": [
                        {"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "ok"}}
                    ],
                },
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
        )
        await adapter.complete(sanitized_request(), Deadline.after(10))
        content = captured["messages"][0]["content"]  # type: ignore[index]
        assert [part["type"] for part in content] == ["text", "image_url"]
        assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")

    async def test_streaming_is_never_requested(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured.update(json.loads(request.content))
            return httpx.Response(
                200,
                json={"model": "model-a", "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "ok"}}]},
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
        )
        await adapter.complete(sanitized_request(), Deadline.after(10))
        assert captured["stream"] is False

    async def test_idempotency_key_is_sent(self) -> None:
        seen: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("Idempotency-Key"))
            return httpx.Response(
                200,
                json={"model": "model-a", "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "ok"}}]},
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
        )
        await adapter.complete(sanitized_request(), Deadline.after(10))
        assert seen == ["req-1"]

    async def test_model_allow_list_is_enforced_at_the_adapter(self) -> None:
        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED,
            client=stub_transport(lambda request: httpx.Response(200, json={})),
        )
        with pytest.raises(Forbidden):
            await adapter.complete(sanitized_request(model="model-z"), Deadline.after(10))


class TestResponseMapping:
    def test_string_content_becomes_one_text_field(self) -> None:
        response = parse_openai_chat_completion(
            {"model": "model-a", "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "hi"}}]},
            model="model-a",
        )
        assert [field.text for field in response.text_fields] == ["hi"]

    def test_content_parts_are_flattened(self) -> None:
        response = parse_openai_chat_completion(
            {"model": "model-a", "choices": [
                {"index": 0, "message": {"role": "assistant", "content": [
                    {"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}}]},
            model="model-a",
        )
        assert len(response.text_fields) == 2

    def test_missing_choices_is_an_error(self) -> None:
        with pytest.raises(ExternalProviderError):
            parse_openai_chat_completion({"model": "model-a"}, model="model-a")

    def test_oversized_response_is_rejected(self) -> None:
        with pytest.raises(ExternalProviderError):
            parse_openai_chat_completion(
                {"model": "model-a", "choices": [
                    {"index": 0, "message": {"content": "x" * 500_001}}]},
                model="model-a",
            )


class TestRetry:
    @pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
    def test_transient_statuses_are_retryable(self, status: int) -> None:
        error = httpx.HTTPStatusError(
            "x", request=httpx.Request("POST", "http://x"),
            response=httpx.Response(status),
        )
        assert is_retryable(error)

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
    def test_client_errors_are_not_retried(self, status: int) -> None:
        error = httpx.HTTPStatusError(
            "x", request=httpx.Request("POST", "http://x"),
            response=httpx.Response(status),
        )
        assert not is_retryable(error)

    async def test_retry_stops_at_max_attempts(self) -> None:
        attempts = 0

        async def operation(_attempt: int) -> str:
            nonlocal attempts
            attempts += 1
            raise httpx.ConnectError("nope")

        with pytest.raises(httpx.ConnectError):
            await with_retry(
                operation,
                policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.0, max_delay_seconds=0.0),
                deadline=Deadline.after(10),
            )
        assert attempts == 3

    async def test_retry_respects_the_deadline(self) -> None:
        async def operation(_attempt: int) -> str:
            raise httpx.ConnectError("nope")

        from app.core.errors import RequestDeadlineExceeded

        with pytest.raises((httpx.ConnectError, RequestDeadlineExceeded)):
            await with_retry(
                operation,
                policy=RetryPolicy(max_attempts=5, base_delay_seconds=10.0),
                deadline=Deadline.after(0.01),
            )


class TestReasoningModelResponses:
    """A reasoning model puts its chain of thought in a separate field and leaves
    ``content`` null until it finishes. Both halves of that need handling."""

    def test_null_content_is_an_error_not_an_empty_answer(self) -> None:
        with pytest.raises(ExternalProviderError):
            parse_openai_chat_completion(
                {
                    "model": "model-a",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "length",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "reasoning": "still thinking...",
                            },
                        }
                    ],
                },
                model="model-a",
            )

    def test_reasoning_field_is_never_treated_as_output(self) -> None:
        """Only declared text fields are restored; a reasoning trace is not one."""
        response = parse_openai_chat_completion(
            {
                "model": "model-a",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "the answer",
                            "reasoning": "internal deliberation",
                        },
                    }
                ],
            },
            model="model-a",
        )
        assert [field.text for field in response.text_fields] == ["the answer"]


class TestMisconfiguredBaseUrl:
    """A base URL missing its API path prefix is the common misconfiguration and
    the one that hides best: the host's web front end answers 200 with an HTML
    page, so status-code checks pass and only the body reveals the problem."""

    async def test_html_response_becomes_a_provider_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<!doctype html><html><body>web console</body></html>",
                headers={"content-type": "text/html; charset=utf-8"},
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
        )
        with pytest.raises(ExternalProviderError) as exc:
            await adapter.complete(sanitized_request(), Deadline.after(10))
        # The message has to name the cause; without it the operator debugs the
        # sanitizer instead of the URL.
        assert "path prefix" in str(exc.value)

    async def test_non_json_body_with_json_content_type(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="not json at all",
                headers={"content-type": "application/json"},
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
        )
        with pytest.raises(ExternalProviderError):
            await adapter.complete(sanitized_request(), Deadline.after(10))


class TestExhaustedOutputBudget:
    def test_budget_consumed_by_reasoning_names_the_cause(self) -> None:
        """Measured against deepseek-v4-flash: an 800-token budget was spent
        entirely on deliberation and the answer came back empty. That is
        indistinguishable from a model with nothing to say unless the error says
        so."""
        with pytest.raises(ExternalProviderError) as exc:
            parse_openai_chat_completion(
                {
                    "model": "model-a",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "length",
                            "message": {"role": "assistant", "content": None,
                                        "reasoning": "…"},
                        }
                    ],
                },
                model="model-a",
            )
        assert "max_output_tokens" in str(exc.value)

    def test_default_budget_leaves_room_for_reasoning(self) -> None:
        from app.domain.content import RequestOptions

        assert RequestOptions().max_output_tokens >= 4000


class TestReasoningSwitch:
    """Turning the provider's chain of thought off is opt-in and provider-specific."""

    async def _captured_body(self, **adapter_kwargs: object) -> dict:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            captured.update(json.loads(request.content))
            return httpx.Response(
                200,
                json={"model": "model-a", "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "ok"}}]},
                headers={"content-type": "application/json"},
            )

        adapter = OpenAICompatibleAdapter(
            base_url="http://provider.test/v1", api_key="k",
            allowed_models=ALLOWED, client=stub_transport(handler),
            **adapter_kwargs,  # type: ignore[arg-type]
        )
        await adapter.complete(sanitized_request(), Deadline.after(10))
        return captured

    async def test_default_sends_no_reasoning_parameter(self) -> None:
        """The external model is the reasoning engine (guide §1); the gateway does
        not quietly change how it thinks."""
        body = await self._captured_body()
        assert "reasoning_effort" not in body

    async def test_disabled_sends_the_switch(self) -> None:
        body = await self._captured_body(reasoning="disabled")
        assert body["reasoning_effort"] == "none"


class TestEmptyContentIsNotAnAnswer:
    """Observed live: deepseek-v4-flash spent all 4000 tokens reasoning about a
    claims document and returned ``content: ""`` with ``finish_reason: length``.

    The first version of this guard only tested for a *missing* field, so an
    empty string sailed through and the gateway reported a completed request
    whose answer was nothing. A caller cannot distinguish that from a model that
    chose not to answer.
    """

    def test_empty_string_content_is_rejected(self) -> None:
        with pytest.raises(ExternalProviderError) as exc:
            parse_openai_chat_completion(
                {
                    "model": "model-a",
                    "choices": [
                        {"index": 0, "finish_reason": "length",
                         "message": {"role": "assistant", "content": ""}}
                    ],
                },
                model="model-a",
            )
        assert "max_output_tokens" in str(exc.value)

    def test_whitespace_only_content_is_rejected(self) -> None:
        with pytest.raises(ExternalProviderError):
            parse_openai_chat_completion(
                {
                    "model": "model-a",
                    "choices": [
                        {"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "   \n\n  "}}
                    ],
                },
                model="model-a",
            )

    def test_content_parts_that_are_all_empty_are_rejected(self) -> None:
        with pytest.raises(ExternalProviderError):
            parse_openai_chat_completion(
                {
                    "model": "model-a",
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": [
                            {"type": "text", "text": ""}, {"type": "text", "text": " "}]}}
                    ],
                },
                model="model-a",
            )

    def test_real_content_still_passes(self) -> None:
        response = parse_openai_chat_completion(
            {"model": "model-a", "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "结论：吻合。"}}]},
            model="model-a",
        )
        assert response.text_fields[0].text == "结论：吻合。"
