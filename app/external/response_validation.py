"""Provider response validation.

The provider's reply is untrusted input from outside the trust boundary. It is
checked for size and shape *before* the restorer looks at it, so a hostile or
broken provider cannot drive the token scanner with a gigabyte of text or a
deeply nested structure.
"""

from __future__ import annotations

from typing import Any

from app.core.errors import ExternalProviderError
from app.domain.responses import ExternalModelResponse, ExternalTextField

MAX_RESPONSE_CHARS = 400_000
MAX_TEXT_FIELDS = 32


def validate(response: ExternalModelResponse) -> ExternalModelResponse:
    if len(response.text_fields) > MAX_TEXT_FIELDS:
        raise ExternalProviderError(
            "provider returned too many text fields",
            public_detail="external provider returned an unexpected response",
        )
    if response.total_text_length() > MAX_RESPONSE_CHARS:
        raise ExternalProviderError(
            "provider response exceeded the size limit",
            public_detail="external provider returned an unexpected response",
        )
    return response


def parse_openai_chat_completion(payload: Any, *, model: str) -> ExternalModelResponse:
    """Map an OpenAI-compatible chat completion onto our typed response.

    Only ``choices[].message.content`` is declared as text. Anything else the
    provider sends is ignored rather than scanned — restoration touches declared
    text fields only (guide §13.4.1).
    """
    if not isinstance(payload, dict):
        raise ExternalProviderError(
            "provider response was not a JSON object",
            public_detail="external provider returned an unexpected response",
        )
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ExternalProviderError(
            "provider response had no choices",
            public_detail="external provider returned an unexpected response",
        )

    fields: list[ExternalTextField] = []
    finish_reason: str | None = None
    for index, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        finish_reason = finish_reason or choice.get("finish_reason")
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            fields.append(ExternalTextField(path=f"choices[{index}].message.content", text=content))
        elif isinstance(content, list):
            # Some providers return content parts; take only the text ones.
            for part_index, part in enumerate(content):
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    fields.append(
                        ExternalTextField(
                            path=f"choices[{index}].message.content[{part_index}].text",
                            text=part["text"],
                        )
                    )

    if not fields:
        # A reasoning model spends the output budget on deliberation before it
        # writes anything, so an exhausted budget looks exactly like a model that
        # had nothing to say. Naming the cause saves an operator from debugging
        # the wrong layer; silently returning an empty answer would hide it
        # entirely.
        if finish_reason == "length":
            raise ExternalProviderError(
                "provider consumed the entire output budget without producing "
                "content; raise options.max_output_tokens",
                public_detail="external provider returned an unexpected response",
            )
        raise ExternalProviderError(
            "provider response contained no text content",
            public_detail="external provider returned an unexpected response",
        )

    usage_raw = payload.get("usage")
    usage: dict[str, int] = {}
    if isinstance(usage_raw, dict):
        usage = {k: int(v) for k, v in usage_raw.items() if isinstance(v, int | float)}

    return validate(
        ExternalModelResponse(
            model=str(payload.get("model") or model),
            text_fields=fields,
            finish_reason=finish_reason,
            usage=usage,
        )
    )
