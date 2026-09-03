#!/usr/bin/env python3
"""Verify the local detection model before wiring it in.

``/health/ready`` probes the model too, but it answers a yes/no. This script says
*why*, which is what you want when the endpoint is on someone else's server:

  * is the base URL right (a path prefix is easy to miss);
  * does the configured model id exist, with the exact casing;
  * is native ``json_schema`` structured output available;
  * does the model emit a chain of thought, and is the thinking switch honoured;
  * does a realistic entity-detection call return spans that survive verification.

Reads configuration from the environment / .env, so it checks what the gateway
will actually use rather than what you type on the command line.

    python scripts/check_local_model.py
"""

from __future__ import annotations

import asyncio
import json
import sys

import httpx

from app.core.config import get_settings
from app.detectors.local_model_detector import (
    ENTITY_SCHEMA,
    OpenAICompatibleLocalModel,
    parse_entity_payload,
    verify_spans,
)
from app.core.deadlines import Deadline
from app.detectors.base import DetectorUnavailable

SAMPLE = "Patient: Wei Zhang, admitted 3 March. Address: 88 Xinghai Street, Suzhou."

OK = "  ok  "
BAD = " FAIL "


def line(status: str, label: str, detail: str = "") -> None:
    print(f"[{status}] {label}" + (f"  —  {detail}" if detail else ""))


async def main() -> int:
    settings = get_settings()
    base = settings.local_model_base_url
    model = settings.local_model_name
    failures = 0

    print(f"base url : {base}")
    print(f"model    : {model}")
    print(f"thinking : {'disabled' if settings.local_model_disable_thinking else 'enabled'}")
    print()

    headers = {"Authorization": f"Bearer {settings.local_model_api_key}"}
    async with httpx.AsyncClient(base_url=base, headers=headers, timeout=30.0) as client:
        # 1. Reachability and model listing.
        try:
            response = await client.get("/models")
            response.raise_for_status()
            served = [entry.get("id") for entry in response.json().get("data", [])]
        except httpx.HTTPError as exc:
            line(BAD, "reachable", f"{type(exc).__name__} — check the path prefix and firewall")
            return 1
        except ValueError:
            line(BAD, "reachable", "endpoint returned non-JSON; the base URL is probably wrong")
            return 1
        line(OK, "reachable", f"{len(served)} model(s) served")

        # 2. Exact model id. Casing matters: vLLM 404s on a mismatch.
        if model in served:
            line(OK, "model id", model)
        else:
            failures += 1
            line(BAD, "model id", f"{model!r} not served; available: {served}")

        # 3. Structured output.
        capabilities = await OpenAICompatibleLocalModel(
            base_url=base, model=model, api_key=settings.local_model_api_key,
            disable_thinking=settings.local_model_disable_thinking,
        ).probe(Deadline.after(30))
        if capabilities.supports_json_schema:
            line(OK, "json_schema", "native structured output available")
        else:
            line(OK, "json_schema", "not available — falling back to prompt-constrained JSON")

        # 4. Reasoning behaviour. A model that keeps thinking with the switch on
        #    will truncate on real documents, which the detector treats as a
        #    failure rather than as an empty result.
        payload: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": 'Return exactly {"entities": []}.'}],
            "max_tokens": 256,
            "temperature": 0.0,
        }
        if settings.local_model_disable_thinking:
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        try:
            body = (await client.post("/chat/completions", json=payload)).json()
            choice = body["choices"][0]
            reasoning = choice["message"].get("reasoning")
            content = choice["message"].get("content")
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            failures += 1
            line(BAD, "chat completion", type(exc).__name__)
            return 1

        if choice.get("finish_reason") == "length":
            failures += 1
            line(BAD, "token budget", "truncated at 256 tokens on a trivial prompt")
        elif content is None:
            failures += 1
            line(BAD, "content", "null — the model is still thinking; raise LOCAL_MODEL_MAX_TOKENS")
        elif settings.local_model_disable_thinking and reasoning:
            line(OK, "thinking switch", "server ignored it, but content came back anyway")
        else:
            line(OK, "thinking switch", f"honoured ({body['usage']['completion_tokens']} tokens)")

        # 5. A realistic detection call, validated exactly as the gateway does.
        detect: dict[str, object] = {
            "model": model,
            "messages": [
                {"role": "system", "content":
                 "You are a local privacy entity detector. Identify spans only. "
                 "Return JSON matching the schema and no other text. "
                 "Every start/end span must exactly match the input."},
                {"role": "user", "content": f"<text>{SAMPLE}</text>"},
            ],
            "max_tokens": settings.local_model_max_tokens,
            "temperature": 0.0,
        }
        if settings.local_model_disable_thinking:
            detect["chat_template_kwargs"] = {"enable_thinking": False}
        if capabilities.supports_json_schema:
            detect["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "entity_detection", "schema": ENTITY_SCHEMA,
                                "strict": True},
            }
        try:
            body = (await client.post("/chat/completions", json=detect)).json()
            entities = parse_entity_payload(body["choices"][0]["message"]["content"])
        except DetectorUnavailable as exc:
            failures += 1
            line(BAD, "entity detection", str(exc))
            return 1 if failures else 0
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            failures += 1
            line(BAD, "entity detection", type(exc).__name__)
            return 1

        verified = verify_spans(SAMPLE, entities)
        line(OK, "schema validation", f"{len(entities)} entity/entities parsed")
        if verified.rejected:
            # Not fatal: the gateway discards these. Worth seeing, because a high
            # rejection rate means the model is guessing at offsets.
            line(OK, "span verification",
                 f"{len(verified.accepted)} accepted, {verified.rejected} rejected as hallucinated")
        else:
            line(OK, "span verification", f"all {len(verified.accepted)} span(s) exact")
        for item in verified.accepted:
            print(f"        {item.type:18s} {SAMPLE[item.start:item.end]!r}")

    print()
    print("local model check:", "passed" if failures == 0 else f"{failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
