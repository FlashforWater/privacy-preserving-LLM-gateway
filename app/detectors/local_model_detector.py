"""Local open-source model as a *detection assistant* (guide §10.3).

The model never decides an action. It returns candidate spans, and every one of
them is verified against the exact input before it is allowed to become evidence:

* JSON schema validation succeeds;
* entity type is on the allow-list;
* offsets are within bounds;
* ``input[start:end]`` equals the returned text character for character;
* entity count and output size are under their limits;
* no extra fields or prose.

A span that fails verification is discarded and counted; a *response* that fails
validation raises :class:`DetectorUnavailable`, because "the detector is broken"
and "the detector found nothing" must not be confused (guide §15.1).

The model's ``text`` field is untrusted. It is used only for comparison against
the input, never as a replacement value — otherwise a model that returned
``{"start": 0, "end": 5, "text": "<script>"}`` could inject content into the
sanitized payload.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from app.core.enums import LOCAL_MODEL_ENTITIES, EntityType, FindingSource
from app.core.deadlines import Deadline
from app.domain.content import ContentItem, ParsedItem
from app.domain.findings import Finding

from .base import DetectorUnavailable, clamp_confidence

PROMPT_PATH = Path(__file__).parent / "prompts" / "entity_detection_v1.txt"

MAX_ENTITIES = 200
MAX_RESPONSE_BYTES = 256_000
MAX_SPAN_LENGTH = 512

ENTITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["entities"],
    "properties": {
        "entities": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["start", "end", "text", "type", "confidence"],
                "properties": {
                    "start": {"type": "integer", "minimum": 0},
                    "end": {"type": "integer", "minimum": 0},
                    "text": {"type": "string", "maxLength": MAX_SPAN_LENGTH},
                    "type": {"enum": sorted(e.value for e in LOCAL_MODEL_ENTITIES)},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        }
    },
}


@dataclass(frozen=True, slots=True)
class RawEntity:
    start: int
    end: int
    text: str
    type: str
    confidence: float


@dataclass(frozen=True, slots=True)
class LocalModelCapabilities:
    """Result of the deployment-time probe (guide §10.3).

    Endpoint compatibility is a deployment fact, not a product decision, so it is
    discovered once at startup and cached rather than negotiated per request.
    """

    reachable: bool
    model_name: str
    supports_json_schema: bool
    detail: str = ""


class LocalModelClient(Protocol):
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities: ...

    async def detect_entities(
        self, *, text: str, document_type: str, deadline: Deadline
    ) -> list[RawEntity]: ...


class OpenAICompatibleLocalModel:
    """Client for a locally served OpenAI-compatible endpoint (vLLM, TGI, …)."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str = "EMPTY",
        timeout_seconds: float = 20.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._client = client
        self._capabilities: LocalModelCapabilities | None = None
        self._prompt_template = PROMPT_PATH.read_text(encoding="utf-8")

    # ---- transport -------------------------------------------------------

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

    # ---- capability probe ------------------------------------------------

    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        if self._capabilities is not None:
            return self._capabilities
        model_name = self._model
        try:
            response = await self._http().get(
                "/models", timeout=deadline.budget_for(self._timeout)
            )
            if response.status_code == httpx.codes.OK:
                served = [entry.get("id") for entry in response.json().get("data", [])]
                if served and self._model not in served:
                    # Trust the endpoint over our configuration: a mismatch here is
                    # a deployment error we should report, not silently paper over.
                    return self._cache(
                        LocalModelCapabilities(
                            reachable=True,
                            model_name=self._model,
                            supports_json_schema=False,
                            detail=f"configured model not served; endpoint offers {len(served)}",
                        )
                    )
        except httpx.HTTPError as exc:
            return self._cache(
                LocalModelCapabilities(
                    reachable=False, model_name=model_name,
                    supports_json_schema=False, detail=type(exc).__name__,
                )
            )

        supports_schema = await self._probe_json_schema(deadline)
        return self._cache(
            LocalModelCapabilities(
                reachable=True, model_name=model_name, supports_json_schema=supports_schema
            )
        )

    def _cache(self, capabilities: LocalModelCapabilities) -> LocalModelCapabilities:
        self._capabilities = capabilities
        return capabilities

    async def _probe_json_schema(self, deadline: Deadline) -> bool:
        """One tiny structured-output call. If the endpoint rejects the parameter
        we fall back to prompt-constrained JSON plus the same gateway-side
        validation, which is the only part that actually protects us."""
        try:
            response = await self._http().post(
                "/chat/completions",
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": "Return {\"entities\": []}."}],
                    "max_tokens": 32,
                    "temperature": 0.0,
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "entity_detection",
                            "schema": ENTITY_SCHEMA,
                            "strict": True,
                        },
                    },
                },
                timeout=deadline.budget_for(self._timeout),
            )
        except httpx.HTTPError:
            return False
        return response.status_code == httpx.codes.OK

    # ---- detection -------------------------------------------------------

    async def detect_entities(
        self, *, text: str, document_type: str, deadline: Deadline
    ) -> list[RawEntity]:
        capabilities = await self.probe(deadline)
        if not capabilities.reachable:
            raise DetectorUnavailable(
                f"local model unreachable: {capabilities.detail}",
                public_detail="local inspection unavailable",
            )

        system_prompt, user_prompt = self._render(text, document_type)
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
            "max_tokens": 4096,
        }
        if capabilities.supports_json_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "entity_detection",
                    "schema": ENTITY_SCHEMA,
                    "strict": True,
                },
            }
        # Never send reasoning_effort in the MVP (guide §10.3).

        try:
            response = await self._http().post(
                "/chat/completions", json=payload,
                timeout=deadline.budget_for(self._timeout),
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise DetectorUnavailable(
                f"local model call failed: {type(exc).__name__}",
                public_detail="local inspection unavailable",
            ) from exc

        body = response.content
        if len(body) > MAX_RESPONSE_BYTES:
            raise DetectorUnavailable(
                "local model response exceeded size limit",
                public_detail="local inspection unavailable",
            )
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise DetectorUnavailable(
                "local model response had an unexpected envelope",
                public_detail="local inspection unavailable",
            ) from exc
        return parse_entity_payload(content)

    def _render(self, text: str, document_type: str) -> tuple[str, str]:
        template = self._prompt_template
        system_part, _, user_part = template.partition("USER:")
        system_prompt = system_part.replace("SYSTEM:", "", 1).strip()
        user_prompt = (
            user_part.replace("{{document_type}}", document_type)
            .replace("{{normalized_text}}", text)
            .strip()
        )
        return system_prompt, user_prompt


def parse_entity_payload(content: str) -> list[RawEntity]:
    """Parse and shape-check the model's JSON. Raises on anything unexpected."""
    text = content.strip()
    if text.startswith("```"):
        text = "\n".join(
            line for line in text.splitlines() if not line.strip().startswith("```")
        ).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DetectorUnavailable(
            "local model returned malformed JSON",
            public_detail="local inspection unavailable",
        ) from exc
    if not isinstance(parsed, dict) or set(parsed) - {"entities"}:
        raise DetectorUnavailable(
            "local model returned unexpected top-level fields",
            public_detail="local inspection unavailable",
        )
    entities = parsed.get("entities")
    if not isinstance(entities, list):
        raise DetectorUnavailable(
            "local model 'entities' is not a list",
            public_detail="local inspection unavailable",
        )
    if len(entities) > MAX_ENTITIES:
        raise DetectorUnavailable(
            "local model returned too many entities",
            public_detail="local inspection unavailable",
        )

    out: list[RawEntity] = []
    required = {"start", "end", "text", "type", "confidence"}
    for entry in entities:
        if not isinstance(entry, dict) or set(entry) != required:
            raise DetectorUnavailable(
                "local model entity had unexpected fields",
                public_detail="local inspection unavailable",
            )
        try:
            out.append(
                RawEntity(
                    start=int(entry["start"]),
                    end=int(entry["end"]),
                    text=str(entry["text"]),
                    type=str(entry["type"]),
                    confidence=float(entry["confidence"]),
                )
            )
        except (TypeError, ValueError) as exc:
            raise DetectorUnavailable(
                "local model entity had non-conforming field types",
                public_detail="local inspection unavailable",
            ) from exc
    return out


@dataclass(frozen=True, slots=True)
class SpanVerification:
    accepted: list[RawEntity]
    rejected: int


def verify_spans(text: str, entities: list[RawEntity]) -> SpanVerification:
    """Drop every entity whose span does not exactly reproduce the input.

    This is what makes the model's output safe to act on. Without it, a
    hallucinated offset would tokenize an unrelated stretch of the document, and
    a hallucinated ``text`` would let the model choose what we replace.
    """
    accepted: list[RawEntity] = []
    rejected = 0
    length = len(text)
    for entity in entities:
        if entity.type not in {e.value for e in LOCAL_MODEL_ENTITIES}:
            rejected += 1
            continue
        if not (0 <= entity.start < entity.end <= length):
            rejected += 1
            continue
        if entity.end - entity.start > MAX_SPAN_LENGTH:
            rejected += 1
            continue
        if text[entity.start : entity.end] != entity.text:
            rejected += 1
            continue
        accepted.append(entity)
    return SpanVerification(accepted=accepted, rejected=rejected)


class LocalModelDetector:
    """Adapts a :class:`LocalModelClient` into gateway findings."""

    name = "local_model_detector"

    def __init__(self, client: LocalModelClient) -> None:
        self._client = client

    async def detect(
        self, item: ContentItem, parsed: ParsedItem, deadline: Deadline
    ) -> list[Finding]:
        text = parsed.normalized_text
        if not text.strip():
            return []
        document_type = parsed.inspection_notes.get("document_type", "unknown")
        raw = await self._client.detect_entities(
            text=text, document_type=str(document_type), deadline=deadline
        )
        verification = verify_spans(text, raw)
        findings: list[Finding] = []
        for entity in verification.accepted:
            findings.append(
                Finding(
                    item_id=item.item_id,
                    entity_type=EntityType(entity.type),
                    source=FindingSource.LOCAL_MODEL,
                    start=entity.start,
                    end=entity.end,
                    confidence=clamp_confidence(entity.confidence),
                    rule_id="local_model_v1",
                    raw_text=text[entity.start : entity.end],
                    metadata={"rejected_spans": verification.rejected},
                )
            )
        return findings


class ScriptedLocalModel:
    """Deterministic fake for tests, smoke runs and offline development.

    Kept in the application package (not in ``tests/``) so the docker ``dev``
    profile can run the whole gateway without a GPU. It is never selected unless
    the configuration explicitly asks for it.
    """

    def __init__(self, responses: dict[str, list[RawEntity]] | None = None,
                 *, default: list[RawEntity] | None = None,
                 supports_json_schema: bool = True) -> None:
        self._responses = responses or {}
        self._default = default or []
        self._supports_json_schema = supports_json_schema
        self.calls: list[str] = []

    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        return LocalModelCapabilities(
            reachable=True, model_name="scripted",
            supports_json_schema=self._supports_json_schema,
        )

    async def detect_entities(
        self, *, text: str, document_type: str, deadline: Deadline
    ) -> list[RawEntity]:
        self.calls.append(text)
        return list(self._responses.get(text, self._default))
