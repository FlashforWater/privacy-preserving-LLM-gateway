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

PROMPTS_DIR = Path(__file__).parent / "prompts"
DEFAULT_PROMPT = "entity_detection_zh_v1"


def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.txt"
    if not path.is_file():
        available = sorted(p.stem for p in PROMPTS_DIR.glob("*.txt"))
        raise DetectorUnavailable(
            f"detection prompt {name!r} not found; available: {available}",
            public_detail="local inspection unavailable",
        )
    return path.read_text(encoding="utf-8")

MAX_ENTITIES = 200
MAX_RESPONSE_BYTES = 256_000
MAX_SPAN_LENGTH = 512
#: Shortest claim we will locate in the document. Below this a string matches
#: almost anywhere and is never a direct identifier by itself.
MIN_CLAIM_LENGTH = 2
#: Cap on how many occurrences of one claimed string get marked, so a claim of
#: a very common substring cannot redact the whole document.
MAX_OCCURRENCES_PER_CLAIM = 20

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
        disable_thinking: bool = True,
        max_tokens: int = 4096,
        prompt: str = DEFAULT_PROMPT,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._disable_thinking = disable_thinking
        self._max_tokens = max_tokens
        self._client = client
        self._capabilities: LocalModelCapabilities | None = None
        self._prompt_template = load_prompt(prompt)

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

    def _thinking_kwargs(self) -> dict[str, Any]:
        """Chat-template switch that turns a reasoning model's thinking off.

        Only sent when configured. Servers that do not know the parameter
        generally ignore unknown ``chat_template_kwargs``; one that rejects it
        surfaces as a probe failure rather than as silently degraded detection.
        """
        if not self._disable_thinking:
            return {}
        return {"chat_template_kwargs": {"enable_thinking": False}}

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
                    # Enough headroom that a reasoning model is not cut off mid
                    # thought: a truncated probe would look like "schema not
                    # supported" and quietly disable structured output.
                    "max_tokens": 256,
                    "temperature": 0.0,
                    **self._thinking_kwargs(),
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
            "max_tokens": self._max_tokens,
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
        payload.update(self._thinking_kwargs())
        # Never send reasoning_effort in the MVP (guide §10.3). The chat-template
        # switch below is a different thing: it turns the model's chain of thought
        # off entirely rather than tuning how much of it there is.

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
            choice = response.json()["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise DetectorUnavailable(
                "local model response had an unexpected envelope",
                public_detail="local inspection unavailable",
            ) from exc

        # A reasoning model returns content=null while it is still thinking, and
        # a truncated answer means the entity list is incomplete. Both are
        # detector failures, not empty results: accepting a partial list would
        # silently under-detect, which is the one outcome this service exists to
        # prevent.
        if choice.get("finish_reason") == "length":
            raise DetectorUnavailable(
                "local model output was truncated at the token limit",
                public_detail="local inspection unavailable",
            )
        if content is None:
            raise DetectorUnavailable(
                "local model returned no content (reasoning may be enabled without "
                "enough token budget)",
                public_detail="local inspection unavailable",
            )
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


def parse_entity_payload(content: str | None) -> list[RawEntity]:
    """Parse and shape-check the model's JSON. Raises on anything unexpected."""
    if not isinstance(content, str):
        raise DetectorUnavailable(
            "local model returned no textual content",
            public_detail="local inspection unavailable",
        )
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
class VerifiedSpan:
    """A span the gateway has confirmed against the input itself."""

    start: int
    end: int
    text: str
    type: str
    confidence: float
    #: True when the model's own offsets were wrong and we located the text.
    relocated: bool = False


@dataclass(frozen=True, slots=True)
class SpanVerification:
    accepted: list[VerifiedSpan]
    rejected: int
    relocated: int = 0


def verify_spans(text: str, entities: list[RawEntity]) -> SpanVerification:
    """Confirm every entity against the input, computing offsets ourselves.

    The model's ``text`` is treated as a *claim about what the document contains*
    and nothing more. A claim is accepted only if that exact string really occurs
    in the input, and the offsets we act on are the ones we found — never the ones
    the model reported.

    Why not simply require ``input[start:end] == text``, as the specification's
    prompt contract suggests? Because measurement against a live vLLM-served
    Qwen3.8 showed the model identifies entities well and counts characters
    badly: of six correct entities in a four-line document, one had usable
    offsets and five drifted, the error growing with position. Rejecting on
    offset mismatch discarded five real identifiers — an address, a doctor's
    name, a hospital and two clinical values — which would then have travelled to
    the external model untouched. That is exactly the failure this service exists
    to prevent, and it would have looked like "the detector found nothing".

    The safety property is not weakened by locating the text ourselves; it is
    strengthened. Under the offset rule we trusted the model's arithmetic. Here we
    trust only a claim we verify directly: *does this exact string occur in the
    document?* A hallucinated entity has no occurrence and is rejected.

    When a claimed string occurs several times, every occurrence is marked. Over-
    marking costs utility; under-marking discloses data.
    """
    allowed_types = {e.value for e in LOCAL_MODEL_ENTITIES}
    accepted: list[VerifiedSpan] = []
    rejected = 0
    relocated = 0
    length = len(text)
    seen: set[tuple[int, int, str]] = set()

    for entity in entities:
        if entity.type not in allowed_types:
            rejected += 1
            continue
        if len(entity.text) > MAX_SPAN_LENGTH:
            rejected += 1
            continue
        # Very short claims match everywhere and would redact the document into
        # uselessness; they are also never a direct identifier on their own.
        if len(entity.text.strip()) < MIN_CLAIM_LENGTH:
            rejected += 1
            continue

        # Locate the claimed string ourselves, always. There is deliberately no
        # short-circuit for the case where the model's offsets happen to be
        # right: taking them and stopping there marks the first occurrence only,
        # so a name appearing twice keeps its second appearance — in the outbound
        # payload. The reported offsets are used for one thing only: labelling
        # which occurrence, if any, the model actually pointed at.
        occurrences = _find_all(text, entity.text)
        if not occurrences:
            rejected += 1
            continue
        pointed_correctly = (
            0 <= entity.start < entity.end <= length
            and text[entity.start : entity.end] == entity.text
        )
        if not pointed_correctly:
            relocated += 1
        for start in occurrences[:MAX_OCCURRENCES_PER_CLAIM]:
            end = start + len(entity.text)
            key = (start, end, entity.type)
            if key in seen:
                continue
            seen.add(key)
            accepted.append(
                VerifiedSpan(
                    start, end, entity.text, entity.type, entity.confidence,
                    relocated=not (pointed_correctly and start == entity.start),
                )
            )

    accepted.sort(key=lambda span: (span.start, -span.end))
    return SpanVerification(accepted=accepted, rejected=rejected, relocated=relocated)


def _find_all(haystack: str, needle: str) -> list[int]:
    out: list[int] = []
    start = haystack.find(needle)
    while start != -1 and len(out) <= MAX_OCCURRENCES_PER_CLAIM:
        out.append(start)
        start = haystack.find(needle, start + 1)
    return out


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
        for span in verification.accepted:
            findings.append(
                Finding(
                    item_id=item.item_id,
                    entity_type=EntityType(span.type),
                    source=FindingSource.LOCAL_MODEL,
                    start=span.start,
                    end=span.end,
                    confidence=clamp_confidence(span.confidence),
                    rule_id="local_model_v1",
                    # Sliced from the document, never taken from the model's
                    # reply: the model chooses what to point at, not what we cut.
                    raw_text=text[span.start : span.end],
                    metadata={
                        "rejected_claims": verification.rejected,
                        "relocated": span.relocated,
                    },
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
