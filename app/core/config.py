"""Configuration, validated at import/startup.

Guide §3.10 and §18: invalid policy or missing security settings must prevent the
service from becoming ready, and production must refuse to start with placeholder
keys, development secrets, wildcard provider hosts, or payload logging enabled.
Those checks live in :meth:`Settings.validate_for_environment`, which
``/health/ready`` and application startup both call.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import ConfigurationError

PLACEHOLDER_SECRETS: frozenset[str] = frozenset(
    {
        "development-only-placeholder",
        "change-me",
        "set-through-secret-manager",
        "",
    }
)


class Principal(BaseModel):
    """An authenticated internal caller. Tenant comes from here, never from the body.

    A plain model, deliberately not a settings class: a principal is constructed
    from a verified credential at request time, and a type that also reads the
    process environment could pick up a stray ``TENANT_ID`` and silently answer
    for the wrong tenant.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str
    tenant_id: str
    allowed_purposes: frozenset[str]

    def may_use_purpose(self, purpose: str) -> bool:
        return purpose in self.allowed_purposes


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="forbid", frozen=True
    )

    app_env: Literal["development", "test", "staging", "production"] = "development"
    app_host: str = "0.0.0.0"  # noqa: S104 - bound inside the container network
    app_port: int = 8080
    log_level: str = "INFO"

    policy_file: Path = Path("config/policy.default.yaml")
    request_deadline_seconds: float = 120.0
    max_concurrent_requests: int = 16

    database_url: str = "postgresql+asyncpg://privacy_gateway:change-me@postgres/privacy_gateway"
    # "memory" is a development convenience. Production is forced to "postgres"
    # by validate_for_environment; there is no way to run production on it.
    storage_backend: Literal["memory", "postgres"] = "memory"
    vault_master_key_b64: str = "development-only-placeholder"
    vault_hmac_key_b64: str = "development-only-placeholder"

    scope_idle_ttl_seconds: int = 7200
    scope_absolute_ttl_seconds: int = 86400
    scope_max_turns: int = 50
    scope_max_files: int = 20
    scope_max_bytes: int = 209_715_200
    scope_max_pages: int = 200
    scope_max_mappings: int = 5000
    mapping_ttl_seconds: int = 86400

    local_model_base_url: str = "http://local-model:8000/v1"
    local_model_name: str = "local-instruct-model"
    local_model_timeout_seconds: float = 20.0
    local_model_api_key: str = "EMPTY"
    # Reasoning models emit a chain of thought before any content. For span
    # detection that is pure cost and a truncation risk, so it is disabled by
    # default via the chat template. Set false for a server that rejects the
    # parameter; the detector then needs a larger token budget.
    local_model_disable_thinking: bool = True
    local_model_max_tokens: int = 4096
    # Detection prompt. The Chinese one is the default because the corpus is
    # Chinese and the served model follows Chinese instructions more closely:
    # measured on a claims note it used 515 completion tokens against 785 for
    # the English prompt, and stopped mis-labelling plates and phone numbers as
    # UNKNOWN_SENSITIVE (which the policy blocks on).
    local_model_prompt: str = "entity_detection_zh_v1"
    # Ask the local vision model to classify images as well. It can only make a
    # classification stricter, so enabling it cannot forward something the
    # text-based classifier would have withheld. Off by default because it costs
    # a model call per image and the served model must accept images.
    local_model_image_analysis: bool = False

    ocr_backend: Literal["local", "none"] = "local"
    ocr_timeout_seconds: float = 30.0

    external_provider: Literal["openai-compatible"] = "openai-compatible"
    external_base_url: str = "http://fake-external:9100/v1"
    external_api_key: str = "set-through-secret-manager"
    external_allowed_models: str = ""
    external_timeout_seconds: float = 60.0
    # Whether to ask the provider to skip its chain of thought.
    #
    # "provider_default" leaves it alone, which is what the design intends: the
    # external model is the reasoning engine, and the analysis it performs —
    # whether an injury matches an accident, whether materials contradict each
    # other — is the product.
    #
    # "disabled" is worth considering. Measured against deepseek-v4-flash on a
    # cross-material claims question (n=6 with reasoning, n=5 without):
    #   latency        2.4–6.3s   ->  1.3–2.1s
    #   completion     181–617    ->  117–138 tokens
    #   marker fidelity  4 of 6   ->  5 of 5 replies used the tokens intact
    # The fidelity difference has a plausible mechanism: during a long
    # deliberation the model paraphrases entities into "甲/乙" and writes the
    # answer from that paraphrase, losing the markers. Lost markers are a
    # utility problem, not a leak — restoration tolerates their absence — but a
    # reply that says "the driver" instead of a token cannot be attributed.
    #
    # The default is left at provider_default because analytical quality on hard
    # cases was assessed by reading a handful of answers, not measured. Decide it
    # with the Phase 2 evaluation set, not from this note.
    external_reasoning: Literal["provider_default", "disabled"] = "provider_default"
    # Models on the allow-list that accept image parts. Empty means the check is
    # off — the provider decides, and rejects with a 400 after the bytes have
    # already crossed the boundary for nothing. Listing them moves that refusal
    # to before the call, which is both a clearer error and one less pointless
    # transmission of an approved image.
    external_vision_models: str = ""
    # Per-model parameter constraints, "model=temperature" comma-separated.
    # Some models accept only one temperature and reject everything else with a
    # 400: kimi-k3 answers "only 1 is allowed for this model". Without this a
    # model can sit on the allow-list and fail every request that uses the
    # default. Parameter shaping is provider-format conversion, which is the
    # adapter's job, so it belongs here rather than in every caller's manifest.
    external_model_temperatures: str = ""

    @property
    def model_temperatures(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for entry in self.external_model_temperatures.split(","):
            entry = entry.strip()
            if not entry:
                continue
            model, _, value = entry.partition("=")
            if not model or not value:
                raise ConfigurationError(
                    "EXTERNAL_MODEL_TEMPERATURES entries must be model=temperature"
                )
            try:
                out[model.strip()] = float(value)
            except ValueError as exc:
                raise ConfigurationError(
                    f"EXTERNAL_MODEL_TEMPERATURES: {value!r} is not a number"
                ) from exc
        return out

    @property
    def vision_models(self) -> frozenset[str]:
        return frozenset(
            m.strip() for m in self.external_vision_models.split(",") if m.strip()
        )

    dev_static_tokens: str = ""

    enable_streaming: bool = False
    enable_payload_logging: bool = False

    # ---- derived helpers -------------------------------------------------

    @property
    def allowed_models(self) -> frozenset[str]:
        return frozenset(m.strip() for m in self.external_allowed_models.split(",") if m.strip())

    @property
    def is_production(self) -> bool:
        return self.app_env in ("staging", "production")

    def vault_master_key(self) -> bytes:
        return _decode_key(self.vault_master_key_b64, "VAULT_MASTER_KEY_B64")

    def vault_hmac_key(self) -> bytes:
        return _decode_key(self.vault_hmac_key_b64, "VAULT_HMAC_KEY_B64")

    def static_principals(self) -> dict[str, Principal]:
        """Parse ``DEV_STATIC_TOKENS``.

        Development-only. Production replaces this with mTLS or short-lived
        identity tokens; :meth:`validate_for_environment` refuses to start a
        production process that still has static tokens configured.
        """
        out: dict[str, Principal] = {}
        for raw in self.dev_static_tokens.split(","):
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(":")
            if len(parts) != 4:
                raise ConfigurationError(
                    "DEV_STATIC_TOKENS entries must be token:tenant:principal:purpose|purpose"
                )
            token, tenant, principal_id, purposes = parts
            out[token] = Principal(
                principal_id=principal_id,
                tenant_id=tenant,
                allowed_purposes=frozenset(p for p in purposes.split("|") if p),
            )
        return out

    # ---- validation ------------------------------------------------------

    @field_validator("external_base_url", "local_model_base_url")
    @classmethod
    def _must_be_absolute_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"{value!r} is not an absolute http(s) URL")
        if "*" in value:
            raise ValueError("wildcard hosts are not allowed for provider endpoints")
        return value

    @model_validator(mode="after")
    def _streaming_is_off(self) -> "Settings":
        if self.enable_streaming:
            # Guide §13.5: safe restoration across chunk boundaries is not designed yet.
            raise ValueError("streaming is not implemented in the MVP; set ENABLE_STREAMING=false")
        return self

    def validate_for_environment(self) -> None:
        """Hard startup gate. Raises :class:`ConfigurationError` on any violation."""
        problems: list[str] = []

        if not self.policy_file.exists():
            problems.append(f"policy file not found: {self.policy_file}")
        if not self.allowed_models:
            problems.append("EXTERNAL_ALLOWED_MODELS must list at least one model")

        for name, value in (
            ("VAULT_MASTER_KEY_B64", self.vault_master_key_b64),
            ("VAULT_HMAC_KEY_B64", self.vault_hmac_key_b64),
        ):
            if value in PLACEHOLDER_SECRETS:
                if self.is_production:
                    problems.append(f"{name} is a placeholder; production requires a real key")
            else:
                try:
                    _decode_key(value, name)
                except ConfigurationError as exc:
                    problems.append(str(exc))

        if self.is_production:
            if self.storage_backend != "postgres":
                problems.append("production requires STORAGE_BACKEND=postgres")
            if self.enable_payload_logging:
                problems.append("ENABLE_PAYLOAD_LOGGING must be false in production")
            if self.dev_static_tokens:
                problems.append("DEV_STATIC_TOKENS must be empty in production")
            if self.external_api_key in PLACEHOLDER_SECRETS:
                problems.append("EXTERNAL_API_KEY must come from the secret manager")
            if "change-me" in self.database_url:
                problems.append("DATABASE_URL still contains the development password")
            if urlparse(self.external_base_url).scheme != "https":
                problems.append("EXTERNAL_BASE_URL must use https in production")

        if problems:
            raise ConfigurationError(
                "configuration rejected: " + "; ".join(problems),
                public_detail="service configuration is invalid",
            )


def _decode_key(value: str, name: str) -> bytes:
    if value in PLACEHOLDER_SECRETS:
        raise ConfigurationError(f"{name} is not configured")
    try:
        key = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - surfaced as a configuration error
        raise ConfigurationError(f"{name} is not valid base64") from exc
    if len(key) != 32:
        raise ConfigurationError(f"{name} must decode to exactly 32 bytes, got {len(key)}")
    return key


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test hook. Never call this from request handling."""
    get_settings.cache_clear()
