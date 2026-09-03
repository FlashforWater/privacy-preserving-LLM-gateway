"""Application wiring.

One place builds every component, so "which vault / which detector / which
adapter is live" has a single answer that can be inspected at startup and
reported by ``/health/ready``.

Two guards live here rather than in the components:

* an in-memory vault or scope store cannot be selected in a production
  environment, whatever the rest of the configuration says;
* the scripted local model and recording adapter are development-only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.core.config import Settings
from app.core.deadlines import Deadline
from app.core.errors import ConfigurationError
from app.core.security import PrincipalVerifier, StaticTokenVerifier
from app.detectors.image_classifier import HeuristicImageClassifier
from app.detectors.keyword_detector import KeywordDetector
from app.detectors.local_model_detector import (
    LocalModelDetector,
    OpenAICompatibleLocalModel,
)
from app.detectors.regex_detector import RegexDetector
from app.domain.scopes import ScopeLimits
from app.external.openai_compatible import OpenAICompatibleAdapter
from app.gateway.normalizer import Normalizer
from app.gateway.orchestrator import Orchestrator, OrchestratorDependencies
from app.gateway.scope_service import InMemoryScopeStore, ScopeService, ScopeStore
from app.ocr.local_ocr import build_ocr_engine
from app.parsers.base import ParserLimits, ParserRegistry
from app.parsers.docx import DocxParser
from app.parsers.image import ImageParser
from app.parsers.pdf import PdfParser
from app.parsers.plain_text import PlainTextParser
from app.parsers.xlsx import XlsxParser
from app.policy.engine import PolicyEngine
from app.policy.loader import get_policy
from app.restore.restorer import Restorer
from app.vault.crypto import StaticKeyProvider, VaultCipher
from app.vault.base import Vault
from app.vault.memory_vault import MemoryVault

logger = logging.getLogger("gateway.wiring")


@dataclass(slots=True)
class Application:
    settings: Settings
    policy: PolicyEngine
    verifier: PrincipalVerifier
    normalizer: Normalizer
    orchestrator: Orchestrator
    scopes: ScopeService
    scope_store: ScopeStore
    parser_limits: ParserLimits
    local_model: OpenAICompatibleLocalModel
    ocr_backend: str
    ready_errors: list[str]

    @property
    def is_ready(self) -> bool:
        return not self.ready_errors

    async def probe_dependencies(self, deadline: Deadline) -> list[str]:
        """Live readiness checks (guide §8.4).

        Static configuration problems are already in ``ready_errors``; this adds
        the ones that can only be answered by asking. The local model is required
        for semantic detection, so an unreachable one means requests that need it
        would fail closed — better to report not-ready and stay out of rotation.
        """
        problems = list(self.ready_errors)
        try:
            capabilities = await self.local_model.probe(deadline)
        except Exception as exc:  # noqa: BLE001 - any probe failure is a readiness failure
            problems.append(f"local model probe failed: {type(exc).__name__}")
        else:
            if not capabilities.reachable:
                problems.append(f"local model unreachable: {capabilities.detail}")
        return problems


def build_application(settings: Settings) -> Application:
    settings.validate_for_environment()

    policy_document = get_policy(settings.policy_file)
    policy = PolicyEngine(policy_document)
    limits = policy_document.limits

    keys = StaticKeyProvider(
        master=settings.vault_master_key(), hmac=settings.vault_hmac_key()
    )
    cipher = VaultCipher(keys)
    cipher.self_test()

    ready_errors: list[str] = []

    scope_store: ScopeStore
    vault: Vault
    if settings.storage_backend == "postgres":
        from sqlalchemy.ext.asyncio import create_async_engine

        from app.gateway.scope_store_postgres import PostgresScopeStore
        from app.vault.postgres_vault import PostgresVault

        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        scope_store = PostgresScopeStore(engine)
        vault = PostgresVault(engine, cipher)
    else:
        if settings.is_production:  # pragma: no cover - blocked by config validation
            raise ConfigurationError("memory storage backend is not permitted in production")
        memory_store = InMemoryScopeStore()
        scope_store = memory_store
        vault = MemoryVault(cipher, memory_store.live_scopes())

    scopes = ScopeService(
        scope_store,
        vault,
        limits=ScopeLimits(
            max_turns=limits.max_scope_turns,
            max_files=limits.max_scope_files,
            max_bytes=limits.max_scope_bytes,
            max_pages=limits.max_scope_pages,
            max_mappings=limits.max_scope_mappings,
        ),
        idle_ttl_seconds=settings.scope_idle_ttl_seconds,
        absolute_ttl_seconds=settings.scope_absolute_ttl_seconds,
        policy_version=policy.version,
    )

    ocr_engine = build_ocr_engine(settings.ocr_backend)
    classifier = HeuristicImageClassifier()
    parser_limits = ParserLimits(
        max_file_bytes=limits.max_file_bytes,
        max_pages=limits.max_scope_pages,
        max_ocr_pixels=limits.max_ocr_pixels,
    )
    parsers = ParserRegistry(
        [
            PlainTextParser(),
            DocxParser(),
            XlsxParser(),
            PdfParser(ocr_engine=ocr_engine),
            ImageParser(ocr_engine=ocr_engine, classifier=classifier),
        ]
    )

    local_model = OpenAICompatibleLocalModel(
        base_url=settings.local_model_base_url,
        model=settings.local_model_name,
        api_key=settings.local_model_api_key,
        timeout_seconds=settings.local_model_timeout_seconds,
    )

    adapter = OpenAICompatibleAdapter(
        base_url=settings.external_base_url,
        api_key=settings.external_api_key,
        allowed_models=settings.allowed_models,
        timeout_seconds=settings.external_timeout_seconds,
    )

    orchestrator = Orchestrator(
        OrchestratorDependencies(
            policy=policy,
            parsers=parsers,
            regex_detector=RegexDetector(),
            keyword_detector=KeywordDetector(),
            local_model_detector=LocalModelDetector(local_model),
            adapter=adapter,
            vault=vault,
            restorer=Restorer(vault),
            hmac_key=keys.hmac_key(),
            mapping_ttl_seconds=settings.mapping_ttl_seconds,
            parser_limits=parser_limits,
            scope_limits=scopes.limits,
            allowed_models=settings.allowed_models,
        )
    )

    verifier = StaticTokenVerifier(settings)
    if settings.is_production:
        # StaticTokenVerifier is a development stand-in. Production must supply an
        # mTLS or short-lived-identity verifier (guide §17.1) before serving.
        ready_errors.append("production requires a real principal verifier (mTLS/JWT)")

    normalizer = Normalizer(
        max_request_bytes=limits.max_request_bytes,
        max_file_bytes=limits.max_file_bytes,
    )

    if not settings.static_principals() and not settings.is_production:
        raise ConfigurationError("no principals configured; set DEV_STATIC_TOKENS")

    return Application(
        settings=settings,
        policy=policy,
        verifier=verifier,
        normalizer=normalizer,
        orchestrator=orchestrator,
        scopes=scopes,
        scope_store=scope_store,
        parser_limits=parser_limits,
        local_model=local_model,
        ocr_backend=settings.ocr_backend,
        ready_errors=ready_errors,
    )
