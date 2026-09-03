"""Shared test wiring.

Everything here is deterministic and offline: a scripted local model, a static
OCR engine, an in-memory vault and a recording provider adapter. Guide §20.2 —
default local development must not send data to the internet, and a test that
needs a network is a test nobody runs.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

os.environ.setdefault("APP_ENV", "test")

from app.core.config import Principal, Settings  # noqa: E402
from app.core.deadlines import Deadline  # noqa: E402
from app.detectors.image_classifier import HeuristicImageClassifier  # noqa: E402
from app.detectors.keyword_detector import KeywordDetector  # noqa: E402
from app.detectors.local_model_detector import (  # noqa: E402
    LocalModelDetector,
    RawEntity,
    ScriptedLocalModel,
)
from app.detectors.regex_detector import RegexDetector  # noqa: E402
from app.domain.content import Manifest  # noqa: E402
from app.domain.requests import NormalizedRequest, RequestContext  # noqa: E402
from app.domain.scopes import ScopeLimits, ScopeRecord  # noqa: E402
from app.external.openai_compatible import RecordingAdapter  # noqa: E402
from app.gateway.normalizer import Normalizer  # noqa: E402
from app.gateway.orchestrator import Orchestrator, OrchestratorDependencies  # noqa: E402
from app.gateway.scope_service import InMemoryScopeStore, ScopeService  # noqa: E402
from app.ocr.local_ocr import StaticOcrEngine  # noqa: E402
from app.parsers.base import ParserLimits, ParserRegistry  # noqa: E402
from app.parsers.docx import DocxParser  # noqa: E402
from app.parsers.image import ImageParser  # noqa: E402
from app.parsers.plain_text import PlainTextParser  # noqa: E402
from app.parsers.xlsx import XlsxParser  # noqa: E402
from app.policy.engine import PolicyEngine  # noqa: E402
from app.policy.loader import load_policy_document  # noqa: E402
from app.restore.restorer import Restorer  # noqa: E402
from app.vault.crypto import StaticKeyProvider, VaultCipher  # noqa: E402
from app.vault.memory_vault import MemoryVault  # noqa: E402

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.default.yaml"

MASTER_KEY = b"\x01" * 32
HMAC_KEY = b"\x02" * 32


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine(load_policy_document(POLICY_PATH))


@pytest.fixture(autouse=True)
def _isolate_from_dotenv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the developer's .env out of the test run.

    Settings reads .env by default, so a machine with a configured gateway made
    assertions about production rejection pass or fail depending on whose laptop
    ran them. Tests have to describe the code, not the checkout.
    """
    for name in list(os.environ):
        if name.startswith(
            ("APP_", "POLICY_", "VAULT_", "SCOPE_", "LOCAL_MODEL_", "EXTERNAL_",
             "OCR_", "DEV_STATIC_", "STORAGE_", "DATABASE_", "MAPPING_", "ENABLE_",
             "REQUEST_", "MAX_CONCURRENT")
        ):
            monkeypatch.delenv(name, raising=False)
    # model_config is a TypedDict, so the entry is replaced rather than an
    # attribute set.
    monkeypatch.setitem(Settings.model_config, "env_file", None)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        policy_file=POLICY_PATH,
        vault_master_key_b64=base64.b64encode(MASTER_KEY).decode(),
        vault_hmac_key_b64=base64.b64encode(HMAC_KEY).decode(),
        external_allowed_models="model-a,external-vlm-model",
        dev_static_tokens="dev-token-1:tenant-a:svc-claims:general|medical_report_analysis",
        storage_backend="memory",
    )


@pytest.fixture
def principal() -> Principal:
    return Principal(
        principal_id="svc-claims",
        tenant_id="tenant-a",
        allowed_purposes=frozenset({"general", "medical_report_analysis"}),
    )


@dataclass
class Harness:
    """A fully wired gateway with deterministic dependencies."""

    policy: PolicyEngine
    orchestrator: Orchestrator
    scopes: ScopeService
    scope_store: InMemoryScopeStore
    vault: MemoryVault
    adapter: RecordingAdapter
    normalizer: Normalizer
    local_model: ScriptedLocalModel
    ocr: StaticOcrEngine
    principal: Principal
    parser_limits: ParserLimits = field(default_factory=ParserLimits)

    async def open_scope(self) -> ScopeRecord:
        return await self.scopes.create(tenant_id=self.principal.tenant_id)

    def normalize(self, manifest: Manifest, files: dict[str, bytes] | None = None) -> NormalizedRequest:
        return self.normalizer.normalize(manifest, files or {}, self.parser_limits)

    def context(self, scope: ScopeRecord, manifest: Manifest, *, seconds: float = 30.0) -> RequestContext:
        return RequestContext.create(
            principal=self.principal,
            scope=scope,
            manifest=manifest,
            deadline=Deadline.after(seconds),
        )


@pytest.fixture
def local_model() -> ScriptedLocalModel:
    return ScriptedLocalModel()


@pytest.fixture
def ocr() -> StaticOcrEngine:
    return StaticOcrEngine()


@pytest.fixture
def harness(
    policy: PolicyEngine,
    principal: Principal,
    local_model: ScriptedLocalModel,
    ocr: StaticOcrEngine,
) -> Iterator[Harness]:
    cipher = VaultCipher(StaticKeyProvider(master=MASTER_KEY, hmac=HMAC_KEY))
    scope_store = InMemoryScopeStore()
    vault = MemoryVault(cipher, scope_store.live_scopes())
    limits = policy.document.limits

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
        idle_ttl_seconds=7200,
        absolute_ttl_seconds=86400,
        policy_version=policy.version,
    )

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
            ImageParser(ocr_engine=ocr, classifier=HeuristicImageClassifier()),
        ]
    )
    adapter = RecordingAdapter()

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
            hmac_key=HMAC_KEY,
            mapping_ttl_seconds=86400,
            parser_limits=parser_limits,
            scope_limits=scopes.limits,
            allowed_models=frozenset({"model-a", "external-vlm-model"}),
        )
    )

    yield Harness(
        policy=policy,
        orchestrator=orchestrator,
        scopes=scopes,
        scope_store=scope_store,
        vault=vault,
        adapter=adapter,
        normalizer=Normalizer(
            max_request_bytes=limits.max_request_bytes, max_file_bytes=limits.max_file_bytes
        ),
        local_model=local_model,
        ocr=ocr,
        principal=principal,
        parser_limits=parser_limits,
    )


def text_manifest(text: str, *, purpose: str = "general", model: str = "model-a",
                  item_id: str = "prompt-1") -> Manifest:
    return Manifest.model_validate(
        {
            "purpose": purpose,
            "model": model,
            "messages": [
                {"role": "user", "content": [{"type": "text", "item_id": item_id, "text": text}]}
            ],
        }
    )


def entity(start: int, end: int, text: str, kind: str, confidence: float = 0.9) -> RawEntity:
    return RawEntity(start=start, end=end, text=text, type=kind, confidence=confidence)
