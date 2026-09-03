"""Failure injection (guide §15.1, §19.5).

The central assertion, repeated for every dependency:

    When inspection or protection is incomplete, the external-provider fake
    receives zero unsafe bytes.

Each test breaks exactly one dependency and asserts both halves: the request
fails, *and* nothing reached the provider.
"""

from __future__ import annotations

import pytest

from app.core.deadlines import Deadline
from app.core.errors import (
    ContentBlocked,
    GatewayError,
    InspectionFailedClosed,
    RequestDeadlineExceeded,
)
from app.detectors.base import DetectorUnavailable
from app.detectors.local_model_detector import LocalModelCapabilities
from app.ocr.base import OcrUnavailable
from app.vault.base import PendingMapping
from tests.conftest import Harness, text_manifest
from tests.fixtures import synthetic


async def attempt(harness: Harness, text: str = None, files=None, manifest=None):
    scope = await harness.open_scope()
    manifest = manifest or text_manifest(text or synthetic.TEXT_WITH_IDENTIFIERS)
    normalized = harness.normalize(manifest, files or {})
    return await harness.orchestrator.process(harness.context(scope, manifest), normalized)


class BrokenLocalModel:
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        return LocalModelCapabilities(
            reachable=False, model_name="broken", supports_json_schema=False,
            detail="ConnectError",
        )

    async def detect_entities(self, *, text: str, document_type: str, deadline: Deadline):
        raise DetectorUnavailable(
            "local model unreachable", public_detail="local inspection unavailable"
        )


class MalformedLocalModel:
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        return LocalModelCapabilities(
            reachable=True, model_name="fake", supports_json_schema=True
        )

    async def detect_entities(self, *, text: str, document_type: str, deadline: Deadline):
        from app.detectors.local_model_detector import parse_entity_payload

        return parse_entity_payload("I could not comply with the schema, sorry.")


class BrokenOcr:
    name = "broken-ocr"

    def read_image(self, data: bytes, *, max_pixels: int):
        raise OcrUnavailable("ocr crashed", public_detail="local inspection unavailable")


class BrokenVault:
    async def find_token_by_digest(self, **kwargs: object) -> str | None:
        return None

    async def put_all_and_lock_scope(self, **kwargs: object) -> int:
        from app.core.errors import VaultError

        raise VaultError("vault write failed", public_detail="request could not be completed")

    async def resolve(self, **kwargs: object) -> str | None:
        return None

    async def delete_scope(self, **kwargs: object) -> int:
        return 0

    async def purge_expired(self, **kwargs: object) -> int:
        return 0


class TestLocalModelFailures:
    async def test_unreachable_model_fails_closed(self, harness: Harness) -> None:
        from app.detectors.local_model_detector import LocalModelDetector

        harness.orchestrator.deps.local_model_detector = LocalModelDetector(
            BrokenLocalModel()
        )
        with pytest.raises(DetectorUnavailable):
            await attempt(harness)
        assert harness.adapter.requests == []

    async def test_malformed_output_fails_closed(self, harness: Harness) -> None:
        from app.detectors.local_model_detector import LocalModelDetector

        harness.orchestrator.deps.local_model_detector = LocalModelDetector(
            MalformedLocalModel()
        )
        with pytest.raises(DetectorUnavailable):
            await attempt(harness)
        assert harness.adapter.requests == []

    async def test_failure_never_degrades_to_rules_only(self, harness: Harness) -> None:
        """A broken semantic detector must not silently reduce coverage.

        Continuing with deterministic rules alone would look like success while
        missing every unlabelled name in the document.
        """
        from app.detectors.local_model_detector import LocalModelDetector

        harness.orchestrator.deps.local_model_detector = LocalModelDetector(
            BrokenLocalModel()
        )
        with pytest.raises(GatewayError):
            await attempt(harness, "A perfectly ordinary sentence with a name in it.")
        assert harness.adapter.requests == []


class TestOcrAndClassifierFailures:
    async def test_ocr_failure_does_not_classify_an_image_as_ordinary(
        self, harness: Harness
    ) -> None:
        from app.detectors.image_classifier import HeuristicImageClassifier
        from app.parsers.base import ParserRegistry
        from app.parsers.docx import DocxParser
        from app.parsers.image import ImageParser
        from app.parsers.plain_text import PlainTextParser
        from app.parsers.xlsx import XlsxParser
        from app.domain.content import Manifest

        harness.orchestrator.deps.parsers = ParserRegistry(
            [
                PlainTextParser(), DocxParser(), XlsxParser(),
                ImageParser(ocr_engine=BrokenOcr(), classifier=HeuristicImageClassifier()),
            ]
        )
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "external-vlm-model",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "image", "item_id": "img-1", "file_field": "file_img-1"}
                        ],
                    }
                ],
            }
        )
        with pytest.raises(ContentBlocked):
            await attempt(harness, manifest=manifest,
                          files={"file_img-1": synthetic.ORDINARY_IMAGE})
        assert harness.adapter.captured_bytes() == b""


class TestVaultFailures:
    async def test_vault_write_failure_prevents_the_external_call(
        self, harness: Harness
    ) -> None:
        harness.orchestrator.deps.vault = BrokenVault()
        with pytest.raises(GatewayError):
            await attempt(harness)
        assert harness.adapter.requests == []

    async def test_mapping_limit_blocks_before_forwarding(self, harness: Harness) -> None:
        from app.core.errors import ScopeLimitExceeded

        scope = await harness.open_scope()
        scope.mapping_count = harness.scopes.limits.max_mappings
        manifest = text_manifest(synthetic.TEXT_WITH_IDENTIFIERS)
        normalized = harness.normalize(manifest)
        with pytest.raises(ScopeLimitExceeded):
            await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        assert harness.adapter.requests == []


class TestDeadlines:
    async def test_expired_deadline_stops_before_the_provider(
        self, harness: Harness
    ) -> None:
        scope = await harness.open_scope()
        manifest = text_manifest(synthetic.CLEAN_TEXT)
        normalized = harness.normalize(manifest)
        context = harness.context(scope, manifest, seconds=0.0)
        with pytest.raises(RequestDeadlineExceeded):
            await harness.orchestrator.process(context, normalized)
        assert harness.adapter.requests == []

    def test_budget_reserves_time_for_downstream_work(self) -> None:
        deadline = Deadline.after(10.0)
        assert deadline.budget_for(60.0, reserve=2.0) <= 8.0

    def test_budget_raises_when_nothing_is_left(self) -> None:
        deadline = Deadline.after(0.0)
        with pytest.raises(RequestDeadlineExceeded):
            deadline.budget_for(5.0)


class TestParserFailures:
    async def test_malformed_archive_fails_closed(self, harness: Harness) -> None:
        from app.domain.content import Manifest

        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "model-a",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "file", "item_id": "doc-1", "file_field": "file_doc-1"}
                        ],
                    }
                ],
            }
        )
        broken = b"PK\x03\x04" + b"\x00" * 64
        with pytest.raises(GatewayError):
            await attempt(harness, manifest=manifest, files={"file_doc-1": broken})
        assert harness.adapter.requests == []

    async def test_partial_parse_is_not_a_pass(self, harness: Harness) -> None:
        """A DOCX with uninspectable embedded media must not take the fast path."""
        from app.domain.content import Manifest

        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "model-a",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "file", "item_id": "doc-1", "file_field": "file_doc-1"}
                        ],
                    }
                ],
            }
        )
        data = synthetic.docx_bytes(with_media=True)
        with pytest.raises(ContentBlocked):
            await attempt(harness, manifest=manifest, files={"file_doc-1": data})
        assert data not in harness.adapter.captured_bytes()
