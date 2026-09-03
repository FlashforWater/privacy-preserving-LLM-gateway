"""Readiness gating and log-field allow-listing (guide §8.4, §17.3)."""

from __future__ import annotations

import logging

import pytest

from app.core.deadlines import Deadline
from app.core.logging import (
    ALLOWED_LOG_FIELDS,
    RedactionFilter,
    content_fingerprint,
    pseudonymous_id,
    safe_extra,
)
from app.detectors.local_model_detector import LocalModelCapabilities


class UnreachableModel:
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        return LocalModelCapabilities(
            reachable=False, model_name="m", supports_json_schema=False, detail="ConnectError"
        )


class ReachableModel:
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        return LocalModelCapabilities(
            reachable=True, model_name="m", supports_json_schema=True
        )


class ExplodingModel:
    async def probe(self, deadline: Deadline) -> LocalModelCapabilities:
        raise RuntimeError("boom")


def application_stub(model: object, ready_errors: list[str] | None = None):
    from app.api.dependencies import Application

    return Application(
        settings=None,  # type: ignore[arg-type]
        policy=None,  # type: ignore[arg-type]
        verifier=None,  # type: ignore[arg-type]
        normalizer=None,  # type: ignore[arg-type]
        orchestrator=None,  # type: ignore[arg-type]
        scopes=None,  # type: ignore[arg-type]
        scope_store=None,  # type: ignore[arg-type]
        parser_limits=None,  # type: ignore[arg-type]
        local_model=model,  # type: ignore[arg-type]
        ocr_backend="none",
        ready_errors=list(ready_errors or []),
    )


class TestReadiness:
    async def test_ready_when_dependencies_answer(self) -> None:
        app = application_stub(ReachableModel())
        assert await app.probe_dependencies(Deadline.after(1)) == []

    async def test_unreachable_local_model_is_not_ready(self) -> None:
        app = application_stub(UnreachableModel())
        problems = await app.probe_dependencies(Deadline.after(1))
        assert problems and "local model unreachable" in problems[0]

    async def test_probe_exception_is_not_ready(self) -> None:
        app = application_stub(ExplodingModel())
        problems = await app.probe_dependencies(Deadline.after(1))
        assert problems and "probe failed" in problems[0]

    async def test_static_configuration_problems_are_reported(self) -> None:
        app = application_stub(ReachableModel(), ["production requires a real verifier"])
        problems = await app.probe_dependencies(Deadline.after(1))
        assert "production requires a real verifier" in problems
        assert not app.is_ready


class TestSafeLogging:
    def test_allow_list_drops_unknown_fields(self) -> None:
        extra = safe_extra(request_id="r1", payload="secret", ocr_text="secret")
        assert extra["safe"] == {"request_id": "r1"}

    def test_every_allow_listed_field_survives(self) -> None:
        fields = dict.fromkeys(ALLOWED_LOG_FIELDS, "x")
        assert set(safe_extra(**fields)["safe"]) == ALLOWED_LOG_FIELDS

    @pytest.mark.parametrize(
        "message",
        [
            "Authorization: Bearer abc123",
            "card 4539578763621486",
            "mail someone@example.com",
            "token [[PGW_V1_PERSON_K7M4Q2Z9F8N3]]",
        ],
    )
    def test_redaction_filter_scrubs_known_shapes(self, message: str) -> None:
        record = logging.LogRecord("x", logging.INFO, __file__, 1, message, (), None)
        RedactionFilter().filter(record)
        assert "[REDACTED]" in record.getMessage()

    def test_pseudonymous_id_is_stable_and_keyed(self) -> None:
        a = pseudonymous_id("tenant-a", b"k" * 32)
        b = pseudonymous_id("tenant-a", b"k" * 32)
        c = pseudonymous_id("tenant-a", b"j" * 32)
        assert a == b
        assert a != c
        assert "tenant-a" not in a

    def test_fingerprint_is_keyed_not_a_bare_hash(self) -> None:
        """An unsalted digest of a phone number is reversible by enumeration.

        Keying it is what stops the audit trail becoming a lookup table.
        """
        import hashlib

        value = "13812345678"
        keyed = content_fingerprint(value, b"k" * 32)
        assert keyed != hashlib.sha256(value.encode()).hexdigest()
        assert value not in keyed
