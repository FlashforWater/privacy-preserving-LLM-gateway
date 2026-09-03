"""Outbound-capture and log-capture assertions (guide §19.4).

Two properties, both stated as "no fixture identifier appears in X":

* the recording provider adapter never receives one;
* normal logs never contain one.

These are the tests that would catch a refactor quietly reintroducing a leak, so
they check the *captured artefacts*, not internal flags.
"""

from __future__ import annotations

import logging

import pytest

from app.core.errors import ContentBlocked
from app.observability.audit import AuditRecord
from tests.conftest import Harness, entity, text_manifest
from tests.fixtures import synthetic


async def send(harness: Harness, text: str, purpose: str = "general"):
    scope = await harness.open_scope()
    manifest = text_manifest(text, purpose=purpose)
    normalized = harness.normalize(manifest)
    return await harness.orchestrator.process(harness.context(scope, manifest), normalized)


class TestOutboundCapture:
    async def test_no_synthetic_identifier_reaches_the_provider(
        self, harness: Harness
    ) -> None:
        text = (
            f"Patient {synthetic.PERSON_CJK}, ID {synthetic.ID_CARD}, "
            f"phone {synthetic.PHONE}, card {synthetic.BANK_CARD}, "
            f"email {synthetic.EMAIL}, plate {synthetic.PLATE}."
        )
        harness.local_model._default = [  # noqa: SLF001
            entity(text.index(synthetic.PERSON_CJK),
                   text.index(synthetic.PERSON_CJK) + len(synthetic.PERSON_CJK),
                   synthetic.PERSON_CJK, "PERSON")
        ]
        await send(harness, text)
        captured = harness.adapter.captured_text()
        for secret in (synthetic.ID_CARD, synthetic.PHONE, synthetic.BANK_CARD,
                       synthetic.EMAIL, synthetic.PLATE):
            assert secret not in captured, secret

    async def test_blocked_request_sends_nothing_at_all(self, harness: Harness) -> None:
        text = f"Diagnosis: acute hepatitis. Patient ID {synthetic.ID_CARD}."
        harness.local_model._default = [  # noqa: SLF001
            entity(text.index("acute hepatitis"),
                   text.index("acute hepatitis") + len("acute hepatitis"),
                   "acute hepatitis", "MEDICAL_DATA")
        ]
        with pytest.raises(ContentBlocked):
            await send(harness, text)
        assert harness.adapter.requests == []
        assert harness.adapter.captured_bytes() == b""


class TestLogCapture:
    async def test_logs_contain_no_fixture_identifiers(
        self, harness: Harness, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        await send(harness, synthetic.TEXT_WITH_IDENTIFIERS)
        blob = "\n".join(record.getMessage() + str(getattr(record, "safe", "")) for record in caplog.records)
        for secret in synthetic.ALL_SECRETS:
            assert secret not in blob, secret

    def test_audit_record_carries_fingerprints_not_values(self) -> None:
        from app.core.enums import EntityType, FindingSource
        from app.domain.findings import Finding

        record = AuditRecord(
            request_id="req", scope_id="scp", tenant_hash="t", principal_hash="p",
            policy_version="v1",
        )
        record.add_findings(
            [
                Finding(
                    item_id="i1", entity_type=EntityType.ID_CARD,
                    source=FindingSource.CHECKSUM, start=0, end=18, confidence=0.99,
                    rule_id="cn_id_card_18", raw_text=synthetic.ID_CARD,
                    text_hash="deadbeef",
                )
            ]
        )
        serialized = str(record.findings)
        assert synthetic.ID_CARD not in serialized
        assert "deadbeef" in serialized

    def test_finding_dump_excludes_raw_text(self) -> None:
        from app.core.enums import EntityType, FindingSource
        from app.domain.findings import Finding

        finding = Finding(
            item_id="i1", entity_type=EntityType.PHONE, source=FindingSource.REGEX,
            start=0, end=11, confidence=0.9, raw_text=synthetic.PHONE,
        )
        assert synthetic.PHONE not in str(finding.model_dump())
        assert synthetic.PHONE not in str(finding.to_audit_dict())

    def test_redaction_filter_scrubs_stray_messages(self) -> None:
        from app.core.logging import RedactionFilter

        record = logging.LogRecord(
            "x", logging.INFO, __file__, 1,
            f"leaked {synthetic.BANK_CARD} and {synthetic.EMAIL}", (), None,
        )
        RedactionFilter().filter(record)
        assert synthetic.BANK_CARD not in record.getMessage()
        assert synthetic.EMAIL not in record.getMessage()

    def test_safe_extra_drops_unknown_fields(self) -> None:
        from app.core.logging import safe_extra

        extra = safe_extra(request_id="req-1", ocr_text=synthetic.ID_CARD)
        assert extra["safe"] == {"request_id": "req-1"}


class TestErrorsDoNotEchoContent:
    async def test_blocked_error_detail_has_no_payload(self, harness: Harness) -> None:
        text = f"Diagnosis: acute hepatitis for {synthetic.PERSON}."
        harness.local_model._default = [  # noqa: SLF001
            entity(text.index("acute hepatitis"),
                   text.index("acute hepatitis") + len("acute hepatitis"),
                   "acute hepatitis", "MEDICAL_DATA")
        ]
        with pytest.raises(ContentBlocked) as exc:
            await send(harness, text)
        rendered = str(exc.value.to_public_dict())
        assert synthetic.PERSON not in rendered
        assert "acute hepatitis" not in rendered
