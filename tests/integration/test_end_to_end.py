"""End-to-end paths against deterministic fakes (guide §19.3).

The recording adapter captures exactly what would have crossed the boundary, so
every assertion here is about real outbound content rather than about internal
state that happens to look right.
"""

from __future__ import annotations

import pytest

from app.core.enums import ForwardPath, PrivacyMode
from app.core.errors import ContentBlocked
from app.domain.responses import ExternalModelResponse, ExternalTextField
from app.sanitization.tokenizer import find_tokens
from tests.conftest import Harness, entity, text_manifest
from tests.fixtures import synthetic


async def run(harness: Harness, text: str, *, purpose: str = "general",
              scope=None):
    scope = scope or await harness.open_scope()
    manifest = text_manifest(text, purpose=purpose)
    normalized = harness.normalize(manifest)
    context = harness.context(scope, manifest)
    response = await harness.orchestrator.process(context, normalized)
    return scope, response


class TestSafeFastPath:
    async def test_clean_text_takes_the_original_fast_path(self, harness: Harness) -> None:
        _scope, response = await run(harness, synthetic.CLEAN_TEXT)
        assert response.privacy.path is ForwardPath.FAST
        assert harness.adapter.captured_text() == synthetic.CLEAN_TEXT

    async def test_fast_path_forwards_text_unmodified(self, harness: Harness) -> None:
        text = "Compare these two policies and summarise the difference."
        await run(harness, text)
        assert harness.adapter.captured_text() == text


class TestSanitizedPath:
    async def test_identifiers_are_tokenized(self, harness: Harness) -> None:
        _scope, response = await run(harness, synthetic.TEXT_WITH_IDENTIFIERS)
        assert response.privacy.path is ForwardPath.SANITIZED
        captured = harness.adapter.captured_text()
        assert synthetic.ID_CARD not in captured
        assert synthetic.PHONE not in captured
        assert find_tokens(captured)

    async def test_unrelated_text_is_left_alone(self, harness: Harness) -> None:
        """Minimum necessary transformation (guide §3.3)."""
        await run(harness, synthetic.TEXT_WITH_IDENTIFIERS)
        assert "Summarise the treatment plan." in harness.adapter.captured_text()

    async def test_medical_values_survive_under_the_purpose_override(
        self, harness: Harness
    ) -> None:
        harness.local_model._default = [  # noqa: SLF001 - scripted fake
            entity(
                synthetic.MEDICAL_TEXT.index("acute hepatitis"),
                synthetic.MEDICAL_TEXT.index("acute hepatitis") + len("acute hepatitis"),
                "acute hepatitis",
                "MEDICAL_DATA",
            )
        ]
        _scope, response = await run(
            harness, synthetic.MEDICAL_TEXT, purpose="medical_report_analysis"
        )
        captured = harness.adapter.captured_text()
        assert "ALT 320 U/L" in captured
        assert "acute hepatitis" in captured
        assert synthetic.ID_CARD not in captured
        assert response.privacy.actions.get("TOKENIZE", 0) > 0

    async def test_medical_data_blocks_without_the_override(self, harness: Harness) -> None:
        harness.local_model._default = [  # noqa: SLF001
            entity(
                synthetic.MEDICAL_TEXT.index("acute hepatitis"),
                synthetic.MEDICAL_TEXT.index("acute hepatitis") + len("acute hepatitis"),
                "acute hepatitis",
                "MEDICAL_DATA",
            )
        ]
        with pytest.raises(ContentBlocked):
            await run(harness, synthetic.MEDICAL_TEXT, purpose="general")
        assert harness.adapter.requests == []


class TestScopeConsistency:
    async def test_same_value_keeps_the_same_token_across_turns(
        self, harness: Harness
    ) -> None:
        scope = await harness.open_scope()
        await run(harness, f"Contact {synthetic.PHONE} for details.", scope=scope)
        first = set(find_tokens(harness.adapter.captured_text()))

        await run(harness, f"Call {synthetic.PHONE_FORMATTED} again.", scope=scope)
        second = set(find_tokens(harness.adapter.captured_text())) - first

        # The formatted and unformatted numbers canonicalize to the same value,
        # so the second turn must reuse the first turn's token.
        assert not second, "a second token was minted for the same canonical value"

    async def test_first_tokenization_locks_the_scope(self, harness: Harness) -> None:
        scope = await harness.open_scope()
        await run(harness, f"Phone {synthetic.PHONE}", scope=scope)
        assert scope.privacy_mode is PrivacyMode.SANITIZED_LOCKED

        # A later clean turn in the same conversation must not reopen the fast path.
        _scope, response = await run(harness, synthetic.CLEAN_TEXT, scope=scope)
        assert response.privacy.path is ForwardPath.SANITIZED

    async def test_different_scopes_get_different_tokens(self, harness: Harness) -> None:
        await run(harness, f"Phone {synthetic.PHONE}")
        first = set(find_tokens(harness.adapter.captured_text()))
        await run(harness, f"Phone {synthetic.PHONE}")
        second = set(find_tokens(harness.adapter.captured_text())) - first
        assert second, "a token was reused across scopes"


class TestRestoration:
    async def test_tokens_in_the_response_are_restored(self, harness: Harness) -> None:
        scope = await harness.open_scope()
        manifest = text_manifest(f"Patient phone is {synthetic.PHONE}.")
        normalized = harness.normalize(manifest)
        context = harness.context(scope, manifest)

        # First pass discovers which token the phone number received.
        harness.adapter._responses = [ExternalModelResponse(model="model-a", text_fields=[])]  # noqa: SLF001
        await harness.orchestrator.process(context, normalized)
        token = find_tokens(harness.adapter.captured_text())[0]

        # Second pass: the provider echoes the token, which must come back as the
        # original value.
        manifest2 = text_manifest("Confirm the number.", item_id="prompt-2")
        normalized2 = harness.normalize(manifest2)
        context2 = harness.context(scope, manifest2)
        harness.adapter._responses = [  # noqa: SLF001
            ExternalModelResponse(
                model="model-a",
                text_fields=[ExternalTextField(path="choices[0]", text=f"Call {token} today.")],
            )
        ]
        response = await harness.orchestrator.process(context2, normalized2)
        assert synthetic.PHONE in response.output["content"][0]["text"]  # type: ignore[index]

    async def test_invented_token_is_left_unchanged(self, harness: Harness) -> None:
        scope = await harness.open_scope()
        manifest = text_manifest("Nothing sensitive here.")
        normalized = harness.normalize(manifest)
        context = harness.context(scope, manifest)
        invented = "[[PGW_V1_PERSON_AAAAAAAAAAAA]]"
        harness.adapter._responses = [  # noqa: SLF001
            ExternalModelResponse(
                model="model-a",
                text_fields=[ExternalTextField(path="choices[0]", text=f"Hello {invented}")],
            )
        ]
        response = await harness.orchestrator.process(context, normalized)
        assert invented in response.output["content"][0]["text"]  # type: ignore[index]
