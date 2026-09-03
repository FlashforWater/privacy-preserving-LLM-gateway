"""Item-level multimodal routing (guide §5.2, §12).

The headline assertions:

* an approved ordinary image reaches the provider **byte-for-byte**;
* an ID document image's pixels never appear in the captured outbound bytes;
* one sensitive attachment does not discard the safe ones.
"""

from __future__ import annotations

from app.core.enums import ForwardPath
from app.domain.content import Manifest
from tests.conftest import Harness
from tests.fixtures import synthetic


def multimodal_manifest(purpose: str = "general") -> Manifest:
    return Manifest.model_validate(
        {
            "purpose": purpose,
            "model": "external-vlm-model",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "item_id": "prompt-1", "text": "Assess the damage."},
                        {"type": "image", "item_id": "scene-1", "file_field": "file_scene-1"},
                        {"type": "image", "item_id": "identity-1", "file_field": "file_identity-1"},
                    ],
                }
            ],
        }
    )


async def run_multimodal(harness: Harness, files: dict[str, bytes], purpose: str = "general"):
    scope = await harness.open_scope()
    manifest = multimodal_manifest(purpose)
    normalized = harness.normalize(manifest, files)
    context = harness.context(scope, manifest)
    return await harness.orchestrator.process(context, normalized)


class TestOrdinaryImages:
    async def test_approved_image_is_forwarded_byte_for_byte(self, harness: Harness) -> None:
        """No re-encoding, no metadata stripping (guide §12.2)."""
        harness.ocr._mapping = {synthetic.ORDINARY_IMAGE: ""}  # noqa: SLF001
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "external-vlm-model",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "item_id": "p1", "text": "Assess the damage."},
                            {"type": "image", "item_id": "scene-1", "file_field": "file_scene-1"},
                        ],
                    }
                ],
            }
        )
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest, {"file_scene-1": synthetic.ORDINARY_IMAGE})
        response = await harness.orchestrator.process(
            harness.context(scope, manifest), normalized
        )
        assert response.privacy.path is ForwardPath.FAST
        assert harness.adapter.captured_bytes() == synthetic.ORDINARY_IMAGE

    async def test_image_with_gps_is_not_forwarded(self, harness: Harness) -> None:
        """The MVP does not mutate images, so a photo carrying GPS cannot be sent."""
        harness.ocr._mapping = {synthetic.GPS_IMAGE: ""}  # noqa: SLF001
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "external-vlm-model",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "image", "item_id": "gps-1", "file_field": "file_gps-1"}
                        ],
                    }
                ],
            }
        )
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest, {"file_gps-1": synthetic.GPS_IMAGE})
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        assert synthetic.GPS_IMAGE not in harness.adapter.captured_bytes()


class TestSensitiveImages:
    async def test_id_document_pixels_never_leave(self, harness: Harness) -> None:
        harness.ocr._mapping = {  # noqa: SLF001
            synthetic.ORDINARY_IMAGE: "",
            synthetic.ID_CARD_IMAGE: f"居民身份证 签发机关 北京市公安局 {synthetic.ID_CARD}",
        }
        # Both images are the same bytes in the fixtures, so give them distinct
        # content to keep the assertion meaningful.
        id_image = synthetic.png_bytes(80, 50)
        harness.ocr._mapping[id_image] = (  # noqa: SLF001
            f"居民身份证 签发机关 北京市公安局 {synthetic.ID_CARD}"
        )
        response = await run_multimodal(
            harness,
            {"file_scene-1": synthetic.ORDINARY_IMAGE, "file_identity-1": id_image},
        )
        captured = harness.adapter.captured_bytes()
        assert id_image not in captured
        assert "identity-1" in response.privacy.withheld_item_ids or (
            synthetic.ID_CARD not in harness.adapter.captured_text()
        )

    async def test_safe_attachment_survives_a_sensitive_sibling(
        self, harness: Harness
    ) -> None:
        """Item-level routing: one bad attachment must not discard the good one."""
        id_image = synthetic.png_bytes(80, 50)
        harness.ocr._mapping = {  # noqa: SLF001
            synthetic.ORDINARY_IMAGE: "",
            id_image: f"居民身份证 {synthetic.ID_CARD}",
        }
        await run_multimodal(
            harness,
            {"file_scene-1": synthetic.ORDINARY_IMAGE, "file_identity-1": id_image},
        )
        assert synthetic.ORDINARY_IMAGE in harness.adapter.captured_bytes()

    async def test_extracted_id_text_is_tokenized_not_passed(self, harness: Harness) -> None:
        id_image = synthetic.png_bytes(80, 50)
        harness.ocr._mapping = {  # noqa: SLF001
            synthetic.ORDINARY_IMAGE: "",
            id_image: f"居民身份证 姓名: {synthetic.PERSON_CJK} 公民身份号码 {synthetic.ID_CARD}",
        }
        await run_multimodal(
            harness,
            {"file_scene-1": synthetic.ORDINARY_IMAGE, "file_identity-1": id_image},
        )
        captured = harness.adapter.captured_text()
        assert synthetic.ID_CARD not in captured


class TestOrdering:
    async def test_message_and_part_order_is_preserved(self, harness: Harness) -> None:
        harness.ocr._mapping = {synthetic.ORDINARY_IMAGE: ""}  # noqa: SLF001
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "external-vlm-model",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "item_id": "a", "text": "first"},
                            {"type": "image", "item_id": "b", "file_field": "file_b"},
                            {"type": "text", "item_id": "c", "text": "third"},
                        ],
                    }
                ],
            }
        )
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest, {"file_b": synthetic.ORDINARY_IMAGE})
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        request = harness.adapter.requests[0]
        assert [part.item_id for part in request.messages[0].parts] == ["a", "b", "c"]
