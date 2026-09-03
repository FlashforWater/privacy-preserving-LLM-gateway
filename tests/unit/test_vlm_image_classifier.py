"""The vision classifier may tighten a verdict and never loosen one.

That constraint is what makes it safe to put a probabilistic component into the
decision of whether original pixels leave. A model that wrongly says "ordinary"
changes nothing; a model that wrongly says "identity document" costs one
photograph. Only the cheap failure is reachable.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.core.deadlines import Deadline
from app.core.enums import ImageClass
from app.detectors.image_classifier import (
    CLASS_STRICTNESS,
    ClassificationResult,
    ImageInspection,
    stricter,
)
from app.detectors.vlm_image_classifier import LocalVlmImageClassifier

IMAGE = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def inspection(data: bytes = IMAGE) -> ImageInspection:
    return ImageInspection(
        width=100, height=100, detected_mime="image/png",
        decode_succeeded=True, ocr_succeeded=True, data=data,
    )


def replying(category: str):
    """A transport that answers with one classification."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(
                {"category": category, "reason": "t"})}}]},
            headers={"content-type": "application/json"},
        )

    return handler


async def classify_with(monkeypatch, handler, heuristic: ClassificationResult):
    instance = LocalVlmImageClassifier(base_url="http://local.test/v1", model="vl")

    class Client(httpx.AsyncClient):
        def __init__(self, **kwargs: object) -> None:
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    return await instance.classify(inspection(), heuristic, Deadline.after(10))


ORDINARY = ClassificationResult(ImageClass.ORDINARY_IMAGE, "no_protected_signals")
SENSITIVE = ClassificationResult(ImageClass.SENSITIVE_IMAGE, "exif_gps_present")


class TestStrictnessOrder:
    def test_every_class_is_ranked(self) -> None:
        assert set(CLASS_STRICTNESS) == set(ImageClass)

    def test_ordinary_is_the_least_strict(self) -> None:
        assert CLASS_STRICTNESS[ImageClass.ORDINARY_IMAGE] == min(CLASS_STRICTNESS.values())

    def test_stricter_picks_the_higher_rank(self) -> None:
        assert stricter(ORDINARY, SENSITIVE) is SENSITIVE
        assert stricter(SENSITIVE, ORDINARY) is SENSITIVE


class TestMonotonicTightening:
    async def test_model_can_tighten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The blind spot this exists for: a face or an injury photograph carries
        no text, so the OCR-driven classifier calls it ordinary and the original
        pixels go out."""
        result = await classify_with(monkeypatch, replying("sensitive"), ORDINARY)
        assert result.image_class is ImageClass.SENSITIVE_IMAGE

    async def test_model_cannot_loosen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = await classify_with(monkeypatch, replying("ordinary"), SENSITIVE)
        assert result.image_class is ImageClass.SENSITIVE_IMAGE

    async def test_identity_document_outranks_sensitive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await classify_with(monkeypatch, replying("identity_document"), SENSITIVE)
        assert result.image_class is ImageClass.ID_DOCUMENT_IMAGE

    async def test_unclear_withholds_rather_than_blocks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An optional tightening signal should not hold a veto over the request.

        UNKNOWN_IMAGE blocks outright; a plain photograph of a dented bumper can
        read as "unclear", and killing the claim over it buys no protection that
        withholding the pixels does not already give.
        """
        result = await classify_with(monkeypatch, replying("unclear"), ORDINARY)
        assert result.image_class is ImageClass.SENSITIVE_IMAGE


class TestFailuresLeaveTheVerdictAlone:
    async def test_transport_error_keeps_the_heuristic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down")

        result = await classify_with(monkeypatch, handler, ORDINARY)
        assert result is ORDINARY

    async def test_off_schema_reply_keeps_the_heuristic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "I think it is a car."}}]},
                headers={"content-type": "application/json"},
            )

        result = await classify_with(monkeypatch, handler, ORDINARY)
        assert result is ORDINARY

    async def test_unknown_category_keeps_the_heuristic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = await classify_with(monkeypatch, replying("banana"), ORDINARY)
        assert result is ORDINARY

    async def test_missing_bytes_skips_the_call(self) -> None:
        instance = LocalVlmImageClassifier(base_url="http://local.test/v1", model="vl")
        blank = inspection(data=b"")
        assert await instance.classify(blank, ORDINARY, Deadline.after(10)) is ORDINARY

    async def test_oversized_image_skips_the_call(self) -> None:
        instance = LocalVlmImageClassifier(
            base_url="http://local.test/v1", model="vl", max_bytes=10
        )
        assert await instance.classify(inspection(), ORDINARY, Deadline.after(10)) is ORDINARY
