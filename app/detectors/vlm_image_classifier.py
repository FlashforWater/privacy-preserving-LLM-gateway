"""Vision-model image classification.

The heuristic classifier reads OCR text, so it is blind to a picture with no
text in it: an injury photograph, a face, a screenshot. Those come back
``ORDINARY_IMAGE``, which forwards the original pixels — and in a claims file the
injury photographs are among the most sensitive things present.

A local vision model can see what the text-based classifier cannot. Putting a
probabilistic component into the decision of whether original pixels leave needs
a constraint, though, so it has one:

    **This classifier can only tighten a verdict, never loosen one.**

Its answer is combined with the heuristic's by taking whichever is stricter. A
model that wrongly says "ordinary" changes nothing; a model that wrongly says
"identity document" costs a photograph that would have been forwarded. The
failure modes are deliberately asymmetric, and only the cheap one is reachable.

If the model is unreachable, slow, or answers off-schema, the heuristic verdict
stands unchanged — which is itself already fail-closed on OCR failure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.deadlines import Deadline
from app.core.enums import ImageClass

from .image_classifier import ClassificationResult, ImageInspection, stricter

CLASSIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["category", "reason"],
    "properties": {
        "category": {
            "enum": ["identity_document", "sensitive", "ordinary", "unclear"],
        },
        "reason": {"type": "string", "maxLength": 120},
    },
}

_CATEGORY_TO_CLASS = {
    "identity_document": ImageClass.ID_DOCUMENT_IMAGE,
    "sensitive": ImageClass.SENSITIVE_IMAGE,
    "ordinary": ImageClass.ORDINARY_IMAGE,
    # "unclear" withholds the image rather than blocking the request.
    #
    # UNKNOWN_IMAGE would be the stricter reading, and it was the first choice —
    # a model that cannot tell should not fall back to "ordinary", the one answer
    # that forwards pixels. But UNKNOWN blocks the whole request, and an optional
    # tightening signal should not hold a veto: a plain photograph of a dented
    # bumper can read as "unclear", and killing the claim over it trades a real
    # cost for no protection that SENSITIVE does not already give. SENSITIVE
    # keeps the pixels local and lets the analysis continue on extracted text.
    "unclear": ImageClass.SENSITIVE_IMAGE,
}

PROMPT = """判断这张图片属于哪一类。只做分类，不要描述细节，不要分析案情。

- identity_document：身份证、护照、驾驶证、行驶证、户口本、银行卡、社保卡、
  营业执照等证件或卡片的照片或扫描件。
- sensitive：包含个人隐私的图片——人脸、人体、伤情伤口、病历或检验单、
  处方、发票单据、手写签名、包含个人信息的屏幕截图。
- ordinary：不包含任何个人信息的图片——车辆损伤、事故现场、道路、物品、
  设备、建筑、风景。
- unclear：看不清、内容不明确，或无法归入以上任何一类。

判断不了就选 unclear，不要猜 ordinary。只输出符合 schema 的 JSON。"""


@dataclass(slots=True)
class LocalVlmImageClassifier:
    """Classifies an image with the locally served vision model."""

    base_url: str
    model: str
    api_key: str = "EMPTY"
    timeout_seconds: float = 30.0
    max_bytes: int = 8 * 1024 * 1024
    name: str = "local_vlm_classifier"

    async def classify(
        self,
        inspection: ImageInspection,
        heuristic: ClassificationResult,
        deadline: Deadline,
    ) -> ClassificationResult:
        """Return the stricter of the heuristic verdict and the model's."""
        if not inspection.data or len(inspection.data) > self.max_bytes:
            return heuristic
        try:
            verdict = await self._ask(inspection, deadline)
        except Exception:  # noqa: BLE001 - the heuristic verdict stands
            # Deliberately swallowed. This classifier exists to tighten; if it
            # cannot run, the pipeline is exactly as safe as it was without it,
            # and failing the request would make an optional signal mandatory.
            return heuristic
        if verdict is None:
            return heuristic
        return stricter(heuristic, verdict)

    async def _ask(
        self, inspection: ImageInspection, deadline: Deadline
    ) -> ClassificationResult | None:
        import base64

        mime = inspection.detected_mime or "image/png"
        encoded = base64.b64encode(inspection.data).decode("ascii")
        body = {
            "model": self.model,
            "temperature": 0.0,
            "max_tokens": 256,
            "chat_template_kwargs": {"enable_thinking": False},
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": PROMPT},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:{mime};base64,{encoded}"},
                        },
                    ],
                }
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "image_class",
                    "schema": CLASSIFY_SCHEMA,
                    "strict": True,
                },
            },
        }
        async with httpx.AsyncClient(
            base_url=self.base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        ) as client:
            response = await client.post(
                "/chat/completions",
                json=body,
                timeout=deadline.budget_for(self.timeout_seconds),
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]

        if not isinstance(content, str):
            return None
        parsed = json.loads(content)
        if not isinstance(parsed, dict) or set(parsed) != {"category", "reason"}:
            return None
        image_class = _CATEGORY_TO_CLASS.get(str(parsed["category"]))
        if image_class is None:
            return None
        return ClassificationResult(
            image_class=image_class,
            reason=f"vlm:{parsed['category']}",
            contains_document_text=image_class is ImageClass.ID_DOCUMENT_IMAGE,
        )
