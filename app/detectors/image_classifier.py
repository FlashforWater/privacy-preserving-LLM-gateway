"""Local image classification (guide §12.1).

The classifier answers one question: is this an ordinary image, a sensitive
document image, or something we cannot place? The third answer is a real answer
and maps to BLOCK — an image the classifier cannot place must never fall back to
the ordinary-image PASS path (§12.3, last bullet).

Two independent signals feed the decision:

* **Metadata.** EXIF GPS or a description field is protected content in itself.
  Because the MVP never mutates images (§12.2), a photo carrying GPS cannot be
  forwarded at all — there is no "strip and send".
* **Visible content.** OCR text from the image is scanned with the same
  deterministic rules used for documents, plus document-layout keywords.

Anything that fails, times out, or is ambiguous returns ``UNKNOWN_IMAGE``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from app.core.enums import ImageClass

#: Words that indicate the picture *is* an identity or financial document rather
#: than a photo that happens to contain text.
DOCUMENT_KEYWORDS: tuple[str, ...] = (
    "身份证", "居民身份证", "护照", "驾驶证", "行驶证", "户口", "签发机关", "有效期限",
    "银行卡", "信用卡", "社会保障", "医保卡", "出生日期", "公民身份号码",
    "passport", "driver licen", "driving licence", "identity card", "id card",
    "date of birth", "place of birth", "issuing authority", "valid until",
    "cardholder", "expiry date", "social security",
)

_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in DOCUMENT_KEYWORDS), re.IGNORECASE)


@dataclass(slots=True)
class ImageInspection:
    """Everything the local pipeline learned about one image."""

    width: int = 0
    height: int = 0
    detected_mime: str = ""
    has_gps: bool = False
    metadata_fields: tuple[str, ...] = ()
    ocr_text: str = ""
    ocr_succeeded: bool = False
    decode_succeeded: bool = False
    notes: dict[str, str | int | bool] = field(default_factory=dict)

    @property
    def pixels(self) -> int:
        return self.width * self.height


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    image_class: ImageClass
    reason: str
    #: Set when the classifier saw identifier-like text; the detector pipeline
    #: turns it into findings so policy, not the classifier, decides what happens.
    contains_document_text: bool = False


class ImageClassifier(Protocol):
    name: str

    def classify(self, inspection: ImageInspection) -> ClassificationResult: ...


class HeuristicImageClassifier:
    """Deterministic classifier over local inspection results.

    Intentionally not a model: the MVP's classifier decides whether original
    pixels may leave the trusted zone, and that decision should be reviewable
    line by line. A learned classifier can be added later behind this protocol,
    with UNKNOWN_IMAGE remaining the fallback.
    """

    name = "heuristic_image_classifier"

    def __init__(self, *, min_ocr_chars_for_document: int = 12) -> None:
        self._min_chars = min_ocr_chars_for_document

    def classify(self, inspection: ImageInspection) -> ClassificationResult:
        if not inspection.decode_succeeded:
            return ClassificationResult(ImageClass.UNKNOWN_IMAGE, "decode_failed")

        # Metadata alone is enough to make the file unforwardable.
        if inspection.has_gps:
            return ClassificationResult(ImageClass.SENSITIVE_IMAGE, "exif_gps_present")
        if inspection.metadata_fields:
            return ClassificationResult(
                ImageClass.SENSITIVE_IMAGE, "protected_metadata_present"
            )

        if not inspection.ocr_succeeded:
            # Required inspection did not complete; not an ordinary image by default.
            return ClassificationResult(ImageClass.UNKNOWN_IMAGE, "ocr_unavailable")

        text = inspection.ocr_text
        if _KEYWORD_RE.search(text):
            return ClassificationResult(
                ImageClass.ID_DOCUMENT_IMAGE, "document_keywords", contains_document_text=True
            )
        if len(text.strip()) >= self._min_chars:
            # Text-bearing but unrecognised: could be a form, a screenshot, a
            # letter. Route it through local analysis rather than guessing.
            return ClassificationResult(
                ImageClass.SENSITIVE_IMAGE, "unclassified_text_bearing_image",
                contains_document_text=True,
            )
        return ClassificationResult(ImageClass.ORDINARY_IMAGE, "no_protected_signals")
