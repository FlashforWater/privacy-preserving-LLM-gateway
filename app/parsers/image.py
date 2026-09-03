"""Image inspection (guide §12).

Everything here answers one question: may these exact bytes leave the trusted
zone? Because the MVP never mutates an image, the answer is binary — forward the
original file byte-for-byte, or withhold it and send locally extracted text.

Metadata is parsed from the raw bytes with the standard library rather than
through an imaging library. That keeps the security-critical check (is there EXIF
GPS in here?) free of a third-party dependency, dependency-free to test, and
immune to a library silently normalising the very metadata we are looking for.

Truncation is checked explicitly: a JPEG without its end-of-image marker may
render fine in one decoder and carry trailing appended data in another, which is
a classic polyglot smuggling trick.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from app.detectors.image_classifier import ImageInspection
from app.domain.content import ContentItem, ParsedItem

from .base import ParserError, ParserLimits

#: EXIF tags whose presence makes an image sensitive on its own.
_GPS_IFD_TAG = 0x8825
_EXIF_DESCRIPTIVE_TAGS: dict[int, str] = {
    0x010E: "ImageDescription",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9286: "UserComment",
    0xA430: "CameraOwnerName",
    0xA433: "LensMake",
    0xC6D2: "OwnerName",
}


@dataclass(frozen=True, slots=True)
class ImageMetadata:
    width: int
    height: int
    has_gps: bool
    fields: tuple[str, ...]
    truncated: bool


class ImageParser:
    """Decodes structure and metadata, then classifies with the local classifier.

    OCR runs whenever the image needs textual inspection. The OCR text becomes
    ``normalized_text`` so the ordinary detector pipeline scans it exactly like a
    document — the classifier never gets to decide what is or is not an
    identifier, it only decides what kind of picture this is.
    """

    name = "image"
    mime_types = frozenset({"image/jpeg", "image/png"})

    def __init__(self, ocr_engine: object, classifier: object) -> None:
        self._ocr = ocr_engine
        self._classifier = classifier

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        if item.data is None:
            raise ParserError(
                "image item has no bytes", public_detail="attachment could not be inspected"
            )
        mime = item.detected_mime or ""
        metadata = read_metadata(item.data, mime)

        if metadata.width <= 0 or metadata.height <= 0:
            raise ParserError(
                "image dimensions could not be determined",
                public_detail="attachment could not be inspected",
            )
        if metadata.width * metadata.height > limits.max_ocr_pixels:
            raise ParserError(
                "image exceeds the configured pixel limit",
                public_detail="image is too large to inspect",
            )

        inspection = ImageInspection(
            width=metadata.width,
            height=metadata.height,
            detected_mime=mime,
            has_gps=metadata.has_gps,
            metadata_fields=metadata.fields,
            decode_succeeded=not metadata.truncated,
            # Kept in process so a pixel-level classifier can look; never
            # serialized and never leaves this request.
            data=item.data,
        )

        ocr_failed = False
        if not metadata.truncated:
            try:
                result = self._ocr.read_image(  # type: ignore[attr-defined]
                    item.data, max_pixels=limits.max_ocr_pixels
                )
                inspection.ocr_text = result.text
                inspection.ocr_succeeded = result.complete
            except Exception:  # noqa: BLE001 - OCR failure must not classify as ordinary
                ocr_failed = True
                inspection.ocr_succeeded = False

        classification = self._classifier.classify(inspection)  # type: ignore[attr-defined]

        # The original bytes may be forwarded only when nothing at all went wrong.
        forwardable = (
            not metadata.truncated
            and not ocr_failed
            and inspection.ocr_succeeded
            and not metadata.has_gps
            and not metadata.fields
        )

        parsed = ParsedItem(
            item_id=item.item_id,
            normalized_text=inspection.ocr_text,
            page_count=1,
            # "Inspected" means every stage ran, not that the image is safe.
            fully_inspected=not metadata.truncated and inspection.ocr_succeeded,
            parser_name=self.name,
            image_class=classification.image_class,
            original_bytes_forwardable=forwardable,
            inspection_notes={
                "document_type": "image",
                "width": metadata.width,
                "height": metadata.height,
                "has_gps": metadata.has_gps,
                "metadata_fields": len(metadata.fields),
                "truncated": metadata.truncated,
                "ocr_chars": len(inspection.ocr_text),
                "classification": classification.image_class.value,
                "classification_reason": classification.reason,
            },
        )
        # Handed to the async vision classifier by the orchestrator, which may
        # tighten image_class. Parsing stays synchronous; a model call does not
        # belong inside a parser.
        parsed.image_inspection = inspection
        return parsed


# ---- metadata readers ----------------------------------------------------


def read_metadata(data: bytes, mime: str) -> ImageMetadata:
    if mime == "image/png":
        return _read_png(data)
    if mime == "image/jpeg":
        return _read_jpeg(data)
    raise ParserError(
        f"unsupported image type {mime}", public_detail="this content type cannot be inspected"
    )


def _read_png(data: bytes) -> ImageMetadata:
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ParserError("PNG header is invalid", public_detail="attachment could not be inspected")
    width = height = 0
    fields: list[str] = []
    has_gps = False
    saw_iend = False

    offset = 8
    while offset + 8 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        body_start = offset + 8
        body_end = body_start + length
        if body_end + 4 > len(data):
            break
        body = data[body_start:body_end]

        if chunk_type == b"IHDR" and length >= 8:
            width, height = struct.unpack(">II", body[:8])
        elif chunk_type in (b"tEXt", b"iTXt", b"zTXt"):
            keyword = body.split(b"\x00", 1)[0].decode("latin-1", "replace")
            fields.append(f"png:{keyword}")
            # PNG can carry EXIF inside iTXt/eXIf; a GPS keyword is enough signal.
            if "gps" in keyword.lower() or "location" in keyword.lower():
                has_gps = True
        elif chunk_type == b"eXIf":
            exif_gps, exif_fields = _read_exif(body)
            has_gps = has_gps or exif_gps
            fields.extend(exif_fields)
        elif chunk_type == b"IEND":
            saw_iend = True
            break

        offset = body_end + 4

    return ImageMetadata(
        width=width, height=height, has_gps=has_gps,
        fields=tuple(fields), truncated=not saw_iend,
    )


def _read_jpeg(data: bytes) -> ImageMetadata:
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise ParserError(
            "JPEG header is invalid", public_detail="attachment could not be inspected"
        )
    width = height = 0
    fields: list[str] = []
    has_gps = False

    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if marker == 0xD9:  # EOI
            break
        segment_length = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
        body_start = offset + 4
        body_end = offset + 2 + segment_length
        if body_end > len(data):
            break
        body = data[body_start:body_end]

        # SOF0..SOF15 except DHT(C4), JPG(C8), DAC(CC) carry the dimensions.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            if len(body) >= 5:
                height, width = struct.unpack(">HH", body[1:5])
        elif marker == 0xE1:  # APP1: EXIF or XMP
            if body.startswith(b"Exif\x00\x00"):
                exif_gps, exif_fields = _read_exif(body[6:])
                has_gps = has_gps or exif_gps
                fields.extend(exif_fields)
            elif b"adobe.com/xap" in body[:64]:
                fields.append("xmp")
        elif marker == 0xFE:  # COM
            fields.append("jpeg:comment")
        elif marker == 0xEE:
            fields.append("jpeg:adobe")

        offset = body_end

    # A well-formed JPEG ends with EOI. Trailing data after it is also suspicious,
    # so require the marker to be at the very end.
    truncated = not data.rstrip(b"\x00").endswith(b"\xff\xd9")
    return ImageMetadata(
        width=width, height=height, has_gps=has_gps,
        fields=tuple(fields), truncated=truncated,
    )


def _read_exif(payload: bytes) -> tuple[bool, list[str]]:
    """Minimal TIFF/EXIF IFD walk: detect a GPS IFD and descriptive tags."""
    if len(payload) < 8:
        return False, []
    byte_order = payload[:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        return False, []
    try:
        (ifd_offset,) = struct.unpack(endian + "I", payload[4:8])
    except struct.error:
        return False, []

    has_gps = False
    fields: list[str] = []
    visited: set[int] = set()
    offset = ifd_offset

    while 0 < offset < len(payload) - 2 and offset not in visited:
        visited.add(offset)
        try:
            (count,) = struct.unpack(endian + "H", payload[offset : offset + 2])
        except struct.error:
            break
        entry_base = offset + 2
        for index in range(min(count, 512)):
            entry = entry_base + index * 12
            if entry + 12 > len(payload):
                break
            (tag,) = struct.unpack(endian + "H", payload[entry : entry + 2])
            if tag == _GPS_IFD_TAG:
                has_gps = True
            elif tag in _EXIF_DESCRIPTIVE_TAGS:
                fields.append(f"exif:{_EXIF_DESCRIPTIVE_TAGS[tag]}")
        next_ptr = entry_base + min(count, 512) * 12
        if next_ptr + 4 > len(payload):
            break
        (offset,) = struct.unpack(endian + "I", payload[next_ptr : next_ptr + 4])

    return has_gps, fields


def png_crc(chunk_type: bytes, body: bytes) -> int:
    """Exposed for test fixtures that build PNGs byte by byte."""
    return zlib.crc32(chunk_type + body) & 0xFFFFFFFF
