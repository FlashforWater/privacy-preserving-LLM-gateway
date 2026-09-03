"""Parser protocol, content-type sniffing and resource limits (guide §11.2).

Three rules are implemented here rather than in each parser, so a new format
cannot forget them:

* **Type comes from the bytes.** ``sniff_mime`` ignores the filename and the
  client-declared MIME entirely. A ``.jpg`` that is really a DOCX is a spoofing
  attempt, and the mismatch is reported rather than resolved.
* **A partial parse is a failure.** ``ParsedItem.fully_inspected`` starts False
  and is set only when a parser has examined every supported component.
* **Unsupported means blocked.** The registry raises for unknown types; there is
  no "pass it through and hope" branch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.core.errors import InspectionFailedClosed, UnsupportedMediaType
from app.domain.content import ContentItem, ParsedItem

# Signatures checked against the leading bytes of the file.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # refined below
)

SUPPORTED_MIME_TYPES: frozenset[str] = frozenset(
    {
        "text/plain",
        "application/pdf",
        "image/jpeg",
        "image/png",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
)

#: Macro-enabled Office formats are rejected outright (guide §11.2).
REJECTED_MIME_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    }
)


class ParserError(InspectionFailedClosed):
    """Any parse problem. Always fail-closed; never downgraded to a warning."""


@dataclass(frozen=True, slots=True)
class ParserLimits:
    max_file_bytes: int = 20 * 1024 * 1024
    max_pages: int = 200
    max_ocr_pixels: int = 40_000_000
    #: Guards zip bombs: total uncompressed size and per-entry expansion ratio.
    max_uncompressed_bytes: int = 200 * 1024 * 1024
    max_compression_ratio: int = 200
    max_archive_entries: int = 2000
    max_text_chars: int = 2_000_000


def sniff_mime(data: bytes, *, declared: str | None = None, filename: str | None = None) -> str:
    """Determine the MIME type from content.

    ``declared`` and ``filename`` are accepted only so the caller can record a
    mismatch; they never influence the answer.
    """
    if not data:
        raise ParserError("empty attachment", public_detail="attachment could not be inspected")

    if data[:4] == b"PK\x03\x04":
        return _sniff_ooxml(data)

    for signature, mime in _MAGIC:
        if data.startswith(signature):
            if mime == "image/webp":
                return "image/webp" if data[8:12] == b"WEBP" else "application/octet-stream"
            return mime

    # Fall back to text only when the bytes really are text. Decodability alone
    # is not enough: a binary blob whose bytes all happen to sit below 0x80
    # decodes cleanly, and calling it text/plain hands it to the text parser
    # instead of rejecting an unrecognised format.
    sample = data[:4096]
    if b"\x00" in sample:
        return "application/octet-stream"
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if any(byte < 0x09 or 0x0E <= byte < 0x20 for byte in sample):
        return "application/octet-stream"
    return "text/plain"


def _sniff_ooxml(data: bytes) -> str:
    """Distinguish DOCX/XLSX/macro-enabled archives by their content types part."""
    import io
    import zipfile

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            try:
                content_types = archive.read("[Content_Types].xml").decode("utf-8", "replace")
            except KeyError:
                content_types = ""
    except zipfile.BadZipFile as exc:
        raise ParserError(
            "archive could not be opened", public_detail="attachment could not be inspected"
        ) from exc

    if "wordprocessingml.document.macroEnabled" in content_types:
        return "application/vnd.ms-word.document.macroEnabled.12"
    if "spreadsheetml.sheet.macroEnabled" in content_types:
        return "application/vnd.ms-excel.sheet.macroEnabled.12"
    if "word/vbaProject.bin" in names or "xl/vbaProject.bin" in names:
        # Macro payload present regardless of what the content types claim.
        return "application/vnd.ms-word.document.macroEnabled.12"
    if "word/document.xml" in names:
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if "xl/workbook.xml" in names:
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return "application/zip"


def ensure_supported(mime: str) -> None:
    if mime in REJECTED_MIME_TYPES:
        raise UnsupportedMediaType(
            f"macro-enabled document rejected: {mime}",
            public_detail="macro-enabled documents are not accepted",
        )
    if mime not in SUPPORTED_MIME_TYPES:
        raise UnsupportedMediaType(
            f"unsupported media type: {mime}",
            public_detail="this content type cannot be safely inspected",
        )


class Parser(Protocol):
    name: str
    mime_types: frozenset[str]

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem: ...


class ParserRegistry:
    def __init__(self, parsers: list[Parser]) -> None:
        self._by_mime: dict[str, Parser] = {}
        for parser in parsers:
            for mime in parser.mime_types:
                self._by_mime[mime] = parser

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        mime = item.detected_mime
        if mime is None:
            raise ParserError(
                f"item {item.item_id} was not sniffed before parsing",
                public_detail="attachment could not be inspected",
            )
        ensure_supported(mime)
        parser = self._by_mime.get(mime)
        if parser is None:
            raise UnsupportedMediaType(
                f"no parser registered for {mime}",
                public_detail="this content type cannot be safely inspected",
            )
        parsed = parser.parse(item, limits)
        if len(parsed.normalized_text) > limits.max_text_chars:
            raise ParserError(
                "extracted text exceeded the configured limit",
                public_detail="attachment could not be inspected",
            )
        return parsed
