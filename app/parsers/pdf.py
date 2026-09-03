"""PDF parser.

The tricky part of PDF is not extraction, it is knowing when extraction was
*insufficient*. A scanned page yields no text; treating that as "no protected
content" would forward an image of an ID card through the fast path. So a page
with no extractable text is only accepted when a page renderer plus OCR could
inspect it, and otherwise the file is marked not fully inspected — which policy
turns into a block.

``pypdf`` is imported lazily and is an optional dependency: if it is absent, PDFs
fail closed rather than being passed along uninspected.
"""

from __future__ import annotations

from typing import Protocol

from app.core.errors import UnsupportedMediaType
from app.domain.content import ContentItem, ExtractedSegment, ParsedItem, normalize_text

from .base import ParserError, ParserLimits

#: Below this many characters a page is treated as image-only.
MIN_CHARS_PER_TEXT_PAGE = 16


class PageRenderer(Protocol):
    """Renders one PDF page to image bytes so OCR can inspect it.

    Left as a protocol with no default implementation: rasterising PDFs pulls in
    a large native dependency, and the honest MVP behaviour without it is to fail
    closed on scanned pages. Phase 2 supplies a concrete renderer.
    """

    name: str

    def render(self, data: bytes, page_index: int) -> bytes: ...


class PdfParser:
    name = "pdf"
    mime_types = frozenset({"application/pdf"})

    def __init__(self, ocr_engine: object | None = None,
                 renderer: PageRenderer | None = None) -> None:
        self._ocr = ocr_engine
        self._renderer = renderer

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        if item.data is None:
            raise ParserError(
                "pdf item has no bytes", public_detail="attachment could not be inspected"
            )
        try:
            from pypdf import PdfReader
            from pypdf.errors import PdfReadError
        except ImportError as exc:
            raise ParserError(
                'PDF support is not installed (pip install ".[documents]")',
                public_detail="this content type cannot be safely inspected",
            ) from exc

        import io

        try:
            reader = PdfReader(io.BytesIO(item.data), strict=False)
        except PdfReadError as exc:
            raise ParserError(
                "PDF could not be opened", public_detail="attachment could not be inspected"
            ) from exc

        if reader.is_encrypted:
            raise UnsupportedMediaType(
                "encrypted PDF rejected",
                public_detail="password-protected documents are not accepted",
            )

        pages = reader.pages
        if len(pages) > limits.max_pages:
            raise ParserError(
                "PDF exceeds the configured page limit",
                public_detail="document has too many pages to inspect",
            )

        segments: list[ExtractedSegment] = []
        uninspected_pages: list[int] = []
        ocr_pages = 0

        for index, page in enumerate(pages, start=1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:  # noqa: BLE001 - a page that will not parse is fail-closed
                raise ParserError(
                    f"PDF page {index} could not be parsed: {type(exc).__name__}",
                    public_detail="attachment could not be inspected",
                ) from exc

            if len(text.strip()) < MIN_CHARS_PER_TEXT_PAGE:
                recovered = self._ocr_page(item.data, index - 1, limits)
                if recovered is None:
                    uninspected_pages.append(index)
                    continue
                text = recovered
                ocr_pages += 1

            segments.append(
                ExtractedSegment(
                    text=normalize_text(text), label="PAGE", origin=f"page-{index}", page=index
                )
            )

        annotations = _annotation_text(reader)
        if annotations:
            segments.append(
                ExtractedSegment(text=normalize_text(annotations), label="ANNOTATIONS",
                                 origin="annotations")
            )
        metadata_text = _metadata_text(reader)
        if metadata_text:
            segments.append(
                ExtractedSegment(text=normalize_text(metadata_text), label="PROPERTIES",
                                 origin="metadata")
            )

        return ParsedItem(
            item_id=item.item_id,
            normalized_text=_render(segments),
            segments=segments,
            page_count=len(pages),
            fully_inspected=not uninspected_pages,
            parser_name=self.name,
            inspection_notes={
                "document_type": "pdf",
                "pages": len(pages),
                "ocr_pages": ocr_pages,
                "uninspected_pages": len(uninspected_pages),
                "blocks_original_forward": bool(uninspected_pages or ocr_pages),
            },
        )

    def _ocr_page(self, data: bytes, page_index: int, limits: ParserLimits) -> str | None:
        if self._renderer is None or self._ocr is None:
            return None
        try:
            image_bytes = self._renderer.render(data, page_index)
            result = self._ocr.read_image(  # type: ignore[attr-defined]
                image_bytes, max_pixels=limits.max_ocr_pixels
            )
        except Exception:  # noqa: BLE001 - OCR failure means the page is uninspected
            return None
        if not result.complete:
            return None
        return result.text


def _annotation_text(reader: object) -> str:
    """Annotations and form fields hold text that never appears in the page
    stream — a reviewer's comment naming the claimant, for instance."""
    chunks: list[str] = []
    try:
        fields = reader.get_fields()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        fields = None
    if fields:
        for name, field in fields.items():
            value = field.get("/V") if hasattr(field, "get") else None
            if value:
                chunks.append(f"{name}: {value}")
    try:
        for page in reader.pages:  # type: ignore[attr-defined]
            for annotation in page.get("/Annots", []) or []:
                obj = annotation.get_object()
                contents = obj.get("/Contents")
                if contents:
                    chunks.append(str(contents))
    except Exception:  # noqa: BLE001 - absence of annotations is normal
        pass
    return "\n".join(chunks)


def _metadata_text(reader: object) -> str:
    try:
        metadata = reader.metadata  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return ""
    if not metadata:
        return ""
    return "\n".join(
        f"{key.lstrip('/')}: {value}" for key, value in metadata.items() if value
    )


def _render(segments: list[ExtractedSegment]) -> str:
    lines = ["[DOCUMENT]"]
    for segment in segments:
        header = f"[{segment.label}" + (f" {segment.page}]" if segment.page else "]")
        lines.append(header)
        lines.append(segment.text)
        lines.append(f"[/{segment.label}]")
    lines.append("[/DOCUMENT]")
    return "\n".join(lines)
