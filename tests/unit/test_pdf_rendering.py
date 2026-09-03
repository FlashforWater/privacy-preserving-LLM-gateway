"""Rasterising scanned PDF pages.

A page with no text layer is a picture of a document. Extraction returns nothing,
and "nothing" reads exactly like "no protected content" — which is how a scan of
an identity card takes the fast path. The parser used to refuse such pages
outright, which was safe but made scanned files unusable.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from app.parsers.base import ParserLimits, sniff_mime
from app.parsers.image import read_metadata
from app.parsers.pdf import PdfParser
from app.parsers.pdf_render import PdfiumRenderer, RenderUnavailable, _png_from_bitmap
from app.core.enums import ContentItemType
from app.domain.content import ContentItem
from app.ocr.base import OcrLine, OcrResult


class StubOcr:
    name = "stub"

    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls = 0

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
        self.calls += 1
        lines = tuple(OcrLine(line, 0.95) for line in self.text.splitlines() if line.strip())
        return OcrResult(lines=lines, engine=self.name)


class BrokenRenderer:
    name = "broken"

    def render(self, data: bytes, page_index: int) -> bytes:
        raise RenderUnavailable("nope", public_detail="attachment could not be inspected")


def text_pdf(body: str = "Patient: Wei Zhang") -> bytes:
    """A PDF with a real text layer."""
    content = f"BT /F1 12 Tf 40 700 Td ({body}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    return _assemble(objects)


def image_only_pdf(width: int = 60, height: int = 40) -> bytes:
    """A PDF whose only content is an image: a scan, as far as extraction goes."""
    pixels = b"\xff" * (width * height * 3)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Contents 4 0 R "
        f"/Resources << /XObject << /Im0 5 0 R >> >> >>".encode(),
        b"<< /Length 30 >>\nstream\n"
        + f"q {width} 0 0 {height} 0 0 cm /Im0 Do Q".encode().ljust(30)
        + b"\nendstream",
        (
            f"<< /Type /XObject /Subtype /Image /Width {width} /Height {height} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length {len(pixels)} >>"
        ).encode()
        + b"\nstream\n"
        + pixels
        + b"\nendstream",
    ]
    return _assemble(objects)


def _assemble(objects: list[bytes]) -> bytes:
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode() + b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n"
    ).encode()
    return bytes(out)


def item_for(data: bytes) -> ContentItem:
    return ContentItem(
        item_id="p1", item_type=ContentItemType.FILE, message_index=0, position=0,
        role="user", data=data, filename="doc.pdf", detected_mime=sniff_mime(data),
    )


class TestPngEncoding:
    def test_bgr_bitmap_becomes_a_valid_png(self) -> None:
        width, height = 4, 2
        # One pure-blue pixel row and one pure-red, written in BGR order.
        row = (b"\xff\x00\x00" * width, b"\x00\x00\xff" * width)
        buffer = row[0] + row[1]
        png = _png_from_bitmap(buffer, width, height, width * 3, "BGR")
        assert sniff_mime(png) == "image/png"
        meta = read_metadata(png, "image/png")
        assert (meta.width, meta.height) == (width, height)
        assert not meta.truncated

    def test_channel_order_is_swapped(self) -> None:
        """Getting this wrong does not fail loudly — OCR just reads a
        colour-inverted page and returns less."""
        png = _png_from_bitmap(b"\xff\x00\x00", 1, 1, 3, "BGR")
        raw = zlib.decompress(_idat(png))
        assert raw == b"\x00\x00\x00\xff"     # filter byte, then R=0 G=0 B=255

    def test_rgb_bitmap_is_left_alone(self) -> None:
        png = _png_from_bitmap(b"\xff\x00\x00", 1, 1, 3, "RGB")
        assert zlib.decompress(_idat(png)) == b"\x00\xff\x00\x00"

    def test_unsupported_mode_fails_closed(self) -> None:
        with pytest.raises(RenderUnavailable):
            _png_from_bitmap(b"\x00", 1, 1, 1, "CMYK")


def _idat(png: bytes) -> bytes:
    offset = 8
    while offset < len(png):
        length = struct.unpack(">I", png[offset : offset + 4])[0]
        tag = png[offset + 4 : offset + 8]
        if tag == b"IDAT":
            return png[offset + 8 : offset + 8 + length]
        offset += length + 12
    raise AssertionError("no IDAT chunk")


class TestScannedPageHandling:
    def test_text_layer_needs_no_rendering(self) -> None:
        ocr = StubOcr()
        parsed = PdfParser(ocr_engine=ocr, renderer=PdfiumRenderer()).parse(
            item_for(text_pdf()), ParserLimits()
        )
        assert parsed.fully_inspected
        assert ocr.calls == 0
        assert "Wei Zhang" in parsed.normalized_text

    def test_image_only_page_is_rendered_and_read(self) -> None:
        ocr = StubOcr("被保险人 张伟")
        parsed = PdfParser(ocr_engine=ocr, renderer=PdfiumRenderer()).parse(
            item_for(image_only_pdf()), ParserLimits()
        )
        assert ocr.calls == 1
        assert parsed.fully_inspected
        assert "张伟" in parsed.normalized_text
        assert parsed.inspection_notes["ocr_pages"] == 1

    def test_ocr_of_a_page_blocks_original_forwarding(self) -> None:
        """The text was reconstructed from pixels, so the file itself carries
        more than the gateway inspected."""
        parsed = PdfParser(ocr_engine=StubOcr("x"), renderer=PdfiumRenderer()).parse(
            item_for(image_only_pdf()), ParserLimits()
        )
        assert parsed.inspection_notes["blocks_original_forward"] is True

    def test_without_a_renderer_the_page_stays_uninspected(self) -> None:
        parsed = PdfParser(ocr_engine=StubOcr("x")).parse(
            item_for(image_only_pdf()), ParserLimits()
        )
        assert not parsed.fully_inspected
        assert parsed.inspection_notes["uninspected_pages"] == 1

    def test_render_failure_leaves_the_page_uninspected(self) -> None:
        """A broken renderer must not look like a blank page."""
        parsed = PdfParser(ocr_engine=StubOcr("x"), renderer=BrokenRenderer()).parse(
            item_for(image_only_pdf()), ParserLimits()
        )
        assert not parsed.fully_inspected

    def test_incomplete_ocr_leaves_the_page_uninspected(self) -> None:
        class PartialOcr(StubOcr):
            def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
                return OcrResult(lines=(OcrLine("half", 0.9),), engine="stub", complete=False)

        parsed = PdfParser(ocr_engine=PartialOcr(), renderer=PdfiumRenderer()).parse(
            item_for(image_only_pdf()), ParserLimits()
        )
        assert not parsed.fully_inspected


def _page(width: float, height: float) -> object:
    class Page:
        @staticmethod
        def get_width() -> float:
            return width

        @staticmethod
        def get_height() -> float:
            return height

    return Page()


class TestRenderLimits:
    def test_large_page_is_scaled_to_fit_the_budget(self) -> None:
        """Shrinking beats refusing while the result stays legible."""
        renderer = PdfiumRenderer(scale=4.0, max_pixels=4_000_000)
        page = _page(1000.0, 1000.0)

        scale = renderer._scale_for(page, 4.0)
        assert scale < 4.0
        assert 1000 * scale * 1000 * scale <= 4_000_000 * 1.01

    def test_page_too_large_to_render_legibly_is_refused(self) -> None:
        """An unreadable render is worse than none: OCR returns no text, and no
        text is indistinguishable from a clean page. Refusing leaves the page
        uninspected, which blocks the file."""
        renderer = PdfiumRenderer(scale=4.0, max_pixels=10_000)
        with pytest.raises(RenderUnavailable):
            renderer._scale_for(_page(600.0, 800.0), 4.0)

    def test_the_pixel_cap_is_actually_enforced(self) -> None:
        """Regression: a floor of 1.0 on the fitted scale silently let a render
        exceed the budget by a factor of forty-eight."""
        renderer = PdfiumRenderer(scale=2.0, max_pixels=1_000_000)
        page = _page(2000.0, 2000.0)
        scale = renderer._scale_for(page, 2.0)
        assert 2000 * scale * 2000 * scale <= 1_000_000 * 1.01

    def test_small_page_keeps_the_requested_scale(self) -> None:
        renderer = PdfiumRenderer(scale=2.0, max_pixels=40_000_000)
        assert renderer._scale_for(_page(612.0, 792.0), 2.0) == 2.0

    def test_a4_at_the_default_budget_is_unaffected(self) -> None:
        """The cap should only bite on genuinely enormous pages."""
        renderer = PdfiumRenderer()
        assert renderer._scale_for(_page(595.0, 842.0), renderer.scale) == renderer.scale
