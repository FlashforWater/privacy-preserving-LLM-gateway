"""Rasterising PDF pages so OCR can inspect them.

A page with no text layer is a picture of a document. Extraction returns nothing,
and "nothing" is indistinguishable from "no protected content" — which is how a
scan of an identity card would take the fast path. Until this module existed the
parser refused such pages outright; now it renders them and lets OCR look.

PDFium is used through ``pypdfium2``: permissively licensed, ships prebuilt
binaries, and needs no system packages. PyMuPDF renders well but is AGPL, which
is a licensing decision rather than an engineering one and not ours to make
quietly.

The rendered bitmap is encoded to PNG here with :mod:`zlib` rather than through an
imaging library. These are pixels the gateway generated a moment ago, so there is
no metadata to preserve and nothing to normalise away — the encoder is twenty
lines, and it keeps the dependency footprint of the trusted zone smaller.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from app.core.errors import InspectionFailedClosed

#: Rendering scale. 2.0 is roughly 144 dpi for a page authored at 72 dpi, which
#: is the usual floor for OCR on printed Chinese text; below it, small print and
#: stamped seals start to disappear.
DEFAULT_SCALE = 2.0

#: The smallest scale still worth handing to OCR. Below this the render is
#: unreadable, and an unreadable render is worse than none: OCR returns no text,
#: and "no text" is indistinguishable from "this page is clean". A page that
#: cannot be rendered legibly within the pixel budget is refused, which leaves it
#: uninspected and blocks the file.
MIN_USABLE_SCALE = 0.5


class RenderUnavailable(InspectionFailedClosed):
    """The renderer is missing or the page could not be rasterised."""


@dataclass(slots=True)
class PdfiumRenderer:
    """Renders one page to PNG bytes."""

    name: str = "pypdfium2"
    scale: float = DEFAULT_SCALE
    #: Upper bound on the rendered bitmap. A page declaring an enormous MediaBox
    #: would otherwise turn a scale factor into gigabytes of pixels.
    max_pixels: int = 40_000_000

    def render(self, data: bytes, page_index: int) -> bytes:
        try:
            import pypdfium2
        except ImportError as exc:
            raise RenderUnavailable(
                'PDF page rendering is not installed (pip install ".[documents]")',
                public_detail="attachment could not be inspected",
            ) from exc

        document = None
        try:
            document = pypdfium2.PdfDocument(data)
            page = document[page_index]
            scale = self._scale_for(page, self.scale)
            bitmap = page.render(scale=scale)
            return _png_from_bitmap(
                bytes(bitmap.buffer), bitmap.width, bitmap.height,
                bitmap.stride, bitmap.mode,
            )
        except RenderUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - any render failure is fail-closed
            raise RenderUnavailable(
                f"page {page_index + 1} could not be rendered: {type(exc).__name__}",
                public_detail="attachment could not be inspected",
            ) from exc
        finally:
            if document is not None:
                document.close()

    def _scale_for(self, page: object, scale: float) -> float:
        """Fit the render inside the pixel budget, or refuse the page.

        Shrinking beats refusing while the result is still legible: a smaller
        render is worse for OCR but is an inspection. Past that point the trade
        inverts — an unreadable page yields no text, and no text reads as a clean
        page. So the scale is fitted to the budget and, if it lands below
        :data:`MIN_USABLE_SCALE`, the page is refused instead.
        """
        width = float(page.get_width())    # type: ignore[attr-defined]
        height = float(page.get_height())  # type: ignore[attr-defined]
        if width <= 0 or height <= 0:
            return scale
        projected = width * scale * height * scale
        if projected <= self.max_pixels:
            return scale
        fitted = scale * (self.max_pixels / projected) ** 0.5
        if fitted < MIN_USABLE_SCALE:
            raise RenderUnavailable(
                f"page is too large to render legibly within {self.max_pixels} pixels "
                f"(would need scale {fitted:.2f})",
                public_detail="attachment could not be inspected",
            )
        return fitted


def _png_from_bitmap(buffer: bytes, width: int, height: int, stride: int, mode: str) -> bytes:
    """Encode a raw bitmap as an 8-bit PNG.

    PDFium hands back BGR or BGRA depending on whether the page has alpha, so the
    channel order is swapped to RGB here. Getting this wrong does not fail
    loudly — OCR simply reads a colour-inverted page and returns less — so the
    mode is checked rather than assumed.
    """
    channels = {"BGR": 3, "RGB": 3, "BGRA": 4, "RGBA": 4, "L": 1}.get(mode)
    if channels is None:
        raise RenderUnavailable(
            f"unsupported bitmap mode {mode!r}",
            public_detail="attachment could not be inspected",
        )
    swap = mode.startswith("BGR")
    colour_type = {1: 0, 3: 2, 4: 6}[channels]

    raw = bytearray()
    for y in range(height):
        row = buffer[y * stride : y * stride + width * channels]
        if swap:
            pixels = bytearray(row)
            pixels[0::channels], pixels[2::channels] = pixels[2::channels], pixels[0::channels]
            row = bytes(pixels)
        raw.append(0)          # filter type 0 (None) for this scanline
        raw.extend(row)

    def chunk(tag: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body))
            + tag
            + body
            + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, colour_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + chunk(b"IEND", b"")
    )
