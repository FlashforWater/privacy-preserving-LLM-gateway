"""Local OCR engines. Nothing here talks to the network."""

from __future__ import annotations

from .base import OcrEngine, OcrLine, OcrResult, OcrUnavailable


class RapidOcrEngine:
    """RapidOCR (ONNX Runtime). Imported lazily so the gateway starts without it;
    if it is missing when OCR is required, the request fails closed rather than
    silently skipping inspection."""

    name = "rapidocr"

    def __init__(self) -> None:
        self._engine = None

    def _get(self) -> object:
        if self._engine is None:
            try:
                from rapidocr_onnxruntime import RapidOCR
            except ImportError as exc:
                raise OcrUnavailable(
                    'OCR backend not installed (pip install ".[ocr]")',
                    public_detail="local inspection unavailable",
                ) from exc
            self._engine = RapidOCR()
        return self._engine

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
        import io

        engine = self._get()
        try:
            result, _elapsed = engine(io.BytesIO(data))  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - any engine failure is fail-closed
            raise OcrUnavailable(
                f"OCR engine failed: {type(exc).__name__}",
                public_detail="local inspection unavailable",
            ) from exc
        lines = tuple(
            OcrLine(text=str(entry[1]), confidence=float(entry[2]))
            for entry in (result or [])
        )
        return OcrResult(lines=lines, engine=self.name)


class DisabledOcrEngine:
    """Explicitly configured absence of OCR (``OCR_BACKEND=none``).

    Selecting this does not make images safe; it makes every image that needs
    textual inspection fail closed. That is the intended, visible consequence.
    """

    name = "disabled"

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
        raise OcrUnavailable(
            "OCR backend is disabled by configuration",
            public_detail="local inspection unavailable",
        )


class StaticOcrEngine:
    """Deterministic fake for tests and the docker dev profile."""

    name = "static-ocr"

    def __init__(self, mapping: dict[bytes, str] | None = None, default: str = "") -> None:
        self._mapping = mapping or {}
        self._default = default

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
        text = self._mapping.get(data, self._default)
        lines = tuple(OcrLine(line, 0.95) for line in text.splitlines() if line.strip())
        return OcrResult(lines=lines, engine=self.name)


def build_ocr_engine(backend: str) -> OcrEngine:
    if backend == "local":
        return RapidOcrEngine()
    if backend == "none":
        return DisabledOcrEngine()
    raise OcrUnavailable(f"unknown OCR backend {backend!r}")
