"""Local OCR engines. Nothing here talks to the network."""

from __future__ import annotations

from .base import OcrEngine, OcrLine, OcrResult, OcrUnavailable


class RapidOcrEngine:
    """RapidOCR. Imported lazily so the gateway starts without it; if it is
    missing when OCR is required the request fails closed rather than silently
    skipping inspection.

    Two package generations are supported because they are genuinely different
    APIs, not a rename with a shim:

    * ``rapidocr`` (3.x) returns a result object carrying ``txts`` and ``scores``;
    * ``rapidocr_onnxruntime`` (1.x) returns a ``(rows, elapsed)`` tuple whose
      rows are ``[box, text, score]``.

    The older distribution has no wheels for recent Python versions, so a
    deployment that pins it will silently be running without OCR — which, given
    the fail-closed behaviour, means every image is blocked. Supporting both
    makes that a choice rather than an accident.
    """

    name = "rapidocr"

    def __init__(self) -> None:
        self._engine: object | None = None
        self._flavour = ""

    def _get(self) -> object:
        if self._engine is None:
            try:
                from rapidocr import RapidOCR

                self._flavour = "v3"
            except ImportError:
                try:
                    from rapidocr_onnxruntime import RapidOCR  # type: ignore[no-redef]

                    self._flavour = "v1"
                except ImportError as exc:
                    raise OcrUnavailable(
                        'OCR backend not installed (pip install ".[ocr]")',
                        public_detail="local inspection unavailable",
                    ) from exc
            self._engine = RapidOCR()
        return self._engine

    def read_image(self, data: bytes, *, max_pixels: int) -> OcrResult:
        engine = self._get()
        try:
            raw = engine(data)  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 - any engine failure is fail-closed
            raise OcrUnavailable(
                f"OCR engine failed: {type(exc).__name__}",
                public_detail="local inspection unavailable",
            ) from exc
        return OcrResult(lines=self._to_lines(raw), engine=self.name)

    @staticmethod
    def _to_lines(raw: object) -> tuple[OcrLine, ...]:
        # 3.x: an output object with parallel txts/scores sequences.
        txts = getattr(raw, "txts", None)
        if txts is not None:
            scores = getattr(raw, "scores", None) or [0.0] * len(txts)
            return tuple(
                OcrLine(text=str(text), confidence=float(score))
                for text, score in zip(txts, scores, strict=False)
            )
        # 1.x: (rows, elapsed), rows of [box, text, score]. An image with no text
        # yields None rather than an empty list.
        rows = raw[0] if isinstance(raw, tuple) else raw
        if not rows:
            return ()
        return tuple(
            OcrLine(text=str(row[1]), confidence=float(row[2]))
            for row in rows
            if len(row) >= 3
        )


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
