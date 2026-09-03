"""Plain text and inline manifest text."""

from __future__ import annotations

from app.domain.content import ContentItem, ExtractedSegment, ParsedItem, normalize_text

from .base import ParserError, ParserLimits


class PlainTextParser:
    name = "plain_text"
    mime_types = frozenset({"text/plain"})

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        if item.data is not None:
            try:
                raw = item.data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ParserError(
                    "text attachment is not valid UTF-8",
                    public_detail="attachment could not be inspected",
                ) from exc
        else:
            raw = item.text or ""

        text = normalize_text(raw)
        return ParsedItem(
            item_id=item.item_id,
            normalized_text=text,
            segments=[ExtractedSegment(text=text, label="", origin="body")],
            page_count=1 if text else 0,
            fully_inspected=True,
            parser_name=self.name,
            inspection_notes={"chars": len(text), "document_type": "plain_text"},
        )
