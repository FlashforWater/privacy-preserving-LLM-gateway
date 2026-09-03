"""DOCX parser.

Guide §11.2 requires inspection of body paragraphs, tables, headers, footers,
comments, text boxes, properties and embedded images — and blocking the file if a
component cannot be inspected. This parser enumerates every XML part in the
archive instead of walking a document object model, so a part nobody anticipated
still ends up either extracted or explicitly listed as uninspectable.
"""

from __future__ import annotations

from app.domain.content import ContentItem, ExtractedSegment, ParsedItem, normalize_text

from .base import ParserError, ParserLimits
from .ooxml_common import (
    OoxmlPart,
    element_text,
    is_ignorable,
    open_archive,
    parse_xml,
)

#: Part name prefix → human-readable component label used in the sanitized
#: representation and in audit notes.
_COMPONENT_LABELS: tuple[tuple[str, str], ...] = (
    ("word/document.xml", "body"),
    ("word/header", "header"),
    ("word/footer", "footer"),
    ("word/comments", "comments"),
    ("word/endnotes", "endnotes"),
    ("word/footnotes", "footnotes"),
    ("word/glossary/", "glossary"),
    ("docProps/core.xml", "properties"),
    ("docProps/app.xml", "properties"),
    ("docProps/custom.xml", "properties"),
)


def _component_for(name: str) -> str | None:
    for prefix, label in _COMPONENT_LABELS:
        if name.startswith(prefix):
            return label
    return None


class DocxParser:
    name = "docx"
    mime_types = frozenset(
        {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    )

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        if item.data is None:
            raise ParserError(
                "docx item has no bytes", public_detail="attachment could not be inspected"
            )
        archive = open_archive(item.data, limits)
        parts: list[OoxmlPart] = []
        media: list[str] = []
        uninspectable: list[str] = []

        with archive:
            for name in sorted(archive.namelist()):
                if name.endswith("/"):
                    continue
                if name.startswith("word/media/"):
                    # Embedded images are content. The parser cannot inspect
                    # pixels, so the file cannot be forwarded as an original.
                    media.append(name)
                    continue
                if is_ignorable(name):
                    continue
                if not name.endswith(".xml"):
                    uninspectable.append(name)
                    continue
                component = _component_for(name)
                if component is None:
                    # Unknown XML part: extract its text anyway so nothing is
                    # skipped, and label it so the audit trail is honest.
                    component = "other"
                raw = archive.read(name)
                text = element_text(parse_xml(raw, name))
                if component == "properties":
                    text = _properties_text(parse_xml(raw, name))
                if text.strip():
                    parts.append(OoxmlPart(name=name, text=text, kind=component))

        segments = [
            ExtractedSegment(
                text=normalize_text(part.text), label=part.kind.upper(), origin=part.name
            )
            for part in parts
        ]
        body = _render(segments, item.filename)
        fully_inspected = not uninspectable and not media

        return ParsedItem(
            item_id=item.item_id,
            normalized_text=body,
            segments=segments,
            page_count=1,
            fully_inspected=fully_inspected,
            parser_name=self.name,
            inspection_notes={
                "document_type": "docx",
                "parts_inspected": len(parts),
                "embedded_media": len(media),
                "uninspectable_parts": len(uninspectable),
                # Media means the original file must not be forwarded even if the
                # text is clean: the pixels were never examined.
                "blocks_original_forward": bool(media or uninspectable),
            },
        )


def _properties_text(root: object) -> str:
    """Document properties carry author, last-modified-by, company and comments —
    all of which routinely contain personal names."""
    chunks: list[str] = []
    for node in root.iter():  # type: ignore[union-attr]
        if node.text and node.text.strip():
            tag = node.tag.rsplit("}", 1)[-1]
            chunks.append(f"{tag}: {node.text.strip()}")
    return "\n".join(chunks)


def _render(segments: list[ExtractedSegment], filename: str | None) -> str:
    """Structured text representation (guide §11.3).

    The delimiters let the external model see document structure while making it
    obvious that the content is quoted data, not instructions.
    """
    lines = [f"[DOCUMENT file={filename or 'document.docx'}]"]
    for segment in segments:
        lines.append(f"[{segment.label}]")
        lines.append(segment.text)
        lines.append(f"[/{segment.label}]")
    lines.append("[/DOCUMENT]")
    return "\n".join(lines)
