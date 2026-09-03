"""XLSX parser.

Guide §11.2: inspect all sheets *including hidden and very-hidden ones*, cell
values, formulas and cached results, comments, defined names and properties, and
never fetch external links.

Hidden sheets are the reason this parser reads ``workbook.xml`` rather than
iterating visible worksheets: a sheet with ``state="veryHidden"`` is invisible in
Excel's UI and is exactly where stale identifier tables tend to live.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element

from app.domain.content import ContentItem, ExtractedSegment, ParsedItem, normalize_text

from .base import ParserError, ParserLimits
from .ooxml_common import is_ignorable, open_archive, parse_xml

_NS_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


class XlsxParser:
    name = "xlsx"
    mime_types = frozenset(
        {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
    )

    def parse(self, item: ContentItem, limits: ParserLimits) -> ParsedItem:
        if item.data is None:
            raise ParserError(
                "xlsx item has no bytes", public_detail="attachment could not be inspected"
            )
        archive = open_archive(item.data, limits)
        segments: list[ExtractedSegment] = []
        media: list[str] = []
        uninspectable: list[str] = []
        external_links = 0
        hidden_sheets = 0

        with archive:
            names = sorted(archive.namelist())
            shared = _shared_strings(archive, names)

            sheet_states = _sheet_states(archive, names)
            hidden_sheets = sum(1 for state in sheet_states.values() if state != "visible")

            for name in names:
                if name.endswith("/"):
                    continue
                if name.startswith("xl/media/"):
                    media.append(name)
                    continue
                if name.startswith("xl/externalLinks/"):
                    # Recorded, never followed (guide §11.2).
                    external_links += 1
                    continue
                if is_ignorable(name):
                    continue
                if not name.endswith(".xml"):
                    uninspectable.append(name)
                    continue

                root = parse_xml(archive.read(name), name)
                if name.startswith("xl/worksheets/sheet"):
                    text = _worksheet_text(root, shared)
                    label = "SHEET"
                elif name.startswith("xl/comments") or name.startswith("xl/threadedComments"):
                    text = _all_text(root)
                    label = "COMMENTS"
                elif name == "xl/workbook.xml":
                    text = _defined_names_text(root)
                    label = "DEFINED_NAMES"
                elif name.startswith("docProps/"):
                    text = _all_text(root)
                    label = "PROPERTIES"
                elif name == "xl/sharedStrings.xml":
                    continue  # already folded into worksheet rendering
                else:
                    text = _all_text(root)
                    label = "OTHER"

                if text.strip():
                    segments.append(
                        ExtractedSegment(
                            text=normalize_text(text),
                            label=label,
                            origin=f"{name}"
                            + (f" state={sheet_states.get(name, 'visible')}" if label == "SHEET" else ""),
                        )
                    )

        body = _render(segments, item.filename)
        return ParsedItem(
            item_id=item.item_id,
            normalized_text=body,
            segments=segments,
            page_count=1,
            fully_inspected=not uninspectable and not media,
            parser_name=self.name,
            inspection_notes={
                "document_type": "xlsx",
                "segments": len(segments),
                "hidden_sheets": hidden_sheets,
                "external_links": external_links,
                "embedded_media": len(media),
                "uninspectable_parts": len(uninspectable),
                "blocks_original_forward": bool(media or uninspectable or external_links),
            },
        )


def _shared_strings(archive: object, names: list[str]) -> list[str]:
    if "xl/sharedStrings.xml" not in names:
        return []
    root = parse_xml(archive.read("xl/sharedStrings.xml"), "xl/sharedStrings.xml")  # type: ignore[attr-defined]
    return ["".join(node.itertext()) for node in root.findall(f"{_NS_MAIN}si")]


def _sheet_states(archive: object, names: list[str]) -> dict[str, str]:
    """Map worksheet part name → visibility state.

    The mapping is positional (sheet1.xml is the first ``<sheet>`` entry), which
    is how the format works when relationship ids are not resolved; it is only
    used for reporting, never to decide what to read — every sheet part is read
    regardless of state.
    """
    if "xl/workbook.xml" not in names:
        return {}
    root = parse_xml(archive.read("xl/workbook.xml"), "xl/workbook.xml")  # type: ignore[attr-defined]
    states: dict[str, str] = {}
    sheets = root.find(f"{_NS_MAIN}sheets")
    if sheets is None:
        return {}
    for index, sheet in enumerate(sheets.findall(f"{_NS_MAIN}sheet"), start=1):
        states[f"xl/worksheets/sheet{index}.xml"] = sheet.get("state", "visible")
    return states


def _worksheet_text(root: Element, shared: list[str]) -> str:
    """Render rows, keeping both the formula and its cached result.

    A formula such as ``="Patient: "&B2`` hides an identifier that the cached
    value reveals, and vice versa when the cache is stale. Both are inspected.
    """
    lines: list[str] = []
    for row in root.iter(f"{_NS_MAIN}row"):
        cells: list[str] = []
        for cell in row.findall(f"{_NS_MAIN}c"):
            formula = cell.find(f"{_NS_MAIN}f")
            value_node = cell.find(f"{_NS_MAIN}v")
            inline = cell.find(f"{_NS_MAIN}is")
            rendered = ""
            if cell.get("t") == "s" and value_node is not None and value_node.text:
                index = int(value_node.text)
                rendered = shared[index] if 0 <= index < len(shared) else ""
            elif inline is not None:
                rendered = "".join(inline.itertext())
            elif value_node is not None and value_node.text:
                rendered = value_node.text
            if formula is not None and formula.text:
                rendered = f"{rendered} [={formula.text}]" if rendered else f"[={formula.text}]"
            cells.append(rendered)
        if any(cell.strip() for cell in cells):
            lines.append(" | ".join(cells))
    return "\n".join(lines)


def _defined_names_text(root: Element) -> str:
    names = root.find(f"{_NS_MAIN}definedNames")
    if names is None:
        return ""
    return "\n".join(
        f"{node.get('name', '')}: {node.text or ''}" for node in names.findall(f"{_NS_MAIN}definedName")
    )


def _all_text(root: Element) -> str:
    return "\n".join(chunk.strip() for chunk in root.itertext() if chunk and chunk.strip())


def _render(segments: list[ExtractedSegment], filename: str | None) -> str:
    lines = [f"[DOCUMENT file={filename or 'workbook.xlsx'}]"]
    for segment in segments:
        lines.append(f"[{segment.label} origin={segment.origin}]")
        lines.append(segment.text)
        lines.append(f"[/{segment.label}]")
    lines.append("[/DOCUMENT]")
    return "\n".join(lines)
