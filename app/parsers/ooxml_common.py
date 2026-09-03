"""Shared OOXML (DOCX/XLSX) handling.

Both formats are zip archives of XML parts. Reading the parts directly — rather
than through a convenience library — is deliberate: the safety requirement is to
inspect *every* component (headers, footers, comments, text boxes, hidden sheets,
document properties), and a library that exposes only the main body would make
"we inspected everything" impossible to assert honestly.

Guards implemented here:

* zip bomb: entry count, total uncompressed size, per-entry compression ratio;
* XML entity expansion: parts declaring a DOCTYPE or ENTITY are rejected outright;
* encrypted archives: detected and rejected;
* unknown/unreadable part: the file is marked not fully inspected, which the
  policy engine turns into a block.
"""

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ElementTree
import zipfile
from dataclasses import dataclass, field

from app.core.errors import UnsupportedMediaType

from .base import ParserError, ParserLimits

_DANGEROUS_XML = re.compile(rb"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
_TEXT_TAGS = ("}t", "}delText", "}instrText")

#: Parts that carry no user content and therefore need no text extraction.
_IGNORABLE_SUFFIXES = (".rels", ".png", ".jpeg", ".jpg", ".gif", ".bmp", ".emf",
                       ".wmf", ".bin", ".xlsb", ".ttf", ".otf")


@dataclass(slots=True)
class OoxmlPart:
    name: str
    text: str
    kind: str


@dataclass(slots=True)
class OoxmlArchive:
    parts: list[OoxmlPart] = field(default_factory=list)
    embedded_media: list[str] = field(default_factory=list)
    uninspectable: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)

    @property
    def fully_inspected(self) -> bool:
        # Embedded media is *not* inspected by the OOXML reader itself; the caller
        # must route it through the image pipeline or block the file. Media alone
        # therefore does not make the archive inspected.
        return not self.uninspectable


def open_archive(data: bytes, limits: ParserLimits) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ParserError(
            "document archive is malformed", public_detail="attachment could not be inspected"
        ) from exc

    infos = archive.infolist()
    if len(infos) > limits.max_archive_entries:
        raise ParserError(
            "document archive has too many entries",
            public_detail="attachment could not be inspected",
        )
    total = 0
    for info in infos:
        if info.flag_bits & 0x1:
            raise UnsupportedMediaType(
                "encrypted document rejected",
                public_detail="password-protected documents are not accepted",
            )
        total += info.file_size
        if total > limits.max_uncompressed_bytes:
            raise ParserError(
                "document expands beyond the configured limit",
                public_detail="attachment could not be inspected",
            )
        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > limits.max_compression_ratio and info.file_size > 1_000_000:
                raise ParserError(
                    "document compression ratio exceeds the configured limit",
                    public_detail="attachment could not be inspected",
                )
    return archive


def parse_xml(raw: bytes, part_name: str) -> ElementTree.Element:
    if _DANGEROUS_XML.search(raw[:4096]):
        raise ParserError(
            f"XML part {part_name} declares a DOCTYPE or ENTITY",
            public_detail="attachment could not be inspected",
        )
    try:
        return ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise ParserError(
            f"XML part {part_name} is malformed",
            public_detail="attachment could not be inspected",
        ) from exc


def element_text(element: ElementTree.Element) -> str:
    """Concatenate every text-bearing node.

    Includes ``instrText`` (field instructions, which can carry a mail-merge
    address) and ``delText`` (tracked deletions, which are still present in the
    file and still readable by anyone who opens it).
    """
    chunks: list[str] = []
    for node in element.iter():
        if any(node.tag.endswith(suffix) for suffix in _TEXT_TAGS):
            if node.text:
                chunks.append(node.text)
    return "".join(chunks)


def is_ignorable(name: str) -> bool:
    return name.endswith(_IGNORABLE_SUFFIXES)
