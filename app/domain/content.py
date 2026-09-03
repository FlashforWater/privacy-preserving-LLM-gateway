"""Normalized content items.

A content item is the unit of routing. One sensitive attachment must not discard
the safe ones (guide §3.4), so every decision, transformation and outbound
assembly step is keyed by ``item_id``.

``ContentItem`` holds raw bytes only while the request is being processed. Nothing
in this module is persisted.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ContentItemType, ImageClass


class ManifestItem(BaseModel):
    """One entry in the client-supplied manifest (guide §8.2)."""

    model_config = ConfigDict(extra="forbid")

    type: ContentItemType
    item_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    text: str | None = None
    file_field: str | None = None
    filename: str | None = Field(default=None, max_length=255)
    declared_mime: str | None = Field(default=None, max_length=128)


class ManifestMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # "tool" carries the result of a tool the agent ran. It is content like any
    # other and is inspected like any other: a directory listing or a file read
    # comes back full of real paths and names, and a gateway that only inspects
    # the first turn protects nothing after it.
    role: str = Field(pattern=r"^(system|user|assistant|tool)$")
    content: list[ManifestItem] = Field(min_length=1)
    #: Links a tool result back to the call that produced it.
    tool_call_id: str | None = Field(default=None, max_length=128)


class RequestOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    # Budget for the *whole* completion, reasoning included. A reasoning model
    # spends this before it writes a word: measured against deepseek-v4-flash, a
    # claims question consumed all 800 tokens on deliberation and returned empty
    # content. The default is set high enough that the answer survives; callers
    # that know their model does not reason can lower it per request.
    max_output_tokens: int = Field(default=4000, ge=1, le=32768)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    model: str = Field(min_length=1, max_length=128)
    messages: list[ManifestMessage] = Field(min_length=1)
    options: RequestOptions = Field(default_factory=RequestOptions)
    client_conversation_id: str | None = Field(default=None, max_length=128)
    #: Tool definitions, forwarded to the provider unchanged. They are inspected
    #: but never rewritten: a definition is developer-authored structure, and
    #: tokenizing a JSON schema would corrupt it. If protected content turns up
    #: in one — an enum of real filenames, say — the request is refused, because
    #: that is a bug in whatever built the schema rather than something to paper
    #: over silently.
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None

    def items(self) -> list[ManifestItem]:
        return [item for message in self.messages for item in message.content]


@dataclass(slots=True)
class ContentItem:
    """A manifest item plus its resolved bytes, in processing order."""

    item_id: str
    item_type: ContentItemType
    message_index: int
    position: int
    role: str
    text: str | None = None
    data: bytes | None = None
    filename: str | None = None
    declared_mime: str | None = None
    #: MIME determined from the bytes themselves, never from the client (guide §11.2).
    detected_mime: str | None = None

    @property
    def byte_size(self) -> int:
        if self.data is not None:
            return len(self.data)
        return len((self.text or "").encode("utf-8"))

    @property
    def is_attachment(self) -> bool:
        return self.item_type in (ContentItemType.FILE, ContentItemType.IMAGE)


@dataclass(slots=True)
class ExtractedSegment:
    """A labelled piece of text pulled out of a document.

    ``label`` reproduces document structure in the sanitized representation
    (guide §11.3) so the external model still sees headings and tables.
    ``origin`` records where it came from (page, sheet, header, comment) which the
    audit trail needs to prove every component was inspected.
    """

    text: str
    label: str = ""
    origin: str = ""
    page: int | None = None


@dataclass(slots=True)
class ParsedItem:
    """Result of parsing one content item.

    ``fully_inspected`` is the field the fast path hinges on. A parser sets it to
    ``False`` whenever any supported component could not be examined; a partial
    parse is a failure, not a partial success (guide §11.2).
    """

    item_id: str
    normalized_text: str = ""
    segments: list[ExtractedSegment] = field(default_factory=list)
    page_count: int = 0
    fully_inspected: bool = False
    parser_name: str = ""
    image_class: ImageClass | None = None
    #: Non-sensitive notes for audit: component names inspected, counts, codes.
    inspection_notes: dict[str, str | int | bool] = field(default_factory=dict)
    #: True when the item's bytes may be forwarded unchanged if policy agrees.
    #: Only ever set for images that passed full inspection (guide §12.2).
    original_bytes_forwardable: bool = False
    #: Image inspection detail, including the raw bytes, for the asynchronous
    #: vision classifier. In-process only; nothing here is serialized.
    image_inspection: object | None = None


def normalize_text(value: str) -> str:
    """The single normalization rule referenced by the local-model span contract.

    Local-model spans are verified against the output of this function, so it must
    be deterministic and applied exactly once. NFC only: it fixes composition
    differences without changing string length in ways that would invalidate the
    offsets the detector returns.
    """
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
