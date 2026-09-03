"""Request normalization.

Turns the multipart manifest plus uploaded bytes into ordered
:class:`ContentItem` objects, and applies every limit that can be enforced
*before* parsing (guide §5.1.3). Doing size and count checks here means a 200 MB
zip bomb is rejected on arrival rather than after a parser has been handed it.

Content type is determined from the bytes; the declared MIME and filename are
recorded only so a mismatch can be reported.
"""

from __future__ import annotations

from app.core.enums import ContentItemType
from app.core.errors import InvalidRequest, PayloadTooLarge
from app.domain.content import ContentItem, Manifest
from app.domain.requests import NormalizedRequest
from app.parsers.base import ParserLimits, ensure_supported, sniff_mime


class Normalizer:
    def __init__(self, *, max_request_bytes: int, max_file_bytes: int) -> None:
        self._max_request_bytes = max_request_bytes
        self._max_file_bytes = max_file_bytes

    def normalize(
        self, manifest: Manifest, files: dict[str, bytes], limits: ParserLimits
    ) -> NormalizedRequest:
        items: list[ContentItem] = []
        seen_ids: set[str] = set()
        total_bytes = 0
        used_fields: set[str] = set()

        for message_index, message in enumerate(manifest.messages):
            for position, entry in enumerate(message.content):
                if entry.item_id in seen_ids:
                    raise InvalidRequest(
                        f"duplicate item_id {entry.item_id!r}",
                        public_detail="manifest contains duplicate item ids",
                    )
                seen_ids.add(entry.item_id)

                if entry.type is ContentItemType.TEXT:
                    if entry.text is None:
                        raise InvalidRequest(
                            f"text item {entry.item_id!r} has no text",
                            public_detail="manifest text item is missing its text",
                        )
                    item = ContentItem(
                        item_id=entry.item_id,
                        item_type=entry.type,
                        message_index=message_index,
                        position=position,
                        role=message.role,
                        text=entry.text,
                        detected_mime="text/plain",
                    )
                else:
                    if not entry.file_field:
                        raise InvalidRequest(
                            f"attachment {entry.item_id!r} has no file_field",
                            public_detail="manifest attachment is missing its file field",
                        )
                    data = files.get(entry.file_field)
                    if data is None:
                        raise InvalidRequest(
                            f"missing upload for field {entry.file_field!r}",
                            public_detail="a referenced attachment was not uploaded",
                        )
                    used_fields.add(entry.file_field)
                    if len(data) > self._max_file_bytes:
                        raise PayloadTooLarge(
                            f"attachment {entry.item_id!r} exceeds the per-file limit",
                            public_detail="attachment is too large",
                        )
                    detected = sniff_mime(
                        data, declared=entry.declared_mime, filename=entry.filename
                    )
                    ensure_supported(detected)
                    item = ContentItem(
                        item_id=entry.item_id,
                        item_type=entry.type,
                        message_index=message_index,
                        position=position,
                        role=message.role,
                        data=data,
                        filename=_safe_filename(entry.filename),
                        declared_mime=entry.declared_mime,
                        detected_mime=detected,
                    )

                total_bytes += item.byte_size
                if total_bytes > self._max_request_bytes:
                    raise PayloadTooLarge(
                        "request exceeds the total byte limit",
                        public_detail="request is too large",
                    )
                items.append(item)

        unreferenced = set(files) - used_fields
        if unreferenced:
            # An upload nothing points at would never be inspected. Rejecting is
            # safer than ignoring: it could be an attempt to slip bytes past the
            # item-level pipeline.
            raise InvalidRequest(
                f"{len(unreferenced)} uploaded file(s) not referenced by the manifest",
                public_detail="uploaded files must be referenced by the manifest",
            )

        return NormalizedRequest(manifest=manifest, items=items)


def _safe_filename(filename: str | None) -> str | None:
    """Strip any path structure. Filenames are user-controlled and are never used
    to open anything, but they do reach logs and the provider envelope."""
    if not filename:
        return None
    cleaned = filename.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = cleaned.replace("\x00", "")
    return cleaned[:128] or None
