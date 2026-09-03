"""Document handling (guide §11, §19.2)."""

from __future__ import annotations

import pytest

from app.core.errors import ContentBlocked, UnsupportedMediaType
from app.domain.content import Manifest
from app.parsers.base import ParserLimits, sniff_mime
from app.parsers.docx import DocxParser
from app.parsers.xlsx import XlsxParser
from app.domain.content import ContentItem
from app.core.enums import ContentItemType
from tests.conftest import Harness
from tests.fixtures import synthetic


def doc_item(data: bytes, filename: str) -> ContentItem:
    return ContentItem(
        item_id="doc-1", item_type=ContentItemType.FILE, message_index=0, position=0,
        role="user", data=data, filename=filename, detected_mime=sniff_mime(data),
    )


class TestDocxInspection:
    def test_every_component_is_extracted(self) -> None:
        data = synthetic.docx_bytes(
            body_text="Claim summary.",
            header_text=f"Patient: {synthetic.PERSON_CJK}",
            comment_text=f"verify {synthetic.ID_CARD}",
            creator="Li Ming",
        )
        parsed = DocxParser().parse(doc_item(data, "claim.docx"), ParserLimits())
        text = parsed.normalized_text
        assert "Claim summary." in text
        assert synthetic.PERSON_CJK in text      # header
        assert synthetic.ID_CARD in text          # comment
        assert "Li Ming" in text                  # document properties
        assert parsed.fully_inspected

    def test_embedded_media_blocks_original_forwarding(self) -> None:
        """Text extraction cannot see pixels, so the original file must not go."""
        data = synthetic.docx_bytes(with_media=True)
        parsed = DocxParser().parse(doc_item(data, "with-image.docx"), ParserLimits())
        assert not parsed.fully_inspected
        assert parsed.inspection_notes["blocks_original_forward"] is True


class TestXlsxInspection:
    def test_hidden_sheet_is_inspected(self) -> None:
        data = synthetic.xlsx_bytes(
            visible_cell="Summary", hidden_cell=f"ID {synthetic.ID_CARD}"
        )
        parsed = XlsxParser().parse(doc_item(data, "book.xlsx"), ParserLimits())
        assert synthetic.ID_CARD in parsed.normalized_text
        assert parsed.inspection_notes["hidden_sheets"] == 1

    def test_comments_are_inspected(self) -> None:
        data = synthetic.xlsx_bytes(comment_text=f"call {synthetic.PHONE}")
        parsed = XlsxParser().parse(doc_item(data, "book.xlsx"), ParserLimits())
        assert synthetic.PHONE in parsed.normalized_text


class TestParserSafety:
    def test_type_comes_from_content_not_filename(self) -> None:
        data = synthetic.docx_bytes()
        assert sniff_mime(data, declared="image/jpeg", filename="photo.jpg").endswith(
            "wordprocessingml.document"
        )

    def test_macro_enabled_document_is_rejected(self) -> None:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", '<Types xmlns="x"/>')
            archive.writestr("word/document.xml", "<w/>")
            archive.writestr("word/vbaProject.bin", b"\x00" * 16)
        data = buffer.getvalue()
        from app.parsers.base import ensure_supported

        with pytest.raises(UnsupportedMediaType):
            ensure_supported(sniff_mime(data))

    def test_encrypted_archive_is_rejected(self) -> None:
        """Python cannot write an encrypted zip, so the flag is set by hand.

        It has to be set in the *central directory*, not the local header:
        ``ZipFile.infolist`` reads the central directory, and an earlier version
        of this test patched the local header only — it passed for the wrong
        reason until the suite was actually run.
        """
        import io
        import struct
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", '<Types xmlns="x"/>')
            archive.writestr("word/document.xml", "<w/>")
        data = bytearray(buffer.getvalue())
        for offset in range(len(data) - 4):
            if data[offset : offset + 4] == b"PK\x01\x02":       # central directory header
                flags = struct.unpack_from("<H", data, offset + 8)[0]
                struct.pack_into("<H", data, offset + 8, flags | 0x1)

        from app.core.errors import UnsupportedMediaType
        from app.parsers.ooxml_common import open_archive

        with pytest.raises(UnsupportedMediaType):
            open_archive(bytes(data), ParserLimits())

    def test_xml_entity_declaration_is_rejected(self) -> None:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", '<Types xmlns="x"/>')
            archive.writestr(
                "word/document.xml",
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document/>',
            )
        with pytest.raises(Exception):
            DocxParser().parse(doc_item(buffer.getvalue(), "bomb.docx"), ParserLimits())


class TestDocumentRouting:
    async def test_document_with_identifiers_is_not_forwarded_as_a_file(
        self, harness: Harness
    ) -> None:
        """Guide §11.1: never forward the original after sanitizing extracted text."""
        data = synthetic.docx_bytes(
            body_text="Claim summary.", header_text=f"电话: {synthetic.PHONE}"
        )
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "model-a",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "file", "item_id": "doc-1", "file_field": "file_doc-1"}
                        ],
                    }
                ],
            }
        )
        scope = await harness.open_scope()
        normalized = harness.normalize(manifest, {"file_doc-1": data})
        await harness.orchestrator.process(harness.context(scope, manifest), normalized)
        assert data not in harness.adapter.captured_bytes()
        assert synthetic.PHONE not in harness.adapter.captured_text()

    async def test_unsupported_type_is_rejected_before_forwarding(
        self, harness: Harness
    ) -> None:
        manifest = Manifest.model_validate(
            {
                "purpose": "general",
                "model": "model-a",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "file", "item_id": "doc-1", "file_field": "file_doc-1"}
                        ],
                    }
                ],
            }
        )
        with pytest.raises((UnsupportedMediaType, ContentBlocked)):
            harness.normalize(manifest, {"file_doc-1": b"\x00\x01\x02binary junk"})
        assert harness.adapter.requests == []
