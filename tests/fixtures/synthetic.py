"""Synthetic fixtures.

Every identifier here is fabricated. The national-ID values carry a valid
checksum because the detector's confidence depends on it, but the numbers do not
belong to anybody: the area and sequence digits are chosen arbitrarily.

Guide §20.3: never use real personal data, including in tests.
"""

from __future__ import annotations

import io
import struct
import zlib

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def make_id_card(prefix17: str) -> str:
    total = sum(int(c) * w for c, w in zip(prefix17, _ID_WEIGHTS, strict=True))
    return prefix17 + _ID_CHECK[total % 11]


#: Valid-checksum synthetic national IDs.
ID_CARD = make_id_card("11010119900307999")
ID_CARD_SECOND = make_id_card("44030119851123456")

PHONE = "13812345678"
PHONE_FORMATTED = "138-1234-5678"
BANK_CARD = "4539578763621486"          # passes Luhn
EMAIL = "wei.zhang@example.invalid"
PLATE = "京A12345"
PERSON = "Wei Zhang"
PERSON_CJK = "张伟"

CLEAN_TEXT = "What documents are required to open a motor claim?"

TEXT_WITH_IDENTIFIERS = (
    f"Patient: {PERSON_CJK}\n"
    f"身份证号: {ID_CARD}\n"
    f"电话: {PHONE_FORMATTED}\n"
    "Summarise the treatment plan."
)

MEDICAL_TEXT = (
    f"Patient: {PERSON}\n"
    f"ID number: {ID_CARD}\n"
    "Diagnosis: acute hepatitis. ALT 320 U/L, AST 210 U/L.\n"
)


# ---- images --------------------------------------------------------------


def png_bytes(width: int = 8, height: int = 4, chunks: tuple[tuple[bytes, bytes], ...] = ()) -> bytes:
    def chunk(tag: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + tag + body + struct.pack(
            ">I", zlib.crc32(tag + body) & 0xFFFFFFFF
        )

    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for tag, body in chunks:
        out += chunk(tag, body)
    out += chunk(b"IDAT", zlib.compress(b"\x00" * ((width * 3 + 1) * height)))
    out += chunk(b"IEND", b"")
    return out


def exif_ifd(tags: tuple[int, ...]) -> bytes:
    body = b"II" + struct.pack("<H", 42) + struct.pack("<I", 8)
    body += struct.pack("<H", len(tags))
    for tag in tags:
        body += struct.pack("<HHI4s", tag, 3, 1, b"\x00\x00\x00\x00")
    body += struct.pack("<I", 0)
    return body


GPS_IFD_TAG = 0x8825
ARTIST_TAG = 0x013B


def jpeg_bytes(
    width: int = 16, height: int = 9, *, exif: bytes | None = None,
    comment: bytes | None = None, truncated: bool = False,
) -> bytes:
    out = b"\xff\xd8"
    if exif is not None:
        segment = b"Exif\x00\x00" + exif
        out += b"\xff\xe1" + struct.pack(">H", len(segment) + 2) + segment
    if comment is not None:
        out += b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment
    sof = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    out += b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof
    out += b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00" + b"\x00\x11\x22"
    if not truncated:
        out += b"\xff\xd9"
    return out


ORDINARY_IMAGE = png_bytes(64, 48)
GPS_IMAGE = jpeg_bytes(exif=exif_ifd((GPS_IFD_TAG,)))
ID_CARD_IMAGE = png_bytes(64, 48)          # OCR text supplied by the fake engine


# ---- office documents ----------------------------------------------------

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def docx_bytes(
    body_text: str = "Claim summary.",
    header_text: str | None = None,
    comment_text: str | None = None,
    creator: str | None = None,
    with_media: bool = False,
) -> bytes:
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="x"/>')
        archive.writestr(
            "word/document.xml",
            f'<w:document xmlns:w="{_W}"><w:body><w:p><w:r><w:t>{body_text}'
            f"</w:t></w:r></w:p></w:body></w:document>",
        )
        if header_text:
            archive.writestr(
                "word/header1.xml",
                f'<w:hdr xmlns:w="{_W}"><w:p><w:r><w:t>{header_text}</w:t></w:r></w:p></w:hdr>',
            )
        if comment_text:
            archive.writestr(
                "word/comments.xml",
                f'<w:comments xmlns:w="{_W}"><w:comment><w:p><w:r><w:t>{comment_text}'
                "</w:t></w:r></w:p></w:comment></w:comments>",
            )
        if creator:
            archive.writestr(
                "docProps/core.xml",
                '<cp:coreProperties xmlns:cp="c" xmlns:dc="d">'
                f"<dc:creator>{creator}</dc:creator></cp:coreProperties>",
            )
        if with_media:
            archive.writestr("word/media/image1.png", png_bytes())
    return buffer.getvalue()


def xlsx_bytes(
    visible_cell: str = "Summary",
    hidden_cell: str | None = None,
    comment_text: str | None = None,
) -> bytes:
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="x"/>')
        sheets = '<sheet name="Visible" sheetId="1"/>'
        if hidden_cell is not None:
            sheets += '<sheet name="Hidden" sheetId="2" state="veryHidden"/>'
        archive.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{_S}"><sheets>{sheets}</sheets></workbook>',
        )
        archive.writestr(
            "xl/sharedStrings.xml",
            f'<sst xmlns="{_S}"><si><t>{visible_cell}</t></si></sst>',
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            f'<worksheet xmlns="{_S}"><sheetData><row><c t="s"><v>0</v></c>'
            "</row></sheetData></worksheet>",
        )
        if hidden_cell is not None:
            archive.writestr(
                "xl/worksheets/sheet2.xml",
                f'<worksheet xmlns="{_S}"><sheetData><row>'
                f"<c t=\"inlineStr\"><is><t>{hidden_cell}</t></is></c>"
                "</row></sheetData></worksheet>",
            )
        if comment_text:
            archive.writestr(
                "xl/comments1.xml",
                f'<comments xmlns="{_S}"><commentList><comment><text><t>{comment_text}'
                "</t></text></comment></commentList></comments>",
            )
    return buffer.getvalue()


#: Every synthetic identifier, for the log-capture and outbound-capture assertions.
ALL_SECRETS: tuple[str, ...] = (
    ID_CARD, ID_CARD_SECOND, PHONE, PHONE_FORMATTED.replace("-", ""),
    BANK_CARD, EMAIL, PLATE, PERSON, PERSON_CJK,
)
