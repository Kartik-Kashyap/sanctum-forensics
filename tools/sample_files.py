"""
Generators for genuinely valid sample files.

The recovery engine validates what it carves, so planted test data must be real
decodable files - not random bytes with a JPEG header glued on. Everything here
is produced with the standard library plus, for JPEG, a small hand-written
baseline encoder, so the test-media builder has no third-party dependencies and
works on any machine.

A word on the JPEG encoder: it emits a legal baseline image using custom
(but spec-compliant) Huffman tables with a single DC symbol and an EOB. That
keeps it short enough to audit and produces a file any decoder accepts, which
is exactly what a carver test needs.
"""

from __future__ import annotations

import io
import sqlite3
import struct
import zlib
import zipfile
from pathlib import Path


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------

def _png_chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def make_png(width: int = 64, height: int = 64, rgb: tuple[int, int, int] = (30, 90, 200)) -> bytes:
    """A valid PNG filled with a solid colour and a diagonal band."""
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: none
        for x in range(width):
            if abs(x - y) < 4:
                raw.extend((255, 255, 255))
            else:
                raw.extend(rgb)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit truecolour
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + _png_chunk(b"IEND", b"")
    )


# --------------------------------------------------------------------------
# JPEG (minimal baseline encoder)
# --------------------------------------------------------------------------

#: Custom but spec-legal tables: one DC category (0) and one AC symbol (EOB).
_DHT_DC = bytes([0x00]) + bytes([1] + [0] * 15) + bytes([0x00])
_DHT_AC = bytes([0x10]) + bytes([1] + [0] * 15) + bytes([0x00])


def make_jpeg(width: int = 64, height: int = 64) -> bytes:
    """
    A valid baseline JPEG that decodes to uniform mid-grey.

    Every MCU codes DC-difference 0 followed by end-of-block, so the entropy
    segment is a run of zero bytes - legal, tiny, and containing no 0xFF that
    would need stuffing.
    """
    if width % 8 or height % 8:
        raise ValueError("width and height must be multiples of 8")

    # Quantisation table: all ones (lossless-ish, keeps the file small).
    dqt = bytes([0x00]) + bytes([1] * 64)

    # Start of frame: baseline, 8-bit, one grayscale component.
    sof0 = (
        bytes([8])
        + struct.pack(">HH", height, width)
        + bytes([1])                      # one component
        + bytes([1, 0x11, 0x00])          # id=1, 1x1 sampling, quant table 0
    )

    # Start of scan: one component, DC table 0, AC table 0.
    sos = bytes([1]) + bytes([1, 0x00]) + bytes([0, 63, 0])

    blocks = (width // 8) * (height // 8)
    # Two bits ('00') per block: DC category 0, then EOB.
    total_bits = blocks * 2
    total_bytes = (total_bits + 7) // 8
    entropy = bytearray(total_bytes)  # all zero bits

    # Pad the final partial byte with 1-bits, as the spec requires.
    leftover = total_bits % 8
    if leftover:
        mask = (0xFF >> leftover) & 0xFF
        entropy[-1] |= mask

    app0 = b"JFIF\x00" + bytes([1, 1, 0]) + struct.pack(">HH", 1, 1) + bytes([0, 0])

    def segment(marker: int, payload: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload

    return (
        b"\xff\xd8"
        + segment(0xE0, app0)
        + segment(0xDB, dqt)
        + segment(0xC0, sof0)
        + segment(0xC4, _DHT_DC + _DHT_AC)
        + segment(0xDA, sos)
        + bytes(entropy)
        + b"\xff\xd9"
    )


# --------------------------------------------------------------------------
# GIF / BMP
# --------------------------------------------------------------------------

def make_gif(width: int = 32, height: int = 32, rgb: tuple[int, int, int] = (200, 40, 40)) -> bytes:
    """A valid single-frame GIF87a with a two-colour table."""
    palette = bytes([0, 0, 0, *rgb])
    header = b"GIF87a" + struct.pack("<HH", width, height) + bytes([0xF0, 0, 0]) + palette

    # Minimal LZW stream: clear code, one pixel run, end-of-information.
    min_code_size = 2
    clear, end = 4, 5
    lzw = _pack_lzw(width * height, clear, end)
    return header + bytes([min_code_size]) + lzw + b"\x00" + b"\x3b"


def _pack_lzw(pixel_count: int, clear: int, end: int) -> bytes:
    """Encode a run of index-1 pixels with the simplest legal LZW stream."""
    codes = [clear, 1, end]
    bits = []
    for code in codes:
        for shift in range(3):  # 3-bit codes
            bits.append((code >> shift) & 1)
    while len(bits) % 8:
        bits.append(0)
    out = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for offset in range(8):
            byte |= bits[index + offset] << offset
        out.append(byte)
    # GIF sub-blocks are capped at 255 bytes.
    blocks = bytearray()
    for start in range(0, len(out), 255):
        chunk = out[start : start + 255]
        blocks.append(len(chunk))
        blocks.extend(chunk)
    return bytes(blocks)


def make_bmp(width: int = 32, height: int = 32, rgb: tuple[int, int, int] = (40, 160, 80)) -> bytes:
    """A valid 24-bit uncompressed BMP."""
    row_padding = (4 - (width * 3) % 4) % 4
    row_size = width * 3 + row_padding
    pixel_data = bytearray()
    for y in range(height):
        for x in range(width):
            if y < height // 2:
                pixel_data.extend((rgb[2], rgb[1], rgb[0]))  # BMP stores BGR
            else:
                pixel_data.extend((30, 30, 30))
        pixel_data.extend(b"\x00" * row_padding)

    file_size = 54 + len(pixel_data)
    file_header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, 54)
    info_header = struct.pack(
        "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixel_data), 2835, 2835, 0, 0
    )
    return file_header + info_header + bytes(pixel_data)


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------

def make_pdf(title: str = "SANCTUM Test Document", body: str = "Recovered PDF content.") -> bytes:
    """A valid, openable single-page PDF written by hand."""
    objects: list[bytes] = []

    def obj(number: int, payload: bytes) -> None:
        objects.append(f"{number} 0 obj\n".encode() + payload + b"\nendobj\n")

    content = f"BT /F1 18 Tf 72 720 Td ({title}) Tj ET\nBT /F1 11 Tf 72 690 Td ({body}) Tj ET".encode()

    obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    )
    obj(4, b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
    obj(5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for chunk in objects:
        offsets.append(len(out))
        out.extend(chunk)

    xref_offset = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
    )
    return bytes(out)


def make_zip(files: dict[str, bytes]) -> bytes:
    """A valid ZIP built with the standard library."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def make_docx(text: str = "Confidential quarterly figures.") -> bytes:
    """A minimal but structurally valid OOXML Word document."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    return make_zip(
        {
            "[Content_Types].xml": content_types.encode(),
            "_rels/.rels": rels.encode(),
            "word/document.xml": document.encode(),
        }
    )


def make_sqlite(rows: list[tuple[str, str]] | None = None) -> bytes:
    """A real SQLite database via the standard library."""
    rows = rows or [
        ("admin", "hash_a1b2c3"),
        ("analyst", "hash_d4e5f6"),
        ("suspect", "hash_998877"),
    ]
    path = ":memory:"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE credentials (username TEXT, secret TEXT)")
        connection.executemany("INSERT INTO credentials VALUES (?, ?)", rows)
        connection.commit()
        # Serialise by re-opening through the backup API to a temp file buffer.
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
            temp_path = handle.name
        target = sqlite3.connect(temp_path)
        try:
            connection.backup(target)
            target.commit()
        finally:
            target.close()
        data = Path(temp_path).read_bytes()
        Path(temp_path).unlink(missing_ok=True)
        return data
    finally:
        connection.close()


def make_html(title: str = "Recovered Page") -> bytes:
    return (
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title></head>\n"
        f"<body><h1>{title}</h1><p>This page was recovered from unallocated space.</p>"
        "</body></html>\n"
    ).encode()


def make_text(lines: int = 40) -> bytes:
    body = "\n".join(
        f"line {i:03d}: INTERNAL USE ONLY - project falcon status nominal" for i in range(lines)
    )
    return (body + "\n").encode()


def make_mp3(frames: int = 24, *, id3: bool = True) -> bytes:
    """
    A structurally valid MPEG-1 Layer III stream of silent frames.

    Only the framing is real - there is no decodable audio, because producing a
    genuine Layer III bitstream means implementing a Huffman encoder and the
    psychoacoustic model, and nothing in SANCTUM needs the samples. What matters
    is that the bytes have the exact shape a carver must recognise: a run of
    frame headers whose offsets are each computed from the previous header, with
    version, layer and sample rate held constant.

    That shape is the whole point of the fixture. A validator that only inspects
    the first four bytes accepts this *and* accepts one random window in 370 of
    a wiped volume, which is how phantom MP3s get reported. A validator that
    requires a second frame at the computed boundary accepts this and almost
    nothing else.

    Fields chosen: MPEG 1, Layer III, 128 kbit/s, 44100 Hz, no padding. That
    gives a frame length of 144 * 128000 / 44100 = 417 bytes, which is not a
    round number and so cannot be satisfied by accidentally stride-aligned data.
    """
    # 0xFF 0xFB = frame sync + MPEG 1 + Layer III + no CRC.
    # 0x90 = bitrate index 9 (128 kbit/s) + sample rate index 0 (44100 Hz).
    header = b"\xff\xfb\x90\x00"
    frame_length = 144 * 128_000 // 44_100        # 417
    body = bytearray()
    for _ in range(frames):
        body.extend(header)
        body.extend(b"\x00" * (frame_length - 4))

    if not id3:
        return bytes(body)

    # A minimal ID3v2.3 tag: header, a synchsafe size of zero, no frames.
    tag = b"ID3\x03\x00\x00" + b"\x00\x00\x00\x00"
    return tag + bytes(body)


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------

def sample_catalogue() -> dict[str, bytes]:
    """
    One of each supported format, keyed by filename.

    Used by the test-media builder and by the test suite, so both exercise the
    same corpus.
    """
    return {
        "Photo_Holiday.JPG": make_jpeg(64, 64),
        "Screenshot.png": make_png(48, 48, (200, 60, 60)),
        "Diagram.GIF": make_gif(32, 32),
        "Chart.bmp": make_bmp(32, 32),
        "Contract.pdf": make_pdf(),
        "Notes.docx": make_docx(),
        "Archive.zip": make_zip({"readme.txt": b"planted archive member\n"}),
        "Credentials.db": make_sqlite(),
        "Report.html": make_html(),
        "Statement.txt": make_text(),
    }


#: Formats whose bytes we can produce but which are large enough to make
#: fragmentation scenarios meaningful.
def large_payload(size: int, seed: bytes = b"FALCON") -> bytes:
    """Deterministic pseudo-random payload of a given size."""
    import random

    rng = random.Random(0xC0FFEE)
    body = bytearray()
    while len(body) < size:
        body.extend(seed)
        body.extend(rng.randbytes(64))
    return bytes(body[:size])
