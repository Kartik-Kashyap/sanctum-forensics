"""
File signature (magic number) database.

The carver's knowledge of file formats lives here as data, so adding a format
never means editing scanning logic.

Each entry records:

* one or more byte sequences that can begin the file,
* an optional byte sequence that ends it,
* an optional *structural validator* - a function that parses the candidate and
  confirms it is genuinely that format rather than a coincidental byte match.

The validator is what separates a toy carver from a useful one. A four-byte
header will match by chance roughly once every 4 GiB of random data; a validator
that checks the JPEG marker chain or reads a PNG chunk length turns that into a
finding with real confidence behind it.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable, Sequence

#: Categories used for auto-classification and for grouping in the UI.
CATEGORY_IMAGE = "Image"
CATEGORY_DOCUMENT = "Document"
CATEGORY_VIDEO = "Video"
CATEGORY_AUDIO = "Audio"
CATEGORY_ARCHIVE = "Archive"
CATEGORY_EXECUTABLE = "Executable"
CATEGORY_DATABASE = "Database"
CATEGORY_EMAIL = "Email"
CATEGORY_WEB = "Web"
CATEGORY_SYSTEM = "System"
CATEGORY_OTHER = "Other"

Validator = Callable[[bytes], bool]


# --------------------------------------------------------------------------
# Structural validators
# --------------------------------------------------------------------------

def validate_jpeg(data: bytes) -> bool:
    """
    Walk the JPEG marker chain and confirm it is a JPEG.

    The question this answers is "is this a JPEG?", not "is this a complete
    JPEG?". Those differ, and conflating them was a real defect: a JPEG cut off
    mid-file - the single most common thing a carver is asked to recover from
    damaged or partially overwritten media - failed the walk when the data ran
    out and was reported as *not a JPEG*, with the warning "likely a coincidental
    header match". The engine's whole truncation-reporting path, which exists to
    tell an examiner that a file is incomplete, was unreachable for every format
    with a structural validator, because being incomplete is what made them fail.

    So the two failure modes are separated here. A malformed marker chain means
    this is not a JPEG and returns False. A well-formed chain that stops because
    the data stops means it *is* a JPEG and returns True; how much of it
    survived is the end-detection layer's answer to give, and it reports that
    through ``truncated`` and a warning of its own.
    """
    if len(data) < 4 or not data.startswith(b"\xff\xd8"):
        return False
    pos = 2
    segments = 0
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            return False
        marker = data[pos + 1]
        if marker == 0xD8 or 0x00 <= marker <= 0x01 or marker == 0xFF:
            pos += 1
            continue
        if marker in (0xD9,):  # EOI
            return True
        if 0xD0 <= marker <= 0xD7:  # RSTn - no length field
            pos += 2
            continue
        if marker == 0xDA:  # start of scan
            return True  # entropy-coded data follows; header chain is sound
        if pos + 4 > len(data):
            return False
        length = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        if length < 2:
            return False
        pos += 2 + length
        segments += 1
    # Ran out of data. At least one length-prefixed segment parsed cleanly, so
    # the header is real and the file is simply cut short.
    return segments > 0


def validate_png(data: bytes) -> bool:
    """Confirm the first chunk is a well-formed IHDR of legal length."""
    if len(data) < 33 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    if data[12:16] != b"IHDR":
        return False
    length = struct.unpack(">I", data[8:12])[0]
    if length != 13:
        return False
    width, height = struct.unpack(">II", data[16:24])
    return 0 < width <= 1_000_000 and 0 < height <= 1_000_000


def validate_gif(data: bytes) -> bool:
    if len(data) < 13:
        return False
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return False
    width, height = struct.unpack("<HH", data[6:10])
    return 0 < width <= 65535 and 0 < height <= 65535


#: DIB header sizes in use across the BMP family: BITMAPCOREHEADER, the
#: ubiquitous BITMAPINFOHEADER, and the V2-V5 extensions.
_BMP_DIB_HEADER_SIZES = frozenset({12, 16, 40, 52, 56, 64, 108, 124})

#: Colour depths BMP actually defines. 0 is tolerated for BI_RGB in old files.
_BMP_BIT_DEPTHS = frozenset({0, 1, 4, 8, 16, 24, 32})


def validate_bmp(data: bytes) -> bool:
    """
    Check the whole 54-byte header, not just the declared size.

    The declared-size test this replaces was close to no test at all. "BM" is two
    bytes, so a 4 MiB block of random data - which is exactly what the random
    pass of a DoD wipe leaves behind - contains about sixty apparent BMP headers,
    and a uniformly random 32-bit length lands inside any wide range almost
    always. The result was that a sanitized volume produced phantom BMPs, which
    is the one thing Module 1 and Module 3 must never do to each other: the
    eraser's own output being reported as recoverable evidence.

    What distinguishes a real header is the several fields that must agree with
    each other. The two reserved words are zero in every writer's output, the DIB
    header size comes from a short list of real values, planes is always 1, and
    the pixel-array offset has to sit past the header and inside the file. Those
    constraints together are worth about 48 bits, which takes the expected number
    of false headers in a 4 MiB block from sixty to far below one.
    """
    if len(data) < 54 or not data.startswith(b"BM"):
        return False

    declared_size, reserved1, reserved2, pixel_offset = struct.unpack("<IHHI", data[2:14])
    if reserved1 or reserved2:
        return False

    dib_size = struct.unpack("<I", data[14:18])[0]
    if dib_size not in _BMP_DIB_HEADER_SIZES:
        return False
    if len(data) < 14 + dib_size:
        return False

    width, height = struct.unpack("<ii", data[18:26])
    if width == 0 or height == 0:
        return False

    planes, bit_depth = struct.unpack("<HH", data[26:30])
    if planes != 1 or bit_depth not in _BMP_BIT_DEPTHS:
        return False

    # The pixel array must begin after the headers and inside the file the
    # header itself declares.
    minimum_offset = 14 + dib_size
    if bit_depth <= 8:
        # Palette entries are four bytes each, between the DIB header and the
        # pixels. Only the lower bound is checkable here; the count depends on
        # whether the palette is full.
        minimum_offset += 4
    if pixel_offset < minimum_offset or pixel_offset > declared_size:
        return False

    return 54 <= declared_size <= 200_000_000


def validate_pdf(data: bytes) -> bool:
    if not data.startswith(b"%PDF-"):
        return False
    return b"obj" in data[:4096] or b"%%EOF" in data[-2048:] or len(data) > 64


def validate_zip(data: bytes) -> bool:
    """
    Confirm a ZIP local file header is coherent.

    Deliberately does not require a parseable central directory: carving a ZIP
    from unallocated space frequently yields a fragment whose directory is gone,
    and such a fragment is still worth recovering.
    """
    if len(data) < 30 or not data.startswith(b"PK\x03\x04"):
        return False
    version, flags, method = struct.unpack("<HHH", data[4:10])
    if version > 100 or method > 99:
        return False
    name_len, extra_len = struct.unpack("<HH", data[26:30])
    return name_len < 4096 and extra_len < 65535


#: Operating-system codes gzip writers emit in the header's OS byte.
_GZIP_OS_CODES = frozenset(
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 255}
)


def validate_gzip(data: bytes) -> bool:
    """
    Check the whole gzip member header, not just the three-byte magic.

    ``\\x1f\\x8b\\x08`` is only three bytes, so a 4 MiB block of random data -
    which is what the final pass of a DoD wipe leaves behind - is expected to
    contain a quarter of an apparent gzip header. With nothing behind the magic
    but a length test, the carver reported a .gz from a sanitized volume. That
    is the one output Module 3 must never produce about Module 1's work.

    Everything checked here is a field the format actually constrains: three
    reserved flag bits that must be clear, an XFL value that is one of the three
    a compressor ever writes, an OS code from the documented list, and, when the
    flags say optional fields follow, those fields actually being present and
    terminated inside the buffer.
    """
    if len(data) < 18 or not data.startswith(b"\x1f\x8b\x08"):
        return False

    flags = data[3]
    if flags & 0xE0:
        return False                       # reserved bits must be zero
    if data[8] not in (0, 2, 4):
        return False                       # XFL: max compression, best, fastest
    if data[9] not in _GZIP_OS_CODES:
        return False

    position = 10
    if flags & 0x04:                       # FEXTRA
        if position + 2 > len(data):
            return False
        extra_len = struct.unpack("<H", data[position : position + 2])[0]
        position += 2 + extra_len
    for flag in (0x08, 0x10):              # FNAME, FCOMMENT - NUL terminated
        if flags & flag:
            terminator = data.find(b"\x00", position)
            if terminator == -1:
                return False
            position = terminator + 1
    if flags & 0x02 and position + 2 > len(data):   # FHCRC
        return False
    position += 2 if flags & 0x02 else 0

    if position >= len(data):
        return False
    # The first byte of the deflate stream carries BFINAL and a two-bit BTYPE,
    # and BTYPE 3 is reserved - no compressor emits it.
    return (data[position] >> 1) & 0x03 != 3


def validate_bzip2(data: bytes) -> bool:
    """
    Require the block magic, not just ``BZh``.

    Same problem as gzip and the same consequence: three bytes of magic, so a
    quarter of an apparent bzip2 header per 4 MiB of noise. The stream header is
    ``BZh``, a level digit 1-9, then the six-byte constant 0x314159265359 that
    opens every bzip2 block. Requiring that constant is what makes this a test.
    """
    if len(data) < 32 or not data.startswith(b"BZh"):
        return False
    if data[3] not in b"123456789":
        return False
    return data[4:10] == b"\x31\x41\x59\x26\x53\x59"


def validate_ole(data: bytes) -> bool:
    """OLE2 compound document (legacy Office, MSG, thumbs.db)."""
    if len(data) < 512 or not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return False
    sector_shift = struct.unpack("<H", data[30:32])[0]
    return 7 <= sector_shift <= 20


def validate_pe(data: bytes) -> bool:
    """Confirm the MZ header points at a plausible PE signature."""
    if len(data) < 64 or not data.startswith(b"MZ"):
        return False
    try:
        lfanew = struct.unpack("<I", data[60:64])[0]
    except struct.error:
        return False
    if lfanew + 4 > len(data) or lfanew < 64:
        return False
    return data[lfanew : lfanew + 4] == b"PE\x00\x00"


def validate_elf(data: bytes) -> bool:
    if len(data) < 20 or not data.startswith(b"\x7fELF"):
        return False
    elf_class = data[4]
    endian = data[5]
    return elf_class in (1, 2) and endian in (1, 2)


def validate_sqlite(data: bytes) -> bool:
    """Read the SQLite header's page size and confirm it is a legal power of two."""
    if len(data) < 100 or not data.startswith(b"SQLite format 3\x00"):
        return False
    page_size = struct.unpack(">H", data[16:18])[0]
    if page_size == 1:
        page_size = 65536
    return page_size >= 512 and (page_size & (page_size - 1)) == 0


def validate_riff(data: bytes, form: bytes) -> bool:
    """RIFF container: check the declared size field is coherent."""
    if len(data) < 12 or not data.startswith(b"RIFF"):
        return False
    if data[8:12] != form:
        return False
    declared = struct.unpack("<I", data[4:8])[0]
    return 4 <= declared <= 4_000_000_000


def validate_mp4(data: bytes) -> bool:
    if len(data) < 12 or data[4:8] != b"ftyp":
        return False
    box_size = struct.unpack(">I", data[0:4])[0]
    return box_size >= 8


#: MPEG audio bitrate tables in kbit/s, indexed by the 4-bit bitrate field.
#: Index 0 is "free format" and index 15 is invalid, so both are zero here.
#: Row order is (MPEG 1 Layer I, Layer II, Layer III) then (MPEG 2/2.5 Layer I,
#: Layer II/III) - the tables genuinely differ between versions, which is why
#: this is a lookup rather than a formula.
_MPEG_BITRATES = {
    (1, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0),
    (1, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0),
    (1, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0),
    (2, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0),
    (2, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0),
}
_MPEG_BITRATES[(2, 3)] = _MPEG_BITRATES[(2, 2)]

#: Sample rates in Hz, indexed by the 2-bit sample-rate field. Index 3 is
#: reserved. MPEG 2.5 shares MPEG 2's layer structure at half the rate again.
_MPEG_SAMPLE_RATES = {
    3: (44100, 48000, 32000),   # MPEG 1
    2: (22050, 24000, 16000),   # MPEG 2
    0: (11025, 12000, 8000),    # MPEG 2.5
}

#: Samples per frame, keyed by (version-group, layer). Layer I is 384 in every
#: version; Layer II is always 1152; Layer III is 1152 for MPEG 1 but 576 for
#: MPEG 2/2.5, which is the single most common source of wrong MP3 boundaries.
_MPEG_SAMPLES_PER_FRAME = {
    (1, 1): 384, (1, 2): 1152, (1, 3): 1152,
    (2, 1): 384, (2, 2): 1152, (2, 3): 576,
}


def _mpeg_frame_length(data: bytes, offset: int) -> int | None:
    """
    Length in bytes of the MPEG audio frame whose header starts at ``offset``.

    Returns ``None`` if there is no valid header there, or if the frame would
    run past the buffer - a frame whose successor cannot be reached is exactly
    the shape random data takes, and is not evidence of audio.

    This exists because a bare frame header is far too weak to validate on. The
    header is four bytes of which only about 11 bits are constrained, so roughly
    one in 370 random four-byte windows matches - measured over a 4 KiB block of
    noise that is more than ten false headers per block. A wiped volume is
    mostly noise, so a header-only test manufactured phantom MP3s out of
    sanitized media, which is the single worst thing a carver can do: it invents
    evidence, and reports it at high confidence, from data that was destroyed.
    """
    if offset + 4 > len(data):
        return None
    header = data[offset : offset + 4]
    if header[0] != 0xFF or (header[1] & 0xE0) != 0xE0:
        return None

    version_bits = (header[1] >> 3) & 0x03   # 3 = MPEG 1, 2 = MPEG 2, 0 = 2.5
    layer_bits = (header[1] >> 1) & 0x03     # 3 = Layer I, 2 = II, 1 = III
    if version_bits == 1 or layer_bits == 0:
        return None                          # both are reserved values

    group = 1 if version_bits == 3 else 2
    layer = 4 - layer_bits                   # 3 -> Layer I, 1 -> Layer III

    bitrate_index = (header[2] >> 4) & 0x0F
    sample_rate_index = (header[2] >> 2) & 0x03
    if bitrate_index in (0, 15) or sample_rate_index == 3:
        return None                          # free-format, invalid, or reserved

    bitrate = _MPEG_BITRATES[(group, layer)][bitrate_index] * 1000
    sample_rate = _MPEG_SAMPLE_RATES[version_bits][sample_rate_index]
    padding = (header[2] >> 1) & 0x01

    samples = _MPEG_SAMPLES_PER_FRAME[(group, layer)]
    if layer == 1:
        # Layer I reads a 4-byte slot per coefficient, hence the extra factor.
        frame_length = (12 * bitrate // sample_rate + padding) * 4
    else:
        frame_length = samples // 8 * bitrate // sample_rate + padding

    if frame_length < 4 or offset + frame_length >= len(data):
        return None
    return frame_length


def _mpeg_frame_identity(data: bytes, offset: int) -> tuple[int, int, int]:
    """The header fields that must stay constant across a stream's frames."""
    header = data[offset : offset + 4]
    return ((header[1] >> 3) & 0x03, (header[1] >> 1) & 0x03, (header[2] >> 2) & 0x03)


def validate_mp3(data: bytes) -> bool:
    """
    Accept an ID3v2 tag followed by audio, or a run of consistent MPEG frames.

    Two consecutive frames are required, and they must agree on version, layer
    and sample rate. That is the cheapest test that distinguishes a stream from
    a coincidence: the second header has to land on a boundary computed from the
    first, which random data does not do.
    """
    offset = 0
    if data.startswith(b"ID3"):
        if len(data) < 10:
            return False
        # Bytes 6..9 are a synchsafe integer - seven bits per byte, so the top
        # bit of each must be clear. A tag declaring a nonsensical length is not
        # a tag, and skipping to a bogus offset would either read audio that is
        # not there or run off the end.
        if any(byte & 0x80 for byte in data[6:10]):
            return False
        declared = 0
        for byte in data[6:10]:
            declared = (declared << 7) | byte
        offset = 10 + declared
        if data[5] & 0x10:
            offset += 10                      # ID3v2.4 footer
        if offset >= len(data):
            # The tag is the whole buffer. Its declared length is the only
            # structure available to check, and it was checked.
            return True

    first = _mpeg_frame_length(data, offset)
    if first is None:
        return False
    if _mpeg_frame_length(data, offset + first) is None:
        return False
    return _mpeg_frame_identity(data, offset) == _mpeg_frame_identity(data, offset + first)


def validate_rtf(data: bytes) -> bool:
    return data.startswith(b"{\\rtf")


def validate_html(data: bytes) -> bool:
    head = data[:512].lower()
    return b"<html" in head or b"<!doctype html" in head or b"<head>" in head


def validate_xml(data: bytes) -> bool:
    head = data[:256]
    return head.startswith(b"<?xml") or head.startswith(b"<")


def validate_pst(data: bytes) -> bool:
    return len(data) >= 12 and data.startswith(b"!BDN")


def validate_evtx(data: bytes) -> bool:
    return len(data) >= 8 and data.startswith(b"ElfFile\x00")


def validate_regf(data: bytes) -> bool:
    return len(data) >= 512 and data.startswith(b"regf")


def validate_always(data: bytes) -> bool:
    """
    The escape hatch, for formats with no reliable structure to check.

    This is deliberately unconditional, including for empty input: a signature
    registered against it is saying it has nothing to verify, and the checks
    that still apply - header match and ``min_size`` - are made by the caller.
    Returning a length test here would look like validation while testing
    nothing the caller is not already testing.
    """
    del data
    return True


def validate_zip_office(data: bytes, needle: bytes) -> bool:
    """Office Open XML: a ZIP whose local entries name a marker file."""
    if not validate_zip(data):
        return False
    return needle in data[:8192]


# --------------------------------------------------------------------------
# Signature definition
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FileSignature:
    """A recoverable file format."""

    id: str
    name: str
    extension: str
    category: str
    headers: tuple[bytes, ...]
    footers: tuple[bytes, ...] = ()
    min_size: int = 16
    max_size: int = 64 * 1024 * 1024
    validator: Validator = validate_always
    priority: int = 100
    #: Some formats carry a prefix before the magic (e.g. MP4's box size, TIFF
    #: variants). ``header_offset`` records how many bytes precede the match.
    header_offset: int = 0
    notes: str = ""

    @property
    def max_header_len(self) -> int:
        return max(len(h) for h in self.headers)

    def matches_header(self, data: bytes) -> bytes | None:
        """Return the matching header bytes, or None."""
        for header in self.headers:
            if data.startswith(header):
                return header
        return None


# --------------------------------------------------------------------------
# The database
# --------------------------------------------------------------------------

SIGNATURES: tuple[FileSignature, ...] = (
    # ---- Images ----------------------------------------------------------
    FileSignature(
        id="jpeg",
        name="JPEG Image",
        extension="jpg",
        category=CATEGORY_IMAGE,
        headers=(b"\xff\xd8\xff",),
        footers=(b"\xff\xd9",),
        min_size=128,
        max_size=64 * 1024 * 1024,
        validator=validate_jpeg,
        priority=10,
        notes="Most commonly recovered format; supports fragmented reassembly.",
    ),
    FileSignature(
        id="png",
        name="PNG Image",
        extension="png",
        category=CATEGORY_IMAGE,
        headers=(b"\x89PNG\r\n\x1a\n",),
        footers=(b"IEND\xaeB`\x82",),
        min_size=67,
        max_size=64 * 1024 * 1024,
        validator=validate_png,
        priority=10,
    ),
    FileSignature(
        id="gif",
        name="GIF Image",
        extension="gif",
        category=CATEGORY_IMAGE,
        headers=(b"GIF87a", b"GIF89a"),
        footers=(b"\x00\x3b",),
        min_size=14,
        max_size=32 * 1024 * 1024,
        validator=validate_gif,
        priority=20,
    ),
    FileSignature(
        id="bmp",
        name="Bitmap Image",
        extension="bmp",
        category=CATEGORY_IMAGE,
        headers=(b"BM",),
        min_size=54,
        max_size=128 * 1024 * 1024,
        validator=validate_bmp,
        priority=60,
        notes="No footer; length taken from the header's declared size field.",
    ),
    FileSignature(
        id="tiff_le",
        name="TIFF Image (little-endian)",
        extension="tif",
        category=CATEGORY_IMAGE,
        headers=(b"II\x2a\x00",),
        min_size=8,
        max_size=256 * 1024 * 1024,
        priority=40,
    ),
    FileSignature(
        id="tiff_be",
        name="TIFF Image (big-endian)",
        extension="tif",
        category=CATEGORY_IMAGE,
        headers=(b"MM\x00\x2a",),
        min_size=8,
        max_size=256 * 1024 * 1024,
        priority=40,
    ),
    FileSignature(
        id="webp",
        name="WebP Image",
        extension="webp",
        category=CATEGORY_IMAGE,
        headers=(b"RIFF",),
        min_size=20,
        max_size=64 * 1024 * 1024,
        validator=lambda d: validate_riff(d, b"WEBP"),
        priority=30,
    ),

    # ---- Documents -------------------------------------------------------
    FileSignature(
        id="pdf",
        name="PDF Document",
        extension="pdf",
        category=CATEGORY_DOCUMENT,
        headers=(b"%PDF-",),
        footers=(b"%%EOF",),
        min_size=64,
        max_size=256 * 1024 * 1024,
        validator=validate_pdf,
        priority=10,
    ),
    FileSignature(
        id="ole",
        name="OLE2 Compound Document (DOC/XLS/PPT/MSG)",
        extension="doc",
        category=CATEGORY_DOCUMENT,
        headers=(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",),
        min_size=512,
        max_size=256 * 1024 * 1024,
        validator=validate_ole,
        priority=15,
        notes="Legacy Office and Outlook formats share this container.",
    ),
    FileSignature(
        id="docx",
        name="Word Document (OOXML)",
        extension="docx",
        category=CATEGORY_DOCUMENT,
        headers=(b"PK\x03\x04",),
        footers=(b"PK\x05\x06",),
        min_size=100,
        max_size=256 * 1024 * 1024,
        validator=lambda d: validate_zip_office(d, b"word/"),
        priority=25,
    ),
    FileSignature(
        id="xlsx",
        name="Excel Workbook (OOXML)",
        extension="xlsx",
        category=CATEGORY_DOCUMENT,
        headers=(b"PK\x03\x04",),
        footers=(b"PK\x05\x06",),
        min_size=100,
        max_size=256 * 1024 * 1024,
        validator=lambda d: validate_zip_office(d, b"xl/"),
        priority=25,
    ),
    FileSignature(
        id="pptx",
        name="PowerPoint Presentation (OOXML)",
        extension="pptx",
        category=CATEGORY_DOCUMENT,
        headers=(b"PK\x03\x04",),
        footers=(b"PK\x05\x06",),
        min_size=100,
        max_size=256 * 1024 * 1024,
        validator=lambda d: validate_zip_office(d, b"ppt/"),
        priority=25,
    ),
    FileSignature(
        id="rtf",
        name="Rich Text Document",
        extension="rtf",
        category=CATEGORY_DOCUMENT,
        headers=(b"{\\rtf",),
        min_size=16,
        max_size=64 * 1024 * 1024,
        validator=validate_rtf,
        priority=70,
    ),

    # ---- Archives --------------------------------------------------------
    FileSignature(
        id="zip",
        name="ZIP Archive",
        extension="zip",
        category=CATEGORY_ARCHIVE,
        headers=(b"PK\x03\x04",),
        footers=(b"PK\x05\x06",),
        min_size=30,
        max_size=512 * 1024 * 1024,
        validator=validate_zip,
        priority=80,
        notes="Lowest priority among ZIP-based types; OOXML signatures win when "
              "their markers are present.",
    ),
    FileSignature(
        id="rar4",
        name="RAR Archive (v4)",
        extension="rar",
        category=CATEGORY_ARCHIVE,
        headers=(b"Rar!\x1a\x07\x00",),
        min_size=20,
        max_size=512 * 1024 * 1024,
        priority=20,
    ),
    FileSignature(
        id="rar5",
        name="RAR Archive (v5)",
        extension="rar",
        category=CATEGORY_ARCHIVE,
        headers=(b"Rar!\x1a\x07\x01\x00",),
        min_size=20,
        max_size=512 * 1024 * 1024,
        priority=15,
    ),
    FileSignature(
        id="7z",
        name="7-Zip Archive",
        extension="7z",
        category=CATEGORY_ARCHIVE,
        headers=(b"7z\xbc\xaf\x27\x1c",),
        min_size=32,
        max_size=512 * 1024 * 1024,
        priority=20,
    ),
    FileSignature(
        id="gzip",
        name="GZIP Archive",
        extension="gz",
        category=CATEGORY_ARCHIVE,
        headers=(b"\x1f\x8b\x08",),
        min_size=18,
        max_size=256 * 1024 * 1024,
        validator=validate_gzip,
        priority=50,
    ),
    FileSignature(
        id="bzip2",
        name="BZIP2 Archive",
        extension="bz2",
        category=CATEGORY_ARCHIVE,
        headers=(b"BZh",),
        min_size=32,
        max_size=256 * 1024 * 1024,
        validator=validate_bzip2,
        priority=60,
    ),
    FileSignature(
        id="xz",
        name="XZ Archive",
        extension="xz",
        category=CATEGORY_ARCHIVE,
        headers=(b"\xfd7zXZ\x00",),
        min_size=32,
        max_size=256 * 1024 * 1024,
        priority=30,
    ),
    FileSignature(
        id="tar",
        name="TAR Archive",
        extension="tar",
        category=CATEGORY_ARCHIVE,
        headers=(b"ustar",),
        header_offset=257,
        min_size=512,
        max_size=512 * 1024 * 1024,
        priority=90,
    ),

    # ---- Media -----------------------------------------------------------
    FileSignature(
        id="mp4",
        name="MP4 Video",
        extension="mp4",
        category=CATEGORY_VIDEO,
        headers=(b"ftyp",),
        header_offset=4,
        min_size=32,
        max_size=2 * 1024 * 1024 * 1024,
        validator=validate_mp4,
        priority=40,
    ),
    FileSignature(
        id="avi",
        name="AVI Video",
        extension="avi",
        category=CATEGORY_VIDEO,
        headers=(b"RIFF",),
        min_size=32,
        max_size=2 * 1024 * 1024 * 1024,
        validator=lambda d: validate_riff(d, b"AVI "),
        priority=40,
    ),
    FileSignature(
        id="wav",
        name="WAV Audio",
        extension="wav",
        category=CATEGORY_AUDIO,
        headers=(b"RIFF",),
        min_size=44,
        max_size=512 * 1024 * 1024,
        validator=lambda d: validate_riff(d, b"WAVE"),
        priority=45,
    ),
    FileSignature(
        id="mkv",
        name="Matroska Video",
        extension="mkv",
        category=CATEGORY_VIDEO,
        headers=(b"\x1a\x45\xdf\xa3",),
        min_size=64,
        max_size=2 * 1024 * 1024 * 1024,
        priority=50,
    ),
    FileSignature(
        id="mp3",
        name="MP3 Audio",
        extension="mp3",
        category=CATEGORY_AUDIO,
        headers=(b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"\xff\xfa"),
        min_size=128,
        max_size=256 * 1024 * 1024,
        validator=validate_mp3,
        priority=65,
    ),
    FileSignature(
        id="flac",
        name="FLAC Audio",
        extension="flac",
        category=CATEGORY_AUDIO,
        headers=(b"fLaC",),
        min_size=42,
        max_size=512 * 1024 * 1024,
        priority=30,
    ),
    FileSignature(
        id="ogg",
        name="OGG Audio",
        extension="ogg",
        category=CATEGORY_AUDIO,
        headers=(b"OggS",),
        min_size=27,
        max_size=512 * 1024 * 1024,
        priority=40,
    ),

    # ---- Executables -----------------------------------------------------
    FileSignature(
        id="pe",
        name="Windows Executable/DLL",
        extension="exe",
        category=CATEGORY_EXECUTABLE,
        headers=(b"MZ",),
        min_size=64,
        max_size=512 * 1024 * 1024,
        validator=validate_pe,
        priority=55,
    ),
    FileSignature(
        id="elf",
        name="ELF Binary",
        extension="elf",
        category=CATEGORY_EXECUTABLE,
        headers=(b"\x7fELF",),
        min_size=52,
        max_size=512 * 1024 * 1024,
        validator=validate_elf,
        priority=25,
    ),
    FileSignature(
        id="class",
        name="Java Class",
        extension="class",
        category=CATEGORY_EXECUTABLE,
        headers=(b"\xca\xfe\xba\xbe",),
        min_size=32,
        max_size=64 * 1024 * 1024,
        priority=30,
    ),

    # ---- Databases & mail ------------------------------------------------
    FileSignature(
        id="sqlite",
        name="SQLite Database",
        extension="db",
        category=CATEGORY_DATABASE,
        headers=(b"SQLite format 3\x00",),
        min_size=512,
        max_size=2 * 1024 * 1024 * 1024,
        validator=validate_sqlite,
        priority=10,
    ),
    FileSignature(
        id="pst",
        name="Outlook Data File",
        extension="pst",
        category=CATEGORY_EMAIL,
        headers=(b"!BDN",),
        min_size=512,
        max_size=4 * 1024 * 1024 * 1024,
        validator=validate_pst,
        priority=20,
    ),

    # ---- Web & text ------------------------------------------------------
    FileSignature(
        id="html",
        name="HTML Document",
        extension="html",
        category=CATEGORY_WEB,
        headers=(b"<!DOCTYPE html", b"<!doctype html", b"<html"),
        # The closing tag is conventional rather than required - the spec permits
        # omitting it - but every writer emits it and it is the only end marker
        # HTML has. Without one the artefact had no footer and no structure, so
        # it ran to the 64 MiB search ceiling: a 185-byte page was reported as a
        # 16 MB artefact whose digest was of the rest of the disk. Both cases are
        # covered because the tag is case-insensitive.
        footers=(b"</html>", b"</HTML>"),
        min_size=32,
        max_size=64 * 1024 * 1024,
        validator=validate_html,
        priority=85,
    ),
    FileSignature(
        id="xml",
        name="XML Document",
        extension="xml",
        category=CATEGORY_WEB,
        headers=(b"<?xml ",),
        min_size=16,
        max_size=64 * 1024 * 1024,
        validator=validate_xml,
        priority=88,
    ),

    # ---- System artefacts -------------------------------------------------
    FileSignature(
        id="regf",
        name="Windows Registry Hive",
        extension="hive",
        category=CATEGORY_SYSTEM,
        headers=(b"regf",),
        min_size=4096,
        max_size=1 * 1024 * 1024 * 1024,
        validator=validate_regf,
        priority=15,
    ),
    FileSignature(
        id="evtx",
        name="Windows Event Log",
        extension="evtx",
        category=CATEGORY_SYSTEM,
        headers=(b"ElfFile\x00",),
        min_size=4096,
        max_size=2 * 1024 * 1024 * 1024,
        validator=validate_evtx,
        priority=12,
    ),
)

SIGNATURES_BY_ID: dict[str, FileSignature] = {s.id: s for s in SIGNATURES}


def get_signature(signature_id: str) -> FileSignature:
    try:
        return SIGNATURES_BY_ID[signature_id]
    except KeyError:
        valid = ", ".join(sorted(SIGNATURES_BY_ID))
        raise KeyError(f"Unknown signature '{signature_id}'. Available: {valid}") from None


def signatures_for_category(category: str) -> tuple[FileSignature, ...]:
    return tuple(s for s in SIGNATURES if s.category == category)


def categories() -> tuple[str, ...]:
    """All categories, in a stable display order."""
    order = [
        CATEGORY_IMAGE, CATEGORY_DOCUMENT, CATEGORY_VIDEO, CATEGORY_AUDIO,
        CATEGORY_ARCHIVE, CATEGORY_EXECUTABLE, CATEGORY_DATABASE,
        CATEGORY_EMAIL, CATEGORY_WEB, CATEGORY_SYSTEM, CATEGORY_OTHER,
    ]
    present = {s.category for s in SIGNATURES}
    return tuple(c for c in order if c in present)


# --------------------------------------------------------------------------
# First-byte index
# --------------------------------------------------------------------------

def build_first_byte_index(
    signatures: Sequence[FileSignature] | None = None,
) -> dict[int, list[FileSignature]]:
    """
    Bucket signatures by the first byte of their header.

    A full Aho-Corasick automaton would be faster, but this gets most of the
    benefit: the scanner tests one ``bytes.find`` per distinct first byte rather
    than one per signature, and the header sets here share very few first bytes.
    """
    index: dict[int, list[FileSignature]] = {}
    for signature in signatures or SIGNATURES:
        for header in signature.headers:
            if not header:
                continue
            index.setdefault(header[0], []).append(signature)
    return index
