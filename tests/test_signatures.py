"""
Signature database and validator tests.

The validators are the carver's false-positive filter, so they earn their place
only if they reject things. A validator that returns True for anything is worse
than no validator, because the confidence score treats a successful parse as the
strongest single piece of evidence a find is real.
"""

from __future__ import annotations

import bz2
import gzip
import os
import sys

import pytest

from tools.sample_files import (
    make_bmp,
    make_docx,
    make_gif,
    make_html,
    make_jpeg,
    make_mp3,
    make_pdf,
    make_png,
    make_sqlite,
    make_text,
    make_zip,
)

from sanctum.recover.signatures import (
    CATEGORY_ARCHIVE,
    CATEGORY_DATABASE,
    CATEGORY_DOCUMENT,
    CATEGORY_IMAGE,
    CATEGORY_OTHER,
    CATEGORY_WEB,
    SIGNATURES,
    SIGNATURES_BY_ID,
    FileSignature,
    build_first_byte_index,
    categories,
    get_signature,
    signatures_for_category,
    validate_always,
    validate_bmp,
    validate_bzip2,
    validate_gif,
    validate_gzip,
    validate_jpeg,
    validate_mp3,
    validate_pe,
    validate_pdf,
    validate_png,
    validate_sqlite,
    validate_zip,
)


# -- registry --------------------------------------------------------------

def test_signature_ids_are_unique():
    ids = [s.id for s in SIGNATURES]
    assert len(ids) == len(set(ids))


def test_registry_index_matches_the_tuple():
    for signature in SIGNATURES:
        assert SIGNATURES_BY_ID[signature.id] is signature
        assert get_signature(signature.id) is signature


def test_unknown_signature_id_raises():
    with pytest.raises(KeyError):
        get_signature("no-such-format")


def test_every_signature_has_a_header_and_a_usable_name():
    for signature in SIGNATURES:
        assert signature.headers, signature.id
        assert signature.name and signature.extension and signature.category, signature.id


def test_every_signature_declares_a_sane_size_range():
    for signature in SIGNATURES:
        assert 0 < signature.min_size <= signature.max_size, signature.id


def test_categories_are_derived_from_the_database():
    listed = categories()
    assert CATEGORY_IMAGE in listed
    assert CATEGORY_DOCUMENT in listed
    assert CATEGORY_ARCHIVE in listed
    assert set(listed) == {s.category for s in SIGNATURES}


def test_signatures_for_category_filters_correctly():
    images = signatures_for_category(CATEGORY_IMAGE)
    assert images
    assert all(s.category == CATEGORY_IMAGE for s in images)
    assert len(images) < len(SIGNATURES)


def test_signatures_for_an_unknown_category_is_empty():
    # The registry's collections are tuples throughout (``SIGNATURES``,
    # ``categories()``), so an empty result is ``()`` rather than ``[]``.
    assert signatures_for_category("No Such Category") == ()


def test_first_byte_index_buckets_signatures_by_their_opening_byte():
    index = build_first_byte_index()
    assert index
    for first_byte, bucket in index.items():
        assert bucket
        for signature in bucket:
            # A signature may declare several headers - MP3 accepts an ID3 tag
            # or a bare MPEG frame - and it is indexed under each of them, so
            # the bucket key is the first byte of *some* header, not
            # necessarily of ``headers[0]``. Indexing only by headers[0] would
            # be the narrower behaviour, and would miss every ID3-less MP3.
            opening_bytes = {header[0] for header in signature.headers if header}
            assert first_byte in opening_bytes, (signature.id, first_byte)


def test_first_byte_index_covers_every_signature():
    index = build_first_byte_index()
    indexed = {s.id for bucket in index.values() for s in bucket}
    assert indexed == {s.id for s in SIGNATURES}


# -- header matching -------------------------------------------------------

def test_matches_header_returns_the_matching_header():
    jpeg = get_signature("jpeg")
    assert jpeg.matches_header(b"\xff\xd8\xff\xe0rest") == b"\xff\xd8\xff"
    assert jpeg.matches_header(b"not a jpeg at all") is None


def test_max_header_len_is_the_longest_alternative():
    signature = FileSignature(
        id="test", name="Test", extension=".t", category=CATEGORY_OTHER,
        headers=(b"AB", b"ABCDEFG"),
    )
    assert signature.max_header_len == 7


# -- validators accept genuine files ---------------------------------------

@pytest.mark.parametrize(
    "validator,builder",
    [
        (validate_jpeg, lambda: make_jpeg(64, 64)),
        (validate_png, lambda: make_png(32, 32, (10, 20, 30))),
        (validate_gif, lambda: make_gif(32, 32)),
        (validate_bmp, lambda: make_bmp(32, 32)),
        (validate_pdf, lambda: make_pdf("Title", "Body")),
        (validate_zip, lambda: make_zip({"a.txt": b"member"})),
        (validate_sqlite, make_sqlite),
        (validate_mp3, make_mp3),
        (validate_gzip, lambda: gzip.compress(b"sanctum gzip payload" * 32)),
        (validate_bzip2, lambda: bz2.compress(b"sanctum bzip2 payload" * 32)),
    ],
)
def test_validators_accept_the_real_thing(validator, builder):
    assert validator(builder())


def _a_readable_pe_file() -> str | None:
    """
    A PE file this process can actually open.

    ``sys.executable`` is the obvious candidate and is not always usable: a
    Store-installed Python is launched through an execution-alias stub in
    ``WindowsApps``, which exists and reports a path but raises
    ``OSError: [Errno 22]`` when opened. Any system DLL or executable will do,
    since the validator is being asked about the format, not about Python.
    """
    candidates = [sys.executable]
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates += [
            os.path.join(system_root, "System32", name)
            for name in ("kernel32.dll", "advapi32.dll", "notepad.exe", "cmd.exe")
        ]
    else:
        candidates += ["/bin/ls", "/usr/bin/env", "/bin/sh"]
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            with open(candidate, "rb"):
                pass
        except OSError:
            continue
        return candidate
    return None


def test_validate_pe_accepts_a_real_executable():
    """Validated against a real PE image rather than a hand-built header."""
    path = _a_readable_pe_file()
    if path is None:
        pytest.skip("no readable PE file on this machine")

    with open(path, "rb") as handle:
        assert validate_pe(handle.read(4096)), path


# -- validators reject junk ------------------------------------------------

@pytest.mark.parametrize(
    "validator",
    [validate_jpeg, validate_png, validate_gif, validate_bmp, validate_pdf,
     validate_zip, validate_sqlite, validate_pe],
)
def test_validators_reject_empty_input(validator):
    assert validator(b"") is False


@pytest.mark.parametrize(
    "validator",
    [validate_jpeg, validate_png, validate_gif, validate_bmp, validate_pdf,
     validate_zip, validate_sqlite, validate_pe, validate_mp3, validate_gzip,
     validate_bzip2],
)
def test_validators_reject_random_data(validator):
    """
    The false-positive filter's whole job.

    Unallocated space is mostly noise; if a validator passed random data the
    carver would report thousands of phantom files.
    """
    for _ in range(8):
        assert validator(os.urandom(4096)) is False


@pytest.mark.parametrize(
    "validator",
    [validate_jpeg, validate_png, validate_gif, validate_bmp, validate_pdf,
     validate_zip, validate_sqlite, validate_pe, validate_mp3, validate_gzip,
     validate_bzip2],
)
def test_validators_reject_zero_filled_regions(validator):
    """A wiped region is the other common source of coincidental header matches."""
    assert validator(b"\x00" * 8192) is False


def test_three_byte_magics_are_not_treated_as_validation():
    """
    The archives whose magic is only three bytes long.

    ``\\x1f\\x8b\\x08`` and ``BZh`` are short enough that a 4 MiB block of random
    data - the residue of a DoD wipe's final pass - contains roughly a quarter of
    an apparent header for each. A validator that stops at the magic therefore
    reports archives recovered from a sanitized volume, which is the one claim
    Module 3 must never make about Module 1's output.

    Each format does carry more structure immediately behind the magic: gzip's
    reserved flag bits and XFL/OS codes, bzip2's block constant. Both are checked.
    """
    real_gzip = gzip.compress(b"payload" * 64)
    assert validate_gzip(real_gzip) is True
    # Reserved flag bits set - no compressor emits this.
    assert validate_gzip(real_gzip[:3] + b"\xe0" + real_gzip[4:]) is False
    # XFL outside the three values a compressor writes.
    assert validate_gzip(real_gzip[:8] + b"\x7f" + real_gzip[9:]) is False
    # OS code not in the documented list.
    assert validate_gzip(real_gzip[:9] + b"\x7e" + real_gzip[10:]) is False

    real_bzip2 = bz2.compress(b"payload" * 64)
    assert validate_bzip2(real_bzip2) is True
    # A level digit is required, and then the block constant.
    assert validate_bzip2(b"BZh" + b"0" + real_bzip2[4:]) is False
    assert validate_bzip2(b"BZh9" + b"\x00" * 32) is False


def test_mp3_needs_a_second_frame_at_the_computed_boundary():
    """
    The MP3 header is too small to validate on its own.

    Four bytes with roughly eleven constrained bits means about one random
    window in 370 matches, so a 4 KiB block of noise from a wiped volume carries
    a dozen apparent headers. A validator that stops there manufactures audio
    out of sanitized media. Requiring the *next* header to land exactly where
    the first one says it should is what separates a stream from a coincidence -
    and it is why the near-miss below, correct in every field but the stride, is
    rejected.
    """
    real = make_mp3(frames=4, id3=False)
    assert validate_mp3(real) is True

    # A second header that is valid in every field but sits at the wrong
    # offset: the real frame length here is 417 bytes, this one is 300.
    header = real[:4]
    wrong_stride = header + b"\x00" * 296 + header + b"\x00" * 2000
    assert validate_mp3(wrong_stride) is False

    # A single header followed by filler is the shape random data takes.
    assert validate_mp3(header + b"\x00" * 2048) is False
    assert validate_mp3(header) is False


def test_mp3_accepts_an_id3_tag_that_declares_a_sane_length():
    """The tag path must still work, and must not skip to a bogus offset."""
    assert validate_mp3(make_mp3(frames=4, id3=True)) is True

    # A tag whose synchsafe size has the high bit set is not a synchsafe size.
    broken = bytearray(make_mp3(frames=4, id3=True))
    broken[6] = 0x80
    assert validate_mp3(bytes(broken)) is False


def test_validators_reject_a_bare_header_with_nothing_behind_it():
    """
    A magic number alone is not a file. This is what distinguishes a validated
    find from a coincidental byte sequence.
    """
    assert validate_png(b"\x89PNG\r\n\x1a\n") is False
    assert validate_zip(b"PK\x03\x04") is False
    assert validate_gif(b"GIF89a") is False
    assert validate_bmp(b"BM") is False


def test_sqlite_validator_rejects_a_header_with_an_absurd_page_size():
    header = b"SQLite format 3\x00" + b"\x00" * 84
    assert validate_sqlite(header) is False


def test_validate_always_accepts_anything():
    """The escape hatch for formats with no structure to check."""
    assert validate_always(b"")
    assert validate_always(os.urandom(64))


# -- document and web formats ---------------------------------------------

def test_html_and_xml_are_registered_as_web_formats():
    web = {s.id for s in signatures_for_category(CATEGORY_WEB)}
    assert "html" in web
    assert "xml" in web


def test_office_formats_are_registered_apart_from_plain_zip():
    """
    A .docx is a ZIP, so both signatures match the same bytes. Without a
    priority ordering every Office file would be reported as a generic archive.
    """
    office = {s.id for s in SIGNATURES if s.id in {"docx", "xlsx", "pptx"}}
    assert office == {"docx", "xlsx", "pptx"}

    zip_priority = get_signature("zip").priority
    for identifier in office:
        assert get_signature(identifier).priority < zip_priority, identifier


def test_a_real_docx_satisfies_both_its_own_and_the_zip_signature():
    data = make_docx("Some content")
    assert validate_zip(data)
    assert get_signature("docx").validator(data)


def test_database_category_covers_sqlite():
    databases = {s.id for s in signatures_for_category(CATEGORY_DATABASE)}
    assert "sqlite" in databases


# -- generated sample corpus ----------------------------------------------

def test_the_sample_corpus_is_recognised_by_its_own_signature(tmp_path):
    """
    Every file the demo corpus plants must be identifiable by signature, or the
    carving demo would quietly fail to find its own fixtures.
    """
    expectations = {
        "Photo_Holiday.JPG": "jpeg",
        "Screenshot.png": "png",
        "Diagram.GIF": "gif",
        "Chart.bmp": "bmp",
        "Contract.pdf": "pdf",
        "Archive.zip": "zip",
        "Credentials.db": "sqlite",
    }
    builders = {
        "Photo_Holiday.JPG": lambda: make_jpeg(64, 64),
        "Screenshot.png": lambda: make_png(48, 48, (200, 60, 60)),
        "Diagram.GIF": lambda: make_gif(32, 32),
        "Chart.bmp": lambda: make_bmp(32, 32),
        "Contract.pdf": lambda: make_pdf("Service Agreement", "Signed copy."),
        "Archive.zip": lambda: make_zip({"readme.txt": b"planted\n"}),
        "Credentials.db": make_sqlite,
    }

    for name, identifier in expectations.items():
        data = builders[name]()
        signature = get_signature(identifier)
        assert signature.matches_header(data), name
        assert signature.validator(data), name
        assert len(data) >= signature.min_size, name


def test_plain_text_has_no_signature_and_that_is_the_honest_answer():
    """
    There is no magic number for prose.

    A carver cannot find a .txt from content alone, and the fixture set is
    arranged so the accuracy tests do not pretend otherwise.
    """
    text = make_text()
    matching = [s.id for s in SIGNATURES if s.matches_header(text)]
    assert matching == []
