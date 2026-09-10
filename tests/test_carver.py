"""
File carving and recovery tests.

Two kinds of test live here, and the distinction matters.

**Structural tests** use inputs built inside the test, so the expected answer is
known exactly and the test is deterministic. These are where the carving
engine's real design claims are pinned - chiefly that a JPEG containing an
embedded EXIF thumbnail is recovered whole rather than truncated at the
thumbnail's own end-of-image marker.

**Accuracy tests** carve the generated FAT16 corpus and compare recovered
SHA-256 digests against ``manifest.json``. The manifest was written when the
files were planted, so this measures recovery rather than asserting that
something was found.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from tools.sample_files import make_jpeg, make_pdf, make_png

from sanctum.core.audit import AuditChain
from sanctum.core.progress import CancelToken, OperationCancelled
from sanctum.recover.carver import SignatureCarver


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _carve(source, output_dir, **kwargs):
    return SignatureCarver().carve(source, output_dir, **kwargs)


# --------------------------------------------------------------------------
# Structural end detection
# --------------------------------------------------------------------------

def _jpeg_with_embedded_thumbnail() -> tuple[bytes, int]:
    """
    A JPEG whose EXIF block carries a complete thumbnail JPEG.

    Returns the crafted file and the offset just past the thumbnail's own
    ``FFD9`` - the point at which a naive footer search stops.
    """
    outer = make_jpeg(64, 64)
    inner = make_jpeg(32, 32)

    payload = b"Exif\x00\x00" + inner
    # APP1 segment: FF E1, then a 2-byte big-endian length that includes the
    # two length bytes themselves.
    segment = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload

    crafted = outer[:2] + segment + outer[2:]
    naive_end = 2 + len(segment)  # first FFD9 the eye can see belongs to the thumbnail
    return crafted, naive_end


def test_embedded_thumbnail_does_not_truncate_the_jpeg(tmp_path):
    """
    The failure mode that motivates structural end detection.

    A JPEG's EXIF block normally embeds a complete thumbnail, which is itself a
    JPEG and ends with its own ``FFD9``. "Find the header, find the next footer"
    therefore yields a file cut off at the end of the thumbnail - a plausible
    looking result that is silently wrong, which is the worst kind of wrong for
    forensic output.
    """
    crafted, naive_end = _jpeg_with_embedded_thumbnail()
    source = tmp_path / "with-thumbnail.jpg"
    source.write_bytes(crafted)

    result = _carve(source, tmp_path / "out", signature_ids=["jpeg"])

    assert result.error == ""
    assert result.recovered_count >= 1

    artifact = result.artifacts[0]
    assert artifact.length == len(crafted), (
        "carved length does not match the planted file - end detection stopped early"
    )
    assert artifact.digests["sha256"] == _sha256(crafted)
    assert artifact.length > naive_end, (
        "the recovered file ends at or before the thumbnail's terminator, which is "
        "exactly the truncation this engine exists to avoid"
    )
    assert artifact.truncated is False


def test_a_truncated_jpeg_is_reported_as_truncated(tmp_path):
    """
    A file whose data really is cut off must say so rather than look complete -
    an examiner has to know the difference.
    """
    complete = make_jpeg(64, 64)
    source = tmp_path / "cut.jpg"
    source.write_bytes(complete[: len(complete) // 2])

    result = _carve(source, tmp_path / "out", signature_ids=["jpeg"])

    assert result.recovered_count >= 1
    assert result.artifacts[0].truncated is True
    assert result.artifacts[0].warnings


def test_png_is_recovered_to_its_exact_length(tmp_path):
    """PNG declares chunk lengths, so the walk reaches IEND exactly."""
    data = make_png(48, 48, (10, 120, 200))
    source = tmp_path / "image.png"
    source.write_bytes(data + b"\x00" * 4096)  # trailing slack, as on real media

    result = _carve(source, tmp_path / "out", signature_ids=["png"])

    assert result.recovered_count == 1
    artifact = result.artifacts[0]
    assert artifact.length == len(data)
    assert artifact.digests["sha256"] == _sha256(data)


def test_pdf_is_recovered_through_its_trailer(tmp_path):
    data = make_pdf("Carved Report", "Body text for the carver." * 20)
    source = tmp_path / "doc.pdf"
    source.write_bytes(data)

    result = _carve(source, tmp_path / "out", signature_ids=["pdf"])

    assert result.recovered_count == 1
    assert result.artifacts[0].digests["sha256"] == _sha256(data)


def test_a_pdf_is_not_extended_into_the_next_document(tmp_path):
    """
    Two PDFs in one image, and the first must stop at its own trailer.

    The single-document test above cannot catch this. With one %%EOF in the
    search window, "the first %%EOF" and "the last %%EOF" are the same offset,
    so a carver that takes the last one looks correct. The PDF signature's
    ceiling is 256 MiB, so as soon as a second document is present in the image
    the last-%%EOF rule runs the first artefact forward until it swallows the
    second: one blob with a valid header, a valid structure and a digest that
    matches neither file, reported at high confidence. Over-running is silent;
    stopping early is not.
    """
    first = make_pdf("First Report", "The first document's body. " * 40)
    second = make_pdf("Second Report", "The second document's body. " * 40)
    gap = b"\x00" * 8192
    source = tmp_path / "two.pdf"
    source.write_bytes(first + gap + second)

    result = _carve(source, tmp_path / "out", signature_ids=["pdf"])

    digests = {artifact.digests["sha256"] for artifact in result.artifacts}
    assert _sha256(first) in digests, (
        "the first PDF was not recovered byte-exact - end detection ran past its "
        "trailer into the next document"
    )
    assert _sha256(second) in digests
    assert _sha256(first + gap + second) not in digests, (
        "a single artefact spans both documents, which is what an over-running "
        "end search produces"
    )


# --------------------------------------------------------------------------
# Extraction and output
# --------------------------------------------------------------------------

def test_recovered_files_are_written_to_disk_with_matching_digests(tmp_path):
    data = make_jpeg(64, 64)
    source = tmp_path / "photo.jpg"
    source.write_bytes(data)
    output = tmp_path / "recovered"

    result = _carve(source, output, signature_ids=["jpeg"])

    artifact = result.artifacts[0]
    written = (output / artifact.name).read_bytes()
    assert written == data
    assert _sha256(written) == artifact.digests["sha256"]


def test_write_files_false_records_without_extracting(tmp_path):
    """A preview scan must not litter the output directory."""
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(32, 32))
    output = tmp_path / "recovered"

    result = _carve(source, output, signature_ids=["jpeg"], write_files=False)

    assert result.recovered_count >= 1
    assert result.artifacts[0].output_path == ""
    assert not list(output.glob("*"))


def test_digests_are_computed_for_every_recovered_artifact(tmp_path):
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(32, 32))

    artifact = _carve(source, tmp_path / "out", signature_ids=["jpeg"]).artifacts[0]

    assert len(artifact.digests["sha256"]) == 64
    assert len(artifact.digests["md5"]) == 32
    assert len(artifact.digests["sha1"]) == 40


# --------------------------------------------------------------------------
# Selection, filtering and limits
# --------------------------------------------------------------------------

def test_restricting_signatures_excludes_other_formats(tmp_path):
    source = tmp_path / "mixed.bin"
    source.write_bytes(make_jpeg(32, 32) + b"\x00" * 1024 + make_png(16, 16, (1, 2, 3)))

    only_jpeg = _carve(source, tmp_path / "a", signature_ids=["jpeg"])
    both = _carve(source, tmp_path / "b", signature_ids=["jpeg", "png"])

    assert all(a.signature_id == "jpeg" for a in only_jpeg.artifacts)
    assert {a.signature_id for a in both.artifacts} == {"jpeg", "png"}


def test_unknown_signature_ids_select_nothing_and_say_so(tmp_path):
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(32, 32))

    result = _carve(source, tmp_path / "out", signature_ids=["not-a-real-signature"])

    assert result.error == "No signatures selected"
    assert result.recovered_count == 0


def test_max_artifacts_caps_the_result(tmp_path):
    """A scan of a large device must be boundable, or it never finishes."""
    blob = b"".join(make_jpeg(16, 16) for _ in range(6))
    source = tmp_path / "many.bin"
    source.write_bytes(blob)

    result = _carve(source, tmp_path / "out", signature_ids=["jpeg"], max_artifacts=2)

    assert result.recovered_count <= 2


def test_min_confidence_filters_low_confidence_candidates(tmp_path):
    complete = make_jpeg(64, 64)
    source = tmp_path / "mixed.bin"
    source.write_bytes(complete + b"\x00" * 512 + complete[: len(complete) // 2])

    unfiltered = _carve(source, tmp_path / "a", signature_ids=["jpeg"], min_confidence=0.0)
    filtered = _carve(source, tmp_path / "b", signature_ids=["jpeg"], min_confidence=95.0)

    assert filtered.recovered_count <= unfiltered.recovered_count
    assert all(a.confidence >= 95.0 for a in filtered.artifacts)


def test_regions_restrict_the_scan(tmp_path):
    """How a caller carves only a filesystem's unallocated extents."""
    first = make_jpeg(32, 32)
    second = make_png(16, 16, (9, 9, 9))
    gap = b"\x00" * 4096
    source = tmp_path / "spanned.bin"
    source.write_bytes(first + gap + second)

    start = len(first) + len(gap)
    result = _carve(source, tmp_path / "out", regions=[(start, len(second))])

    assert result.regions_scanned == 1
    assert all(a.offset >= start for a in result.artifacts)
    assert {a.signature_id for a in result.artifacts} == {"png"}


def test_a_region_beyond_the_end_of_the_source_yields_nothing(tmp_path):
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(32, 32))

    result = _carve(source, tmp_path / "out", regions=[(10 ** 9, 4096)])

    assert result.regions_scanned == 0
    assert result.recovered_count == 0


# --------------------------------------------------------------------------
# Failure and cancellation
# --------------------------------------------------------------------------

def test_a_missing_source_is_an_error_not_a_crash(tmp_path, capsys):
    result = _carve(tmp_path / "ghost.img", tmp_path / "out")

    assert result.error
    assert "not found" in result.error.lower()
    assert result.recovered_count == 0


def test_cancellation_stops_the_scan(tmp_path):
    source = tmp_path / "big.bin"
    source.write_bytes(b"\x00" * (4 * 1024 * 1024) + make_jpeg(32, 32))

    token = CancelToken()
    token.cancel()

    with pytest.raises(OperationCancelled):
        _carve(source, tmp_path / "out", cancel=token)


def test_progress_is_reported_during_a_scan(tmp_path):
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(64, 64))
    seen: list = []

    _carve(source, tmp_path / "out", signature_ids=["jpeg"], progress=seen.append)

    assert seen
    assert seen[0].phase == "Scanning"


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def test_a_carve_is_bracketed_in_the_audit_chain(tmp_path):
    chain = AuditChain(tmp_path / "audit.jsonl")
    source = tmp_path / "photo.jpg"
    source.write_bytes(make_jpeg(32, 32))

    SignatureCarver(chain).carve(source, tmp_path / "out", signature_ids=["jpeg"])

    actions = [entry.action for entry in chain.entries()]
    assert actions == ["file_carving_started", "file_carving_finished"]
    assert chain.verify().ok


# --------------------------------------------------------------------------
# Accuracy against planted ground truth
# --------------------------------------------------------------------------

#: Formats whose signatures and structural validators are unambiguous, so the
#: corpus must come back byte-exact. Formats with no magic bytes at all (a plain
#: .txt) are deliberately absent - no content-based carver can find them, and
#: pretending otherwise would misrepresent what the engine does.
_MUST_RECOVER = {
    "Photo_Holiday.JPG",
    "Screenshot.png",
    "Diagram.GIF",
    "Chart.bmp",
    "Contract.pdf",
    "Archive.zip",
    "Credentials.db",
}


def test_recovery_accuracy_against_the_planted_corpus(tmp_path, test_media, manifest):
    """
    The headline measurement.

    Every planted file's SHA-256 was recorded in the manifest at build time, so
    a recovered artifact either matches a planted file byte-for-byte or it does
    not. Recall and precision are both computed and reported, because a carver
    that finds everything by inventing candidates is not better than one that
    finds nothing.
    """
    scenario = manifest["scenarios"]["deleted_files"]
    source = test_media / scenario["image"]

    result = _carve(source, tmp_path / "recovered")
    assert result.error == ""

    artifacts = result.as_dict()["artifacts"]
    recovered_digests = {a["sha256"] for a in artifacts}

    planted = {record["name"]: record for record in scenario["files"]}
    expected_digests = {record["sha256"] for record in scenario["files"]}

    matched = sorted(
        name for name, record in planted.items() if record["sha256"] in recovered_digests
    )
    true_positives = sum(1 for a in artifacts if a["sha256"] in expected_digests)

    recall = len(matched) / len(planted)
    precision = true_positives / len(artifacts) if artifacts else 0.0

    report = (
        f"\n  carved {len(artifacts)} artifact(s), {result.recovered_bytes:,} bytes\n"
        f"  recall    {len(matched)}/{len(planted)} planted files ({recall:.0%})\n"
        f"  precision {true_positives}/{len(artifacts)} artifacts match a planted "
        f"file ({precision:.0%})\n"
        f"  matched: {', '.join(matched)}\n"
        f"  missed:  {', '.join(sorted(set(planted) - set(matched)))}\n"
    )
    print(report)

    missing = sorted(_MUST_RECOVER - set(matched))
    assert not missing, f"formats with unambiguous signatures were not recovered: {missing}{report}"

    # Every artifact that claims to be one of the planted files must be
    # byte-identical to it - a near miss is a corrupted recovery, not a partial
    # success, and must never be presented as a recovery.
    for artifact in artifacts:
        if artifact["sha256"] in expected_digests:
            assert artifact["length"] == next(
                r["size"] for r in scenario["files"] if r["sha256"] == artifact["sha256"]
            )


def test_the_carver_does_not_fabricate_high_confidence_files(tmp_path, test_media, manifest):
    """
    Precision on the artifacts an examiner would act on.

    Low-confidence debris is expected and is labelled as such. A *high*
    confidence artifact that matches nothing planted would mean the confidence
    scoring is claiming more than the evidence supports.
    """
    scenario = manifest["scenarios"]["deleted_files"]
    expected_digests = {record["sha256"] for record in scenario["files"]}

    result = _carve(test_media / scenario["image"], tmp_path / "recovered")

    unsupported = [
        a for a in result.as_dict()["artifacts"]
        if a["confidence_label"] == "High" and a["sha256"] not in expected_digests
    ]
    assert not unsupported, (
        "high-confidence artifacts that match no planted file: "
        f"{[a['name'] for a in unsupported]}"
    )


def test_deleted_files_are_found_in_unallocated_space(tmp_path, test_media, manifest):
    """
    The scenario's premise: the deleted files' bytes must still be sitting in
    unallocated clusters, reachable by content alone.

    This also guards the fixture itself - if the FAT16 builder were one day
    changed to zero freed clusters, every other carving test would quietly start
    measuring nothing.
    """
    scenario = manifest["scenarios"]["deleted_files"]
    source = test_media / scenario["image"]

    result = _carve(source, tmp_path / "recovered")
    recovered_digests = {a["sha256"] for a in result.as_dict()["artifacts"]}

    deleted_records = [r for r in scenario["files"] if r["deleted"]]
    assert deleted_records

    still_present = [r for r in deleted_records if r["sha256"] in recovered_digests]
    assert still_present, (
        "no deleted file's bytes survived in the image - the fixture or the "
        "erasure path is zeroing freed clusters, which would invalidate the "
        "carving tests"
    )


def test_the_wiped_image_yields_nothing_recoverable(tmp_path, test_media, manifest):
    """
    The other side of the claim.

    The `wiped` scenario was sanitized by running the real DriveEraser over a
    populated volume. A carver that still finds files in it would mean either
    the erasure or the carving engine is lying - and this is exactly the
    end-to-end property the product exists to demonstrate.
    """
    scenario = manifest["scenarios"]["wiped"]
    assert scenario["success"], "the wiped fixture was not produced by a successful erasure"

    source = test_media / scenario["image"]
    result = _carve(source, tmp_path / "recovered")

    assert result.recovered_count == 0, (
        "files were recovered from a sanitized volume: "
        f"{[a.name for a in result.artifacts]}"
    )
