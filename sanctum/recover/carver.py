"""
Advanced file carving and recovery.

Recovers files from media where the filesystem no longer helps: formatted
volumes, corrupted filesystems, raw images, and the unallocated space of a live
device. The engine works from content alone - it scans for known file headers,
confirms the candidate structurally, determines where the file ends, and
extracts it with hashes computed in the same pass.

Why end detection gets its own machinery
----------------------------------------
"Search for the header, then search for the footer" is the naive approach and
it fails in a specific, damaging way: a JPEG's EXIF block normally contains a
complete thumbnail, which is itself a JPEG with its own ``FFD9``. Taking the
first footer yields a file truncated at the end of the thumbnail. For the
formats where this matters, this module walks the actual container structure -
JPEG marker chain, PNG chunk chain, ZIP end-of-central-directory record,
PDF trailer - and only falls back to a footer search where the format offers
no structure to follow.

Scanning is deliberately region-based so that carving can be restricted to a
filesystem's unallocated extents rather than the whole device.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

from sanctum.config import CHUNK_SIZE
from sanctum.core import hashing
from sanctum.core.audit import AuditCategory, AuditChain, AuditOutcome
from sanctum.core.progress import CancelToken, OperationCancelled, ProgressReporter, ProgressUpdate
from sanctum.recover.classify import Classification, score_artifact, summarize_artifacts
from sanctum.recover.signatures import (
    SIGNATURES,
    FileSignature,
    build_first_byte_index,
    categories,
    get_signature,
)

#: Bytes read per scan step. Larger is faster but costs memory.
DEFAULT_BLOCK = 8 * 1024 * 1024

#: Bytes read to validate a candidate header before committing to extraction.
PROBE_BYTES = 128 * 1024


@dataclass
class CarvedArtifact:
    """One recovered file."""

    index: int
    offset: int
    length: int
    signature_id: str
    name: str
    extension: str
    category: str
    confidence: float
    confidence_label: str
    digests: dict[str, str] = field(default_factory=dict)
    output_path: str = ""
    validated: bool = False
    footer_found: bool = False
    truncated: bool = False
    factors: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    extraction_error: str = ""

    @property
    def end_offset(self) -> int:
        return self.offset + self.length

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "offset": self.offset,
            "end_offset": self.end_offset,
            "length": self.length,
            "signature_id": self.signature_id,
            "name": self.name,
            "extension": self.extension,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "sha256": self.digests.get("sha256", ""),
            "md5": self.digests.get("md5", ""),
            "sha1": self.digests.get("sha1", ""),
            "validated": self.validated,
            "footer_found": self.footer_found,
            "truncated": self.truncated,
            "factors": self.factors,
            "warnings": self.warnings,
            "notes": self.notes,
            "output_path": self.output_path,
            "extraction_error": self.extraction_error,
        }


@dataclass
class CarveResult:
    """Complete record of a carving run."""

    source: str
    source_size: int = 0
    started_at: str = ""
    finished_at: str = ""
    artifacts: list[CarvedArtifact] = field(default_factory=list)
    bytes_scanned: int = 0
    regions_scanned: int = 0
    signatures_used: int = 0
    elapsed_seconds: float = 0.0
    cancelled: bool = False
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    audit_range: tuple[int, int] = (0, 0)

    @property
    def recovered_count(self) -> int:
        return len(self.artifacts)

    @property
    def recovered_bytes(self) -> int:
        return sum(a.length for a in self.artifacts)

    @property
    def high_confidence(self) -> int:
        return sum(1 for a in self.artifacts if a.confidence_label == "High")

    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for artifact in self.artifacts:
            counts[artifact.category] = counts.get(artifact.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def summary(self) -> dict:
        return summarize_artifacts(
            [
                Classification(
                    category=a.category,
                    signature_id=a.signature_id,
                    label=a.confidence_label,
                    confidence=a.confidence,
                )
                for a in self.artifacts
            ]
        )

    def as_dict(self) -> dict:
        return {
            "operation": "file_carving",
            "source": self.source,
            "source_size": self.source_size,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "bytes_scanned": self.bytes_scanned,
            "regions_scanned": self.regions_scanned,
            "signatures_used": self.signatures_used,
            "recovered_count": self.recovered_count,
            "recovered_bytes": self.recovered_bytes,
            "high_confidence": self.high_confidence,
            "by_category": self.by_category(),
            "summary": self.summary(),
            "cancelled": self.cancelled,
            "error": self.error,
            "warnings": self.warnings,
            "artifacts": [a.as_dict() for a in self.artifacts],
            "audit_range": list(self.audit_range),
        }


# --------------------------------------------------------------------------
# Random-access reader with a small cache
# --------------------------------------------------------------------------

class _RegionReader:
    """
    Cached random access over one region of a file.

    Structural walks jump around (chunk tables, marker lengths), so reading
    through a cache turns thousands of tiny seeks into a handful of buffered
    reads.
    """

    def __init__(self, handle, start: int, end: int, cache_size: int = 1 << 20) -> None:
        self.handle = handle
        self.start = start
        self.end = end
        self.cache_size = cache_size
        self._cache_start = -1
        self._cache = b""

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < self.start or offset >= self.end:
            return b""
        size = min(size, self.end - offset)
        cache_end = self._cache_start + len(self._cache)
        if self._cache_start <= offset and offset + size <= cache_end:
            begin = offset - self._cache_start
            return self._cache[begin : begin + size]

        # Refill around the requested offset.
        read_start = max(self.start, offset)
        read_size = min(max(self.cache_size, size), self.end - read_start)
        self.handle.seek(read_start)
        self._cache = self.handle.read(read_size)
        self._cache_start = read_start
        begin = offset - self._cache_start
        return self._cache[begin : begin + size]

    def u8(self, offset: int) -> int:
        data = self.read_at(offset, 1)
        return data[0] if data else -1

    def u16_be(self, offset: int) -> int:
        data = self.read_at(offset, 2)
        return struct.unpack(">H", data)[0] if len(data) == 2 else -1

    def u32_be(self, offset: int) -> int:
        data = self.read_at(offset, 4)
        return struct.unpack(">I", data)[0] if len(data) == 4 else -1

    def find(self, needle: bytes, offset: int, limit: int, *, last: bool = False) -> int:
        """Search for ``needle`` in [offset, limit). Returns -1 if absent."""
        if not needle:
            return -1
        chunk = 1 << 20
        pos = offset
        found = -1
        overlap = len(needle) - 1
        while pos < limit:
            size = min(chunk, limit - pos)
            data = self.read_at(pos, size)
            if not data:
                break
            search_from = 0
            while True:
                hit = data.find(needle, search_from)
                if hit == -1:
                    break
                found = pos + hit
                if not last:
                    return found
                search_from = hit + 1
            if not last:
                break
            pos += max(1, size - overlap)
        return found


# --------------------------------------------------------------------------
# End detection
# --------------------------------------------------------------------------

def _end_jpeg(reader: _RegionReader, start: int) -> int | None:
    """
    Walk the JPEG marker chain to the true EOI.

    This is the case that justifies the whole structural approach: EXIF
    thumbnails embed a complete JPEG, so a footer search would stop early.
    """
    pos = start + 2
    limit = reader.end
    guard = 0
    while pos < limit and guard < 1_000_000:
        guard += 1
        if reader.u8(pos) != 0xFF:
            return None
        marker = reader.u8(pos + 1)
        if marker == -1:
            return None

        if marker == 0xD9:  # EOI
            return pos + 2
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # standalone markers
            pos += 2
            continue
        if marker == 0xFF:  # fill byte
            pos += 1
            continue
        if marker == 0xDA:  # SOS - entropy-coded data follows
            length = reader.u16_be(pos + 2)
            if length < 2:
                return None
            pos += 2 + length
            # Skip entropy data: advance to the next real marker.
            while pos < limit:
                hit = reader.find(b"\xff", pos, limit)
                if hit == -1 or hit + 1 >= limit:
                    return None
                nxt = reader.u8(hit + 1)
                if nxt == -1:
                    return None
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    pos = hit + 2
                    continue
                pos = hit
                break
            continue

        length = reader.u16_be(pos + 2)
        if length < 2:
            return None
        pos += 2 + length
    return None


def _end_png(reader: _RegionReader, start: int) -> int | None:
    """Walk PNG chunks to IEND."""
    pos = start + 8
    limit = reader.end
    guard = 0
    while pos + 12 <= limit and guard < 1_000_000:
        guard += 1
        length = reader.u32_be(pos)
        if length < 0 or length > 0x7FFFFFFF:
            return None
        chunk_type = reader.read_at(pos + 4, 4)
        if len(chunk_type) < 4:
            return None
        if chunk_type == b"IEND":
            return pos + 12
        pos += 12 + length
    return None


def _end_zip(reader: _RegionReader, start: int) -> int | None:
    """Locate the end-of-central-directory record and include its comment."""
    eocd = reader.find(b"PK\x05\x06", start, reader.end)
    if eocd == -1:
        return None
    tail = reader.read_at(eocd + 20, 2)
    if len(tail) < 2:
        return eocd + 22
    comment_len = struct.unpack("<H", tail)[0]
    return eocd + 22 + comment_len


def _absorb_trailing_eol(reader: _RegionReader, end: int) -> int:
    """
    Extend ``end`` over a single trailing end-of-line, if one is there.

    A text format's terminator marker is followed by the newline that ended its
    line, and that newline is part of the file on disk. Stopping before it makes
    every recovered document one byte short of the original and failing digest
    comparison - a silent, uniform truncation that no length or structure check
    flags, because the artefact is otherwise perfect.

    Only one terminator is consumed. A file followed by blank lines is not the
    same as a file that ends with a newline, and swallowing trailing whitespace
    wholesale would run the artefact into whatever padding follows it.
    """
    tail = reader.read_at(end, 2)
    if tail.startswith(b"\r\n"):
        return end + 2
    if tail[:1] in (b"\n", b"\r"):
        return end + 1
    return end


def _end_html(reader: _RegionReader, start: int) -> int | None:
    """
    The first closing ``</html>``, plus the line terminator that follows it.

    HTML's closing tag is optional in the specification and its case is not
    significant, so both spellings are searched and the earlier hit wins. When
    neither is present the document is a fragment with no discoverable end, and
    ``None`` hands it back to the generic fallback - which reports the artefact
    as truncated rather than pretending to know where it stopped.
    """
    hits = [
        hit
        for hit in (
            reader.find(b"</html>", start, reader.end),
            reader.find(b"</HTML>", start, reader.end),
        )
        if hit != -1
    ]
    if not hits:
        return None
    return _absorb_trailing_eol(reader, min(hits) + len(b"</html>"))


def _end_pdf(reader: _RegionReader, start: int) -> int | None:
    """
    The first %%EOF at or after the header terminates the document.

    First, not last. The PDF specification requires the *last* line of a
    document to be %%EOF, and for a file whose extent is known the correct
    procedure is to search backwards from the end. A carver does not know the
    extent - that is the thing being determined - and the search ceiling here
    is the signature's ``max_size``, which is 256 MiB. Taking the last %%EOF in
    that window would run the artefact forward until it swallowed the %%EOF of
    the *next* PDF in the image, merging two documents into one blob with a
    correct header, a valid structure and a digest that matches nothing. Over-
    running is silent and catastrophic; stopping early is visible and bounded.

    So the first %%EOF wins, which is also what foremost and scalpel do.

    The limitation this accepts: a PDF written with incremental updates carries
    several %%EOFs - one per revision - and is therefore recovered to its first
    revision rather than its last. Distinguishing a revision boundary from a
    neighbouring document's end needs the file's true extent on both sides, so
    it is not decidable from the byte stream alone. ``tools/make_test_media``
    writes single-revision PDFs, so the fixture does not exercise this; it is
    recorded in docs/VALIDATION.md as a known limitation rather than papered
    over.
    """
    hit = reader.find(b"%%EOF", start, reader.end)
    if hit == -1:
        return None
    # The specification requires the end-of-file marker to be followed by an
    # end-of-line, so that terminator is part of the document.
    return _absorb_trailing_eol(reader, hit + 5)


def _declared_length(signature: FileSignature, reader: _RegionReader, start: int) -> int | None:
    """Formats that record their own total size up front."""
    if signature.id == "bmp":
        declared = struct.unpack("<I", reader.read_at(start + 2, 4))[0] if len(reader.read_at(start + 2, 4)) == 4 else 0
        return declared or None
    if signature.id in ("wav", "avi", "webp"):
        raw = reader.read_at(start + 4, 4)
        if len(raw) == 4:
            return struct.unpack("<I", raw)[0] + 8
    if signature.id == "sqlite":
        return _sqlite_declared_length(reader, start)
    return None


def _sqlite_declared_length(reader: _RegionReader, start: int) -> int | None:
    """
    A SQLite database states its own size as a page count in the header.

    Without this the artefact had no footer and no structural walk, so it ran to
    the search ceiling - 2 GiB - and swallowed every byte that followed it in
    the image. The database's own pages were recovered correctly and then buried
    inside a 16 MB blob whose digest matched nothing, which is worse than not
    finding it: the find is reported, at whatever confidence a valid header
    earns, and the bytes are wrong.

    The counters are checked before the size is trusted. SQLite writes the file
    change counter at offset 24 and repeats it at offset 92 as "version valid
    for"; the in-header page count is only authoritative when the two agree. If
    they disagree the database is mid-transaction, the header is stale, and the
    honest answer is that the length is unknown - so ``None`` is returned and the
    caller falls back to its ceiling, explicitly marked as a search limit.
    """
    header = reader.read_at(start + 16, 4)
    if len(header) < 4:
        return None

    page_size = struct.unpack(">H", header[0:2])[0]
    if page_size == 1:
        page_size = 65536          # the encoding SQLite uses for a 64 KiB page
    elif page_size < 512 or page_size & (page_size - 1):
        return None                # must be a power of two, 512 or larger

    change_counter = reader.read_at(start + 24, 4)
    valid_for = reader.read_at(start + 92, 4)
    if len(change_counter) < 4 or len(valid_for) < 4 or change_counter != valid_for:
        return None

    page_count = struct.unpack(">I", reader.read_at(start + 28, 4))[0]
    if page_count == 0:
        # Legal, and means the size was never written back to the header - the
        # file's extent has to come from the filesystem, which a carver does not
        # have. Reported as unknown rather than guessed at.
        return None
    return page_size * page_count


_STRUCTURAL_END = {
    "jpeg": _end_jpeg,
    "png": _end_png,
    "zip": _end_zip,
    "docx": _end_zip,
    "xlsx": _end_zip,
    "pptx": _end_zip,
    "pdf": _end_pdf,
    "html": _end_html,
}


def find_end(
    signature: FileSignature,
    handle,
    start: int,
    region_end: int,
) -> tuple[int, bool, bool]:
    """
    Determine where the artefact ends.

    Returns ``(end_exclusive, footer_found, truncated)``. When nothing
    conclusive is found the artefact is capped at the signature's ``max_size``
    and flagged truncated, so the report never silently presents a partial
    recovery as complete.
    """
    ceiling = min(region_end, start + signature.max_size)
    reader = _RegionReader(handle, start, ceiling)

    declared = _declared_length(signature, reader, start)
    if declared and start + declared <= ceiling:
        return start + declared, True, False

    structural = _STRUCTURAL_END.get(signature.id)
    if structural is not None:
        end = structural(reader, start)
        if end is not None and start < end <= ceiling:
            return end, True, False
        # Structural walk failed - fall through to the footer search rather
        # than discarding an otherwise valid candidate.

    if signature.footers:
        search_from = start + signature.max_header_len
        for footer in signature.footers:
            hit = reader.find(footer, search_from, ceiling)
            if hit != -1:
                return hit + len(footer), True, False
        return ceiling, False, True

    # No footer and no structure: recover up to the ceiling and be explicit
    # that the bound is a search limit, not a discovered end.
    return ceiling, False, True


# --------------------------------------------------------------------------
# Carver
# --------------------------------------------------------------------------

class SignatureCarver:
    """
    Content-based file recovery.

    Example - carve JPEGs and PDFs out of a disk image::

        carver = SignatureCarver(audit)
        result = carver.carve("evidence/disk.img", "case/artifacts",
                              signature_ids=["jpeg", "pdf"])
        for art in result.artifacts:
            print(art.name, art.confidence_label, art.digests["sha256"])
    """

    def __init__(self, audit: AuditChain | None = None) -> None:
        self.audit = audit

    # -- public API --------------------------------------------------------

    def carve(
        self,
        source: str | os.PathLike[str],
        output_dir: str | os.PathLike[str],
        *,
        signature_ids: Sequence[str] | None = None,
        categories_filter: Sequence[str] | None = None,
        regions: Iterable[tuple[int, int]] | None = None,
        min_confidence: float = 0.0,
        max_artifacts: int = 5000,
        block_size: int = DEFAULT_BLOCK,
        require_validation: bool = True,
        advance_after_hit: bool = True,
        write_files: bool = True,
        progress: Callable[[ProgressUpdate], None] | None = None,
        cancel: CancelToken | None = None,
    ) -> CarveResult:
        """
        Scan ``source`` and recover matching files into ``output_dir``.

        ``regions`` restricts scanning to specific ``(offset, length)`` extents -
        this is how a caller carves only unallocated space. ``min_confidence``
        filters output; the default of 0 keeps everything, including
        low-confidence candidates, and lets the report rank them.
        """
        cancel = cancel or CancelToken()
        reporter = ProgressReporter(progress)
        source_path = Path(source)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        result = CarveResult(
            source=str(source_path),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

        if not source_path.exists():
            result.error = f"Source not found: {source_path}"
            return result

        result.source_size = source_path.stat().st_size

        signatures = self._select_signatures(signature_ids, categories_filter)
        result.signatures_used = len(signatures)
        if not signatures:
            result.error = "No signatures selected"
            return result

        scan_regions = list(regions) if regions else [(0, result.source_size)]
        # Clip to the source and drop empty regions.
        scan_regions = [
            (max(0, off), min(length, result.source_size - max(0, off)))
            for off, length in scan_regions
        ]
        scan_regions = [(o, l) for o, l in scan_regions if l > 0]
        result.regions_scanned = len(scan_regions)

        total_bytes = sum(length for _, length in scan_regions) or 1

        # Cancelled before the scan began: raise rather than return. The handler
        # below turns a cancellation that lands mid-scan into a partial result,
        # which is what the operator needs then - how far did it get, and what
        # was recovered. Here nothing has been read, so the returned result would
        # be empty and indistinguishable from a scan that ran and found nothing.
        # ``FileEraser.secure_delete_paths`` draws the same line for the same
        # reason, and the two engines must agree or the UI has to special-case
        # one of them.
        cancel.check()

        self._audit_start(source_path, signatures, scan_regions)
        started = time.monotonic()

        try:
            with open(source_path, "rb") as handle:
                reporter.start("Scanning", total_bytes)
                scanned = 0
                for region_offset, region_length in scan_regions:
                    cancel.check()
                    scanned += self._scan_region(
                        handle,
                        region_offset,
                        region_length,
                        signatures,
                        output_path,
                        result,
                        reporter,
                        cancel,
                        total_bytes,
                        scanned,
                        min_confidence,
                        max_artifacts,
                        require_validation,
                        advance_after_hit,
                        write_files,
                        block_size,
                    )
                    if len(result.artifacts) >= max_artifacts:
                        result.warnings.append(
                            f"Stopped at the {max_artifacts}-artefact ceiling; "
                            "raise the limit or narrow the scan to recover more."
                        )
                        break
                result.bytes_scanned = scanned
                reporter.finish("Scanning", total_bytes, f"{result.recovered_count} artefact(s)")
        except OperationCancelled:
            result.cancelled = True
            result.warnings.append("Carving cancelled by operator")
        except Exception as exc:  # noqa: BLE001 - reported, never raised into the UI
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.elapsed_seconds = time.monotonic() - started
            result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._audit_finish(result)

        return result

    # -- scanning ----------------------------------------------------------

    def _scan_region(
        self,
        handle,
        region_offset: int,
        region_length: int,
        signatures: Sequence[FileSignature],
        output_path: Path,
        result: CarveResult,
        reporter: ProgressReporter,
        cancel: CancelToken,
        total_bytes: int,
        scanned_before: int,
        min_confidence: float,
        max_artifacts: int,
        require_validation: bool,
        advance_after_hit: bool,
        write_files: bool,
        block_size: int,
    ) -> int:
        region_end = region_offset + region_length
        # Overlap keeps a header that straddles a block boundary from being
        # missed at the seam.
        max_prefix = max((s.max_header_len + s.header_offset) for s in signatures)
        step = max(1, block_size)
        scanned = 0
        last_end = region_offset
        pos = region_offset

        while pos < region_end:
            cancel.check()
            read_size = min(step + max_prefix, region_end - pos)
            handle.seek(pos)
            buffer = handle.read(read_size)
            if not buffer:
                break

            hits = self._find_headers(buffer, pos, signatures, region_end)
            for file_start, signature in hits:
                if len(result.artifacts) >= max_artifacts:
                    return scanned + read_size
                if advance_after_hit and file_start < last_end:
                    continue  # inside an artefact we already recovered

                artifact = self._recover_one(
                    handle,
                    file_start,
                    signature,
                    region_end,
                    output_path,
                    len(result.artifacts) + 1,
                    require_validation,
                    write_files,
                )
                if artifact is None:
                    continue
                if artifact.confidence < min_confidence:
                    continue

                result.artifacts.append(artifact)
                if advance_after_hit:
                    last_end = artifact.end_offset

            scanned += read_size
            pos += step
            reporter.update(
                "Scanning",
                min(scanned_before + scanned, total_bytes),
                total_bytes,
                f"{result.recovered_count} found",
            )

        return scanned

    def _find_headers(
        self,
        buffer: bytes,
        buffer_offset: int,
        signatures: Sequence[FileSignature],
        region_end: int,
    ) -> list[tuple[int, FileSignature]]:
        """
        Locate every plausible header start within one block.

        Returns ``(file_start_offset, signature)`` pairs sorted by offset, so
        the caller processes artefacts in media order - which matters for
        reporting and for the fragmentation pass.
        """
        found: dict[tuple[int, str], tuple[int, FileSignature]] = {}

        for signature in signatures:
            for header in signature.headers:
                if not header:
                    continue
                search_from = 0
                while True:
                    hit = buffer.find(header, search_from)
                    if hit == -1:
                        break
                    search_from = hit + 1
                    file_start = buffer_offset + hit - signature.header_offset
                    if file_start < 0:
                        continue
                    if file_start >= region_end:
                        continue
                    # A header starting inside this block's overlap region will
                    # be re-examined by the next block; no need to dedupe here
                    # since the caller advances past recovered artefacts.
                    key = (file_start, signature.id)
                    if key not in found:
                        found[key] = (file_start, signature)

        return sorted(found.values(), key=lambda item: (item[0], item[1].priority))

    def _recover_one(
        self,
        handle,
        start: int,
        signature: FileSignature,
        region_end: int,
        output_path: Path,
        index: int,
        require_validation: bool,
        write_files: bool,
    ) -> CarvedArtifact | None:
        """Validate, bound, extract and score a single candidate."""
        # Probe first: validation is cheap compared to extraction, and this is
        # what rejects the overwhelming majority of coincidental matches.
        handle.seek(start)
        probe = handle.read(min(PROBE_BYTES, signature.max_size))

        validated = False
        try:
            validated = bool(signature.validator(probe))
        except Exception:  # noqa: BLE001 - a hostile/corrupt file must not abort the scan
            validated = False

        if require_validation and not validated:
            return None

        end, footer_found, truncated = find_end(signature, handle, start, region_end)
        length = max(0, end - start)
        if length < signature.min_size:
            # ``min_size`` asks "could this be a whole file of this format?", and
            # a truncated artefact is smaller than that by definition - being cut
            # short is what truncation means. Holding it to the complete-file
            # minimum discarded precisely the finds the truncation path exists to
            # report, so for a truncated candidate the floor drops to twice the
            # format's own header: enough that a bare magic number, which is what
            # a coincidental match yields once it is cut, still cannot pass.
            if not truncated or length < 2 * signature.max_header_len:
                return None
        # The probe is already the first bytes of the artefact, so trimming it to
        # the now-known length measures entropy over the artefact itself rather
        # than over the full 128 KiB probe window. No second read is needed.
        probe = probe[:length]

        classification = score_artifact(
            signature,
            probe,
            validated=validated,
            footer_found=footer_found,
            truncated=truncated,
            recovered_length=length,
        )

        artifact = CarvedArtifact(
            index=index,
            offset=start,
            length=length,
            signature_id=signature.id,
            name="",
            extension=signature.extension,
            category=signature.category,
            confidence=classification.confidence,
            confidence_label=classification.label,
            validated=validated,
            footer_found=footer_found,
            truncated=truncated,
            factors=[f.as_dict() for f in classification.factors],
            warnings=list(classification.warnings),
            notes=[signature.notes] if signature.notes else [],
        )
        artifact.name = f"{index:05d}_{signature.id}_0x{start:012X}.{signature.extension}"

        if write_files:
            destination = output_path / artifact.name
            try:
                artifact.digests = self._extract(handle, start, length, destination)
                artifact.output_path = str(destination)
            except OSError as exc:
                artifact.extraction_error = f"{type(exc).__name__}: {exc}"
        else:
            artifact.digests = self._hash_region(handle, start, length)

        return artifact

    def _extract(self, handle, start: int, length: int, destination: Path) -> dict[str, str]:
        """Stream the region out to disk, hashing as we go (single read pass)."""
        import hashlib

        digests = {name: hashlib.new(name) for name in hashing.FORENSIC_ALGOS}
        handle.seek(start)
        remaining = length
        with open(destination, "wb") as out:
            while remaining > 0:
                chunk = handle.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                out.write(chunk)
                for digest in digests.values():
                    digest.update(chunk)
                remaining -= len(chunk)
        return {name: digest.hexdigest() for name, digest in digests.items()}

    def _hash_region(self, handle, start: int, length: int) -> dict[str, str]:
        handle.seek(start)
        return hashing.hash_stream(handle, limit=length)

    def _select_signatures(
        self,
        signature_ids: Sequence[str] | None,
        categories_filter: Sequence[str] | None,
    ) -> list[FileSignature]:
        selected = list(SIGNATURES)
        if signature_ids:
            wanted = {s.lower() for s in signature_ids}
            selected = [s for s in selected if s.id in wanted]
        if categories_filter:
            wanted_categories = set(categories_filter)
            selected = [s for s in selected if s.category in wanted_categories]
        return selected

    # -- audit -------------------------------------------------------------

    def _audit_start(self, source: Path, signatures, regions) -> None:
        if self.audit is None:
            return
        entry = self.audit.log(
            AuditCategory.RECOVER,
            # Named to match the rest of the chain and the module's own label in
            # ``CarveResult.as_dict()``: every other engine prefixes its actions
            # with the module that owns them (``drive_erase_started``,
            # ``file_erase_started``). A bare ``carving_started`` breaks that, and
            # the prefix is exactly what lets a reviewer filter one module's work
            # out of a case that used all three.
            "file_carving_started",
            outcome=AuditOutcome.INFO,
            target=str(source),
            details={
                "signatures": [s.id for s in signatures],
                "signature_count": len(signatures),
                "regions": [{"offset": o, "length": l} for o, l in regions[:64]],
                "region_count": len(regions),
            },
        )
        self._start_seq = entry.seq

    def _audit_finish(self, result: CarveResult) -> None:
        if self.audit is None:
            return
        outcome = AuditOutcome.SUCCESS
        if result.error:
            outcome = AuditOutcome.FAILURE
        elif result.cancelled:
            outcome = AuditOutcome.INFO
        entry = self.audit.log(
            AuditCategory.RECOVER,
            "file_carving_finished",
            outcome=outcome,
            target=result.source,
            details={
                "recovered_count": result.recovered_count,
                "recovered_bytes": result.recovered_bytes,
                "high_confidence": result.high_confidence,
                "by_category": result.by_category(),
                "bytes_scanned": result.bytes_scanned,
                "elapsed_seconds": round(result.elapsed_seconds, 3),
                "error": result.error,
                "cancelled": result.cancelled,
            },
        )
        result.audit_range = (getattr(self, "_start_seq", 0), entry.seq)
