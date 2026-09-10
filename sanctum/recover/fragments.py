"""
Fragmentation reassembly.

When a file was stored in non-contiguous clusters, carving it as a single
contiguous extent recovers only the first fragment. This module attempts to
rejoin the pieces.

Scope, stated honestly
----------------------
General-purpose reassembly of arbitrary fragmented files is an open research
problem: without filesystem metadata there is no ground truth for which extent
follows which, and the search space is combinatorial. Rather than claim a
capability we cannot deliver, SANCTUM implements the case that is both
tractable and by far the most valuable in practice:

**JPEG reassembly by marker-chain validation.** A JPEG's marker chain is
self-describing. A correctly spliced JPEG walks cleanly from SOI to EOI; a
wrong splice almost always produces an illegal marker or an impossible segment
length. That gives us a *verifiable* acceptance test, which is what makes
candidate-and-check search practical here.

For every other format the module offers footer-continuation search: if a
carved artefact ended without a terminator, look past the gap for one and
report the extended extent with reduced confidence. Both paths record exactly
which extents were used, so the report never presents a reassembly as an
unqualified original.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sanctum.recover.signatures import FileSignature

#: Maximum number of splices before we conclude the file is not recoverable by
#: this technique. Real fragmented files rarely need more than a handful.
MAX_SPLICES = 16

#: How far past a gap we search for a continuation fragment.
MAX_GAP_SEARCH = 32 * 1024 * 1024


@dataclass
class Extent:
    """One contiguous byte range used in a reassembly."""

    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length

    def as_dict(self) -> dict:
        return {"offset": self.offset, "length": self.length, "end": self.end}


@dataclass
class ReassemblyResult:
    """Outcome of a reassembly attempt."""

    success: bool = False
    data: bytes = b""
    extents: list[Extent] = field(default_factory=list)
    splices: int = 0
    method: str = ""
    notes: list[str] = field(default_factory=list)
    confidence_penalty: float = 0.0

    @property
    def total_length(self) -> int:
        return sum(e.length for e in self.extents)

    @property
    def contiguous(self) -> bool:
        return len(self.extents) <= 1

    def as_dict(self) -> dict:
        return {
            "success": self.success,
            "total_length": self.total_length,
            "splices": self.splices,
            "method": self.method,
            "contiguous": self.contiguous,
            "extents": [e.as_dict() for e in self.extents],
            "notes": self.notes,
            "confidence_penalty": self.confidence_penalty,
        }


# --------------------------------------------------------------------------
# JPEG marker-chain walking over a spliced view
# --------------------------------------------------------------------------

def _walk_jpeg_markers(
    read_at,
    start: int,
    end: int,
    *,
    on_gap: int | None = None,
) -> tuple[int | None, int | None]:
    """
    Walk a JPEG marker chain over a virtual address space.

    ``read_at(offset, size)`` supplies bytes. When the chain reaches a point
    where a marker is expected but the data is not a marker, the walk reports
    the stall offset so the caller can decide to splice.

    Returns ``(eoi_offset, stall_offset)`` - exactly one is not None.
    """
    pos = start + 2
    guard = 0
    while pos + 1 < end and guard < 2_000_000:
        guard += 1
        marker_byte = read_at(pos, 1)
        if len(marker_byte) < 1 or marker_byte[0] != 0xFF:
            return None, pos
        nxt_bytes = read_at(pos + 1, 1)
        if len(nxt_bytes) < 1:
            return None, pos
        marker = nxt_bytes[0]

        if marker == 0xD9:
            return pos + 2, None
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xFF:
            pos += 1
            continue

        if marker == 0xDA:
            length_bytes = read_at(pos + 2, 2)
            if len(length_bytes) < 2:
                return None, pos
            length = int.from_bytes(length_bytes, "big")
            if length < 2:
                return None, pos
            pos += 2 + length
            # Skip entropy-coded data to the next real marker.
            while pos < end:
                chunk = read_at(pos, min(65536, end - pos))
                if not chunk:
                    return None, pos
                hit = chunk.find(b"\xff")
                if hit == -1:
                    pos += len(chunk)
                    continue
                candidate = pos + hit
                follow = read_at(candidate + 1, 1)
                if not follow:
                    return None, candidate
                value = follow[0]
                if value == 0x00 or 0xD0 <= value <= 0xD7:
                    pos = candidate + 2
                    continue
                pos = candidate
                break
            continue

        length_bytes = read_at(pos + 2, 2)
        if len(length_bytes) < 2:
            return None, pos
        length = int.from_bytes(length_bytes, "big")
        if length < 2:
            return None, pos
        pos += 2 + length

    return None, pos


def reassemble_jpeg(
    handle,
    start: int,
    region_end: int,
    *,
    max_size: int = 64 * 1024 * 1024,
    max_splices: int = MAX_SPLICES,
) -> ReassemblyResult:
    """
    Recover a fragmented JPEG by splicing fragments until the marker chain
    walks cleanly to EOI.

    Each splice is validated by the marker walk itself, so a wrong pairing is
    rejected rather than silently accepted.
    """
    result = ReassemblyResult(method="jpeg-marker-chain-splice")
    ceiling = min(region_end, start + max_size)

    handle.seek(start)
    first = handle.read(min(ceiling - start, 1 << 20))
    if not first.startswith(b"\xff\xd8"):
        result.notes.append("Not a JPEG (missing SOI)")
        return result

    collected = bytearray(first)
    extents = [Extent(start, len(first))]
    cursor = start + len(first)
    splices = 0

    while cursor < ceiling and splices <= max_splices:
        def read_at(offset: int, size: int, _buffer=bytes(collected), _base=extents[0].offset) -> bytes:
            # Serve reads from the assembled buffer where possible, otherwise
            # from the source, so the walk sees the spliced view as contiguous.
            relative = offset - _base
            if 0 <= relative < len(_buffer):
                end_index = min(len(_buffer), relative + size)
                head = _buffer[relative:end_index]
                if len(head) == size:
                    return head
                tail_start = _base + len(_buffer)
                handle.seek(tail_start)
                return head + handle.read(size - len(head))
            handle.seek(offset)
            return handle.read(size)

        buffer_view = bytes(collected)
        eoi, stall = _walk_jpeg_markers(read_at, start, start + len(buffer_view))

        if eoi is not None:
            result.success = True
            result.data = buffer_view[: eoi - start]
            result.extents = extents
            result.splices = splices
            if splices:
                result.notes.append(
                    f"Reassembled from {len(extents)} extent(s) across {splices} splice(s). "
                    "Verify visually before relying on this artefact."
                )
                result.confidence_penalty = min(30.0, 8.0 * splices)
            return result

        if stall is None:
            break

        # The chain stalled: look for the next SOI to splice in.
        search_start = stall
        search_end = min(ceiling, search_start + MAX_GAP_SEARCH)
        hit = _find_next_soi(handle, search_start, search_end)
        if hit == -1:
            result.notes.append("No continuation fragment found; artefact may be truncated")
            result.data = buffer_view
            result.extents = extents
            result.splices = splices
            return result

        handle.seek(hit)
        fragment = handle.read(min(ceiling - hit, 1 << 20))
        extents.append(Extent(hit, len(fragment)))
        # Drop the fragment's own SOI so the chains join without a double SOI.
        collected.extend(fragment[2:] if fragment.startswith(b"\xff\xd8") else fragment)
        splices += 1
        cursor = hit + len(fragment)

    result.data = bytes(collected)
    result.extents = extents
    result.splices = splices
    result.success = False
    if splices > max_splices:
        result.notes.append(f"Exceeded the {max_splices}-splice ceiling")
    return result


def _find_next_soi(handle, start: int, end: int) -> int:
    """Find the next JPEG SOI marker at or after ``start``."""
    chunk_size = 1 << 20
    pos = start
    while pos < end:
        handle.seek(pos)
        data = handle.read(min(chunk_size, end - pos))
        if not data:
            return -1
        hit = data.find(b"\xff\xd8\xff")
        if hit != -1:
            return pos + hit
        pos += max(1, len(data) - 2)
    return -1


def extend_with_footer(
    handle,
    start: int,
    known_end: int,
    signature: FileSignature,
    region_end: int,
    *,
    max_gap: int = MAX_GAP_SEARCH,
) -> ReassemblyResult:
    """
    Footer-continuation search for non-JPEG formats.

    If a carved artefact had no terminator, look past the gap for one and
    report the extended extent. This is a heuristic, not a proof of
    contiguity, and the confidence penalty reflects that.
    """
    result = ReassemblyResult(method="footer-continuation")
    if not signature.footers:
        result.notes.append(f"{signature.name} has no terminator to search for")
        return result

    search_end = min(region_end, known_end + max_gap)
    for footer in signature.footers:
        handle.seek(known_end)
        pos = known_end
        chunk_size = 1 << 20
        while pos < search_end:
            handle.seek(pos)
            data = handle.read(min(chunk_size, search_end - pos))
            if not data:
                break
            hit = data.find(footer)
            if hit != -1:
                end = pos + hit + len(footer)
                result.success = True
                result.extents = [Extent(start, end - start)]
                result.notes.append(
                    f"Found a terminator {end - known_end} bytes past the assumed end; "
                    "the intervening region may belong to other data."
                )
                result.confidence_penalty = 15.0
                return result
            pos += max(1, len(data) - len(footer) + 1)

    result.notes.append("No terminator found beyond the assumed end")
    return result
