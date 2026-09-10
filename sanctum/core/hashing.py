"""
Hashing and content-analysis primitives.

Every hash SANCTUM computes - evidence intake, erasure verification, recovered
artefact integrity - flows through this module so that a single implementation
is responsible for the chain-of-custody story. A second, subtly different
hashing routine elsewhere in the codebase would quietly undermine every report
the platform produces.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator, Mapping, Sequence

from sanctum.config import CHUNK_SIZE

#: Algorithms computed for evidence. MD5 is retained deliberately: it is broken
#: for adversarial collision resistance, but it remains the interoperable
#: baseline that legacy forensic tooling and court exhibits still expect to see
#: alongside the modern digests.
FORENSIC_ALGOS: tuple[str, ...] = ("md5", "sha1", "sha256")

ProgressFn = Callable[[int, int], None]


def iter_chunks(
    stream: BinaryIO,
    chunk_size: int = CHUNK_SIZE,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> Iterator[bytes]:
    """
    Yield fixed-size chunks from a binary stream.

    ``limit`` caps the total number of bytes read (None means to EOF), and
    ``offset`` seeks before reading. Both are used heavily by the carver, which
    reads windows out of multi-gigabyte images.
    """
    if offset:
        stream.seek(offset)
    remaining = limit
    while True:
        if remaining is not None:
            if remaining <= 0:
                return
            read_size = min(chunk_size, remaining)
        else:
            read_size = chunk_size

        data = stream.read(read_size)
        if not data:
            return
        if remaining is not None:
            remaining -= len(data)
        yield data


def _new_digests(algos: Sequence[str]) -> dict[str, "hashlib._Hash"]:
    digests = {}
    for name in algos:
        try:
            digests[name] = hashlib.new(name)
        except ValueError as exc:  # pragma: no cover - depends on OpenSSL build
            raise ValueError(f"Hash algorithm not available: {name}") from exc
    return digests


def hash_stream(
    stream: BinaryIO,
    algos: Sequence[str] = FORENSIC_ALGOS,
    *,
    chunk_size: int = CHUNK_SIZE,
    limit: int | None = None,
    offset: int = 0,
    progress: ProgressFn | None = None,
) -> dict[str, str]:
    """Hash a binary stream, returning ``{algorithm: hexdigest}``."""
    digests = _new_digests(algos)
    total = 0
    for chunk in iter_chunks(stream, chunk_size, limit=limit, offset=offset):
        for digest in digests.values():
            digest.update(chunk)
        total += len(chunk)
        if progress is not None:
            progress(total, limit if limit is not None else total)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def hash_file(
    path: str | Path,
    algos: Sequence[str] = FORENSIC_ALGOS,
    *,
    chunk_size: int = CHUNK_SIZE,
    progress: ProgressFn | None = None,
) -> dict[str, str]:
    """Hash a file on disk."""
    with open(path, "rb") as handle:
        return hash_stream(handle, algos, chunk_size=chunk_size, progress=progress)


def hash_bytes(data: bytes, algos: Sequence[str] = FORENSIC_ALGOS) -> dict[str, str]:
    """Hash an in-memory buffer."""
    digests = _new_digests(algos)
    for digest in digests.values():
        digest.update(data)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def hash_algo_hexdigest(data: bytes, algo: str) -> str:
    """Digest a single buffer with one algorithm."""
    digest = hashlib.new(algo)
    digest.update(data)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Content characterisation
# --------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits per byte (0.0 - 8.0).

    Used to characterise recovered regions: encrypted or compressed content sits
    near 8.0, zeroed regions sit at 0.0, and structured text lands in between.
    The carver uses this to validate candidate extents and to distinguish a
    genuinely wiped region from one that merely looks empty.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_profile(data: bytes, block: int = 4096) -> list[float]:
    """Per-block entropy, for charting an artefact's internal structure."""
    return [shannon_entropy(data[i : i + block]) for i in range(0, len(data), block)]


def is_probably_wiped(data: bytes, *, threshold: float = 0.15) -> bool:
    """
    Heuristic: does this buffer look like sanitized media?

    A wiped region is overwhelmingly a single repeated byte value (zeros, 0xFF,
    or a random pass's leftovers notwithstanding). Low entropy *plus* strong
    single-byte dominance is the signature we look for.
    """
    if not data:
        return True
    if shannon_entropy(data) > threshold:
        return False
    most_common = Counter(data).most_common(1)[0][1]
    return (most_common / len(data)) > 0.95


def constant_byte(data: bytes) -> int | None:
    """
    If the buffer is a single repeated byte, return it; otherwise None.

    This is how verification distinguishes 'pass wrote 0x00' from 'pass wrote a
    pattern that happens to be low-entropy'.
    """
    if not data:
        return None
    first = data[0]
    if data.count(first) == len(data):
        return first
    return None


def compare_digests(expected: Mapping[str, str], actual: Mapping[str, str]) -> tuple[bool, list[str]]:
    """
    Compare two digest maps, returning ``(matched, differing_algorithms)``.

    Only algorithms present in both maps participate - a report generated with
    a wider algorithm set must not be judged mismatched against one using fewer.
    """
    differing = [
        name
        for name, value in expected.items()
        if name in actual and actual[name].lower() != value.lower()
    ]
    return (not differing), differing


def human_bytes(size: float) -> str:
    """Format a byte count for display."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} EB"
