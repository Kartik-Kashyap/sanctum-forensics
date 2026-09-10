"""
Post-erasure verification.

"The wipe succeeded" is a claim, and this module exists to make it a defensible
one. After each pass SANCTUM can re-read the media and confirm what is actually
there.

Two modes:

``full``
    Read every byte and compare against the expected pattern. Correct and
    unambiguous, but on a large drive this doubles the wall-clock cost.

``sample``
    Read a set of windows distributed evenly across the device. This is the
    standard practice for large media: a write pass that failed would almost
    certainly fail across the whole device (a dropped link, a bad controller,
    a short write), so sampling catches the realistic failure modes at a
    fraction of the cost. It is honest about being a sample - the report records
    exactly how many windows were checked and over what span.

Verifying a *random* pass needs different logic: we never retained the bytes we
wrote, so exact comparison is impossible. Instead the check confirms the region
now holds high-entropy, non-constant data - which is what a successful random
write looks like, and which a failed or skipped write would not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import BinaryIO

from sanctum.config import CHUNK_SIZE, VERIFY_SAMPLE_WINDOWS, VERIFY_WINDOW_BYTES
from sanctum.core.hashing import constant_byte, shannon_entropy
from sanctum.core.progress import CancelToken, OperationCancelled, ProgressReporter
from sanctum.core.standards import PassSpec, PatternKind


class VerifyMode(str, Enum):
    FULL = "full"
    SAMPLE = "sample"
    NONE = "none"


@dataclass
class WindowResult:
    """One verified window of media."""

    offset: int
    length: int
    matched: bool
    observed: str = ""

    def describe(self) -> str:
        status = "OK" if self.matched else "MISMATCH"
        return f"0x{self.offset:012X} len={self.length} {status} {self.observed}".strip()


@dataclass
class VerifyOutcome:
    """Aggregate result of a verification pass."""

    passed: bool
    mode: VerifyMode
    windows_checked: int
    bytes_checked: int
    mismatches: list[WindowResult] = field(default_factory=list)
    skipped_reason: str = ""
    sample_span: tuple[int, int] = (0, 0)

    @property
    def first_mismatch_offset(self) -> int | None:
        return self.mismatches[0].offset if self.mismatches else None

    def summary(self) -> str:
        if self.mode is VerifyMode.NONE:
            return f"Verification skipped ({self.skipped_reason})"
        if self.passed:
            return (
                f"Verified {self.bytes_checked:,} bytes across "
                f"{self.windows_checked} window(s) - all matched"
            )
        return (
            f"VERIFICATION FAILED: {len(self.mismatches)} of {self.windows_checked} "
            f"window(s) did not match (first at offset "
            f"0x{self.first_mismatch_offset or 0:X})"
        )


def _sample_windows(total: int, count: int, window: int) -> list[tuple[int, int]]:
    """
    Evenly spread ``count`` read windows across ``total`` bytes.

    Includes the first and last window, because the boundaries are where short
    writes and off-by-one errors surface.
    """
    if total <= 0:
        return []
    window = min(window, total)
    if total <= window * count:
        # Small target: just read the whole thing in one window.
        return [(0, total)]

    max_start = total - window
    if count == 1:
        return [(0, window)]

    step = max_start / (count - 1)
    windows: list[tuple[int, int]] = []
    seen: set[int] = set()
    for index in range(count):
        start = int(index * step)
        start -= start % 512  # align to a sector for device friendliness
        if start in seen:
            continue
        seen.add(start)
        windows.append((min(start, max_start), window))
    return windows


def _expected_for_window(pass_spec: PassSpec, length: int, offset: int = 0) -> bytes:
    """
    The bytes the pass should have left at absolute ``offset``.

    Phase matters: a cycling pattern read at an offset that is not a multiple of
    its period must be compared against the sequence starting at that phase, not
    from the beginning.
    """
    return pass_spec.expected_at(offset, length)


def verify_pass(
    handle: BinaryIO,
    total_bytes: int,
    pass_spec: PassSpec,
    *,
    mode: VerifyMode = VerifyMode.SAMPLE,
    sample_windows: int = VERIFY_SAMPLE_WINDOWS,
    window_bytes: int = VERIFY_WINDOW_BYTES,
    progress: ProgressReporter | None = None,
    cancel: CancelToken | None = None,
    phase: str = "Verify",
) -> VerifyOutcome:
    """
    Re-read media and confirm the pass landed.

    ``handle`` is a read-capable binary stream positioned anywhere; this
    function seeks explicitly.
    """
    if mode is VerifyMode.NONE:
        return VerifyOutcome(
            passed=True,
            mode=mode,
            windows_checked=0,
            bytes_checked=0,
            skipped_reason="verification disabled by operator",
        )

    if total_bytes <= 0:
        return VerifyOutcome(
            passed=False,
            mode=mode,
            windows_checked=0,
            bytes_checked=0,
            skipped_reason="target size is zero",
        )

    is_random = pass_spec.kind is PatternKind.RANDOM

    if mode is VerifyMode.FULL:
        windows = [
            (offset, min(CHUNK_SIZE, total_bytes - offset))
            for offset in range(0, total_bytes, CHUNK_SIZE)
        ]
        span = (0, total_bytes)
    else:
        windows = _sample_windows(total_bytes, sample_windows, window_bytes)
        span = (windows[0][0], windows[-1][0] + windows[-1][1]) if windows else (0, 0)

    outcome = VerifyOutcome(
        passed=True,
        mode=mode,
        windows_checked=0,
        bytes_checked=0,
        sample_span=span,
    )

    if progress is not None:
        progress.start(phase, total_bytes)

    checked = 0
    for offset, length in windows:
        if cancel is not None:
            cancel.check()

        handle.seek(offset)
        data = handle.read(length)
        if not data:
            outcome.passed = False
            outcome.mismatches.append(
                WindowResult(offset, length, False, "read returned no data")
            )
            break

        if len(data) < length:
            # A short read means the media did not return everything asked for.
            # Comparing only the bytes that did arrive would let a truncated
            # read pass as verified - the failure mode this module exists to
            # catch - so it is recorded as a mismatch and not inspected further.
            outcome.passed = False
            outcome.mismatches.append(
                WindowResult(
                    offset,
                    length,
                    False,
                    f"short read: got {len(data)} of {length} bytes",
                )
            )
            checked += len(data)
            outcome.windows_checked += 1
            continue

        if is_random:
            # A successful random write leaves high-entropy, non-constant data.
            # A skipped or failed write leaves whatever was there before, which
            # after a patterned pass is constant and near-zero entropy.
            entropy = shannon_entropy(data)
            matched = entropy > 6.0 and constant_byte(data) is None
            observed = f"entropy={entropy:.3f}"
        else:
            expected = _expected_for_window(pass_spec, len(data), offset)
            matched = data == expected
            observed = "pattern mismatch" if not matched else pass_spec.describe()

        if not matched:
            outcome.passed = False
            outcome.mismatches.append(WindowResult(offset, len(data), False, observed))

        checked += len(data)
        outcome.windows_checked += 1
        if progress is not None:
            progress.update(phase, min(checked, total_bytes), total_bytes)

    outcome.bytes_checked = checked
    if progress is not None:
        progress.finish(phase, total_bytes, "verified" if outcome.passed else "FAILED")

    return outcome
