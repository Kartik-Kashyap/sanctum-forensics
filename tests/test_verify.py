"""
Post-erasure verification tests.

Verification is the module that turns "the wipe succeeded" into a claim someone
can check. The cases that matter are the failures: a verification routine that
only ever reports success is worse than none at all, because it manufactures
confidence.
"""

from __future__ import annotations

import io
import os

import pytest

from sanctum.erase.verify import (
    VerifyMode,
    _sample_windows,
    verify_pass,
)
from sanctum.core.standards import PassSpec, PatternKind


# -- window selection ------------------------------------------------------

def test_small_targets_are_checked_in_one_window():
    """A target smaller than the sampling budget is read in full, not sampled."""
    assert _sample_windows(4096, 64, 1024 * 1024) == [(0, 4096)]


def test_sampling_spans_the_whole_device():
    """
    The first and last byte must be inside the sampled set.

    Boundaries are exactly where short writes and off-by-one errors show up, so
    a sample that skips them would miss the most likely failure.
    """
    total = 100 * 1024 * 1024
    windows = _sample_windows(total, 64, 1024 * 1024)

    assert windows[0][0] == 0
    last_start, last_length = windows[-1]
    assert last_start + last_length == total


def test_sampling_returns_no_more_than_requested():
    windows = _sample_windows(100 * 1024 * 1024, 8, 1024 * 1024)
    assert 1 < len(windows) <= 8


def test_sampling_handles_a_zero_length_target():
    assert _sample_windows(0, 64, 1024) == []


def test_sampling_windows_are_sector_aligned():
    """Misaligned reads on real devices are slow or refused outright."""
    for offset, _ in _sample_windows(50 * 1024 * 1024, 16, 4096):
        assert offset % 512 == 0


# -- full mode -------------------------------------------------------------

def test_full_verification_accepts_a_correctly_written_region():
    data = b"\x00" * 8192
    outcome = verify_pass(io.BytesIO(data), len(data), PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)
    assert outcome.passed
    assert outcome.bytes_checked == 8192


def test_full_verification_catches_a_half_completed_write():
    """
    The realistic failure: the write stopped partway.

    This is what verification exists for - the engine reported success, the
    media disagrees. Windows are CHUNK_SIZE-granular, so the whole 8 KiB target
    is one window and the mismatch is reported at its start rather than at the
    half-way byte; the point is that the pass is *not* reported as verified.
    """
    total = 8192
    half_written = b"\x00" * 4096 + b"\xff" * 4096
    outcome = verify_pass(io.BytesIO(half_written), total, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)

    assert not outcome.passed
    assert outcome.first_mismatch_offset == 0
    assert outcome.mismatches[0].observed == "pattern mismatch"


def test_full_verification_catches_a_byte_pass_that_wrote_the_wrong_byte():
    data = b"\x5a" * 1024
    outcome = verify_pass(io.BytesIO(data), len(data), PassSpec(PatternKind.BYTE, byte=0xA5),
                          mode=VerifyMode.FULL)
    assert not outcome.passed


def test_full_verification_checks_a_cycle_pattern():
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    data = spec.build_buffer(4096)
    assert verify_pass(io.BytesIO(data), len(data), spec, mode=VerifyMode.FULL).passed

    mangled = bytearray(data)
    mangled[-1] ^= 0xFF
    assert not verify_pass(io.BytesIO(bytes(mangled)), len(data), spec,
                           mode=VerifyMode.FULL).passed


# -- random passes ---------------------------------------------------------

def test_random_pass_verification_accepts_high_entropy_data():
    """
    A random pass cannot be byte-compared - the written bytes were never kept.

    The check is instead that the region now looks like a successful random
    write, which is the strongest statement available.
    """
    outcome = verify_pass(io.BytesIO(os.urandom(65536)), 65536,
                          PassSpec(PatternKind.RANDOM), mode=VerifyMode.FULL)
    assert outcome.passed


def test_random_pass_verification_rejects_a_skipped_write():
    """
    If the random pass silently did nothing, the previous patterned pass is
    still on the media. That must be caught.
    """
    outcome = verify_pass(io.BytesIO(b"\x00" * 65536), 65536,
                          PassSpec(PatternKind.RANDOM), mode=VerifyMode.FULL)
    assert not outcome.passed
    assert outcome.first_mismatch_offset == 0


def test_random_pass_verification_rejects_low_entropy_repeating_data():
    """Not constant, but plainly not random either."""
    outcome = verify_pass(io.BytesIO(b"ABCD" * 16384), 65536,
                          PassSpec(PatternKind.RANDOM), mode=VerifyMode.FULL)
    assert not outcome.passed


# -- mode handling ---------------------------------------------------------

def test_none_mode_skips_and_says_so():
    """
    A skipped verification must report ``passed=True`` but record *why* it was
    skipped, so a report cannot present a skip as a check.
    """
    outcome = verify_pass(io.BytesIO(b"\xff" * 1024), 1024, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.NONE)
    assert outcome.mode is VerifyMode.NONE
    assert outcome.windows_checked == 0
    assert "disabled" in outcome.skipped_reason
    assert "skipped" in outcome.summary().lower()


def test_zero_length_target_fails_verification():
    outcome = verify_pass(io.BytesIO(b""), 0, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)
    assert not outcome.passed
    assert "zero" in outcome.skipped_reason


def test_a_short_read_is_a_mismatch_not_a_pass():
    """
    Media that returns less than asked for is not verified media.

    Treating a truncated read as success is the quiet way a verification
    routine becomes decorative.
    """
    outcome = verify_pass(io.BytesIO(b"\x00" * 512), 4096, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)
    assert not outcome.passed
    assert outcome.mismatches


# -- reporting -------------------------------------------------------------

def test_summary_of_a_pass_reads_plainly():
    outcome = verify_pass(io.BytesIO(b"\x00" * 4096), 4096, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)
    text = outcome.summary()
    assert "all matched" in text
    assert "4,096" in text


def test_summary_of_a_failure_names_the_offset():
    outcome = verify_pass(io.BytesIO(b"\xff" * 4096), 4096, PassSpec(PatternKind.ZERO),
                          mode=VerifyMode.FULL)
    text = outcome.summary()
    assert "FAILED" in text
    assert "0x0" in text


def test_window_description_includes_the_offset():
    outcome = verify_pass(io.BytesIO(b"\xff" * 1024 + b"\x00" * 1024), 2048,
                          PassSpec(PatternKind.ZERO), mode=VerifyMode.FULL)
    assert outcome.mismatches[0].describe()
    assert "0x000000000000" in outcome.mismatches[0].describe()


# -- cancellation and progress --------------------------------------------

def test_verification_honours_cancellation():
    from sanctum.core.progress import CancelToken, OperationCancelled

    token = CancelToken()
    token.cancel()
    with pytest.raises(OperationCancelled):
        verify_pass(io.BytesIO(os.urandom(1024)), 1024, PassSpec(PatternKind.RANDOM),
                    mode=VerifyMode.FULL, cancel=token)


def test_verification_reports_progress():
    from sanctum.core.progress import ProgressReporter

    seen: list = []
    reporter = ProgressReporter(seen.append, min_interval=0.0)
    verify_pass(io.BytesIO(b"\x00" * 65536), 65536, PassSpec(PatternKind.ZERO),
                mode=VerifyMode.SAMPLE, progress=reporter)
    assert seen
    assert any(update.phase.startswith("Verify") for update in seen)


# -- how the verification cost is measured ---------------------------------

def test_the_verification_benchmark_takes_enough_samples_to_be_meaningful(tmp_path):
    """
    A published overhead ratio must not be noise.

    Each verification sample is one whole write of the target plus the
    read-back, so the measurement is dominated by the write, and the write
    varies substantially between runs on ordinary hardware. Measured three
    times, the harness reported SAMPLE at 1.64x an unverified write against
    FULL at 1.29x - reading a quarter of the media as dearer than reading all
    of it. The floor exists so a report cannot be published off three samples.

    A tiny target is used: the sampling floor is a property of the harness, and
    the assertion is about how many samples it takes, not how big they are.
    """
    from tools.benchmark import _VERIFY_MIN_REPEATS, bench_verification

    assert _VERIFY_MIN_REPEATS >= 5, "too few samples to report a ratio"

    rows = bench_verification(tmp_path, 8, 1)
    assert rows
    for row in rows:
        assert row.metrics["repeats"] == _VERIFY_MIN_REPEATS, row.subject


def test_the_verification_benchmark_erases_clean_media_every_sample(
    tmp_path, monkeypatch
):
    """
    Every sample must erase a target that has not just been erased.

    A seven-sample floor was not enough on its own. Sampled in sequential
    blocks against one long-lived target, the same harness reported SAMPLE at
    0.54x and FULL at 0.74x of an unverified write - a saving from doing
    strictly more IO. ``tools/probe_verify.py`` runs the four candidate designs
    side by side and shows why: once the first sample has filled the file with
    the pattern being written, the later ones write the same bytes over the same
    bytes, out of page cache, and come out cheaper. Whichever mode runs first
    absorbs that cost, and the ratio between the modes becomes a ratio between
    their positions in the sequence.

    The design is therefore pinned here rather than left to survive on its
    merits: one freshly created target per sample, in a seeded random order.
    """
    from tools import benchmark

    fresh_calls: list = []
    order: list[str] = []

    real_fresh = benchmark._fresh_target
    real_run = benchmark.DriveEraser.run

    def counting_fresh(path, size_mb):
        fresh_calls.append(path)
        return real_fresh(path, size_mb)

    def counting_run(self, target, standard, **kwargs):
        order.append(kwargs.get("verify_mode").value)
        return real_run(self, target, standard, **kwargs)

    monkeypatch.setattr(benchmark, "_fresh_target", counting_fresh)
    monkeypatch.setattr(benchmark.DriveEraser, "run", counting_run)

    rows = benchmark.bench_verification(tmp_path, 8, 1)
    repeats = rows[0].metrics["repeats"]

    assert len(fresh_calls) == len(order) == len(rows) * repeats
    assert len(set(fresh_calls)) == 1, "the samples shared a target"

    # Interleaved rather than blocked: no mode may occupy a contiguous run of
    # the sequence, which is what "all seven NONE, then all seven FULL" is.
    assert order.count("none") == repeats
    for mode in ("none", "sample", "full"):
        first, last = order.index(mode), len(order) - 1 - order[::-1].index(mode)
        assert last - first > repeats, (
            f"{mode} was measured in one contiguous block: {order}"
        )


def test_the_verification_benchmark_reports_what_was_actually_read(tmp_path):
    """
    ``bytes_read_back`` is how a reader checks the ratio against the work.

    It used to be recorded as ``None`` for SAMPLE, so the one mode whose cost is
    least obvious was the one mode with no byte count attached to it. The figure
    comes from the engine's own accounting rather than being recomputed from the
    mode, so it describes the run rather than the harness's expectation of it.

    The harness is driven at a small target here, where sampling reads the whole
    of it: below the sampling budget the verifier deliberately reads everything
    in one window, so ``sample == full`` is the correct answer at this size and
    not a sign the mode was ignored. The size at which sampling becomes a strict
    subset is checked through the window geometry itself, which costs nothing.
    """
    from tools.benchmark import bench_verification

    rows = {row.subject.split(" @")[0]: row for row in bench_verification(tmp_path, 8, 1)}
    total = 8 * 1024 * 1024

    assert rows["none"].metrics["bytes_read_back"] == 0
    sampled = rows["sample"].metrics["bytes_read_back"]
    full = rows["full"].metrics["bytes_read_back"]

    assert full == total
    assert sampled is not None and 0 < sampled <= total, sampled

    # Above the sampling budget the count must be a strict subset - that is the
    # property the ratio in the report depends on.
    above_budget = 256 * 1024 * 1024
    windows = _sample_windows(above_budget, 64, 1024 * 1024)
    assert 0 < sum(length for _, length in windows) < above_budget
