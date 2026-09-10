"""
Probe: why does the verification benchmark report verification as free?

``bench_verification`` has twice reported ratios below 1.0 - SAMPLE at 0.54x of
an unverified write, and after interleaving, NONE at 0.84 s against FULL at
0.77 s. Verification can only add work, so at least one of those numbers is not
measuring what it claims to.

This runs the same engine on the same target under three designs and prints
every sample, so the cause can be read off rather than argued about:

  A  sequential blocks        (the original harness shape)
  B  interleaved rounds       (the current harness shape)
  C  interleaved, random order, fresh file per run

If C is clean and B is not, the residue is order within the round. If none of
them is clean, the target itself is the problem - a file that has already been
filled with the pattern being written is not the same target on the second
write, and page cache makes that difference enormous.
"""

from __future__ import annotations

import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sanctum.config import SafetyPolicy  # noqa: E402
from sanctum.core.audit import AuditChain  # noqa: E402
from sanctum.core.targets import TargetKind, describe_target  # noqa: E402
from sanctum.erase.drive import DriveEraser  # noqa: E402
from sanctum.erase.verify import VerifyMode  # noqa: E402

WORK = ROOT / "deck" / "work" / "probe"
SIZE_MB = 256
REPEATS = 7
MODES = (VerifyMode.NONE, VerifyMode.SAMPLE, VerifyMode.FULL)

POLICY = SafetyPolicy(dry_run=False, require_confirmation_token=False)


def timed(source: Path, mode: VerifyMode, audit: AuditChain) -> float:
    target = describe_target(str(source), kind=TargetKind.DISK_IMAGE)
    started = time.perf_counter()
    result = DriveEraser(audit).run(
        target, "zero1", policy=POLICY, verify=True, verify_mode=mode,
    )
    elapsed = time.perf_counter() - started
    if not result.success:
        raise SystemExit(f"{mode.value} failed: {result.error}")
    return elapsed


def fresh(path: Path) -> Path:
    """A target that has not already been filled with the pattern."""
    if path.exists():
        path.unlink()
    with open(path, "wb") as handle:
        handle.truncate(SIZE_MB * 1024 * 1024)
    return path


def report(title: str, samples: dict[VerifyMode, list[float]]) -> None:
    print(f"\n{title}")
    print(f"  {'mode':8} {'median':>8}  {'min':>7}  {'max':>7}   ratio   samples")
    baseline = statistics.median(samples[VerifyMode.NONE])
    for mode in MODES:
        values = samples[mode]
        median = statistics.median(values)
        ratio = median / baseline if baseline else float("nan")
        shown = " ".join(f"{v:.2f}" for v in values)
        print(f"  {mode.value:8} {median:8.3f}  {min(values):7.3f}  "
              f"{max(values):7.3f}   {ratio:5.2f}   {shown}")


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / f"probe-{SIZE_MB}mb.img"
    audit = AuditChain(WORK / "probe.jsonl")

    # ---- A: sequential blocks, one long-lived target ---------------------
    fresh(source)
    block: dict[VerifyMode, list[float]] = {mode: [] for mode in MODES}
    for mode in MODES:
        for _ in range(REPEATS):
            block[mode].append(timed(source, mode, audit))
    report("A  sequential blocks (original harness shape)", block)

    # ---- B: interleaved rounds, one long-lived target --------------------
    fresh(source)
    rounds: dict[VerifyMode, list[float]] = {mode: [] for mode in MODES}
    for _ in range(REPEATS):
        for mode in MODES:
            rounds[mode].append(timed(source, mode, audit))
    report("B  interleaved rounds (current harness shape)", rounds)

    # ---- C: interleaved, shuffled order, fresh target every run ----------
    shuffled: dict[VerifyMode, list[float]] = {mode: [] for mode in MODES}
    order = [mode for _ in range(REPEATS) for mode in MODES]
    random.Random(20260910).shuffle(order)
    for mode in order:
        fresh(source)
        shuffled[mode].append(timed(source, mode, audit))
    report("C  shuffled order, fresh target per run", shuffled)

    # ---- D: interleaved in fixed order, fresh target every run -----------
    #
    # C changes two things at once. D changes only the target's lifetime, so
    # the difference between B and D is attributable to the target and the
    # difference between C and D is attributable to the order.
    fixed: dict[VerifyMode, list[float]] = {mode: [] for mode in MODES}
    for _ in range(REPEATS):
        for mode in MODES:
            fresh(source)
            fixed[mode].append(timed(source, mode, audit))
    report("D  fixed order, fresh target per run", fixed)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
