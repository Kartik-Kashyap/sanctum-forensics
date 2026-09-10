"""
Performance evaluation harness.

The performance report is generated, not written. Every figure in
``docs/PERFORMANCE.md`` comes from a run of this script, and the script prints
the machine it ran on so a reader can judge whether the numbers transfer.

    python -m tools.benchmark --output bench/
    python -m tools.benchmark --quick

What is measured, and why each one:

* **Erase throughput** - MB/s written per pass, for each standard. This is the
  number that decides whether whole-disk sanitization is practical, and it is
  dominated by the storage device, not by SANCTUM. Reported alongside the
  device so the attribution is clear.

* **Verification cost** - the same erase with verification off, sampled, and
  full. Verification reads the media back, so it roughly doubles or triples the
  wall clock. An examiner needs to know that price before choosing FULL on a
  2 TB drive.

* **Carve throughput** - MB/s scanned and artefacts recovered per second, over
  a FAT16 image with a known planted corpus.

* **Recovery accuracy** - recall and precision against the SHA-256 digests
  recorded when the corpus was built. This is the measurement that matters:
  throughput is worthless if the bytes are wrong.

* **Peak allocation** - via ``tracemalloc``, which reports Python-level
  allocation. The carver is written to work in fixed-size blocks precisely so
  that scanning a 2 TB image does not require 2 TB of RAM; this is the check on
  that claim.

Nothing in this module is imported by the application. It is a measurement
instrument, and it is kept out of the tool's own dependency graph.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import shutil
import statistics
import sys
import tempfile
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):  # pragma: no cover - direct invocation
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sanctum.config import SafetyPolicy  # noqa: E402
from sanctum.core.audit import AuditChain  # noqa: E402
from sanctum.core.hashing import human_bytes  # noqa: E402
from sanctum.core.standards import get_standard  # noqa: E402
from sanctum.core.targets import TargetKind, describe_target  # noqa: E402
from sanctum.erase.drive import DriveEraser  # noqa: E402
from sanctum.erase.file import FileEraser  # noqa: E402
from sanctum.erase.verify import VerifyMode  # noqa: E402
from sanctum.recover.carver import SignatureCarver  # noqa: E402


@dataclass
class Row:
    """One measured line of the report."""

    benchmark: str
    subject: str
    metrics: dict = field(default_factory=dict)
    notes: str = ""


def _environment() -> dict:
    from sanctum.core.devices import platform_summary
    from sanctum.recover.native import capabilities

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "summary": platform_summary(),
        "native_backend": capabilities().as_dict(),
        "storage": str(Path(tempfile.gettempdir()).anchor or tempfile.gettempdir()),
    }


# --------------------------------------------------------------------------
# Erasure
# --------------------------------------------------------------------------

def bench_erase(work: Path, sizes_mb: list[int], repeats: int) -> list[Row]:
    """Throughput per standard, at each image size."""
    rows: list[Row] = []
    policy = SafetyPolicy(dry_run=False, require_confirmation_token=False)
    audit = AuditChain(work / "bench-erase.jsonl")

    for size_mb in sizes_mb:
        source = work / f"erase-{size_mb}mb.img"
        if not source.exists():
            with open(source, "wb") as handle:
                handle.truncate(size_mb * 1024 * 1024)

        for standard_id in ("zero1", "dod3", "dod7", "gutmann"):
            timings: list[float] = []
            throughputs: list[float] = []
            for _ in range(repeats):
                target = describe_target(str(source), kind=TargetKind.DISK_IMAGE)
                started = time.perf_counter()
                result = DriveEraser(audit).run(
                    target, standard_id, policy=policy,
                    verify=False, verify_mode=VerifyMode.NONE,
                )
                elapsed = time.perf_counter() - started
                if not result.success:
                    break
                timings.append(elapsed)
                throughputs.append(result.throughput_mbps)

            if not throughputs:
                rows.append(Row("erase", f"{standard_id} @ {size_mb} MB",
                                notes="run did not complete"))
                continue

            standard = get_standard(standard_id)
            rows.append(Row(
                "erase",
                f"{standard_id} @ {size_mb} MB",
                {
                    "passes": standard.pass_count,
                    "median_seconds": round(statistics.median(timings), 3),
                    "median_mbps": round(statistics.median(throughputs), 1),
                    "bytes_written": size_mb * 1024 * 1024 * standard.pass_count,
                    "repeats": len(timings),
                },
                notes=f"{standard.name} ({standard.pass_count} pass)",
            ))
    return rows


#: Sampling the verification modes fewer times than this produces ratios that
#: are noise rather than measurement. Each sample is one full write of the
#: target plus the read-back, so the measurement is dominated by the write -
#: which on this hardware varies by a third between runs. With three samples
#: the harness reported SAMPLE costing 1.64x an unverified write and FULL
#: costing 1.29x, i.e. reading a quarter of the media as dearer than reading
#: all of it. Seven samples on the same machine give 1.02x and 1.24x, which is
#: the ordering the hardware actually has. The verification section is cheap
#: next to the erase and carve sections, so the extra samples cost seconds.
_VERIFY_MIN_REPEATS = 7


def _fresh_target(path: Path, size_mb: int) -> Path:
    """
    Re-create the scratch target so every sample erases clean media.

    Erasing is a one-shot operation on a device that has not just been erased.
    Handing the same file to twenty-one consecutive erasures measures something
    else entirely: the later samples write the pattern over a file already full
    of it, already in page cache, and come out cheaper than the first - so
    whichever mode ran first pays for the difference.
    """
    if path.exists():
        path.unlink()
    with open(path, "wb") as handle:
        handle.truncate(size_mb * 1024 * 1024)
    return path


def bench_verification(work: Path, size_mb: int, repeats: int) -> list[Row]:
    """
    The wall-clock price of verifying, at each mode.

    Each sample is one complete erasure of a **freshly created target**, run in
    a randomised order. Both halves of that matter, and both were arrived at by
    measurement rather than by taste - ``tools/probe_verify.py`` runs the same
    engine under four designs and prints every sample.

    *A fresh target each time.* Writing the pattern over a file that is already
    full of that pattern, and already resident in page cache, is not the same
    operation as writing it to clean media - and it is not the operation a user
    performs either. Reusing one target made later samples systematically
    cheaper than earlier ones, so the mode measured first paid a cost the others
    did not.

    *Interleaved, in randomised order.* Measuring seven NONE samples and then
    seven FULL samples compares *when* each block ran rather than what it did.
    On a machine that drifts, the drift lands entirely on whichever mode went
    first.

    Together these replaced a harness that twice published ratios below 1.0 - a
    saving from doing strictly more IO. Three samples gave SAMPLE 1.64x and FULL
    1.29x; a seven-sample floor in sequential blocks gave 0.54x and 0.74x; only
    fresh targets in randomised order give the monotone ordering the hardware
    actually has. The residual spread is the machine, which is why the min and
    max are reported alongside the median: a ratio whose samples overlap is not
    a measurement.
    """
    rows: list[Row] = []
    policy = SafetyPolicy(dry_run=False, require_confirmation_token=False)
    audit = AuditChain(work / "bench-verify.jsonl")
    source = work / f"verify-{size_mb}mb.img"

    repeats = max(repeats, _VERIFY_MIN_REPEATS)
    modes = (VerifyMode.NONE, VerifyMode.SAMPLE, VerifyMode.FULL)
    timings: dict[VerifyMode, list[float]] = {mode: [] for mode in modes}
    read_back: dict[VerifyMode, int] = {mode: 0 for mode in modes}

    # Seeded, so a rerun of the report reproduces the same ordering even though
    # the timings will differ - the order is a control, not a variable.
    order = [mode for _ in range(repeats) for mode in modes]
    random.Random(0x5A17).shuffle(order)

    for mode in order:
        _fresh_target(source, size_mb)
        target = describe_target(str(source), kind=TargetKind.DISK_IMAGE)
        started = time.perf_counter()
        result = DriveEraser(audit).run(
            target, "zero1", policy=policy, verify=True, verify_mode=mode,
        )
        timings[mode].append(time.perf_counter() - started)
        # Read the checked-byte count out of the engine rather than recomputing
        # it from the mode. SAMPLE's window geometry lives in the verifier; a
        # second copy of that arithmetic here would be free to disagree with it,
        # and the report is supposed to describe what ran, not what this file
        # believes ran.
        if result.success:
            read_back[mode] = sum(
                p.verification.bytes_checked
                for p in result.passes
                if p.verification is not None
            )

    baseline = (
        statistics.median(timings[VerifyMode.NONE]) if timings[VerifyMode.NONE] else 0.0
    )

    for mode in modes:
        samples = timings[mode]
        median = statistics.median(samples) if samples else 0.0
        overhead = round(median / baseline, 2) if baseline > 0 else None
        rows.append(Row(
            "verification",
            f"{mode.value} @ {size_mb} MB",
            {
                "median_seconds": round(median, 3),
                "overhead_vs_unverified": overhead,
                "seconds_min": round(min(samples), 3) if samples else None,
                "seconds_max": round(max(samples), 3) if samples else None,
                "bytes_read_back": read_back[mode],
                "repeats": len(samples),
            },
            notes=(
                "no read-back" if mode is VerifyMode.NONE
                else "evenly-spread sample windows" if mode is VerifyMode.SAMPLE
                else "every byte compared against the expected pattern"
            ),
        ))
    return rows


# --------------------------------------------------------------------------
# Carving
# --------------------------------------------------------------------------

def bench_carve(work: Path, repeats: int) -> list[Row]:
    """Scan throughput and recovery accuracy, measured against ground truth."""
    from tools.make_test_media import build_all

    rows: list[Row] = []
    media = work / "media"
    manifest_path = media / "manifest.json"
    if not manifest_path.exists():
        build_all(media, quiet=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scenario = manifest["scenarios"]["deleted_files"]
    source = media / scenario["image"]

    audit = AuditChain(work / "bench-carve.jsonl")
    scan_times: list[float] = []
    throughputs: list[float] = []
    peak_bytes = 0
    last = None

    for index in range(repeats):
        out = work / f"carved-{index}"
        shutil.rmtree(out, ignore_errors=True)
        tracemalloc.start()
        started = time.perf_counter()
        last = SignatureCarver(audit).carve(source, out, write_files=True)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_bytes = max(peak_bytes, peak)
        scan_times.append(elapsed)
        if elapsed > 0:
            throughputs.append(last.bytes_scanned / (1024 * 1024) / elapsed)

    if last is None:
        return rows

    # Accuracy is measured against the digests recorded when the corpus was
    # built, not against a count someone wrote down.
    planted = {r["sha256"]: r for r in scenario["files"]}
    deleted_planted = {r["sha256"] for r in scenario["files"] if r.get("deleted")}
    recovered = {a.digests.get("sha256", "") for a in last.artifacts}
    true_positives = recovered & set(planted)
    recall = len(recovered & deleted_planted) / len(deleted_planted) if deleted_planted else 0.0
    precision = len(true_positives) / len(recovered) if recovered else 0.0

    rows.append(Row(
        "carve",
        f"{Path(source).name} ({human_bytes(source.stat().st_size)})",
        {
            "median_seconds": round(statistics.median(scan_times), 3),
            "median_mbps": round(statistics.median(throughputs), 1) if throughputs else 0.0,
            "artefacts": last.recovered_count,
            "high_confidence": last.high_confidence,
            "planted_deleted": len(deleted_planted),
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "peak_python_allocation_mb": round(peak_bytes / (1024 * 1024), 2),
            "repeats": repeats,
        },
        notes="recall and precision are SHA-256 matches against the build manifest",
    ))

    # The memory claim: scanning must not scale with image size.
    for size_mb in (32, 128):
        big = work / f"carve-scale-{size_mb}mb.img"
        with open(big, "wb") as handle:
            handle.truncate(size_mb * 1024 * 1024)
        out = work / f"carve-scale-{size_mb}"
        shutil.rmtree(out, ignore_errors=True)
        tracemalloc.start()
        started = time.perf_counter()
        SignatureCarver(audit).carve(big, out, write_files=True)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(Row(
            "carve-scaling",
            f"zero-filled image @ {size_mb} MB",
            {
                "seconds": round(elapsed, 3),
                "mbps": round(size_mb / elapsed, 1) if elapsed > 0 else 0.0,
                "peak_python_allocation_mb": round(peak / (1024 * 1024), 2),
            },
            notes="peak allocation should stay flat as the image grows",
        ))
    return rows


# --------------------------------------------------------------------------
# File erasure
# --------------------------------------------------------------------------

def bench_file_erase(work: Path, counts: list[int], repeats: int) -> list[Row]:
    """Per-file cost of secure deletion, including the metadata pass."""
    rows: list[Row] = []
    policy = SafetyPolicy(dry_run=False, require_confirmation_token=False)
    audit = AuditChain(work / "bench-file.jsonl")
    eraser = FileEraser(audit)

    for count in counts:
        timings: list[float] = []
        total_bytes = 0
        for run in range(repeats):
            directory = work / f"files-{count}-{run}"
            shutil.rmtree(directory, ignore_errors=True)
            directory.mkdir(parents=True)
            payload = b"SANCTUM-BENCHMARK-PAYLOAD" * 1024  # 25 KiB per file
            paths = []
            for index in range(count):
                path = directory / f"item-{index:05d}.bin"
                path.write_bytes(payload)
                paths.append(path)
            total_bytes = count * len(payload)

            started = time.perf_counter()
            batch = eraser.secure_delete_paths(
                paths, "dod3", policy=policy, recursive=False
            )
            timings.append(time.perf_counter() - started)
            if batch.succeeded != count:
                break

        median = statistics.median(timings) if timings else 0.0
        rows.append(Row(
            "file-erase",
            f"{count} files @ {human_bytes(total_bytes // max(1, count))} each",
            {
                "median_seconds": round(median, 3),
                "files_per_second": round(count / median, 1) if median > 0 else 0.0,
                "mbps": round((total_bytes / (1024 * 1024)) / median, 1) if median > 0 else 0.0,
                "repeats": len(timings),
            },
            notes="dod3, metadata cleansing on",
        ))
    return rows


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def _markdown(rows: list[Row], environment: dict) -> str:
    lines = [
        "# SANCTUM performance evaluation",
        "",
        "Generated by `python -m tools.benchmark`. Every figure below was",
        "measured on the machine described here, by the script in this",
        "repository - not estimated.",
        "",
        "## Environment",
        "",
        f"- Python: `{environment['python']}`",
        f"- Platform: `{environment['platform']}`",
        f"- Processor: `{environment['processor']}`",
        f"- Storage under test: `{environment['storage']}`",
        f"- Native backend: {environment['native_backend']['summary']}",
        "",
    ]

    for section in dict.fromkeys(row.benchmark for row in rows):
        selected = [row for row in rows if row.benchmark == section]
        keys: list[str] = []
        for row in selected:
            for key in row.metrics:
                if key not in keys:
                    keys.append(key)

        lines.append(f"## {section}")
        lines.append("")
        lines.append("| subject | " + " | ".join(keys) + " | notes |")
        lines.append("|---|" + "---|" * len(keys) + "---|")
        for row in selected:
            cells = [str(row.metrics.get(key, "")) for key in keys]
            lines.append(
                f"| {row.subject} | " + " | ".join(cells) + f" | {row.notes} |"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SANCTUM performance evaluation")
    parser.add_argument("--output", default="bench", help="Directory for results")
    parser.add_argument("--quick", action="store_true",
                        help="Small sizes, one repeat - a smoke run, not a measurement")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args(argv)

    if args.quick:
        sizes, verify_mb, file_counts, repeats = [8], 16, [50], 1
    else:
        sizes, verify_mb, file_counts, repeats = [16, 64, 256], 256, [100, 1000], args.repeats

    output = Path(args.output)
    work = output / "work"
    work.mkdir(parents=True, exist_ok=True)

    environment = _environment()
    print(f"SANCTUM benchmark - Python {environment['python']} on {environment['platform']}")
    if args.quick:
        print("QUICK MODE: these figures are indicative only, not a measurement.")
    print(f"Scratch: {work}\n")

    rows: list[Row] = []
    stages = [
        ("erase", lambda: bench_erase(work, sizes, repeats)),
        ("verification", lambda: bench_verification(work, verify_mb, repeats)),
        ("carve", lambda: bench_carve(work, repeats)),
        ("file-erase", lambda: bench_file_erase(work, file_counts, repeats)),
    ]
    for name, stage in stages:
        print(f"Running {name} ...")
        try:
            rows.extend(stage())
        except Exception as exc:  # noqa: BLE001 - one failed stage must not lose the rest
            print(f"  {name} failed: {type(exc).__name__}: {exc}")
            rows.append(Row(name, "FAILED", notes=f"{type(exc).__name__}: {exc}"))

    payload = {
        "environment": environment,
        "quick_mode": args.quick,
        "rows": [
            {"benchmark": r.benchmark, "subject": r.subject,
             "metrics": r.metrics, "notes": r.notes}
            for r in rows
        ],
    }
    (output / "benchmark.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    (output / "PERFORMANCE.md").write_text(_markdown(rows, environment), encoding="utf-8")

    print(f"\nWrote {output / 'benchmark.json'}")
    print(f"Wrote {output / 'PERFORMANCE.md'}")
    print("\nMachine-readable results are in benchmark.json; the markdown is the report.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
