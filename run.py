#!/usr/bin/env python3
"""
SANCTUM entry point.

    python run.py                       launch the desktop application
    python run.py --selftest            run the end-to-end engine check
    python run.py --make-media DIR      build the synthetic test media
    python run.py --version             print the version

``--selftest`` is the headless path: it exercises all three modules and the
audit chain against synthetic media and prints what it actually measured. It
exists so the tool can be validated on a machine with no display, and so a
claim about the tool can be checked rather than taken on trust.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

#: Added so ``python run.py`` works from a checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sanctum import __product_name__, __tagline__, __version__  # noqa: E402


def _print_environment() -> None:
    from sanctum.core.devices import platform_summary
    from sanctum.recover.native import capabilities

    print(f"{__product_name__} {__version__} - {__tagline__}")
    print("-" * 72)
    print(platform_summary())
    print(capabilities().summary())
    print()


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

class _Check:
    """One named assertion, so the summary can report what actually ran."""

    def __init__(self) -> None:
        self.results: list[tuple[str, bool, str]] = []

    def record(self, name: str, passed: bool, detail: str = "") -> bool:
        self.results.append((name, passed, detail))
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}" + (f" - {detail}" if detail else ""))
        return passed

    @property
    def failed(self) -> list[tuple[str, bool, str]]:
        return [row for row in self.results if not row[1]]

    def summary(self) -> str:
        passed = len(self.results) - len(self.failed)
        return f"{passed}/{len(self.results)} checks passed"


def _selftest(workdir: Path | None, keep: bool) -> int:
    """
    Exercise every module against synthetic media and report real numbers.

    Nothing here asserts a hard-coded expected result. The FAT16 image is built
    with its own manifest of SHA-256 digests, so recovery is measured against
    ground truth rather than against a number someone wrote down.
    """
    from sanctum.core.audit import AuditCategory, AuditChain
    from sanctum.core.standards import get_standard
    from sanctum.core.targets import TargetKind, describe_target
    from sanctum.erase.drive import DriveEraser
    from sanctum.erase.file import FileEraser
    from sanctum.erase.verify import VerifyMode
    from sanctum.config import SafetyPolicy, ensure_layout
    from sanctum.recover.carver import SignatureCarver
    from sanctum.report.builder import ReportBuilder, ReportContext
    from tools.make_test_media import build_all

    ensure_layout()
    work = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="sanctum-selftest-"))
    work.mkdir(parents=True, exist_ok=True)

    check = _Check()
    _print_environment()
    print(f"Working directory: {work}\n")

    try:
        # ---- build the media ---------------------------------------------
        print("Building synthetic media ...")
        media_dir = work / "media"
        manifest = build_all(media_dir, quiet=True)
        scenarios = manifest["scenarios"]
        check.record(
            "test media built",
            "deleted_files" in scenarios and "wiped" in scenarios,
            f"{len(scenarios)} scenario(s)",
        )

        # The manifest records image filenames, not paths, so they are resolved
        # against the directory the fixtures were written into.
        def image_of(name: str) -> Path:
            return media_dir / scenarios[name]["image"]

        audit = AuditChain(work / "audit.jsonl")

        # ---- module 3: carving -------------------------------------------
        print("\nModule 3 - advanced file carving")
        deleted = scenarios["deleted_files"]
        carve_out = work / "carved"
        carver = SignatureCarver(audit)
        carved = carver.carve(image_of("deleted_files"), carve_out, write_files=True)

        # ``CarveResult.summary()`` returns a mapping, so it must not be handed
        # to ``record`` as a detail string - a raw dict repr in a PASS line
        # reads like a debugging leftover. The counts are composed instead.
        carve_detail = carved.error or (
            f"{carved.recovered_count} artefact(s), "
            f"{carved.high_confidence} at High confidence, "
            f"{carved.recovered_bytes:,} bytes, {carved.elapsed_seconds:.1f}s"
        )
        check.record("carver completed", not carved.error, carve_detail)

        recovered = {a.digests.get("sha256", "") for a in carved.artifacts}
        planted = {record["sha256"]: record["name"] for record in deleted["files"]}
        expected = {
            record["sha256"]
            for record in deleted["files"]
            if record.get("deleted")
        }
        hits = recovered & expected
        recall = len(hits) / len(expected) if expected else 0.0
        check.record(
            "deleted files recovered from unallocated space",
            len(hits) > 0,
            f"{len(hits)}/{len(expected)} planted files matched by SHA-256 "
            f"({recall:.0%} recall)",
        )

        named = sorted(planted[h] for h in hits)
        if named:
            print(f"        recovered: {', '.join(named)}")

        # Byte-exactness is the claim that matters; a carver that finds the
        # right offset but writes the wrong bytes is worse than one that
        # finds nothing, because it looks like success.
        exact = all(
            a.length == next(
                r["size"] for r in deleted["files"] if r["sha256"] == a.digests.get("sha256")
            )
            for a in carved.artifacts
            if a.digests.get("sha256") in planted
        )
        check.record("recovered files are byte-exact", exact)

        phantom = [
            a for a in carved.artifacts
            if a.confidence_label == "High" and a.digests.get("sha256") not in planted
        ]
        check.record(
            "no fabricated high-confidence artefacts",
            not phantom,
            f"{len(phantom)} phantom(s)",
        )

        # ---- module 1: drive erasure -------------------------------------
        print("\nModule 1 - secure drive erasure")
        scratch = work / "scratch-target.img"
        # A copy, so the fixture the manifest describes is left intact.
        shutil.copyfile(image_of("scratch"), scratch)
        target = describe_target(str(scratch), kind=TargetKind.DISK_IMAGE)
        policy = SafetyPolicy(dry_run=False, require_confirmation_token=False)

        erased = DriveEraser(audit).run(
            target, "dod3", policy=policy, verify=True, verify_mode=VerifyMode.FULL
        )
        check.record("multi-pass erase completed", erased.success, erased.headline())
        check.record(
            "every pass verified",
            erased.verified is True,
            f"{erased.total_passes} pass(es), {erased.throughput_mbps:.1f} MB/s",
        )

        # The engine verifies by reading back through the same code path that
        # wrote, so the media is checked once more from outside it. A single
        # zero pass is used because its expected content is unambiguous: after
        # dod3 the final pass is random, and a random fill cannot be told apart
        # from the original content by inspection alone.
        zeroed = DriveEraser(audit).run(
            target, "zero1", policy=policy, verify=True, verify_mode=VerifyMode.FULL
        )
        with open(scratch, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 4096))
            tail = handle.read()
        check.record(
            "media independently reads back as the overwrite pattern",
            zeroed.success and tail == b"\x00" * len(tail),
            f"last {len(tail):,} bytes of {size:,}: {tail[:8].hex()}...",
        )

        # ---- module 2: file erasure --------------------------------------
        print("\nModule 2 - secure file and folder erasure")
        victim = work / "to-delete.txt"
        victim.write_bytes(b"CONFIDENTIAL-SELFTEST-PAYLOAD" * 512)
        victim_size = victim.stat().st_size

        batch = FileEraser(audit).secure_delete_paths(
            [victim], "dod3", policy=policy, recursive=False
        )
        file_standard = get_standard("dod3")
        check.record(
            "file securely deleted",
            batch.succeeded == 1 and not victim.exists(),
            # Bytes written over the whole pass sequence, not "bytes of the
            # file" - a 3-pass standard writes three times the file's length, so
            # phrasing it as a ratio against the file size reads as a nonsense
            # figure. The pass count is what makes the number make sense.
            f"{batch.succeeded}/{batch.planned} removed, "
            f"{batch.total_bytes:,} bytes written over {file_standard.pass_count} pass(es) "
            f"for a {victim_size:,}-byte file",
        )

        # ---- audit chain --------------------------------------------------
        print("\nAudit and reporting")
        verification = audit.verify()
        check.record(
            "audit chain verifies",
            verification.ok,
            f"{len(audit.entries())} entries",
        )

        # Tamper with a copy and confirm the chain notices. A tamper-evident
        # log that does not detect tampering is decoration.
        tampered_path = work / "tampered.jsonl"
        shutil.copyfile(work / "audit.jsonl", tampered_path)
        tamper_chain = AuditChain(tampered_path)
        original = tamper_chain.entries()
        if original:
            import json as json_module

            lines = [
                json_module.loads(line)
                for line in tampered_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            lines[0]["action"] = "rewritten_by_attacker"
            tampered_path.write_text(
                "\n".join(json_module.dumps(row, sort_keys=True) for row in lines) + "\n",
                encoding="utf-8",
            )
            detected = not AuditChain(tampered_path).verify().ok
            check.record("audit chain detects tampering", detected)

        # ---- report -------------------------------------------------------
        builder = ReportBuilder(
            ReportContext(
                case_name="SANCTUM self-test",
                case_id="SELFTEST",
                examiner="run.py --selftest",
                description="Automated end-to-end check of all three modules.",
            )
        )
        builder.add_operation(erased)
        builder.add_operation(batch)
        builder.add_operation(carved)
        builder.attach_audit(audit)
        written = builder.write(work / "reports", stem="selftest",
                                formats=("html", "json", "csv"))
        check.record(
            "report generated",
            all(path.exists() and path.stat().st_size > 0 for path in written.values()),
            ", ".join(sorted(path.name for path in written.values())),
        )

    except Exception as exc:  # noqa: BLE001 - the point of a self-test is to report
        traceback.print_exc()
        check.record("self-test ran without an unhandled error", False,
                     f"{type(exc).__name__}: {exc}")

    # ---- summary ----------------------------------------------------------
    print("\n" + "=" * 72)
    print(f"  {check.summary()}")
    for name, _, detail in check.failed:
        print(f"    FAILED: {name}" + (f" - {detail}" if detail else ""))
    print("=" * 72)

    if keep or workdir:
        print(f"\nArtifacts kept in {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
        print("\nWorking directory removed (pass --keep to retain it).")

    return 1 if check.failed else 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description=f"{__product_name__} - {__tagline__}",
    )
    parser.add_argument("--version", action="version",
                        version=f"{__product_name__} {__version__}")
    parser.add_argument("--selftest", action="store_true",
                        help="run the headless end-to-end engine check")
    parser.add_argument("--make-media", metavar="DIR",
                        help="build the synthetic test media into DIR and exit")
    parser.add_argument("--workdir", metavar="DIR",
                        help="directory for self-test artifacts (implies --keep)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the self-test working directory")

    args = parser.parse_args(argv)

    if args.make_media:
        from tools.make_test_media import build_all

        destination = Path(args.make_media)
        manifest = build_all(destination)
        print(f"\nTest media written to {destination}")
        print(f"Manifest: {destination / 'manifest.json'}")
        del manifest
        return 0

    if args.selftest:
        return _selftest(Path(args.workdir) if args.workdir else None, args.keep)

    try:
        from sanctum.gui.app import run as run_gui
    except ImportError as exc:
        print(
            f"The desktop interface needs PyQt6, which is not installed ({exc}).\n"
            f"Install it with:  pip install PyQt6\n"
            f"Or run the headless check:  python run.py --selftest",
            file=sys.stderr,
        )
        return 2
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
