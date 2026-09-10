"""
Build the test environments SANCTUM is demonstrated and validated against.

Produces four artefacts under the output directory:

``deleted_files.img``
    A FAT16 volume holding a realistic mixed corpus. Some files are deleted
    with their FAT chains freed, so their bytes sit in unallocated space
    reachable only by content-based carving.

``fragmented.img``
    A FAT16 volume where a JPEG and a PDF are stored across deliberately
    non-contiguous cluster chains, so contiguous carving recovers only the
    first fragment and the reassembly path has something real to solve.

``wiped.img``
    A volume sanitized with a chosen standard - the fixture for verifying that
    verification actually detects what it claims to.

``scratch.img``
    A blank writable image, so the Drive Eraser module can be demonstrated
    end-to-end without touching real hardware.

A ``manifest.json`` records the ground truth (cluster chains and SHA-256
digests) so the test suite can measure recovery accuracy rather than merely
asserting that something was found.

Run directly::

    python -m tools.make_test_media --output testdata
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Allow direct execution as a script.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.fat16 import Fat16Image, Fat16Params
from tools.sample_files import (
    large_payload,
    make_bmp,
    make_docx,
    make_gif,
    make_html,
    make_jpeg,
    make_pdf,
    make_png,
    make_sqlite,
    make_text,
    make_zip,
    sample_catalogue,
)

#: A corpus for the deleted-files scenario: (filename, generator, delete?)
DELETED_SCENARIO_FILES = (
    ("Photo_Holiday.JPG", lambda: make_jpeg(64, 64), True),
    ("Screenshot.png", lambda: make_png(48, 48, (200, 60, 60)), True),
    ("Diagram.GIF", lambda: make_gif(32, 32), True),
    ("Chart.bmp", lambda: make_bmp(32, 32), True),
    ("Contract.pdf", lambda: make_pdf("Service Agreement", "Signed copy - confidential."), True),
    ("Notes.docx", lambda: make_docx("Project falcon - internal notes."), True),
    ("Archive.zip", lambda: make_zip({"readme.txt": b"planted archive member\n"}), True),
    ("Credentials.db", make_sqlite, True),
    ("Report.html", lambda: make_html("Recovered Page"), True),
    ("Statement.txt", lambda: make_text(), True),
    # Kept allocated, to prove the carver can distinguish nothing and that a
    # whole-image scan really does surface live files too.
    ("Live_Photo.jpg", lambda: make_jpeg(64, 64), False),
    ("Live_Document.pdf", lambda: make_pdf("Live Document", "Still allocated."), False),
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(name: str, data: bytes, entry, deleted: bool, chain: list[int]) -> dict:
    return {
        "name": name,
        "size": len(data),
        "sha256": _digest(data),
        "first_cluster": entry.first_cluster if entry else 0,
        "chain": chain,
        "deleted": deleted,
    }


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

def build_deleted_files_image(output_dir: Path) -> tuple[Path, dict]:
    """
    A volume with a mixed corpus, most of it deleted.

    Every file is written *before* any of them is deleted. Deleting as we go
    looked equivalent and is not: the allocator hands out the lowest free run,
    so the moment a file's clusters were freed the next file was written
    straight over them. The result was a fixture whose "deleted" files had been
    destroyed by each other - only the first survivor's bytes were still in the
    image, and a recovery-accuracy measurement against it would have been
    measuring nothing. Writing everything first leaves each file's data in
    unallocated space exactly as a real deletion would.
    """
    image = Fat16Image(Fat16Params(total_sectors=32768)).format()
    records: list[dict] = []

    for filename, generator, should_delete in DELETED_SCENARIO_FILES:
        data = generator()
        chain = image._alloc_contiguous(
            (len(data) + image.params.cluster_size - 1) // image.params.cluster_size
        )
        entry = image.write_file(filename, data, chain=chain)
        records.append(_record(filename, data, entry, should_delete, chain))

    for record in records:
        if record["deleted"]:
            image.delete(record["name"], free_clusters=True)

    path = image.save(output_dir / "deleted_files.img")
    return path, {
        "image": path.name,
        "scenario": "deleted_files",
        "parameters": image.params.as_dict(),
        "files": records,
        "recoverable": [r for r in records if r["deleted"]],
        "expected_sha256": [r["sha256"] for r in records if r["deleted"]],
    }


def build_fragmented_image(output_dir: Path) -> tuple[Path, dict]:
    """
    A volume where two files are stored across non-contiguous cluster chains.

    The chains are chosen to interleave, so a contiguous scan of the first
    fragment stops well short of the true file size.
    """
    image = Fat16Image(Fat16Params(total_sectors=32768)).format()
    records: list[dict] = []
    cluster_size = image.params.cluster_size

    # Some ordinary files first, to occupy the start of the data region.
    for filename, generator in (
        ("Readme.txt", lambda: make_text(20)),
        ("Intro.pdf", lambda: make_pdf("Intro", "Ordinary file.")),
    ):
        data = generator()
        entry = image.write_file(filename, data)
        records.append(_record(filename, data, entry, False, [entry.first_cluster]))

    # A large, deliberately fragmented JPEG: clusters 20-21, then 60-61, then 100.
    photo = make_jpeg(96, 96)
    # Pad so the payload genuinely spans several clusters.
    photo = photo + large_payload(cluster_size * 4 - len(photo) % cluster_size + cluster_size)
    photo_chain = [20, 21, 60, 61, 100]
    needed = (len(photo) + cluster_size - 1) // cluster_size
    photo_chain = photo_chain[:needed] if needed <= len(photo_chain) else photo_chain
    entry = image.write_file("Fragmented.jpg", photo, chain=photo_chain)
    records.append(_record("Fragmented.jpg", photo, entry, False, photo_chain))

    # A fragmented PDF stored around it.
    document = make_pdf("Fragmented Report", "Stored across non-contiguous clusters." * 60)
    pdf_chain = [40, 41, 42, 120, 121]
    needed = (len(document) + cluster_size - 1) // cluster_size
    pdf_chain = pdf_chain[:needed] if needed <= len(pdf_chain) else pdf_chain
    entry = image.write_file("Fragmented.pdf", document, chain=pdf_chain)
    records.append(_record("Fragmented.pdf", document, entry, False, pdf_chain))

    path = image.save(output_dir / "fragmented.img")
    return path, {
        "image": path.name,
        "scenario": "fragmented",
        "parameters": image.params.as_dict(),
        "files": records,
        "fragmented": [r for r in records if len(r["chain"]) > 1],
    }


def build_wiped_image(output_dir: Path, standard_id: str = "dod3") -> tuple[Path, dict]:
    """
    A sanitized volume, for exercising the erasure and verification path.

    Built by running the real DriveEraser over a freshly populated image, so the
    fixture is produced by the same code under test rather than by a shortcut.
    """
    from sanctum.config import SafetyPolicy
    from sanctum.core.audit import AuditChain
    from sanctum.core.targets import EraseTarget, TargetKind, MediaType
    from sanctum.erase import DriveEraser

    image = Fat16Image(Fat16Params(total_sectors=8192)).format()
    for filename, generator in (
        ("Secret1.txt", lambda: make_text(60)),
        ("Secret2.pdf", lambda: make_pdf("Secret", "Sensitive.")),
    ):
        image.write_file(filename, generator())

    path = image.save(output_dir / "wiped.img")
    size = path.stat().st_size

    target = EraseTarget(
        path=str(path),
        kind=TargetKind.DISK_IMAGE,
        size_bytes=size,
        display_name="wiped.img",
        media_type=MediaType.VIRTUAL,
    )
    audit = AuditChain(output_dir / "wiped_audit.jsonl")
    result = DriveEraser(audit).run(
        target,
        standard_id,
        policy=SafetyPolicy(dry_run=False, require_confirmation_token=False),
    )

    return path, {
        "image": path.name,
        "scenario": "wiped",
        "standard": standard_id,
        "success": result.success,
        "verified": result.verified,
        "headline": result.headline(),
        "passes": [p.as_dict() for p in result.passes],
    }


def build_scratch_image(output_dir: Path, megabytes: int = 8) -> tuple[Path, dict]:
    """A blank writable image for demonstrating the Drive Eraser."""
    sectors = (megabytes * 1024 * 1024) // 512
    image = Fat16Image(Fat16Params(total_sectors=sectors)).format()
    path = image.save(output_dir / "scratch.img")
    return path, {
        "image": path.name,
        "scenario": "scratch",
        "size_bytes": path.stat().st_size,
        "note": "Blank volume; target this with the Drive Eraser for a safe demo.",
    }


def build_evidence_folder(output_dir: Path) -> tuple[Path, dict]:
    """
    A directory of real files for the File & Folder Eraser module.

    Includes a nested tree and a set of duplicate copies to delete, so batch
    operations and per-file reporting both have something to show.
    """
    root = output_dir / "evidence_files"
    root.mkdir(parents=True, exist_ok=True)
    (root / "nested" / "deeper").mkdir(parents=True, exist_ok=True)

    planted: list[dict] = []
    layout = {
        "statement.txt": lambda: make_text(30),
        "contract.pdf": lambda: make_pdf("Contract", "To be securely destroyed."),
        "photo.jpg": lambda: make_jpeg(64, 64),
        "records.db": make_sqlite,
        "nested/notes.docx": lambda: make_docx("Nested note."),
        "nested/deeper/archive.zip": lambda: make_zip({"a.txt": b"nested member\n"}),
    }
    for relative, generator in layout.items():
        data = generator()
        destination = root / relative
        destination.write_bytes(data)
        planted.append({"path": relative, "size": len(data), "sha256": _digest(data)})

    return root, {
        "scenario": "evidence_files",
        "root": str(root),
        "files": planted,
    }


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def build_all(output_dir: Path, quiet: bool = False) -> dict:
    """Build every fixture and write the manifest."""
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"output_dir": str(output_dir), "scenarios": {}}

    def announce(message: str) -> None:
        if not quiet:
            print(f"  {message}")

    announce("Building SANCTUM test media...")

    path, info = build_deleted_files_image(output_dir)
    manifest["scenarios"]["deleted_files"] = info
    announce(f"{path.name}  ({path.stat().st_size:,} bytes, "
             f"{len(info['recoverable'])} deleted file(s) planted)")

    path, info = build_fragmented_image(output_dir)
    manifest["scenarios"]["fragmented"] = info
    announce(f"{path.name}  ({path.stat().st_size:,} bytes, "
             f"{len(info['fragmented'])} fragmented file(s))")

    path, info = build_wiped_image(output_dir)
    manifest["scenarios"]["wiped"] = info
    announce(f"{path.name}  ({path.stat().st_size:,} bytes, wiped with {info['standard']}: {info['headline']})")

    path, info = build_scratch_image(output_dir)
    manifest["scenarios"]["scratch"] = info
    announce(f"{path.name}  ({info['size_bytes']:,} bytes, blank)")

    path, info = build_evidence_folder(output_dir)
    manifest["scenarios"]["evidence_files"] = info
    announce(f"{path.name}/  ({len(info['files'])} files for the File Eraser)")

    catalogue = sample_catalogue()
    manifest["sample_catalogue"] = {
        name: {"size": len(data), "sha256": _digest(data)}
        for name, data in catalogue.items()
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    announce(f"manifest.json written")

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build SANCTUM's demonstration and validation media."
    )
    parser.add_argument(
        "--output",
        default="testdata",
        help="Directory to write fixtures into (default: testdata)",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    manifest = build_all(Path(args.output), quiet=args.quiet)
    if not args.quiet:
        total = sum(
            (Path(args.output) / s["image"]).stat().st_size
            for s in manifest["scenarios"].values()
            if "image" in s
        )
        print(f"\nDone. {len(manifest['scenarios'])} scenarios, {total:,} bytes of test media.")
        print(f"Manifest: {Path(args.output) / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
