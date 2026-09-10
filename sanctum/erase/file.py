"""
Secure File & Folder Eraser.

Selective deletion is a different problem from whole-drive sanitization, and a
harder one. Deleting a file does not erase its bytes - it removes a directory
entry and marks the clusters as free. The data remains until something else
happens to overwrite that space, and the *metadata* (filename, timestamps,
size) frequently survives in the filesystem's own journal or table.

This module attacks both:

1. **Content** - overwrite the file's data in place, in full, before unlinking.
2. **Metadata** - rename the file to a randomly generated name of identical
   length before deletion, so the original filename no longer sits in a
   directory entry; truncate to zero so the size is uninformative; then unlink.
3. **Residual traces** - :meth:`FileEraser.wipe_free_space` fills the volume's
   unallocated space with pattern data and then deletes it, overwriting whatever
   deleted-file content was still sitting in free clusters.

Honest limitation, stated in the UI and in every report: filesystem journaling
(NTFS ``$LogFile``/``$UsnJrnl``, ext3/4 ``journal``) and NTFS MFT records can
retain filename fragments outside our reach from user space. A rename reduces
but does not eliminate this. Only full-media sanitization, or a platform tool
that operates on the journal directly, removes it completely.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

from sanctum.config import CHUNK_SIZE, IS_WINDOWS, SafetyPolicy
from sanctum.core import hashing
from sanctum.core.audit import AuditCategory, AuditChain, AuditOutcome
from sanctum.core.progress import CancelToken, OperationCancelled, ProgressReporter, ProgressUpdate
from sanctum.core.standards import EraseStandard, PassSpec, PatternKind, get_standard
from sanctum.core.targets import (
    SafetyViolation,
    is_filesystem_root,
    is_inside_sanctum_home,
    is_os_directory,
)

#: Alternate data streams that commonly carry provenance on Windows. Deleting
#: the file removes its streams, but naming them lets the report show what was
#: cleansed.
COMMON_WINDOWS_ADS = (
    "Zone.Identifier",
    "SmartScreen",
    "SummaryInformation",
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
)

#: Filesystem journal files a report should mention as out of reach.
_JOURNAL_NOTE = (
    "Filesystem journals and table records (NTFS $UsnJrnl/$LogFile/MFT, "
    "ext3/4 journal) may retain filename and timestamp fragments outside "
    "user-space reach. Use whole-media sanitization to remove these."
)

#: Bytes per filler file during a free-space sweep. The sweep writes many files
#: of this size rather than one huge one: a single file large enough to fill a
#: multi-gigabyte volume would exceed FAT32's 4 GiB per-file ceiling - and a USB
#: stick is the most likely place this runs - so the sweep would stop early
#: having written a fraction of the free space while reporting success. Many
#: moderate files also claim free space that is fragmented into pieces smaller
#: than one large extent would need, which a single allocation cannot.
_FILL_FILE_BYTES = 16 * 1024 * 1024


@dataclass
class FileEraseResult:
    """Outcome of deleting one file."""

    path: str
    success: bool = False
    dry_run: bool = False
    cancelled: bool = False
    size_bytes: int = 0
    passes_executed: int = 0
    bytes_overwritten: int = 0
    verified: bool | None = None
    renamed_to: str = ""
    metadata_actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    elapsed_seconds: float = 0.0

    def headline(self) -> str:
        if self.dry_run:
            return "Dry run - file untouched"
        if self.cancelled:
            return "CANCELLED mid-erasure - file may be partially overwritten"
        if self.error:
            return f"FAILED: {self.error}"
        if self.verified is False:
            return "Deleted, but post-deletion verification failed"
        return "Securely deleted"

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "success": self.success,
            "dry_run": self.dry_run,
            "cancelled": self.cancelled,
            "headline": self.headline(),
            "size_bytes": self.size_bytes,
            "passes_executed": self.passes_executed,
            "bytes_overwritten": self.bytes_overwritten,
            "verified": self.verified,
            "renamed_to": self.renamed_to,
            "metadata_actions": self.metadata_actions,
            "warnings": self.warnings,
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


@dataclass
class FileEraseBatchResult:
    """Aggregate outcome across many paths."""

    results: list[FileEraseResult] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    #: How many paths the operator asked to delete. Distinct from ``total``,
    #: which counts only the paths actually attempted: a cancelled batch has
    #: fewer results than it had targets, and reporting "3/3 removed" for a run
    #: that was told to delete 100 files would be a false record of success.
    planned: int = 0
    cancelled: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def not_attempted(self) -> int:
        """Targets the run never reached because it was stopped."""
        return max(0, self.planned - self.total)

    @property
    def succeeded(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.success and not r.dry_run)

    @property
    def total_bytes(self) -> int:
        return sum(r.bytes_overwritten for r in self.results)

    def headline(self) -> str:
        base = (
            f"{self.succeeded}/{self.total} removed, "
            f"{hashing.human_bytes(self.total_bytes)} overwritten"
        )
        if self.cancelled:
            return (
                f"CANCELLED - {base}; {self.not_attempted} of {self.planned} "
                "path(s) were never attempted"
            )
        return base

    def as_dict(self) -> dict:
        return {
            "operation": "file_erase",
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "planned": self.planned,
            "not_attempted": self.not_attempted,
            "cancelled": self.cancelled,
            "headline": self.headline(),
            "warnings": self.warnings,
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "total_bytes_overwritten": self.total_bytes,
            "results": [r.as_dict() for r in self.results],
        }


@dataclass
class FreeSpaceResult:
    """Outcome of a free-space sanitization sweep."""

    root: str
    success: bool = False
    passes_executed: int = 0
    bytes_written: int = 0
    files_created: int = 0
    free_bytes_start: int = 0
    dry_run: bool = False
    cancelled: bool = False
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def headline(self) -> str:
        if self.dry_run:
            return "Dry run - free space untouched"
        if self.cancelled:
            return (
                f"CANCELLED after overwriting "
                f"{hashing.human_bytes(self.bytes_written)} of free space"
            )
        if self.error:
            return f"FAILED: {self.error}"
        return f"Overwrote {hashing.human_bytes(self.bytes_written)} of free space"

    def as_dict(self) -> dict:
        return {
            "operation": "free_space_wipe",
            "root": self.root,
            "success": self.success,
            "dry_run": self.dry_run,
            "cancelled": self.cancelled,
            "headline": self.headline(),
            "passes_executed": self.passes_executed,
            "bytes_written": self.bytes_written,
            "files_created": self.files_created,
            "free_bytes_start": self.free_bytes_start,
            "warnings": self.warnings,
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def _random_name(length: int, rng_bytes: Callable[[int], bytes] = os.urandom) -> str:
    """
    A random filename of exactly ``length`` characters.

    The extension is deliberately not preserved: an extension is metadata, and
    the point of the rename is to leave nothing in the directory entry that
    describes what the file was. Length is preserved because the entry's name
    field would otherwise visibly change in size.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    raw = rng_bytes(length)
    return "".join(alphabet[b % len(alphabet)] for b in raw[:length])


class FileEraser:
    """
    Selective secure deletion for files and directory trees.

    Example - deleting a single file with the 3-pass scheme::

        eraser = FileEraser(audit)
        result = eraser.secure_delete_file("secrets.txt", "dod3",
                                           policy=SafetyPolicy(dry_run=False))
    """

    def __init__(self, audit: AuditChain | None = None) -> None:
        self.audit = audit

    # -- single file -------------------------------------------------------

    def secure_delete_file(
        self,
        path: str | os.PathLike[str],
        standard: EraseStandard | str = "dod3",
        *,
        policy: SafetyPolicy | None = None,
        progress: Callable[[ProgressUpdate], None] | None = None,
        cancel: CancelToken | None = None,
        cleanse_metadata: bool = True,
    ) -> FileEraseResult:
        """Overwrite a file's contents, cleanse its metadata, then unlink it."""
        policy = policy or SafetyPolicy()
        if isinstance(standard, str):
            standard = get_standard(standard)

        path = Path(path)
        result = FileEraseResult(path=str(path), dry_run=policy.dry_run)
        cancel = cancel or CancelToken()
        reporter = ProgressReporter(progress, min_interval=0.1)

        try:
            self._validate_file_target(path, policy)
        except SafetyViolation as violation:
            result.error = violation.reason
            self._audit(AuditCategory.SAFETY, "file_erase_refused", AuditOutcome.DENIED,
                        str(path), {"reason": violation.reason})
            return result

        try:
            info = path.stat()
            result.size_bytes = info.st_size
        except OSError as exc:
            result.error = f"cannot stat file: {exc}"
            return result

        if policy.dry_run:
            result.success = True
            result.warnings.append(
                f"Would overwrite {hashing.human_bytes(result.size_bytes)} with "
                f"{standard.pass_count} pass(es) [{standard.name}], rename, truncate and unlink."
            )
            return result

        self._audit(AuditCategory.ERASE, "file_erase_started", AuditOutcome.INFO, str(path),
                    {"standard": standard.id, "size_bytes": result.size_bytes,
                     "passes": standard.pass_count})

        started = time.monotonic()
        try:
            self._make_writable(path)

            # 1. Overwrite content in place.
            if result.size_bytes > 0:
                result.bytes_overwritten = self._overwrite_in_place(
                    path, standard.effective_passes(None), reporter, cancel
                )
                result.passes_executed = standard.pass_count

            # 2. Cleanse metadata: rename to an uninformative name of the same
            #    length, then truncate so the size reveals nothing.
            if cleanse_metadata:
                renamed = self._cleanse_name(path)
                if renamed:
                    result.renamed_to = str(renamed)
                    result.metadata_actions.append(
                        f"Renamed to '{Path(renamed).name}' (same length) to clear the "
                        "original filename from the directory entry"
                    )
                    path = renamed
                self._truncate(path)
                result.metadata_actions.append("Truncated to zero length before unlink")

            self._delete_alternate_streams(path, result)

            # 3. Unlink.
            os.remove(path)
            result.metadata_actions.append("Unlinked directory entry")

            # 4. Post-condition: the path must be gone.
            result.verified = not path.exists()
            result.success = result.verified

            if cleanse_metadata:
                result.warnings.append(_JOURNAL_NOTE)

        except OperationCancelled:
            result.cancelled = True
            result.error = "Cancelled by operator"
        except OSError as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.elapsed_seconds = time.monotonic() - started
            outcome = AuditOutcome.SUCCESS if result.success else AuditOutcome.FAILURE
            self._audit(AuditCategory.ERASE, "file_erase_finished", outcome, str(path),
                        {"headline": result.headline(), "success": result.success,
                         "cancelled": result.cancelled,
                         "bytes_overwritten": result.bytes_overwritten,
                         "verified": result.verified, "error": result.error})

        return result

    # -- batch -------------------------------------------------------------

    def secure_delete_paths(
        self,
        paths: Iterable[str | os.PathLike[str]],
        standard: EraseStandard | str = "dod3",
        *,
        policy: SafetyPolicy | None = None,
        recursive: bool = True,
        progress: Callable[[ProgressUpdate], None] | None = None,
        cancel: CancelToken | None = None,
    ) -> FileEraseBatchResult:
        """
        Delete many files and/or folder trees.

        Directories are expanded depth-first so that a folder's contents are
        overwritten before the directory entries themselves disappear - deleting
        the tree first would leave the files unreachable and therefore
        un-overwritable.
        """
        policy = policy or SafetyPolicy()
        cancel = cancel or CancelToken()
        batch = FileEraseBatchResult(
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds")
        )

        targets = self._expand(paths, recursive)
        total = len(targets)
        batch.planned = total
        reporter = ProgressReporter(progress)

        if total == 0:
            batch.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return batch

        # A batch cancelled before it began raises rather than returning. The
        # ``except`` below turns a mid-flight cancellation into a partial result,
        # which is right when work has already happened and the operator needs to
        # know how far it got. Here nothing has happened: a returned batch would
        # be empty, and an empty result object reads as "the batch ran and did
        # nothing" - the caller cannot tell it apart from the zero-target case
        # above, which is a legitimate no-op. The two must not look the same.
        cancel.check()

        reporter.start("Deleting", total)
        directories: list[Path] = []

        try:
            for index, item in enumerate(targets, start=1):
                cancel.check()
                if item.is_dir():
                    directories.append(item)
                    continue
                result = self.secure_delete_file(
                    item, standard, policy=policy, cancel=cancel, cleanse_metadata=True
                )
                batch.results.append(result)
                reporter.update("Deleting", index, total, item.name)

            # Directories last, deepest first.
            for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
                cancel.check()
                batch.results.append(self._remove_directory(directory, policy))
        except OperationCancelled:
            # The batch stops where it stopped. Recording it as a completed run
            # would claim deletion of files the tool never touched, so the
            # shortfall is carried on the result and into the audit entry.
            batch.cancelled = True
            batch.warnings.append(
                f"Stopped by the operator after {batch.total} of {total} path(s). "
                f"{batch.not_attempted} path(s) were never attempted and remain "
                "on the media."
            )

        reporter.finish("Deleting", total, batch.headline())
        batch.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._audit(AuditCategory.ERASE, "file_erase_batch_finished",
                    AuditOutcome.SUCCESS if (batch.failed == 0 and not batch.cancelled)
                    else AuditOutcome.FAILURE,
                    f"{total} paths",
                    {"succeeded": batch.succeeded, "failed": batch.failed,
                     "planned": total, "not_attempted": batch.not_attempted,
                     "cancelled": batch.cancelled,
                     "bytes_overwritten": batch.total_bytes,
                     "standard": get_standard(standard).id if isinstance(standard, str) else standard.id})
        return batch

    # -- free space --------------------------------------------------------

    def wipe_free_space(
        self,
        root: str | os.PathLike[str],
        standard: EraseStandard | str = "random1",
        *,
        policy: SafetyPolicy | None = None,
        fill_fraction: float = 0.98,
        max_bytes: int | None = None,
        progress: Callable[[ProgressUpdate], None] | None = None,
        cancel: CancelToken | None = None,
    ) -> FreeSpaceResult:
        """
        Overwrite unallocated space on the volume containing ``root``.

        This is the step that actually removes deleted-file residue: those bytes
        are still physically present in free clusters until something claims
        them. ``fill_fraction`` leaves a small margin so the filesystem does not
        become unusable if the sweep is interrupted.

        ``max_bytes`` bounds the sweep. By default there is no bound, because a
        free-space scrub is *supposed* to consume the volume's free space - but
        on a system volume that is an availability risk (no room left for the
        page file, logs or temp files), so callers that need a bounded scrub can
        say so.
        """
        policy = policy or SafetyPolicy()
        if isinstance(standard, str):
            standard = get_standard(standard)
        cancel = cancel or CancelToken()
        reporter = ProgressReporter(progress)

        root = Path(root)
        result = FreeSpaceResult(root=str(root), dry_run=policy.dry_run)

        try:
            # Free-space sweeping writes only to *unallocated* clusters, so it
            # cannot destroy live data. That makes it legitimate on a system
            # volume (the OS is untouched), so the OS-directory guard is
            # deliberately relaxed here - unlike for destructive file deletion.
            self._validate_file_target(
                root, policy, expect_directory=True, check_os_directory=False
            )
        except SafetyViolation as violation:
            result.error = violation.reason
            return result

        try:
            usage = shutil.disk_usage(root)
        except OSError as exc:
            result.error = f"cannot read volume usage: {exc}"
            return result

        result.free_bytes_start = usage.free
        target_bytes = int(usage.free * fill_fraction)
        if max_bytes is not None:
            target_bytes = min(target_bytes, max(0, int(max_bytes)))

        # Filling a volume to the brim is a real risk to whatever else is
        # running on it, so say so before doing it rather than after.
        if target_bytes >= 1024 ** 3:
            result.warnings.append(
                f"This sweep will write up to {hashing.human_bytes(target_bytes)} of "
                f"data to {root}, which may leave the volume with almost no free "
                "space for other programs while it runs."
            )
        if is_filesystem_root(root) or is_os_directory(root):
            result.warnings.append(
                "Target is an operating-system volume. The sweep cannot damage "
                "existing files - it writes only to unallocated clusters - but it "
                "will fill the volume's free space, which can disrupt a running "
                "system. Close other work before starting."
            )

        if policy.dry_run:
            result.success = True
            result.warnings.append(
                f"Would overwrite up to {hashing.human_bytes(target_bytes)} of free "
                f"space on {root} using {standard.name}."
            )
            return result

        self._audit(AuditCategory.ERASE, "free_space_wipe_started", AuditOutcome.INFO, str(root),
                    {"standard": standard.id, "free_bytes": usage.free,
                     "target_bytes": target_bytes})

        started = time.monotonic()
        session_dir = root / f".sanctum_freespace_{os.getpid()}"
        try:
            session_dir.mkdir(exist_ok=True)
            reporter.start("Free space sweep", target_bytes)

            for pass_index, pass_spec in enumerate(standard.effective_passes(False), start=1):
                cancel.check()
                # Each earlier pass's filler files must be released before this
                # pass runs. Without this the volume is already full when pass 2
                # starts, so passes 2..N write almost nothing while the result
                # reports "3 passes executed" - the sweep would claim a
                # multi-pass standard having overwritten the free space once.
                # The standard's protection comes from every pass writing over
                # the same clusters in turn, which requires the space back.
                self._clear_fillers(session_dir)
                written, created = self._fill_once(
                    session_dir, pass_spec, target_bytes, reporter, cancel, pass_index
                )
                result.bytes_written += written
                result.files_created += created
                result.passes_executed = pass_index

            result.success = True
            result.warnings.append(
                "Free-space sweeping reduces recoverable residue on this volume but "
                "does not sanitize slack space inside existing files, nor journal "
                "records. For full assurance use whole-media sanitization."
            )
        except OperationCancelled:
            result.cancelled = True
            result.error = "Cancelled by operator"
            result.warnings.append(
                "The sweep stopped early. Free space written before the stop "
                "point is sanitized; the remainder is not, so this volume must "
                "not be reported as fully swept."
            )
        except OSError as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            # Always remove our scratch files - leaving them would be worse than
            # not running the sweep at all.
            self._cleanup_session(session_dir)
            result.elapsed_seconds = time.monotonic() - started
            self._audit(AuditCategory.ERASE, "free_space_wipe_finished",
                        AuditOutcome.SUCCESS if result.success else AuditOutcome.FAILURE,
                        str(root),
                        {"bytes_written": result.bytes_written,
                         "files_created": result.files_created,
                         "passes": result.passes_executed,
                         "cancelled": result.cancelled,
                         "error": result.error})

        return result

    # -- internals ---------------------------------------------------------

    def _validate_file_target(
        self,
        path: Path,
        policy: SafetyPolicy,
        *,
        expect_directory: bool = False,
        check_os_directory: bool = True,
    ) -> None:
        if not path.exists():
            raise SafetyViolation("Path does not exist", str(path))
        if is_inside_sanctum_home(path):
            raise SafetyViolation(
                "Refusing to target SANCTUM's own data directory", str(path)
            )
        if is_filesystem_root(path):
            raise SafetyViolation(
                "Refusing to treat a whole drive/filesystem root as a file-tree "
                "operation - use the Drive Eraser module for whole-media work",
                str(path),
            )
        if check_os_directory and is_os_directory(path):
            raise SafetyViolation(
                "Refusing to target an operating-system directory", str(path)
            )
        if expect_directory and not path.is_dir():
            raise SafetyViolation("Expected a directory", str(path))
        if not os.access(path, os.W_OK):
            raise SafetyViolation("Path is not writable by this process", str(path))

    def _make_writable(self, path: Path) -> None:
        """Clear the read-only attribute so an overwrite can proceed."""
        try:
            mode = path.stat().st_mode
            os.chmod(path, mode | stat.S_IWRITE)
        except OSError:
            pass

    def _overwrite_in_place(
        self,
        path: Path,
        passes: Sequence[PassSpec],
        reporter: ProgressReporter,
        cancel: CancelToken,
    ) -> int:
        """Overwrite the file's bytes without altering its length mid-pass."""
        total = path.stat().st_size
        written_total = 0

        with open(path, "r+b") as handle:
            for index, pass_spec in enumerate(passes, start=1):
                cancel.check()
                phase = f"Pass {index}/{len(passes)} [{pass_spec.describe()}] {path.name}"
                reporter.start(phase, total)
                handle.seek(0)
                written = 0
                # Sized to whole pattern periods so a repeating sequence keeps
                # its phase across a file larger than one chunk.
                chunk = (
                    CHUNK_SIZE if pass_spec.kind is PatternKind.RANDOM
                    else pass_spec.aligned_size(CHUNK_SIZE)
                )
                static_buffer = (
                    None if pass_spec.kind is PatternKind.RANDOM
                    else pass_spec.build_buffer(chunk)
                )
                while written < total:
                    cancel.check()
                    remaining = total - written
                    size = min(chunk, remaining)
                    if pass_spec.kind is PatternKind.RANDOM:
                        payload = pass_spec.build_buffer(size)
                    else:
                        payload = static_buffer if size >= len(static_buffer) else static_buffer[:size]  # type: ignore[index]
                    handle.write(payload)
                    written += len(payload)
                    reporter.update(phase, written, total)
                handle.flush()
                os.fsync(handle.fileno())
                written_total += written

        return written_total

    def _cleanse_name(self, path: Path) -> Path | None:
        """
        Rename the file to a random name of identical length.

        Length is preserved so the directory entry's name field does not visibly
        change in size, and the extension is dropped because it is itself
        metadata. Returns the new path, or None if the rename did not apply.
        """
        try:
            stem_len = len(path.name)
            if stem_len == 0:
                return None
            for _ in range(16):
                candidate = path.with_name(_random_name(stem_len))
                if not candidate.exists():
                    os.rename(path, candidate)
                    return candidate
        except OSError:
            return None
        return None

    def _truncate(self, path: Path) -> None:
        try:
            with open(path, "r+b") as handle:
                handle.truncate(0)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            pass

    def _delete_alternate_streams(self, path: Path, result: FileEraseResult) -> None:
        """Best-effort removal of Windows alternate data streams."""
        if not IS_WINDOWS:
            return
        for stream in COMMON_WINDOWS_ADS:
            candidate = f"{path}:{stream}"
            if os.path.exists(candidate):
                try:
                    os.remove(candidate)
                    result.metadata_actions.append(f"Removed alternate data stream '{stream}'")
                except OSError:
                    result.warnings.append(
                        f"Could not remove alternate data stream '{stream}'"
                    )

    def _remove_directory(self, directory: Path, policy: SafetyPolicy) -> FileEraseResult:
        """Rename then remove a now-empty directory."""
        result = FileEraseResult(path=str(directory), dry_run=policy.dry_run)
        if policy.dry_run:
            result.success = True
            return result
        try:
            if not directory.exists():
                result.success = True
                return result
            # Only remove if empty - never recursively delete here, because
            # anything left means the overwrite phase did not cover it.
            remaining = list(directory.iterdir())
            if remaining:
                result.error = f"directory not empty ({len(remaining)} entries remain)"
                return result
            renamed = self._cleanse_name(directory)
            target = renamed or directory
            os.rmdir(target)
            result.renamed_to = str(renamed) if renamed else ""
            result.success = not target.exists()
            result.metadata_actions.append("Removed empty directory entry")
        except OSError as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    def _expand(self, paths: Iterable[str | os.PathLike[str]], recursive: bool) -> list[Path]:
        """Flatten inputs into an ordered list, files before their directories."""
        collected: list[Path] = []
        for raw in paths:
            path = Path(raw)
            if path.is_dir():
                if recursive:
                    for child in sorted(path.rglob("*")):
                        collected.append(child)
                    # The directory itself, after its contents. ``rglob("*")``
                    # yields everything *inside* the tree and never the tree, so
                    # without this the batch deleted every file a folder held and
                    # left the folder standing - reporting success for an
                    # operation whose stated purpose was to remove the tree.
                    collected.append(path)
                else:
                    collected.extend(sorted(path.iterdir()))
            else:
                collected.append(path)
        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique: list[Path] = []
        for item in collected:
            key = str(item)
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _fill_once(
        self,
        session_dir: Path,
        pass_spec: PassSpec,
        target_bytes: int,
        reporter: ProgressReporter,
        cancel: CancelToken,
        pass_index: int,
    ) -> tuple[int, int]:
        """
        Write one pass of filler files until the volume is nearly full.

        Running out of space is expected, not an error - the sweep is *supposed*
        to consume all free space. ENOSPC ends the pass cleanly.

        The outer loop creates one file per iteration and the inner loop fills
        that file. Writing the whole budget into the first file would create a
        single multi-gigabyte file, which FAT32 refuses past 4 GiB - so on a USB
        stick the sweep would silently stop a fraction of the way in and still
        report success. ``_FILL_FILE_BYTES`` keeps every file well inside that
        ceiling and lets the loop keep claiming whatever free space is left.
        """
        written = 0
        created = 0
        chunk = (
            None if pass_spec.kind is PatternKind.RANDOM
            else pass_spec.build_buffer(pass_spec.aligned_size(CHUNK_SIZE))
        )

        while written < target_bytes:
            cancel.check()
            filler = session_dir / f"f{pass_index}_{created:05d}.tmp"
            # This file's share of what is left, capped so the volume is filled
            # by many files rather than one.
            file_budget = min(_FILL_FILE_BYTES, target_bytes - written)
            file_written = 0
            try:
                with open(filler, "wb") as handle:
                    while file_written < file_budget:
                        cancel.check()
                        size = min(CHUNK_SIZE, file_budget - file_written)
                        payload = pass_spec.build_buffer(size) if chunk is None else chunk[:size]
                        handle.write(payload)
                        file_written += len(payload)
                        written += len(payload)
                        reporter.update(f"Free space pass {pass_index}", written, target_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
                created += 1
            except OSError:
                # The volume is full, or the file could not be created. Both end
                # this pass: ENOSPC (errno 28, or 112 on Windows) is the expected
                # terminus of a sweep, and anything else means continuing would
                # only thrash. What was written is counted and reported.
                break
        return written, created

    def _clear_fillers(self, session_dir: Path) -> None:
        """
        Release the filler files a previous pass wrote.

        A free-space sweep works by consuming the volume's free space. Once one
        pass has done that there is no space left for the next, so the previous
        pass's fillers are deleted first and the clusters are claimed again -
        this time with the next pass's pattern. Failures are ignored: a file
        that cannot be removed simply means less space is reclaimed for this
        pass, and the byte count reported is what was actually written.
        """
        try:
            entries = list(session_dir.iterdir())
        except OSError:
            return
        for item in entries:
            try:
                if item.is_file():
                    item.unlink()
            except OSError:
                pass

    def _cleanup_session(self, session_dir: Path) -> None:
        try:
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
        except OSError:
            pass

    def _audit(
        self,
        category: AuditCategory,
        action: str,
        outcome: AuditOutcome,
        target: str,
        details: dict,
    ) -> None:
        if self.audit is not None:
            self.audit.log(category, action, outcome=outcome, target=target, details=details)
