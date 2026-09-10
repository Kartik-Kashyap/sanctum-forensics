"""
Optional native forensic backend (pytsk3 / pyewf).

Pure-Python carving works from content alone, which is powerful but blind: it
cannot tell an allocated file from a deleted one, cannot read a file's original
name or timestamps, and cannot restrict a scan to unallocated space. Those
capabilities need a real filesystem parser.

This module wraps SleuthKit (``pytsk3``) and ``pyewf`` when they are installed,
and reports cleanly when they are not. Nothing else in SANCTUM hard-depends on
them - the carver degrades to its pure-Python path and the UI shows which
capabilities are active. That design is deliberate: the tool must run on any
demo machine, but should be maximally capable where the libraries exist.

Install with::

    pip install pytsk3 pyewf
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# --- optional imports, resolved once ---------------------------------------

try:  # pragma: no cover - presence depends on the host
    import pytsk3  # type: ignore

    HAS_PYTSK3 = True
except ImportError:  # pragma: no cover
    pytsk3 = None  # type: ignore
    HAS_PYTSK3 = False

try:  # pragma: no cover
    import pyewf  # type: ignore

    HAS_PYEWF = True
except ImportError:  # pragma: no cover
    pyewf = None  # type: ignore
    HAS_PYEWF = False


@dataclass
class NativeCapabilities:
    """Which native capabilities are available in this installation."""

    filesystem_parsing: bool = HAS_PYTSK3
    encase_images: bool = HAS_PYEWF

    @property
    def any(self) -> bool:
        return self.filesystem_parsing or self.encase_images

    def summary(self) -> str:
        if not self.any:
            return (
                "Native backend unavailable - using pure-Python carving. "
                "Install pytsk3 and pyewf for filesystem metadata recovery and "
                "E01 image support."
            )
        parts = []
        if self.filesystem_parsing:
            parts.append("SleuthKit filesystem parsing (NTFS/FAT/ext)")
        if self.encase_images:
            parts.append("EnCase E01 image support")
        return "Native backend active: " + "; ".join(parts)

    def as_dict(self) -> dict:
        return {
            "filesystem_parsing": self.filesystem_parsing,
            "encase_images": self.encase_images,
            "summary": self.summary(),
        }


def capabilities() -> NativeCapabilities:
    return NativeCapabilities()


# --------------------------------------------------------------------------
# Image access
# --------------------------------------------------------------------------

class NativeImage:
    """
    Uniform read access over raw and EnCase images.

    E01 support requires the image to be opened through pyewf and then adapted
    to SleuthKit's ``Img_Info`` interface - a small shim that makes the rest of
    the code indifferent to which container format is in play.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._handle = None
        self._img_info = None
        self._is_ewf = False
        self._size = 0

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> "NativeImage":
        if not HAS_PYTSK3:
            raise RuntimeError(
                "pytsk3 is not installed - native image access is unavailable"
            )
        suffix = self.path.suffix.lower()
        if suffix in (".e01", ".ex01") or _looks_like_ewf(self.path):
            if not HAS_PYEWF:
                raise RuntimeError(
                    "This looks like an EnCase image but pyewf is not installed"
                )
            self._open_ewf()
        else:
            self._img_info = pytsk3.Img_Info(str(self.path))
            self._size = self._img_info.get_size()
        return self

    def _open_ewf(self) -> None:
        filenames = pyewf.glob(str(self.path))
        if not filenames:
            raise RuntimeError(f"No E01 segments found for {self.path}")
        handle = pyewf.handle()
        handle.open(filenames)
        self._handle = handle
        self._is_ewf = True
        self._img_info = _EwfImgInfo(handle)
        self._size = handle.get_media_size()

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:  # noqa: BLE001
                pass
            self._handle = None

    def __enter__(self) -> "NativeImage":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # -- access ------------------------------------------------------------

    @property
    def img_info(self):
        if self._img_info is None:
            raise RuntimeError("Image is not open")
        return self._img_info

    @property
    def size(self) -> int:
        return self._size

    @property
    def is_encase(self) -> bool:
        return self._is_ewf

    def read(self, offset: int, size: int) -> bytes:
        return self.img_info.read(offset, size)

    def filesystem(self, offset: int = 0):
        """Open a filesystem at ``offset`` (bytes; 0 for the volume start)."""
        if not HAS_PYTSK3:
            raise RuntimeError("pytsk3 is not installed")
        return pytsk3.FS_Info(self.img_info, offset=offset)


def _looks_like_ewf(path: Path) -> bool:
    """EWF files begin with the EVF signature."""
    try:
        with open(path, "rb") as handle:
            return handle.read(3) == b"EVF"
    except OSError:
        return False


if HAS_PYTSK3:
    class _EwfImgInfo(pytsk3.Img_Info):  # type: ignore[misc]
        """Adapts a pyewf handle to SleuthKit's Img_Info interface."""

        def __init__(self, ewf_handle) -> None:
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self) -> None:
            self._ewf_handle.close()

        def read(self, offset: int, size: int) -> bytes:
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self) -> int:
            return self._ewf_handle.get_media_size()
else:  # pragma: no cover
    _EwfImgInfo = None  # type: ignore


# --------------------------------------------------------------------------
# Filesystem walking
# --------------------------------------------------------------------------

@dataclass
class FsEntry:
    """A file or directory as reported by SleuthKit."""

    name: str
    path: str
    inode: int
    size: int
    allocated: bool
    is_directory: bool = False
    meta_type: str = ""
    modified: str = ""
    accessed: str = ""
    changed: str = ""
    created: str = ""

    @property
    def deleted(self) -> bool:
        return not self.allocated

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "inode": self.inode,
            "size": self.size,
            "allocated": self.allocated,
            "deleted": self.deleted,
            "is_directory": self.is_directory,
            "meta_type": self.meta_type,
            "modified": self.modified,
            "accessed": self.accessed,
            "changed": self.changed,
            "created": self.created,
        }


def _tsk_time(value) -> str:
    """SleuthKit timestamps are epoch seconds, or 0 when unset."""
    if not value:
        return ""
    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OSError, OverflowError):
        return ""


class NativeFilesystem:
    """
    Filesystem-aware recovery: deleted-file enumeration, metadata, and
    unallocated-extent mapping.

    Example - list deleted files and their original names::

        with NativeImage("disk.img") as image:
            fs = NativeFilesystem(image)
            for entry in fs.walk_deleted():
                print(entry.path, entry.size, entry.modified)
    """

    def __init__(self, image: NativeImage, fs_offset: int = 0) -> None:
        self.image = image
        self.fs_offset = fs_offset
        self._fs = None
        self._block_size = 512

    def open(self) -> "NativeFilesystem":
        if not HAS_PYTSK3:
            raise RuntimeError("pytsk3 is not installed")
        self._fs = self.image.filesystem(self.fs_offset)
        try:
            self._block_size = self._fs.info.block_size or 512
        except Exception:  # noqa: BLE001
            self._block_size = 512
        return self

    @property
    def info(self) -> dict:
        if self._fs is None:
            return {}
        try:
            return {
                "block_size": self._block_size,
                "block_count": self._fs.info.block_count,
                "fstype": str(self._fs.info.ftype),
                "root_inode": self._fs.info.root_inum,
            }
        except Exception:  # noqa: BLE001
            return {}

    # -- enumeration -------------------------------------------------------

    def walk(
        self,
        path: str = "/",
        *,
        max_entries: int = 200_000,
        on_progress=None,
    ) -> Iterator[FsEntry]:
        """Recursively yield every entry, including deleted ones."""
        yield from self._walk_dir(path, max_entries, on_progress, [0])

    def walk_deleted(
        self,
        path: str = "/",
        *,
        max_entries: int = 200_000,
        on_progress=None,
    ) -> Iterator[FsEntry]:
        """Yield only deleted entries."""
        for entry in self.walk(path, max_entries=max_entries, on_progress=on_progress):
            if entry.deleted and not entry.is_directory:
                yield entry

    def _walk_dir(
        self,
        path: str,
        max_entries: int,
        on_progress,
        counter: list[int],
    ) -> Iterator[FsEntry]:
        if self._fs is None:
            raise RuntimeError("Filesystem is not open - call open() first")
        try:
            directory = self._fs.open_dir(path)
        except Exception:  # noqa: BLE001 - unreadable corrupt directories are expected
            return

        for node in directory:
            if counter[0] >= max_entries:
                return
            try:
                name_bytes = node.info.name.name
                name = name_bytes.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            if name in (".", ".."):
                continue

            meta = node.info.meta
            if meta is None:
                continue

            full_path = f"{path.rstrip('/')}/{name}"
            meta_type = str(meta.type)
            is_directory = "DIR" in meta_type.upper()
            allocated = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)

            entry = FsEntry(
                name=name,
                path=full_path,
                inode=int(meta.addr),
                size=int(meta.size),
                allocated=allocated,
                is_directory=is_directory,
                meta_type=meta_type,
                modified=_tsk_time(getattr(meta, "mtime", 0)),
                accessed=_tsk_time(getattr(meta, "atime", 0)),
                changed=_tsk_time(getattr(meta, "ctime", 0)),
                created=_tsk_time(getattr(meta, "crtime", 0)),
            )
            counter[0] += 1
            if on_progress is not None and counter[0] % 250 == 0:
                on_progress(counter[0], path)
            yield entry

            if is_directory and allocated:
                yield from self._walk_dir(full_path, max_entries, on_progress, counter)

    # -- recovery ----------------------------------------------------------

    def read_file(self, entry: FsEntry, max_bytes: int | None = None) -> bytes:
        """Read an entry's content by inode (works for deleted files whose clusters survive)."""
        if self._fs is None:
            raise RuntimeError("Filesystem is not open")
        file_obj = self._fs.open_meta(inode=entry.inode)
        size = entry.size if max_bytes is None else min(entry.size, max_bytes)
        return file_obj.read_random(0, size)

    def recover_to(self, entry: FsEntry, destination: Path) -> int:
        """Write a recovered entry to disk, returning the byte count."""
        data = self.read_file(entry)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(destination, "wb") as handle:
            handle.write(data)
        return len(data)

    # -- unallocated mapping ----------------------------------------------

    def allocated_extents(self, max_entries: int = 100_000, on_progress=None) -> list[tuple[int, int]]:
        """
        Byte extents currently in use by allocated files.

        Computed by walking every allocated file's data runs. The complement of
        this set, within the volume, is the unallocated space - the region a
        professional workflow carves from, and where deleted content survives.
        """
        if self._fs is None:
            raise RuntimeError("Filesystem is not open")
        extents: list[tuple[int, int]] = []
        examined = 0

        for entry in self.walk(max_entries=max_entries, on_progress=on_progress):
            if entry.is_directory or not entry.allocated or entry.size == 0:
                continue
            examined += 1
            try:
                file_obj = self._fs.open_meta(inode=entry.inode)
                for attribute in file_obj:
                    if attribute.info.type != pytsk3.TSK_FS_ATTR_TYPE_DEFAULT:
                        continue
                    if attribute.info.name and attribute.info.name != b"$DATA":
                        continue
                    for run_index in range(attribute.info.run_count):
                        run = attribute.get_run(run_index)
                        if not run:
                            continue
                        offset = int(run[0]) * self._block_size
                        length = int(run[1]) * self._block_size
                        if length > 0:
                            extents.append((offset, length))
            except Exception:  # noqa: BLE001
                continue

        extents.sort()
        return _merge_extents(extents)

    def unallocated_extents(self, max_entries: int = 100_000, on_progress=None) -> list[tuple[int, int]]:
        """The complement of :meth:`allocated_extents` within the volume."""
        if self._fs is None:
            raise RuntimeError("Filesystem is not open")
        try:
            volume_size = int(self._fs.info.block_count) * self._block_size
        except Exception:  # noqa: BLE001
            volume_size = self.image.size

        allocated = self.allocated_extents(max_entries, on_progress)
        return _complement(allocated, volume_size)


def _merge_extents(extents: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Coalesce overlapping or adjacent extents."""
    if not extents:
        return []
    merged: list[list[int]] = [[extents[0][0], extents[0][1]]]
    for offset, length in extents[1:]:
        last = merged[-1]
        last_end = last[0] + last[1]
        if offset <= last_end:
            last[1] = max(last_end, offset + length) - last[0]
        else:
            merged.append([offset, length])
    return [(int(o), int(l)) for o, l in merged]


def _complement(extents: list[tuple[int, int]], total: int) -> list[tuple[int, int]]:
    """Invert a sorted, merged extent list across [0, total)."""
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for offset, length in extents:
        if offset > cursor:
            gaps.append((cursor, offset - cursor))
        cursor = max(cursor, offset + length)
    if cursor < total:
        gaps.append((cursor, total - cursor))
    return gaps
