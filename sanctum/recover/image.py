"""
Disk image handling.

A thin, dependency-free wrapper for reading disk images, plus the logic that
decides *where* to carve. That decision matters more than it might appear:

* Carving a whole device scans allocated files too, so every live file is
  recovered alongside the deleted ones - noisy and slow.
* Carving only unallocated space targets exactly the region where deleted
  content survives.

The second is the professional workflow. It requires filesystem knowledge, so
this module uses the native backend when it is present and falls back to
whole-image scanning (with a clear warning in the result) when it is not.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from sanctum.recover.native import NativeImage, capabilities

#: Containers we recognise, and whether we can read them without native libs.
RAW_EXTENSIONS = {".img", ".dd", ".raw", ".bin", ".iso", ".001"}
EWF_EXTENSIONS = {".e01", ".ex01", ".l01"}


@dataclass
class ImageInfo:
    """What we determined about an image file."""

    path: str
    size_bytes: int = 0
    container: str = "raw"
    readable: bool = True
    partitions: list[dict] = field(default_factory=list)
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "container": self.container,
            "readable": self.readable,
            "partitions": self.partitions,
            "note": self.note,
        }


def detect_container(path: str | Path) -> str:
    """Identify the image container format."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in EWF_EXTENSIONS:
        return "ewf"
    try:
        with open(path, "rb") as handle:
            signature = handle.read(16)
    except OSError:
        return "unknown"
    if signature.startswith(b"EVF"):
        return "ewf"
    if signature[510:512] == b"\x55\xaa":
        return "raw-mbr"
    if signature.startswith(b"KDMV"):
        return "vmdk"
    if signature.startswith(b"QFI\xfb"):
        return "qcow2"
    return "raw"


def parse_mbr_partitions(path: str | Path) -> list[dict]:
    """
    Read the MBR partition table.

    Useful for pointing the user at the right filesystem offset when an image
    contains more than one volume.
    """
    partitions: list[dict] = []
    try:
        with open(path, "rb") as handle:
            sector = handle.read(512)
    except OSError:
        return partitions
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        return partitions

    for index in range(4):
        entry = sector[446 + index * 16 : 446 + (index + 1) * 16]
        if len(entry) < 16:
            continue
        status, ptype = entry[0], entry[4]
        lba_start, sector_count = struct.unpack("<II", entry[8:16])
        if lba_start == 0 and sector_count == 0:
            continue
        partitions.append(
            {
                "index": index + 1,
                "bootable": status == 0x80,
                "type": f"0x{ptype:02X}",
                "offset": lba_start * 512,
                "length": sector_count * 512,
            }
        )
    return partitions


class DiskImage:
    """
    Read access to a disk image, raw or EnCase.

    Example - carve only the unallocated space of a volume::

        with DiskImage("evidence/disk.img") as image:
            regions = image.unallocated_regions(fs_offset=1048576)
            result = carver.carve("evidence/disk.img", "out", regions=regions)
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._native: NativeImage | None = None
        self._handle = None

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "DiskImage":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> "DiskImage":
        container = detect_container(self.path)
        if container == "ewf":
            if not capabilities().encase_images:
                raise RuntimeError(
                    "This is an EnCase E01 image, which requires pyewf. "
                    "Install pyewf to open it, or convert to raw with ewfexport."
                )
            self._native = NativeImage(self.path).open()
        else:
            self._handle = open(self.path, "rb")
        return self

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        if self._native is not None:
            self._native.close()

    # -- access ------------------------------------------------------------

    @property
    def size(self) -> int:
        if self._native is not None:
            return self._native.size
        if self._handle is not None:
            return self._handle.seek(0, 2)
        return 0

    def read_at(self, offset: int, size: int) -> bytes:
        if self._native is not None:
            return self._native.read(offset, size)
        if self._handle is None:
            raise RuntimeError("Image is not open")
        self._handle.seek(offset)
        return self._handle.read(size)

    # -- interrogation -----------------------------------------------------

    def info(self) -> ImageInfo:
        """Describe the image without a full scan."""
        info = ImageInfo(path=str(self.path), size_bytes=self.size)
        info.container = detect_container(self.path)

        if info.container in ("raw", "raw-mbr"):
            info.partitions = parse_mbr_partitions(self.path)

        caps = capabilities()
        if info.container == "ewf" and not caps.encase_images:
            info.readable = False
            info.note = "pyewf is required to read EnCase images"
        elif not caps.filesystem_parsing:
            info.note = (
                "pytsk3 is not installed: filesystem metadata recovery and "
                "unallocated-space targeting are unavailable. Carving will scan "
                "the whole image."
            )
        return info

    def unallocated_regions(self, fs_offset: int = 0) -> list[tuple[int, int]]:
        """
        Extents of unallocated space, or the whole image if we cannot tell.

        The fallback is explicit rather than silent - callers can inspect
        :meth:`used_fallback` to warn the operator that the scan was broader
        than intended.
        """
        self._used_fallback = True
        if not capabilities().filesystem_parsing:
            return [(0, self.size)]
        try:
            from sanctum.recover.native import NativeFilesystem

            image = self._native or NativeImage(self.path).open()
            filesystem = NativeFilesystem(image, fs_offset).open()
            regions = filesystem.unallocated_extents()
            if regions:
                self._used_fallback = False
                return regions
        except Exception:  # noqa: BLE001 - fall back rather than fail the scan
            pass
        return [(0, self.size)]

    @property
    def used_fallback(self) -> bool:
        """True if :meth:`unallocated_regions` could not determine real extents."""
        return getattr(self, "_used_fallback", True)

    def deleted_files(self, fs_offset: int = 0, limit: int = 5000) -> list[dict]:
        """List deleted entries via SleuthKit, or an empty list without it."""
        if not capabilities().filesystem_parsing:
            return []
        from sanctum.recover.native import NativeFilesystem

        image = self._native or NativeImage(self.path).open()
        filesystem = NativeFilesystem(image, fs_offset).open()
        collected: list[dict] = []
        for entry in filesystem.walk_deleted(max_entries=limit * 4):
            collected.append(entry.as_dict())
            if len(collected) >= limit:
                break
        return collected
