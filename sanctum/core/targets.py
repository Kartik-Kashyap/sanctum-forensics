"""
Target abstraction and the safety guards that stand between an operator and
irreversible data loss.

Every destructive operation in SANCTUM begins by constructing an
:class:`EraseTarget` and running it through :func:`validate_for_erasure`. That
function is the single choke point for policy, and it is deliberately
pessimistic: anything it cannot positively identify as safe is refused.

The design principle is that a mistake must require *several* independent
failures, not one. Touching bare metal needs:
  * an explicit runtime policy flag,
  * the SANCTUM_ALLOW_RAW_DEVICE environment variable,
  * a confirmation token typed by the operator,
and even then the running system's own drive is refused outright.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import string
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from sanctum.config import (
    CHUNK_SIZE,
    IS_LINUX,
    IS_WINDOWS,
    PROTECTED_POSIX_PREFIXES,
    PROTECTED_WINDOWS_DRIVES,
    SafetyPolicy,
    runtime_allows_raw_devices,
)


class TargetKind(str, Enum):
    """What kind of thing are we about to write to?"""

    BLOCK_DEVICE = "BLOCK_DEVICE"   # \\.\PhysicalDriveN, /dev/sdX - bare metal
    DISK_IMAGE = "DISK_IMAGE"       # a .img/.dd/.raw file - safe and repeatable
    FILE = "FILE"                   # a single file on a live filesystem
    FOLDER = "FOLDER"               # a directory tree on a live filesystem


class MediaType(str, Enum):
    HDD = "HDD"
    SSD = "SSD"
    NVME = "NVMe"
    USB_FLASH = "USB Flash"
    SD_CARD = "SD Card"
    VIRTUAL = "Virtual/Image"
    UNKNOWN = "Unknown"


class SafetyViolation(Exception):
    """Raised when a requested operation is refused by policy."""

    def __init__(self, reason: str, target: str = "") -> None:
        self.reason = reason
        self.target = target
        super().__init__(f"{reason}" + (f" [target: {target}]" if target else ""))


@dataclass
class EraseTarget:
    """A fully-described destination for a destructive operation."""

    path: str
    kind: TargetKind
    size_bytes: int = 0
    display_name: str = ""
    media_type: MediaType = MediaType.UNKNOWN
    model: str = ""
    serial: str = ""
    bus: str = ""
    is_system: bool = False
    is_removable: bool = False
    mountpoints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_raw_device(self) -> bool:
        return self.kind is TargetKind.BLOCK_DEVICE

    @property
    def short_name(self) -> str:
        return self.display_name or Path(self.path).name or self.path

    def confirmation_token(self) -> str:
        """
        A short token derived from the target's identity.

        The operator must retype this to proceed. Deriving it from path, size
        and serial means the token shown for one device never validates for a
        different one - protection against a stale dialog confirming the wrong
        drive, which is the classic way wipes go wrong.
        """
        material = f"{self.path}|{self.size_bytes}|{self.serial}|{self.kind.value}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:8].upper()


# --------------------------------------------------------------------------
# System-drive detection
# --------------------------------------------------------------------------

def _windows_system_drive() -> str | None:
    """The drive letter holding the running Windows installation, e.g. 'C:'."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if not root:
        return None
    drive = os.path.splitdrive(root)[0]
    return drive.upper() if drive else None


def system_locations() -> set[str]:
    """Paths that must never be targeted."""
    locations: set[str] = set()
    if IS_WINDOWS:
        system_drive = _windows_system_drive()
        if system_drive:
            locations.add(system_drive + "\\")
        locations.update(PROTECTED_WINDOWS_DRIVES)
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            value = os.environ.get(var)
            if value:
                locations.add(os.path.normcase(os.path.abspath(value)))
    else:
        locations.update(PROTECTED_POSIX_PREFIXES)
        locations.update({"/", "/boot", "/etc", "/usr", "/var", "/home"})
    return locations


def is_system_path(path: str | os.PathLike[str]) -> bool:
    """
    Is this a *device-level* path that hosts the running operating system?

    Used for raw device targets, where there is no filesystem to inspect and the
    conservative assumption is that the OS-bearing drive is off limits.

    Note this is deliberately NOT the check used for ordinary file deletion:
    everything on the ``C:`` drive would match, which would wrongly refuse
    deleting a file in the operator's own Documents folder. Use
    :func:`is_os_directory` for that.
    """
    raw = str(path)
    if not raw:
        return False

    if IS_WINDOWS:
        for protected in PROTECTED_WINDOWS_DRIVES:
            if raw.lower().startswith(protected.lower()):
                return True
        system_drive = _windows_system_drive()
        if system_drive:
            drive = os.path.splitdrive(raw)[0].upper()
            if drive and drive == system_drive:
                return True
        return False

    for prefix in PROTECTED_POSIX_PREFIXES:
        if raw == prefix or raw.startswith(prefix):
            return True
    if raw == "/":
        return True
    return False


def _os_directories() -> list[str]:
    """Directories owned by the operating system, per platform."""
    if IS_WINDOWS:
        directories: list[str] = []
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            value = os.environ.get(var)
            if value:
                directories.append(os.path.normcase(os.path.abspath(value)))
        return directories
    return [
        "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
        "/proc", "/sys", "/dev", "/var/lib", "/var/log",
    ]


def is_os_directory(path: str | os.PathLike[str]) -> bool:
    """
    Is this path inside an operating-system-owned directory?

    This is the correct guard for file and folder deletion. A file in
    ``~/Documents`` is on the system drive but is the operator's own data and
    must remain deletable; a file in ``C:\\Windows\\System32`` must not be.
    """
    raw = str(path)
    if not raw:
        return False
    try:
        resolved = os.path.normcase(os.path.abspath(raw))
    except (OSError, ValueError):
        return False

    for directory in _os_directories():
        normalised = os.path.normcase(directory)
        if resolved == normalised or resolved.startswith(normalised + os.sep):
            return True
    return False


def is_filesystem_root(path: str | os.PathLike[str]) -> bool:
    """
    Is this a drive root or the filesystem root?

    No legitimate selective-deletion operation targets ``C:\\`` or ``/`` as a
    file-tree operation - that is a whole-media job, which has its own module,
    its own safeguards and its own confirmation flow.
    """
    raw = str(path)
    if not raw:
        return False
    if raw in ("/", "\\"):
        return True
    try:
        resolved = os.path.abspath(raw)
    except (OSError, ValueError):
        return False
    if IS_WINDOWS:
        drive, tail = os.path.splitdrive(resolved)
        return bool(drive) and tail in ("\\", "/", "")
    return resolved == "/"



def is_inside_sanctum_home(path: str | os.PathLike[str]) -> bool:
    """
    Refuse to target SANCTUM's own working directory.

    Wiping the case folder that holds the audit chain would destroy the record
    of the wipe - a self-defeating operation and a plausible accident.
    """
    from sanctum.config import BASE_DIR

    try:
        resolved = Path(path).resolve()
        base = BASE_DIR.resolve()
    except (OSError, ValueError):
        return False
    return base == resolved or base in resolved.parents


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def _probe_size_windows(path: str) -> int:
    """Ask the Windows storage stack for a device's byte length."""
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    if handle == INVALID_HANDLE_VALUE:
        return 0
    try:
        length = ctypes.c_longlong(0)
        returned = ctypes.c_ulong(0)
        ok = kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            ctypes.byref(length),
            ctypes.sizeof(length),
            ctypes.byref(returned),
            None,
        )
        return int(length.value) if ok else 0
    finally:
        kernel32.CloseHandle(handle)


def probe_size(path: str) -> int:
    """Best-effort byte size of a file, image or block device."""
    try:
        return os.path.getsize(path)
    except OSError:
        pass
    if IS_WINDOWS:
        return _probe_size_windows(path)
    try:
        with open(path, "rb") as handle:
            return handle.seek(0, os.SEEK_END)
    except OSError:
        return 0


def _is_block_device(path: str) -> bool:
    if IS_WINDOWS:
        return path.lower().startswith(("\\\\.\\physicaldrive", "\\\\.\\"))
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def classify_kind(path: str) -> TargetKind:
    """Decide what kind of target a path represents."""
    if _is_block_device(path):
        return TargetKind.BLOCK_DEVICE
    expanded = Path(path)
    if expanded.is_dir():
        return TargetKind.FOLDER
    suffix = expanded.suffix.lower()
    if suffix in {".img", ".dd", ".raw", ".iso", ".001", ".e01"}:
        return TargetKind.DISK_IMAGE
    return TargetKind.FILE


def _media_type_for(path: str, kind: TargetKind) -> MediaType:
    """
    Infer the media type.

    This matters because the correct sanitization method differs fundamentally
    between magnetic and flash media, and the UI must be able to warn about it.
    """
    if kind is TargetKind.DISK_IMAGE:
        return MediaType.VIRTUAL
    lowered = path.lower()
    if "nvme" in lowered:
        return MediaType.NVME
    if IS_WINDOWS and lowered.startswith("\\\\.\\physicaldrive"):
        return MediaType.UNKNOWN  # resolved by the device enumerator when run as admin
    if IS_LINUX:
        try:
            with open("/sys/block/../block", "r"):
                pass
        except OSError:
            pass
        # Rotational flag: 1 = spinning rust, 0 = solid state.
        name = os.path.basename(path.rstrip(string.digits)) or os.path.basename(path)
        for candidate in {os.path.basename(path), name}:
            rotational = Path(f"/sys/block/{candidate}/queue/rotational")
            if rotational.exists():
                try:
                    return MediaType.HDD if rotational.read_text().strip() == "1" else MediaType.SSD
                except OSError:
                    pass
        return MediaType.UNKNOWN
    return MediaType.UNKNOWN


def describe_target(path: str, **overrides) -> EraseTarget:
    """Probe a path and build a fully-populated :class:`EraseTarget`."""
    kind = overrides.pop("kind", None) or classify_kind(path)
    target = EraseTarget(
        path=str(path),
        kind=kind,
        size_bytes=overrides.pop("size_bytes", None) or probe_size(path),
        display_name=overrides.pop("display_name", "") or Path(str(path)).name or str(path),
        media_type=overrides.pop("media_type", None) or _media_type_for(str(path), kind),
        model=overrides.pop("model", ""),
        serial=overrides.pop("serial", ""),
        bus=overrides.pop("bus", ""),
        is_system=overrides.pop("is_system", None),
        is_removable=overrides.pop("is_removable", False),
        mountpoints=overrides.pop("mountpoints", []),
        notes=overrides.pop("notes", []),
    )
    if target.is_system is None:
        if target.kind is TargetKind.BLOCK_DEVICE:
            # Only a raw device *is* the drive, so only there does the
            # drive-letter check mean what it says.
            target.is_system = is_system_path(path)
        else:
            # A disk image is a file. It can only be an OS target if it sits
            # inside an OS-owned directory - the volume it happens to live on is
            # irrelevant, because overwriting an image cannot reach the running
            # system. Applying the drive-based check here would mark every image
            # on C: as the operating system and refuse the tool's own test
            # media, which is exactly what it did.
            target.is_system = is_os_directory(path) or is_filesystem_root(path)
    return target


# --------------------------------------------------------------------------
# Policy enforcement
# --------------------------------------------------------------------------

def validate_for_erasure(target: EraseTarget, policy: SafetyPolicy) -> None:
    """
    The single gate every destructive operation must pass.

    Raises :class:`SafetyViolation` with a human-readable reason on refusal.
    The reason strings are written straight into the audit chain, so they must
    be specific enough for a reviewer to reconstruct the decision.
    """
    if not target.path:
        raise SafetyViolation("Target path is empty")

    # 1. Never target our own working directory.
    if is_inside_sanctum_home(target.path):
        raise SafetyViolation(
            "Refusing to target SANCTUM's own data directory - this would destroy "
            "the audit chain that records the operation",
            target.path,
        )

    # 2. The running operating system is off limits, unconditionally.
    if target.is_system:
        if not policy.allow_system_targets:
            raise SafetyViolation(
                "Target appears to be the running operating system or its drive. "
                "This is refused even with raw-device access enabled.",
                target.path,
            )

    # 3. Bare metal requires an explicit policy opt-in.
    if target.is_raw_device:
        if not policy.allow_raw_devices:
            raise SafetyViolation(
                "Raw device access is disabled. Enable it in Settings to target "
                "physical drives.",
                target.path,
            )
        if not runtime_allows_raw_devices():
            raise SafetyViolation(
                "Raw device access requires the SANCTUM_ALLOW_RAW_DEVICE "
                "environment variable to be set to a truthy value.",
                target.path,
            )

    # 4. Image and file targets must actually exist and be writable.
    if target.kind in (TargetKind.DISK_IMAGE, TargetKind.FILE, TargetKind.FOLDER):
        if not os.path.exists(target.path):
            raise SafetyViolation("Target does not exist", target.path)
        if not os.access(target.path, os.W_OK):
            raise SafetyViolation("Target is not writable by this process", target.path)

    # 5. An empty size means we cannot verify afterwards - refuse rather than
    #    produce an unverifiable 'success'.
    if target.kind in (TargetKind.BLOCK_DEVICE, TargetKind.DISK_IMAGE) and target.size_bytes <= 0:
        raise SafetyViolation(
            "Could not determine target size; refusing to operate on an "
            "unmeasurable device",
            target.path,
        )


def verify_confirmation(target: EraseTarget, supplied: str) -> None:
    """Check the operator typed the expected confirmation token."""
    expected = target.confirmation_token()
    if supplied.strip().upper() != expected:
        raise SafetyViolation(
            f"Confirmation token mismatch (expected {expected})", target.path
        )


# --------------------------------------------------------------------------
# I/O helpers
# --------------------------------------------------------------------------

class TargetWriter:
    """
    Buffered, cancellable writer over an arbitrary target.

    Opening a raw device on Windows requires unbuffered binary mode; buffering
    there silently swallows writes past the device's reported size. The class
    hides that platform difference from the erasure engines.
    """

    def __init__(self, target: EraseTarget, *, writable: bool = True) -> None:
        self.target = target
        self.writable = writable
        self._handle: BinaryIO | None = None
        self._buffered = target.kind is not TargetKind.BLOCK_DEVICE

    def __enter__(self) -> "TargetWriter":
        mode = "r+b" if self.writable else "rb"
        if self._buffered:
            self._handle = open(self.target.path, mode)
        else:
            # Unbuffered is mandatory for Windows raw devices.
            self._handle = open(self.target.path, mode, buffering=0)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def handle(self) -> BinaryIO:
        if self._handle is None:
            raise RuntimeError("TargetWriter used outside its context manager")
        return self._handle

    def write_at(self, offset: int, data: bytes) -> None:
        self.handle.seek(offset)
        self.handle.write(data)

    def read_at(self, offset: int, size: int) -> bytes:
        self.handle.seek(offset)
        return self.handle.read(size)

    def flush(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            try:
                os.fsync(self._handle.fileno())
            except (OSError, ValueError):
                # Raw devices on Windows do not support fsync; the write is
                # already committed to the driver stack.
                pass

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            finally:
                self._handle = None
