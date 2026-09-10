"""
Storage device enumeration.

Enumerating storage is inherently platform-specific and privilege-sensitive:
listing physical drives and reading their media type generally requires
administrator rights, while listing mounted volumes does not. Rather than fail
when unprivileged, this module degrades in stages and records in each
:class:`DeviceInfo` exactly how confident it is about what it found.

That honesty matters for the safety layer. A device whose media type could not
be determined is reported as :data:`MediaType.UNKNOWN` and the UI refuses to
recommend an overwrite for it, rather than guessing.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sanctum.config import IS_LINUX, IS_WINDOWS
from sanctum.core.targets import MediaType, TargetKind, is_system_path


@dataclass
class DeviceInfo:
    """A storage device as reported by the operating system."""

    path: str
    name: str
    kind: TargetKind
    size_bytes: int = 0
    media_type: MediaType = MediaType.UNKNOWN
    model: str = ""
    serial: str = ""
    bus: str = ""
    is_system: bool = False
    is_removable: bool = False
    mountpoints: list[str] = field(default_factory=list)
    accessible: bool = True
    note: str = ""

    @property
    def size_gb(self) -> float:
        return self.size_bytes / (1024 ** 3)

    def summary(self) -> str:
        size = f"{self.size_gb:.1f} GB" if self.size_bytes else "size unknown"
        parts = [self.name, f"({self.media_type.value}, {size})"]
        if self.is_system:
            parts.append("[SYSTEM - protected]")
        if not self.accessible:
            parts.append("[requires administrator]")
        return "  ".join(parts)


# --------------------------------------------------------------------------
# Windows backend
# --------------------------------------------------------------------------

def _no_window_kwargs() -> dict:
    """Keep console windows from flashing when we shell out from a GUI app."""
    if IS_WINDOWS:
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def _run_powershell(script: str, timeout: int = 25) -> str:
    """Run PowerShell and return stdout, or '' on any failure."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            **_no_window_kwargs(),
        )
        if completed.returncode != 0:
            return ""
        return completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _parse_size(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _windows_media_type(media: str, bus: str) -> MediaType:
    media = (media or "").lower()
    bus = (bus or "").lower()
    if "nvme" in bus:
        return MediaType.NVME
    if "ssd" in media:
        return MediaType.SSD
    if "hdd" in media or "hard disk" in media:
        return MediaType.HDD
    if "usb" in bus:
        return MediaType.USB_FLASH
    if "sd" in bus:
        return MediaType.SD_CARD
    return MediaType.UNKNOWN


def _enumerate_windows_physical() -> list[DeviceInfo]:
    """
    Physical drives via the Storage module.

    Falls back silently when the cmdlet is missing (Server Core, older builds)
    or when the caller lacks the rights to query physical disks.
    """
    script = (
        "Get-PhysicalDisk -ErrorAction SilentlyContinue | "
        "Select-Object DeviceId,FriendlyName,MediaType,BusType,Size,SerialNumber | "
        "ConvertTo-Json -Compress"
    )
    raw = _run_powershell(script)
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = [payload]

    devices: list[DeviceInfo] = []
    for index, item in enumerate(payload):
        device_id = item.get("DeviceId", index)
        path = rf"\\.\PhysicalDrive{device_id}"
        bus = item.get("BusType") or ""
        devices.append(
            DeviceInfo(
                path=path,
                name=item.get("FriendlyName") or f"Physical Drive {device_id}",
                kind=TargetKind.BLOCK_DEVICE,
                size_bytes=_parse_size(item.get("Size")),
                media_type=_windows_media_type(item.get("MediaType"), bus),
                model=item.get("FriendlyName") or "",
                serial=(item.get("SerialNumber") or "").strip(),
                bus=bus,
                is_system=is_system_path(path),
                is_removable=bus.lower() == "usb",
                accessible=False,
                note="Raw access requires administrator privileges",
            )
        )
    return devices


def _enumerate_windows_volumes() -> list[DeviceInfo]:
    """Mounted volumes via the Win32 drive API - works without elevation."""
    kernel32 = ctypes.windll.kernel32

    DRIVE_TYPES = {
        2: ("Removable", True, MediaType.USB_FLASH),
        3: ("Fixed", False, MediaType.UNKNOWN),
        4: ("Network", False, MediaType.UNKNOWN),
        5: ("CD-ROM", False, MediaType.UNKNOWN),
        6: ("RAM disk", False, MediaType.VIRTUAL),
    }

    mask = kernel32.GetLogicalDrives()
    devices: list[DeviceInfo] = []
    for index in range(26):
        if not (mask >> index) & 1:
            continue
        letter = chr(ord("A") + index)
        root = f"{letter}:\\"
        drive_type = kernel32.GetDriveTypeW(root)
        label, removable, media = DRIVE_TYPES.get(drive_type, ("Unknown", False, MediaType.UNKNOWN))

        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        available = ctypes.c_ulonglong(0)
        ok = kernel32.GetDiskFreeSpaceExW(
            root,
            ctypes.byref(available),
            ctypes.byref(total),
            ctypes.byref(free),
        )
        size = int(total.value) if ok else 0

        volume_label = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_ulong(0)
        kernel32.GetVolumeInformationW(
            root,
            volume_label,
            261,
            ctypes.byref(serial),
            None,
            None,
            fs_name,
            261,
        )

        devices.append(
            DeviceInfo(
                path=root,
                name=f"{letter}: {volume_label.value}".strip() or root,
                kind=TargetKind.FOLDER,
                size_bytes=size,
                media_type=media,
                model=fs_name.value,
                serial=f"{serial.value:08X}" if serial.value else "",
                bus="Volume",
                is_system=is_system_path(root),
                is_removable=removable,
                mountpoints=[root],
                accessible=True,
                note=f"{label} volume, filesystem {fs_name.value or 'unknown'}",
            )
        )
    return devices


# --------------------------------------------------------------------------
# Linux backend
# --------------------------------------------------------------------------

def _enumerate_linux() -> list[DeviceInfo]:
    devices: list[DeviceInfo] = []
    sys_block = Path("/sys/block")
    if not sys_block.is_dir():
        return devices

    mounts = _linux_mounts()

    for entry in sorted(sys_block.iterdir()):
        name = entry.name
        # Skip loop, ram and device-mapper pseudo-devices; they clutter the list
        # and are not meaningful sanitization targets for an operator.
        if name.startswith(("loop", "ram", "zram", "dm-", "sr")):
            continue

        size_sectors = 0
        size_file = entry / "size"
        if size_file.exists():
            try:
                size_sectors = int(size_file.read_text().strip())
            except (OSError, ValueError):
                size_sectors = 0

        rotational = "1"
        rot_file = entry / "queue" / "rotational"
        if rot_file.exists():
            try:
                rotational = rot_file.read_text().strip()
            except OSError:
                rotational = "1"

        if "nvme" in name:
            media = MediaType.NVME
        elif rotational == "1":
            media = MediaType.HDD
        else:
            media = MediaType.SSD

        removable = False
        rem_file = entry / "removable"
        if rem_file.exists():
            try:
                removable = rem_file.read_text().strip() == "1"
            except OSError:
                removable = False

        model = ""
        model_file = entry / "device" / "model"
        if model_file.exists():
            try:
                model = model_file.read_text().strip()
            except OSError:
                model = ""

        dev_path = f"/dev/{name}"
        devices.append(
            DeviceInfo(
                path=dev_path,
                name=f"{dev_path}  {model}".strip(),
                kind=TargetKind.BLOCK_DEVICE,
                size_bytes=size_sectors * 512,
                media_type=media,
                model=model,
                bus="USB" if removable else "",
                is_system=is_system_path(dev_path),
                is_removable=removable,
                mountpoints=mounts.get(dev_path, []),
                accessible=os.access(dev_path, os.R_OK),
                note="Raw access requires root (or CAP_SYS_RAWIO)",
            )
        )
    return devices


def _linux_mounts() -> dict[str, list[str]]:
    """Map block device -> mount points, from /proc/mounts."""
    mapping: dict[str, list[str]] = {}
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 2:
                    continue
                source, mountpoint = parts[0], parts[1]
                # Reduce partitions to their parent device (sda1 -> sda,
                # nvme0n1p1 -> nvme0n1) so the mount shows on the disk entry.
                parent = re.sub(r"p?\d+$", "", source)
                mapping.setdefault(parent, []).append(mountpoint)
    except OSError:
        pass
    return mapping


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def enumerate_devices(include_volumes: bool = True) -> list[DeviceInfo]:
    """
    List storage devices, best-effort and never raising.

    Physical devices come first (they are the real sanitization targets), then
    mounted volumes, then nothing if enumeration failed entirely - the caller
    can still add an image file manually.
    """
    devices: list[DeviceInfo] = []
    try:
        if IS_WINDOWS:
            devices.extend(_enumerate_windows_physical())
            if include_volumes:
                devices.extend(_enumerate_windows_volumes())
        elif IS_LINUX:
            devices.extend(_enumerate_linux())
        else:
            devices.extend(_enumerate_posix_generic())
    except Exception as exc:  # noqa: BLE001 - enumeration must not crash the UI
        devices.append(
            DeviceInfo(
                path="",
                name=f"Device enumeration failed: {exc}",
                kind=TargetKind.BLOCK_DEVICE,
                accessible=False,
                note=str(exc),
            )
        )
    return devices


def _enumerate_posix_generic() -> list[DeviceInfo]:
    """macOS and other POSIX: list mounted filesystems only."""
    devices: list[DeviceInfo] = []
    try:
        completed = subprocess.run(
            ["df", "-k"], capture_output=True, text=True, timeout=10
        )
        for line in completed.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            source, mount = parts[0], parts[-1]
            if not source.startswith("/dev/"):
                continue
            devices.append(
                DeviceInfo(
                    path=mount,
                    name=f"{source}  ->  {mount}",
                    kind=TargetKind.FOLDER,
                    size_bytes=_parse_size(parts[1]) * 1024,
                    media_type=MediaType.UNKNOWN,
                    is_system=is_system_path(mount),
                    mountpoints=[mount],
                    accessible=os.access(mount, os.W_OK),
                )
            )
    except (OSError, subprocess.SubprocessError):
        pass
    return devices


def is_elevated() -> bool:
    """Are we running with administrator/root privileges?"""
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def platform_summary() -> dict[str, object]:
    """Environment facts for the dashboard and reports."""
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "elevated": is_elevated(),
    }
