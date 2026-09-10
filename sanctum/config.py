"""
Application-wide configuration, filesystem layout and runtime constants.

All mutable state lives under ``BASE_DIR`` so that a run leaves no artefacts
scattered across the host - important for a forensic tool, where the analyst
must be able to account for every file the tool itself created.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

APP_NAME = "SANCTUM"
APP_SLUG = "sanctum"

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"


# --------------------------------------------------------------------------
# Filesystem layout
# --------------------------------------------------------------------------

def _default_base_dir() -> Path:
    """Per-user data directory, following each platform's convention."""
    override = os.environ.get("SANCTUM_HOME")
    if override:
        return Path(override).expanduser().resolve()

    if IS_WINDOWS:
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif IS_MACOS:
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / APP_SLUG


BASE_DIR: Path = _default_base_dir()
CASES_DIR: Path = BASE_DIR / "cases"
LOGS_DIR: Path = BASE_DIR / "logs"
CONFIG_FILE: Path = BASE_DIR / "settings.json"


def ensure_layout() -> None:
    """Create the working directory tree. Safe to call repeatedly."""
    for directory in (BASE_DIR, CASES_DIR, LOGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# I/O tuning
# --------------------------------------------------------------------------

#: Chunk size for all bulk reads/writes. 1 MiB balances syscall overhead
#: against the memory ceiling of a modest demo laptop.
CHUNK_SIZE: int = 1024 * 1024

#: Verification of a multi-terabyte drive byte-for-byte is impractical, so
#: verification samples this many windows spread across the device. Full
#: verification is still available via ``verify_mode="full"``.
VERIFY_SAMPLE_WINDOWS: int = 64
VERIFY_WINDOW_BYTES: int = 1024 * 1024


# --------------------------------------------------------------------------
# Safety policy
# --------------------------------------------------------------------------

#: Environment variable that must be set, in addition to the runtime flag, before
#: SANCTUM will touch a real physical device. This two-key design means an
#: accidental click can never reach bare metal.
ALLOW_RAW_DEVICE_ENV = "SANCTUM_ALLOW_RAW_DEVICE"

#: Windows physical drive numbers that hold the running OS are refused outright.
#: PhysicalDrive0 is the conservative assumption on a default install.
PROTECTED_WINDOWS_DRIVES: tuple[str, ...] = (r"\\.\PhysicalDrive0",)

#: POSIX device prefixes considered system-critical.
PROTECTED_POSIX_PREFIXES: tuple[str, ...] = ("/dev/sda", "/dev/nvme0n1", "/dev/vda", "/dev/disk0")


@dataclass(frozen=True)
class SafetyPolicy:
    """
    Everything that must be true before a destructive operation is permitted.

    Kept as an immutable value object so it can be logged verbatim into the
    audit chain - the record then states exactly which policy was in force.
    """

    allow_raw_devices: bool = False
    allow_system_targets: bool = False
    require_confirmation_token: bool = True
    dry_run: bool = True

    def summary(self) -> str:
        return (
            f"raw_devices={self.allow_raw_devices} "
            f"system_targets={self.allow_system_targets} "
            f"dry_run={self.dry_run}"
        )


def runtime_allows_raw_devices() -> bool:
    """True when the operator has exported the raw-device unlock variable."""
    value = os.environ.get(ALLOW_RAW_DEVICE_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

#: Salt for the audit-chain HMAC. Overridable so a team can pin a shared secret
#: across machines; the default keeps single-machine installs self-consistent.
AUDIT_HMAC_KEY: bytes = os.environ.get("SANCTUM_AUDIT_KEY", "sanctum-default-audit-key").encode()


#: Bound before the class body below, which rebinds ``platform`` as a field name.
#: A dataclass body is executed like any other class body, so the assignment to
#: a field called ``platform`` replaces the module in that namespace and the
#: *next* field's ``platform.machine`` resolves against a ``Field`` object
#: instead. Aliasing the two functions keeps the report's key names intact.
_PLATFORM_DESCRIPTION = platform.platform
_PLATFORM_MACHINE = platform.machine


@dataclass
class AppInfo:
    """Snapshot of the runtime environment, embedded in every report."""

    platform: str = field(default_factory=_PLATFORM_DESCRIPTION)
    machine: str = field(default_factory=_PLATFORM_MACHINE)
    python: str = field(default_factory=lambda: sys.version.split()[0])
    executable: str = field(default_factory=lambda: sys.executable)

    def as_dict(self) -> dict[str, str]:
        return {
            "platform": self.platform,
            "machine": self.machine,
            "python": self.python,
            "executable": self.executable,
        }
