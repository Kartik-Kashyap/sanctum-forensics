"""
Shared test fixtures.

Two things matter here and both are deliberate:

1. **SANCTUM_HOME is redirected to a temporary directory before any sanctum
   module is imported.** ``sanctum.config`` computes BASE_DIR at import time, so
   setting this later would be too late - and a test run must never write into
   the developer's real case store.

2. **Sample media is generated, not committed.** The FAT16 builder in
   ``tools/fat16.py`` produces spec-correct images with a manifest recording
   every planted file's cluster chain and SHA-256. That ground truth is what
   turns "the carver found something" into "the carver found 10 of 10 files,
   byte-identical."
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Redirect the application's data directory before importing anything from it.
_TEMP_HOME = tempfile.mkdtemp(prefix="sanctum-tests-")
os.environ["SANCTUM_HOME"] = _TEMP_HOME
os.environ.pop("SANCTUM_ALLOW_RAW_DEVICE", None)  # raw devices off unless a test opts in

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sanctum.config import SafetyPolicy, ensure_layout  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _layout():
    ensure_layout()
    yield


@pytest.fixture
def tmp_home(tmp_path) -> Path:
    """
    A throwaway directory for case storage.

    Note this does *not* point ``sanctum.config.BASE_DIR`` at the new location -
    that constant is resolved at import time. Tests that create cases pass the
    path explicitly (``CaseManager(base_dir=tmp_home / "cases")``), which is the
    supported way to relocate storage anyway.
    """
    home = tmp_path / "sanctum-home"
    home.mkdir()
    return home


@pytest.fixture
def safe_policy():
    """
    Policy for image-backed work: writes happen, nothing is refused.

    The typed-confirmation gate is switched off here because every test using
    this fixture drives a disk image, and the token exists to stop an operator
    committing a *device*. The gate itself has dedicated coverage in
    ``test_erase_drive.py`` and ``test_safety.py``, including the cases where it
    must refuse.
    """
    return SafetyPolicy(dry_run=False, allow_raw_devices=False,
                        require_confirmation_token=False)


@pytest.fixture
def dry_policy():
    return SafetyPolicy(dry_run=True)


@pytest.fixture(scope="session")
def sample_dir() -> Path:
    """A directory of valid sample files, built once per session."""
    from tools.sample_files import sample_catalogue

    target = Path(_TEMP_HOME) / "samples"
    target.mkdir(parents=True, exist_ok=True)
    for name, data in sample_catalogue().items():
        path = target / name
        if not path.exists():
            path.write_bytes(data)
    return target


@pytest.fixture(scope="session")
def test_media(tmp_path_factory) -> Path:
    """
    The generated evidence images and their manifest.

    Built once per session because constructing them runs the real erasure
    engine (the wiped image comes from the code under test) and that is not
    cheap.
    """
    from tools.make_test_media import build_all

    output = tmp_path_factory.mktemp("media")
    build_all(output)
    return output


@pytest.fixture(scope="session")
def manifest(test_media) -> dict:
    import json

    return json.loads((test_media / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture
def scratch_image(tmp_path, test_media, manifest) -> Path:
    """
    A writable copy of the blank scratch image.

    Copied per-test because erasure tests destroy their target, and a shared
    fixture would make test outcomes depend on execution order.
    """
    import shutil

    source = test_media / manifest["scenarios"]["scratch"]["image"]
    destination = tmp_path / "scratch.img"
    shutil.copy2(source, destination)
    return destination
