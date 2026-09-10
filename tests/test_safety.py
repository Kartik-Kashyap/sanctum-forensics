"""
Safety-guard tests.

This is the most important test module in the suite. Everything else measures
whether SANCTUM works; this measures whether it refuses to work when it should.
A bug in the erasure engine costs a demo. A bug here costs somebody's disk.

The design claim being tested is that a mistake requires *several* independent
failures - policy flag, environment unlock, confirmation token - rather than
one.
"""

from __future__ import annotations

import os

import pytest

from sanctum.config import ALLOW_RAW_DEVICE_ENV, BASE_DIR, SafetyPolicy, runtime_allows_raw_devices
from sanctum.core.targets import (
    EraseTarget,
    MediaType,
    SafetyViolation,
    TargetKind,
    classify_kind,
    describe_target,
    is_filesystem_root,
    is_inside_sanctum_home,
    is_os_directory,
    is_system_path,
    validate_for_erasure,
    verify_confirmation,
)


def _image(path, size: int = 4096) -> EraseTarget:
    path.write_bytes(b"\x00" * size)
    return describe_target(str(path), kind=TargetKind.DISK_IMAGE)


# -- SANCTUM's own data directory ------------------------------------------

def test_refuses_to_target_its_own_data_directory(tmp_path):
    """
    Wiping the folder that holds the audit chain would destroy the record of the
    wipe - a self-defeating operation, and a plausible accident.
    """
    inside = BASE_DIR / "cases" / "some-case"
    inside.mkdir(parents=True, exist_ok=True)
    target = EraseTarget(path=str(inside), kind=TargetKind.DISK_IMAGE, size_bytes=1024)

    with pytest.raises(SafetyViolation, match="SANCTUM's own data directory"):
        validate_for_erasure(target, SafetyPolicy(dry_run=False, allow_raw_devices=True))


def test_is_inside_sanctum_home_is_containment_not_prefix():
    assert is_inside_sanctum_home(BASE_DIR / "logs" / "audit.jsonl")
    assert is_inside_sanctum_home(BASE_DIR)
    # A sibling directory whose name merely starts with the same characters.
    assert not is_inside_sanctum_home(str(BASE_DIR) + "-backup")


# -- the running operating system ------------------------------------------

def test_refuses_a_target_flagged_as_the_running_system():
    target = EraseTarget(
        path=r"\\.\PhysicalDrive0",
        kind=TargetKind.BLOCK_DEVICE,
        size_bytes=500 * 1024 ** 3,
        is_system=True,
    )
    with pytest.raises(SafetyViolation, match="running operating system"):
        validate_for_erasure(
            target, SafetyPolicy(dry_run=False, allow_raw_devices=True, allow_system_targets=False)
        )


def test_system_refusal_is_auditable_as_a_denial(tmp_path):
    """A refusal must be an exception the caller can record, not a silent no-op."""
    from sanctum.core.audit import AuditChain

    chain = AuditChain(tmp_path / "audit.jsonl")
    target = EraseTarget(path=r"\\.\PhysicalDrive0", kind=TargetKind.BLOCK_DEVICE,
                         size_bytes=1, is_system=True)
    with pytest.raises(SafetyViolation):
        validate_for_erasure(target, SafetyPolicy(dry_run=False))
    chain.log("SAFETY", "erasure_refused", outcome="DENIED", target=target.path,
              details={"reason": "system drive"})
    assert chain.verify().ok


# -- raw device interlocks -------------------------------------------------

def test_raw_device_refused_without_the_policy_flag():
    target = EraseTarget(path=r"\\.\PhysicalDrive1", kind=TargetKind.BLOCK_DEVICE,
                         size_bytes=1024, is_system=False)
    with pytest.raises(SafetyViolation, match="Raw device access is disabled"):
        validate_for_erasure(target, SafetyPolicy(dry_run=False, allow_raw_devices=False))


def test_raw_device_refused_without_the_environment_unlock(monkeypatch):
    """
    The second key. A misclick cannot set an environment variable, which is the
    entire point of requiring one.
    """
    monkeypatch.delenv(ALLOW_RAW_DEVICE_ENV, raising=False)
    target = EraseTarget(path=r"\\.\PhysicalDrive1", kind=TargetKind.BLOCK_DEVICE,
                         size_bytes=1024, is_system=False)

    with pytest.raises(SafetyViolation, match="SANCTUM_ALLOW_RAW_DEVICE"):
        validate_for_erasure(target, SafetyPolicy(dry_run=False, allow_raw_devices=True))


def test_raw_device_accepted_only_with_both_keys(monkeypatch):
    monkeypatch.setenv(ALLOW_RAW_DEVICE_ENV, "1")
    assert runtime_allows_raw_devices()

    target = EraseTarget(path=r"\\.\PhysicalDrive1", kind=TargetKind.BLOCK_DEVICE,
                         size_bytes=1024, is_system=False)
    # Both keys present: this one does not raise.
    validate_for_erasure(target, SafetyPolicy(dry_run=False, allow_raw_devices=True))


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("maybe", False),
])
def test_environment_unlock_parsing(monkeypatch, value, expected):
    monkeypatch.setenv(ALLOW_RAW_DEVICE_ENV, value)
    assert runtime_allows_raw_devices() is expected


# -- unmeasurable and missing targets --------------------------------------

def test_refuses_a_device_whose_size_cannot_be_determined(monkeypatch):
    """
    An unmeasurable target cannot be verified afterwards, so a 'success' would
    be unverifiable. Refusing is the honest answer.
    """
    monkeypatch.setenv(ALLOW_RAW_DEVICE_ENV, "1")  # both keys present, so the
    target = EraseTarget(path=r"\\.\PhysicalDrive1", kind=TargetKind.BLOCK_DEVICE,
                         size_bytes=0, is_system=False)  # size check is what fires
    with pytest.raises(SafetyViolation, match="Could not determine target size"):
        validate_for_erasure(target, SafetyPolicy(dry_run=False, allow_raw_devices=True))


def test_refuses_a_nonexistent_image(tmp_path):
    target = EraseTarget(path=str(tmp_path / "nope.img"), kind=TargetKind.DISK_IMAGE,
                         size_bytes=1024)
    with pytest.raises(SafetyViolation, match="does not exist"):
        validate_for_erasure(target, SafetyPolicy(dry_run=False))


def test_refuses_an_empty_path():
    with pytest.raises(SafetyViolation, match="empty"):
        validate_for_erasure(EraseTarget(path="", kind=TargetKind.DISK_IMAGE), SafetyPolicy())


def test_accepts_a_writable_image(tmp_path, safe_policy):
    validate_for_erasure(_image(tmp_path / "ok.img"), safe_policy)


# -- the device-vs-file distinction ----------------------------------------

def test_system_path_check_is_drive_based_and_therefore_wrong_for_files(tmp_path):
    """
    The bug this separation exists to prevent.

    ``is_system_path`` is drive-letter based, so on Windows it flags *everything*
    on ``C:`` - including the operator's own Documents folder. Using it as the
    guard for file deletion would refuse legitimate work.
    """
    if os.name != "nt":
        pytest.skip("drive-letter semantics are Windows-specific")

    documents = os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Documents", "notes.txt")
    assert is_system_path(documents) is True       # too broad for file work
    assert is_os_directory(documents) is False     # correctly narrow


def test_os_directory_accepts_system_locations():
    for variable in ("SystemRoot", "ProgramFiles", "ProgramData"):
        value = os.environ.get(variable)
        if not value:
            continue
        assert is_os_directory(os.path.join(value, "some.dll")), variable


def test_os_directory_rejects_an_ordinary_user_folder(tmp_path):
    assert not is_os_directory(tmp_path / "holiday-photos")


@pytest.mark.parametrize("path", ["/", "\\", "C:\\", "C:/"])
def test_filesystem_root_detection(path):
    assert is_filesystem_root(path)


def test_filesystem_root_rejects_an_ordinary_path(tmp_path):
    assert not is_filesystem_root(tmp_path / "folder" / "file.txt")


# -- confirmation tokens ---------------------------------------------------

def test_confirmation_token_is_stable_for_the_same_target(tmp_path):
    target = _image(tmp_path / "same.img")
    assert target.confirmation_token() == target.confirmation_token()
    assert len(target.confirmation_token()) == 8


def test_confirmation_token_changes_with_serial():
    """
    A token shown for one device must never validate for another.

    This is the protection against a stale dialog confirming the wrong drive,
    which is the classic way wipes go catastrophically wrong.
    """
    common = dict(kind=TargetKind.BLOCK_DEVICE, size_bytes=1000)
    a = EraseTarget(path=r"\\.\PhysicalDrive1", serial="SN-AAA", **common)
    b = EraseTarget(path=r"\\.\PhysicalDrive1", serial="SN-BBB", **common)
    assert a.confirmation_token() != b.confirmation_token()


def test_confirmation_token_changes_with_size():
    common = dict(kind=TargetKind.BLOCK_DEVICE, path=r"\\.\PhysicalDrive1", serial="SN")
    assert (
        EraseTarget(size_bytes=1000, **common).confirmation_token()
        != EraseTarget(size_bytes=2000, **common).confirmation_token()
    )


def test_confirmation_token_changes_with_kind(tmp_path):
    path = str(tmp_path / "x.img")
    as_image = EraseTarget(path=path, kind=TargetKind.DISK_IMAGE, size_bytes=10)
    as_device = EraseTarget(path=path, kind=TargetKind.BLOCK_DEVICE, size_bytes=10)
    assert as_image.confirmation_token() != as_device.confirmation_token()


def test_verify_confirmation_accepts_correct_token_and_is_case_insensitive(tmp_path):
    target = _image(tmp_path / "tok.img")
    verify_confirmation(target, target.confirmation_token())
    verify_confirmation(target, target.confirmation_token().lower())


def test_verify_confirmation_rejects_a_wrong_token(tmp_path):
    target = _image(tmp_path / "tok.img")
    with pytest.raises(SafetyViolation, match="Confirmation token mismatch"):
        verify_confirmation(target, "DEADBEEF")


def test_verify_confirmation_rejects_an_empty_token(tmp_path):
    target = _image(tmp_path / "tok.img")
    with pytest.raises(SafetyViolation):
        verify_confirmation(target, "")


# -- classification --------------------------------------------------------

def test_classify_kind_recognises_image_extensions(tmp_path):
    for name in ("a.img", "b.dd", "c.raw", "d.iso", "e.001", "f.E01"):
        path = tmp_path / name
        path.write_bytes(b"x")
        assert classify_kind(str(path)) is TargetKind.DISK_IMAGE, name


def test_classify_kind_recognises_directories_and_files(tmp_path):
    (tmp_path / "folder").mkdir()
    (tmp_path / "plain.txt").write_text("x")
    assert classify_kind(str(tmp_path / "folder")) is TargetKind.FOLDER
    assert classify_kind(str(tmp_path / "plain.txt")) is TargetKind.FILE


def test_images_are_reported_as_virtual_media(tmp_path):
    """A disk image is not flash media, so the overwrite warning must not fire."""
    assert _image(tmp_path / "v.img").media_type is MediaType.VIRTUAL


def test_describe_target_marks_an_image_as_not_system(tmp_path):
    assert _image(tmp_path / "s.img").is_system is False


def test_describe_target_marks_an_os_directory_as_system():
    root = os.environ.get("SystemRoot")
    if not root:
        pytest.skip("Windows-specific")
    assert describe_target(root).is_system is True


def test_describe_target_marks_an_ordinary_folder_as_not_system(tmp_path):
    folder = tmp_path / "my-stuff"
    folder.mkdir()
    assert describe_target(str(folder)).is_system is False


def test_erase_target_short_name_falls_back_to_the_path():
    assert EraseTarget(path="/tmp/x.img", kind=TargetKind.DISK_IMAGE).short_name == "x.img"
