"""
Secure File & Folder Eraser tests.

Deleting a file does not erase its bytes, so the claims worth testing are
ordering claims: the content must be overwritten *before* the directory entry
disappears, the original name must be gone from the entry, and the guards must
refuse OS-owned locations without refusing the operator's own documents.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sanctum.config import BASE_DIR, SafetyPolicy
from sanctum.core.audit import AuditChain, AuditOutcome
from sanctum.core.progress import CancelToken
from sanctum.erase.file import FileEraser


@pytest.fixture
def eraser():
    return FileEraser()


def _secret(tmp_path, name: str = "secrets.txt", size: int = 8192) -> Path:
    """A file of exactly ``size`` bytes, so pass arithmetic can be asserted."""
    payload = b"TOP-SECRET-PAYLOAD"
    path = tmp_path / name
    path.write_bytes((payload * (size // len(payload) + 1))[:size])
    return path


# -- dry run ---------------------------------------------------------------

def test_dry_run_leaves_the_file_untouched(tmp_path, eraser, dry_policy):
    path = _secret(tmp_path)
    before = path.read_bytes()

    result = eraser.secure_delete_file(path, "dod3", policy=dry_policy)

    assert result.success
    assert result.dry_run
    assert path.exists()
    assert path.read_bytes() == before
    assert "untouched" in result.headline()


# -- the core claim: overwrite happens before unlink ----------------------

def test_content_is_overwritten_before_the_file_is_unlinked(tmp_path, eraser, safe_policy):
    """
    The claim the whole module rests on.

    Observing it needs the bytes at the moment of unlink, so ``os.remove`` is
    wrapped for the duration of the test. ``cleanse_metadata`` is off because
    the metadata phase truncates the file, which would erase the evidence of the
    overwrite before we could look at it.
    """
    path = _secret(tmp_path)
    captured: dict[str, bytes] = {}
    real_remove = os.remove

    def capture(target, *args, **kwargs):
        candidate = Path(target)
        if candidate.exists() and candidate.is_file():
            captured["data"] = candidate.read_bytes()
        return real_remove(target, *args, **kwargs)

    import sanctum.erase.file as module

    original = module.os.remove
    module.os.remove = capture
    try:
        result = eraser.secure_delete_file(path, "zero1", policy=safe_policy,
                                           cleanse_metadata=False)
    finally:
        module.os.remove = original

    assert result.success
    assert "data" in captured, "the file was never unlinked through os.remove"
    assert set(captured["data"]) == {0}, "bytes were still present at unlink time"
    assert not path.exists()


def test_a_multi_pass_standard_overwrites_the_full_length_each_time(tmp_path, eraser, safe_policy):
    path = _secret(tmp_path, size=4096)
    result = eraser.secure_delete_file(path, "dod3", policy=safe_policy)

    assert result.passes_executed == 3
    assert result.bytes_overwritten == 4096 * 3


def test_the_result_reports_success_and_verification(tmp_path, eraser, safe_policy):
    path = _secret(tmp_path)
    result = eraser.secure_delete_file(path, "zero1", policy=safe_policy)

    assert result.success
    assert result.verified is True
    assert not path.exists()
    assert result.headline() == "Securely deleted"


# -- metadata cleansing ----------------------------------------------------

def test_metadata_cleansing_renames_to_a_same_length_name(tmp_path, eraser, safe_policy):
    """
    A rename of identical length stops the original filename sitting in the
    directory entry without changing the entry's size field.
    """
    path = _secret(tmp_path, name="Quarterly-Fraud-Report.txt")
    original_name = path.name

    result = eraser.secure_delete_file(path, "zero1", policy=safe_policy,
                                       cleanse_metadata=True)

    assert result.renamed_to
    assert Path(result.renamed_to).name != original_name
    assert len(Path(result.renamed_to).name) == len(original_name)
    assert any("Renamed" in action for action in result.metadata_actions)
    assert any("Truncated" in action for action in result.metadata_actions)
    assert any("Unlinked" in action for action in result.metadata_actions)


def test_metadata_cleansing_records_the_journal_limitation(tmp_path, eraser, safe_policy):
    """
    The rename helps but is not complete. A report that omitted this would
    overstate what was achieved.
    """
    result = eraser.secure_delete_file(_secret(tmp_path), "zero1", policy=safe_policy)

    assert any("journal" in warning.lower() for warning in result.warnings)


def test_metadata_cleansing_can_be_switched_off(tmp_path, eraser, safe_policy):
    result = eraser.secure_delete_file(_secret(tmp_path), "zero1", policy=safe_policy,
                                       cleanse_metadata=False)

    assert result.renamed_to == ""
    assert result.metadata_actions == ["Unlinked directory entry"]
    assert result.warnings == []


# -- refusals --------------------------------------------------------------

def test_refuses_a_file_inside_sanctums_own_store(tmp_path, eraser, safe_policy):
    inside = BASE_DIR / "cases" / "operator-notes.txt"
    inside.parent.mkdir(parents=True, exist_ok=True)
    inside.write_bytes(b"do not delete me")

    result = eraser.secure_delete_file(inside, "zero1", policy=safe_policy)

    assert not result.success
    assert "SANCTUM's own data directory" in result.error
    assert inside.exists()


def test_refuses_a_filesystem_root(tmp_path, eraser, safe_policy):
    root = Path(tmp_path.anchor)  # e.g. "C:\\"
    result = eraser.secure_delete_file(root, "zero1", policy=safe_policy)

    assert not result.success
    assert "filesystem root" in result.error or "whole drive" in result.error


def test_refuses_an_operating_system_directory(tmp_path, eraser, safe_policy, monkeypatch):
    """
    The guard is exercised by making an ordinary temporary directory report as
    OS-owned, rather than by aiming a delete at a real system path. A test that
    only passes because the guard works is not worth the risk of it not working.
    """
    monkeypatch.setattr("sanctum.erase.file.is_os_directory", lambda path: True)
    victim = _secret(tmp_path, "looks-like-a-system-file.dll")

    result = eraser.secure_delete_file(victim, "zero1", policy=safe_policy)

    assert not result.success
    assert "operating-system" in result.error
    assert victim.exists()


def test_refuses_a_nonexistent_file(tmp_path, eraser, safe_policy):
    result = eraser.secure_delete_file(tmp_path / "ghost.txt", "zero1", policy=safe_policy)
    assert not result.success
    assert "does not exist" in result.error


def test_refusal_is_audited_as_denied(tmp_path, eraser, safe_policy):
    chain = AuditChain(tmp_path / "audit.jsonl")
    eraser_with_audit = FileEraser(chain)
    eraser_with_audit.secure_delete_file(tmp_path / "ghost.txt", "zero1", policy=safe_policy)

    assert chain.entries()[-1].outcome == AuditOutcome.DENIED.value
    assert chain.verify().ok


def test_refusal_is_a_result_not_an_exception(tmp_path, eraser, safe_policy):
    """
    A batch must be able to continue past a refused entry and report it,
    so a refusal cannot be raised out of the batch loop.
    """
    result = eraser.secure_delete_file(tmp_path / "ghost.txt", "zero1", policy=safe_policy)
    assert result.error


# -- audit -----------------------------------------------------------------

def test_a_deletion_is_bracketed_in_the_audit_chain(tmp_path, safe_policy):
    chain = AuditChain(tmp_path / "audit.jsonl")
    path = _secret(tmp_path)

    FileEraser(chain).secure_delete_file(path, "zero1", policy=safe_policy)

    actions = [entry.action for entry in chain.entries()]
    assert actions == ["file_erase_started", "file_erase_finished"]
    assert chain.entries()[-1].outcome == AuditOutcome.SUCCESS.value
    assert chain.verify().ok


# -- batch -----------------------------------------------------------------

def test_batch_deletes_every_listed_file(tmp_path, eraser, safe_policy):
    paths = [_secret(tmp_path, f"f{index}.txt") for index in range(4)]
    batch = eraser.secure_delete_paths(paths, "zero1", policy=safe_policy)

    assert batch.total == 4
    assert batch.succeeded == 4
    assert batch.failed == 0
    assert not any(path.exists() for path in paths)
    assert batch.as_dict()["operation"] == "file_erase"


def test_batch_removes_a_folder_tree(tmp_path, eraser, safe_policy):
    """
    Contents are overwritten before the directory entries disappear - deleting
    the tree first would leave the files unreachable and un-overwritable.
    """
    tree = tmp_path / "evidence"
    (tree / "nested").mkdir(parents=True)
    for name in ("a.txt", "b.txt", "nested/c.txt", "nested/d.txt"):
        (tree / name).write_bytes(b"data" * 512)

    batch = eraser.secure_delete_paths([tree], "zero1", policy=safe_policy)

    assert not tree.exists()
    assert batch.failed == 0
    assert batch.total >= 4


def test_batch_reports_partial_failure(tmp_path, eraser, safe_policy):
    good = _secret(tmp_path, "good.txt")
    batch = eraser.secure_delete_paths([good, tmp_path / "ghost.txt"], "zero1",
                                       policy=safe_policy)

    assert batch.total == 2
    assert batch.succeeded == 1
    assert batch.failed == 1
    assert not good.exists()


def test_empty_batch_is_not_an_error(tmp_path, eraser, safe_policy):
    batch = eraser.secure_delete_paths([], "zero1", policy=safe_policy)
    assert batch.total == 0
    assert batch.finished_at


def test_batch_honours_cancellation(tmp_path, eraser, safe_policy):
    paths = [_secret(tmp_path, f"f{index}.txt") for index in range(4)]
    token = CancelToken()
    token.cancel()

    from sanctum.core.progress import OperationCancelled

    with pytest.raises(OperationCancelled):
        eraser.secure_delete_paths(paths, "zero1", policy=safe_policy, cancel=token)


# -- free space sweep ------------------------------------------------------

def test_free_space_dry_run_writes_nothing(tmp_path, eraser, dry_policy):
    result = eraser.wipe_free_space(tmp_path, "random1", policy=dry_policy, max_bytes=1024)

    assert result.success
    assert result.dry_run
    assert result.bytes_written == 0
    assert not list(tmp_path.glob(".sanctum_freespace_*"))


def test_free_space_sweep_writes_and_cleans_up_its_scratch_files(tmp_path, eraser, safe_policy):
    """
    The sweep's own filler files must never be left behind - leaving them would
    be worse than not sweeping at all.
    """
    result = eraser.wipe_free_space(tmp_path, "random1", policy=safe_policy,
                                    max_bytes=256 * 1024)

    assert result.success
    assert result.bytes_written >= 256 * 1024
    assert result.files_created >= 1
    assert not list(tmp_path.glob(".sanctum_freespace_*"))
    assert result.headline().startswith("Overwrote")


def test_a_multi_pass_sweep_overwrites_the_space_once_per_pass(tmp_path, eraser, safe_policy):
    """
    Every pass must get its turn at the same clusters.

    A sweep works by consuming the volume's free space. If one pass's filler
    files are still present when the next begins, the volume is already full and
    the next pass writes nothing - while the result still reports
    ``passes_executed: 3``. That is a compliance claim the tool would be making
    without having done the work, so the byte count is asserted against the
    number of passes rather than merely against zero.
    """
    budget = 256 * 1024
    result = eraser.wipe_free_space(tmp_path, "dod3", policy=safe_policy, max_bytes=budget)

    assert result.success
    assert result.passes_executed == 3
    assert result.bytes_written >= 3 * budget, (
        "the sweep wrote less than one budget per pass - the space was not "
        "released between passes, so later passes had nothing to overwrite"
    )


def test_the_sweep_fills_with_many_files_not_one_enormous_one(tmp_path, eraser, safe_policy,
                                                              monkeypatch):
    """
    A single filler file large enough to fill a volume would hit FAT32's 4 GiB
    per-file ceiling, which is where a USB stick - the most likely target for
    this module - would silently stop part-way and still report success.

    The per-file bound is lowered rather than writing gigabytes, so what is
    under test is the loop's structure, not the specific size.
    """
    monkeypatch.setattr("sanctum.erase.file._FILL_FILE_BYTES", 64 * 1024)
    result = eraser.wipe_free_space(tmp_path, "random1", policy=safe_policy,
                                    max_bytes=256 * 1024)

    assert result.success
    assert result.bytes_written >= 256 * 1024
    assert result.files_created >= 4, (
        f"only {result.files_created} filler file(s) were created for 256 KiB at a "
        "64 KiB per-file bound - the fill is not bounded per file"
    )


def test_free_space_sweep_states_its_limitations(tmp_path, eraser, safe_policy):
    result = eraser.wipe_free_space(tmp_path, "zero1", policy=safe_policy, max_bytes=64 * 1024)

    assert any("slack space" in warning for warning in result.warnings)
    assert any("journal" in warning for warning in result.warnings)


def test_free_space_sweep_warns_about_filling_an_os_volume(tmp_path, eraser, safe_policy,
                                                           monkeypatch):
    monkeypatch.setattr("sanctum.erase.file.is_os_directory", lambda path: True)
    result = eraser.wipe_free_space(tmp_path, "zero1", policy=safe_policy, max_bytes=1024)

    assert any("operating-system volume" in warning for warning in result.warnings)


def test_free_space_sweep_refuses_a_nonexistent_root(tmp_path, eraser, safe_policy):
    result = eraser.wipe_free_space(tmp_path / "nope", "zero1", policy=safe_policy)
    assert not result.success
    assert result.error


def test_free_space_sweep_refuses_a_file_as_its_root(tmp_path, eraser, safe_policy):
    path = _secret(tmp_path)
    result = eraser.wipe_free_space(path, "zero1", policy=safe_policy)

    assert not result.success
    assert "directory" in result.error.lower()


def test_free_space_sweep_is_audited(tmp_path, safe_policy):
    chain = AuditChain(tmp_path / "audit.jsonl")
    FileEraser(chain).wipe_free_space(tmp_path, "zero1", policy=safe_policy,
                                     max_bytes=32 * 1024)

    actions = [entry.action for entry in chain.entries()]
    assert actions == ["free_space_wipe_started", "free_space_wipe_finished"]
    assert chain.verify().ok


def test_free_space_sweep_reports_progress(tmp_path, eraser, safe_policy):
    seen: list = []
    eraser.wipe_free_space(tmp_path, "zero1", policy=safe_policy, max_bytes=128 * 1024,
                           progress=seen.append)
    assert seen
    assert any("Free space" in update.phase for update in seen)


# -- zero-length files -----------------------------------------------------

def test_an_empty_file_is_deleted_without_a_write_pass(tmp_path, eraser, safe_policy):
    """
    There is nothing to overwrite, but the directory entry still has to go -
    and reporting a zero-byte overwrite as a pass would be misleading.
    """
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")

    result = eraser.secure_delete_file(path, "zero1", policy=safe_policy)

    assert result.success
    assert result.size_bytes == 0
    assert result.bytes_overwritten == 0
    assert result.passes_executed == 0
    assert not path.exists()
