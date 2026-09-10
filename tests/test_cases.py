"""
Case management tests.

A forensic result is only defensible if it is attached to a named case with its
own audit chain and evidence register, and if that record survives being closed
and reopened. These tests cover both the round trip and the containment rules
that stop a case operation reaching outside the cases directory.
"""

from __future__ import annotations

import json

import pytest

from sanctum.cases import Case, CaseManager
from sanctum.core.audit import AuditCategory


@pytest.fixture
def manager(tmp_path):
    return CaseManager(base_dir=tmp_path / "cases")


def _evidence_file(tmp_path, name: str = "usb-image.img", size: int = 4096):
    path = tmp_path / name
    path.write_bytes(b"\xab" * size)
    return path


# -- creation --------------------------------------------------------------

def test_create_lays_out_the_case_directory(manager):
    case = manager.create("Operation Falcon", examiner="A. Examiner")

    assert case.path.is_dir()
    assert case.audit_path.exists()
    assert case.artifacts_dir.is_dir()
    assert case.reports_dir.is_dir()
    assert case.meta_path.exists()


def test_create_records_the_examiner_and_description(manager):
    case = manager.create("Falcon", examiner="A. Examiner", description="Test device")
    reloaded = manager.open(case.case_id)

    assert reloaded.name == "Falcon"
    assert reloaded.examiner == "A. Examiner"
    assert reloaded.description == "Test device"


def test_create_writes_a_case_created_audit_entry(manager):
    case = manager.create("Falcon")
    entries = case.audit().entries()

    assert entries[0].action == "case_created"
    assert case.audit().verify().ok


def test_case_ids_are_unique_even_for_identical_names(manager):
    first = manager.create("Same Name")
    second = manager.create("Same Name")
    assert first.case_id != second.case_id


def test_case_ids_are_filesystem_safe_for_awkward_names(manager):
    case = manager.create("Case #1: USB / drive <seized> *test*")
    assert "/" not in case.case_id
    assert "\\" not in case.case_id
    assert ":" not in case.case_id
    assert " " not in case.case_id
    assert case.path.is_dir()


# -- listing and opening ---------------------------------------------------

def test_list_cases_returns_every_case(manager):
    manager.create("One")
    manager.create("Two")
    assert len(manager.list_cases()) == 2


def test_list_cases_is_empty_before_anything_is_created(manager):
    assert manager.list_cases() == []


def test_list_cases_skips_a_corrupt_case_directory(manager):
    """
    One unreadable case must not make the case list unusable - an examiner
    needs to see the others while they investigate the damaged one.
    """
    manager.create("Good")
    broken = manager.base_dir / "broken-case"
    broken.mkdir()
    (broken / "case.json").write_text("{ not valid json", encoding="utf-8")

    summaries = manager.list_cases()
    assert len(summaries) == 1
    assert summaries[0]["name"] == "Good"


def test_open_by_id_round_trips(manager):
    case = manager.create("Falcon")
    assert manager.open(case.case_id).case_id == case.case_id


def test_open_by_directory_path_works(manager):
    case = manager.create("Falcon")
    assert manager.open(case.path).case_id == case.case_id


def test_open_a_missing_case_raises(manager):
    with pytest.raises(FileNotFoundError):
        manager.open("no-such-case")


# -- evidence register -----------------------------------------------------

def test_register_evidence_hashes_the_item_at_intake(manager, tmp_path):
    case = manager.create("Falcon")
    path = _evidence_file(tmp_path)

    item = case.register_evidence(path, "Seized USB image")

    assert item.size_bytes == 4096
    assert len(item.sha256) == 64
    assert len(item.md5) == 32
    assert item.description == "Seized USB image"


def test_evidence_digest_matches_an_independent_hash(manager, tmp_path):
    """
    The chain-of-custody claim rests on this digest, so it must be the real
    digest of the real bytes.
    """
    import hashlib

    case = manager.create("Falcon")
    path = _evidence_file(tmp_path, size=100_000)

    item = case.register_evidence(path)
    assert item.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_registering_a_missing_file_records_it_without_raising(manager, tmp_path):
    """
    Evidence is often registered before it is imaged, so a missing path is
    recorded rather than treated as an error.
    """
    case = manager.create("Falcon")
    item = case.register_evidence(tmp_path / "not-yet.img", "Awaiting transfer")

    assert item.size_bytes == 0
    assert item.sha256 == ""


def test_registering_without_hashing_is_allowed(manager, tmp_path):
    case = manager.create("Falcon")
    item = case.register_evidence(_evidence_file(tmp_path), compute_hash=False)
    assert item.sha256 == ""
    assert item.size_bytes == 4096


def test_evidence_survives_a_save_and_reload(manager, tmp_path):
    case = manager.create("Falcon")
    case.register_evidence(_evidence_file(tmp_path), "Seized USB")
    case.save()

    reloaded = manager.open(case.case_id)
    assert len(reloaded.evidence) == 1
    assert reloaded.evidence[0].sha256 == case.evidence[0].sha256
    assert reloaded.evidence[0].description == "Seized USB"


# -- operations ------------------------------------------------------------

def test_record_operation_appends_and_persists(manager):
    case = manager.create("Falcon")
    case.record_operation("drive_erase", "Wiped scratch.img", {"standard": "dod3"})
    case.save()

    reloaded = manager.open(case.case_id)
    assert len(reloaded.operations) == 1
    assert reloaded.operations[0]["kind"] == "drive_erase"
    assert reloaded.operations[0]["details"]["standard"] == "dod3"


def test_touch_updates_the_timestamp(manager):
    case = manager.create("Falcon")
    original = case.updated_at
    case.touch()
    assert case.updated_at >= original


def test_summary_reports_counts(manager, tmp_path):
    case = manager.create("Falcon")
    case.register_evidence(_evidence_file(tmp_path))
    case.record_operation("file_carving", "Carved scratch.img")

    summary = case.summary()
    assert summary["evidence_count"] == 1
    assert summary["operation_count"] == 1
    assert summary["name"] == "Falcon"


# -- the audit chain is per-case and continuous ---------------------------

def test_each_case_has_its_own_audit_chain(manager):
    first = manager.create("One")
    second = manager.create("Two")

    first.audit().log(AuditCategory.ERASE, "only_in_one")

    assert len(first.audit().entries()) == 2   # case_created + the new entry
    assert len(second.audit().entries()) == 1  # only case_created


def test_the_chain_continues_across_reopening(manager):
    case = manager.create("Falcon")
    case.audit().log(AuditCategory.ERASE, "first_session")

    reopened = manager.open(case.case_id)
    entry = reopened.audit().log(AuditCategory.ERASE, "second_session")

    assert entry.seq == 3
    assert reopened.audit().verify().ok


def test_the_audit_chain_is_not_stored_inside_case_json(manager):
    """The chain is append-only on disk; inlining it would defeat that."""
    case = manager.create("Falcon")
    payload = json.loads(case.meta_path.read_text(encoding="utf-8"))
    assert "audit" not in payload
    assert case.audit_path.name == "audit.jsonl"


# -- deletion --------------------------------------------------------------

def test_delete_removes_the_case_directory(manager):
    case = manager.create("Falcon")
    manager.delete(case.case_id)
    assert not case.path.exists()
    assert manager.list_cases() == []


def test_delete_refuses_a_path_outside_the_cases_directory(manager):
    """
    The containment rule. A traversal or wildcard must not be able to turn
    case cleanup into a deletion anywhere on the filesystem.
    """
    outsider = manager.base_dir.parent / "unrelated"
    outsider.mkdir()

    for attempt in ("../unrelated", str(outsider)):
        with pytest.raises((ValueError, FileNotFoundError)):
            manager.delete(attempt)
    assert outsider.exists()


def test_delete_a_missing_case_raises(manager):
    with pytest.raises(FileNotFoundError):
        manager.delete("no-such-case")


# -- persistence format ----------------------------------------------------

def test_case_json_is_human_readable(manager):
    """A case file an examiner can read in a text editor is a feature."""
    case = manager.create("Falcon", examiner="A. Examiner")
    payload = json.loads(case.meta_path.read_text(encoding="utf-8"))

    assert payload["case_id"] == case.case_id
    assert payload["name"] == "Falcon"
    assert isinstance(payload["evidence"], list)
    assert isinstance(payload["operations"], list)
    assert "\n" in case.meta_path.read_text(encoding="utf-8")


def test_load_from_the_meta_file_directly(manager):
    case = manager.create("Falcon")
    assert Case.load(case.meta_path).case_id == case.case_id
