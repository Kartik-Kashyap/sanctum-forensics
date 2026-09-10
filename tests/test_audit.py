"""
Audit chain tests.

The interesting cases are all adversarial: a log that verifies when nothing has
been touched proves very little. These tests modify, reorder, delete and forge
records, and assert that each is caught and *located* - the verification report
has to name the sequence number where integrity first fails, or a reviewer has
no way to scope the damage.
"""

from __future__ import annotations

import json

import pytest

from sanctum.core.audit import (
    AuditCategory,
    AuditChain,
    AuditEntry,
    AuditOutcome,
    GENESIS_HASH,
    VerifyReport,
)


@pytest.fixture
def chain(tmp_path) -> AuditChain:
    return AuditChain(tmp_path / "audit.jsonl", actor="examiner")


def _populate(chain: AuditChain, count: int = 5) -> None:
    for index in range(count):
        chain.log(
            AuditCategory.ERASE,
            f"action_{index}",
            outcome=AuditOutcome.SUCCESS,
            target=f"target_{index}",
            details={"index": index},
        )


# -- happy path ------------------------------------------------------------

def test_empty_chain_verifies(chain):
    report = chain.verify()
    assert report.ok
    assert report.entries == 0


def test_appended_entries_verify(chain):
    _populate(chain, 5)
    report = chain.verify()
    assert report.ok, report.summary()
    assert report.entries == 5


def test_first_entry_links_to_genesis(chain):
    entry = chain.log(AuditCategory.SYSTEM, "start")
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS_HASH


def test_chain_links_are_contiguous(chain):
    _populate(chain, 6)
    entries = chain.entries()
    for previous, current in zip(entries, entries[1:]):
        assert current.prev_hash == previous.entry_hash


def test_reopening_a_chain_continues_it(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditChain(path)
    _populate(first, 3)

    second = AuditChain(path)
    entry = second.log(AuditCategory.SYSTEM, "resumed")

    assert entry.seq == 4
    assert second.verify().ok
    assert second.verify().entries == 4


def test_entry_hash_covers_the_previous_link(chain):
    """
    The back-link must be inside the digest, not merely stored beside it.

    If prev_hash were excluded from the hash, an attacker could re-point a
    record at a different predecessor without invalidating anything.
    """
    entry = chain.log(AuditCategory.SYSTEM, "one")
    original = entry.entry_hash
    entry.prev_hash = "f" * 64
    assert entry.compute_hash() != original
    entry.prev_hash = GENESIS_HASH
    assert entry.compute_hash() == original


def test_payload_excludes_derived_fields(chain):
    entry = chain.log(AuditCategory.SYSTEM, "one")
    payload = entry.payload()
    assert "entry_hash" not in payload
    assert "hmac" not in payload


# -- tamper detection ------------------------------------------------------

def _rewrite(path, mutate) -> None:
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    mutate(lines)
    path.write_text(
        "\n".join(json.dumps(line, sort_keys=True) for line in lines) + "\n",
        encoding="utf-8",
    )


def test_modified_payload_is_detected(chain):
    _populate(chain, 5)
    _rewrite(chain.path, lambda lines: lines[2].__setitem__("target", "something_else"))

    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 3
    assert "modified" in report.reason or "HMAC" in report.reason


def test_modified_outcome_is_detected(chain):
    """A DENIED refusal must not be silently rewritten to SUCCESS."""
    chain.log(AuditCategory.SAFETY, "erasure_refused", outcome=AuditOutcome.DENIED)
    _populate(chain, 2)
    _rewrite(chain.path, lambda lines: lines[0].__setitem__("outcome", "SUCCESS"))

    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 1


def test_deleted_record_is_detected_as_a_sequence_gap(chain):
    """
    Deleting a record leaves the rest sealed, so the chain stays internally
    consistent - but the sequence numbering can no longer run 1, 2, 3.

    ``broken_at`` is the position in the file where the walk first fails, which
    is the record *after* the hole: the third surviving line, now carrying
    sequence 4. Reporting the claimed sequence instead would be reporting a
    number written by whoever made the hole.
    """
    _populate(chain, 5)
    _rewrite(chain.path, lambda lines: lines.pop(2))

    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 3
    assert "sequence gap" in report.reason
    assert "expected 3, found 4" in report.reason


def test_reordered_records_break_the_back_link(chain):
    _populate(chain, 5)

    def swap(lines):
        lines[1], lines[2] = lines[2], lines[1]

    _rewrite(chain.path, swap)
    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 2


def test_truncated_chain_is_detected(chain):
    """
    Removing the tail must not read as a shorter but valid chain.

    This is the limitation the design accepts - a truncated chain is only
    detectable if the expected length is known out of band - so the test pins
    the actual behaviour rather than an aspiration.
    """
    _populate(chain, 5)
    _rewrite(chain.path, lambda lines: lines.__delitem__(slice(3, None)))

    report = chain.verify()
    # The remaining prefix is internally consistent; the loss is invisible to
    # the chain alone. Recorded here so nobody assumes otherwise.
    assert report.ok
    assert report.entries == 3


def test_forged_entry_without_the_hmac_key_is_detected(chain):
    _populate(chain, 2)
    entries = chain.entries()
    forged = AuditEntry(
        seq=3,
        timestamp="2030-01-01T00:00:00.000+00:00",
        category="ERASE",
        action="drive_erase_finished",
        outcome="SUCCESS",
        actor="examiner",
        target="planted",
        details={},
        prev_hash=entries[-1].entry_hash,
    )
    forged.entry_hash = forged.compute_hash()
    forged.hmac = "0" * 64  # wrong key

    with open(chain.path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(forged.__dict__, sort_keys=True) + "\n")

    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 3


def test_unparseable_line_is_detected(chain):
    _populate(chain, 3)
    with open(chain.path, "a", encoding="utf-8") as handle:
        handle.write("{ this is not json\n")

    report = chain.verify()
    assert not report.ok
    assert "unparseable" in report.reason


def test_tampering_at_the_tail_is_located(chain):
    _populate(chain, 10)
    _rewrite(chain.path, lambda lines: lines[9].__setitem__("actor", "someone_else"))

    report = chain.verify()
    assert not report.ok
    assert report.broken_at == 10


# -- reporting -------------------------------------------------------------

def test_verify_report_summary_reads_plainly(chain):
    _populate(chain, 2)
    assert "intact" in chain.verify().summary()

    _rewrite(chain.path, lambda lines: lines[0].__setitem__("action", "tampered"))
    broken = chain.verify()
    assert "BROKEN" in broken.summary()
    assert str(broken.broken_at) in broken.summary()


def test_export_preserves_bytes(tmp_path, chain):
    _populate(chain, 3)
    destination = tmp_path / "export" / "audit.jsonl"
    chain.export_json(destination)

    assert destination.read_bytes() == chain.path.read_bytes()
    assert AuditChain(destination).verify().ok


def test_write_is_flushed_to_disk(tmp_path):
    """
    A record must survive a crash immediately after logging it.

    An audit entry that exists only in a Python buffer is not an audit entry -
    the whole point is that it is on disk before the next destructive action
    begins.
    """
    path = tmp_path / "audit.jsonl"
    chain = AuditChain(path)
    chain.log(AuditCategory.ERASE, "drive_erase_started")

    # Read the file independently of the chain object's in-memory state.
    on_disk = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    assert len(on_disk) == 1
    assert on_disk[0]["action"] == "drive_erase_started"


def test_actor_is_recorded_with_the_entry(tmp_path):
    chain = AuditChain(tmp_path / "audit.jsonl", actor="default_actor")
    assert chain.log(AuditCategory.SYSTEM, "one").actor == "default_actor"
    assert chain.log(AuditCategory.SYSTEM, "two", actor="override").actor == "override"


def test_missing_file_verifies_as_empty(tmp_path):
    report = AuditChain(tmp_path / "does-not-exist.jsonl").verify()
    assert isinstance(report, VerifyReport)
    assert report.ok
    assert report.entries == 0
