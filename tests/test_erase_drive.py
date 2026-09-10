"""
Secure Drive Eraser engine tests.

These run against disk *images*, never real devices. That is not a limitation
being worked around - it is the demo mode of the product, and it is the only way
to assert on the resulting bytes, which is what makes the verification claims
checkable rather than asserted.
"""

from __future__ import annotations

import pytest

from sanctum.config import CHUNK_SIZE, SafetyPolicy
from sanctum.core.audit import AuditChain, AuditOutcome
from sanctum.core.progress import CancelToken
from sanctum.core.standards import PassSpec, PatternKind, get_standard
from sanctum.core.targets import (
    EraseTarget,
    MediaType,
    SafetyViolation,
    TargetKind,
    describe_target,
)
from sanctum.erase.drive import DriveEraser
from sanctum.erase.verify import VerifyMode, VerifyOutcome


def _target(path, size: int = 64 * 1024, fill: bytes = b"\xaa") -> EraseTarget:
    """A disk image pre-filled with recognisable content."""
    path.write_bytes(fill * size)
    return describe_target(str(path), kind=TargetKind.DISK_IMAGE)


@pytest.fixture
def image(tmp_path):
    return _target(tmp_path / "evidence.img")


# -- dry run ---------------------------------------------------------------

def test_dry_run_writes_nothing(image, dry_policy):
    before = open(image.path, "rb").read()
    result = DriveEraser().run(image, "dod3", policy=dry_policy)

    assert result.success
    assert result.dry_run
    assert result.passes == []
    assert open(image.path, "rb").read() == before
    assert "no data was written" in result.headline()


def test_dry_run_still_reports_the_standard_it_would_apply(image, dry_policy):
    result = DriveEraser().run(image, "gutmann", policy=dry_policy)
    assert result.standard.id == "gutmann"
    assert result.standard.pass_count == 35


# -- execution -------------------------------------------------------------

def test_single_zero_pass_overwrites_the_whole_image(tmp_path, safe_policy):
    image = _target(tmp_path / "z.img", size=32 * 1024, fill=b"\xaa")
    result = DriveEraser().run(image, "zero1", policy=safe_policy,
                               verify=True, verify_mode=VerifyMode.FULL)

    assert result.success
    assert result.verified is True
    assert result.passes[0].bytes_written == 32 * 1024

    on_disk = open(image.path, "rb").read()
    assert set(on_disk) == {0}


def test_a_three_pass_standard_executes_three_passes(tmp_path, safe_policy):
    image = _target(tmp_path / "d.img", size=16 * 1024)
    result = DriveEraser().run(image, "dod3", policy=safe_policy)

    assert result.total_passes == 3
    assert [p.index for p in result.passes] == [1, 2, 3]


def test_verification_runs_when_asked(tmp_path, safe_policy):
    image = _target(tmp_path / "v.img", size=16 * 1024)
    result = DriveEraser().run(image, "zero1", policy=safe_policy,
                               verify=True, verify_mode=VerifyMode.FULL)

    assert result.passes[0].verification is not None
    assert result.passes[0].verification.passed
    assert result.verified is True


def test_verification_skipped_reports_none_not_false(tmp_path, safe_policy):
    """
    "Not checked" and "checked and failed" must not collapse into the same
    value - a report that cannot tell them apart is misleading.
    """
    image = _target(tmp_path / "n.img", size=16 * 1024)
    result = DriveEraser().run(image, "zero1", policy=safe_policy,
                               verify=False, verify_mode=VerifyMode.FULL)

    assert result.passes[0].verification is None
    assert result.verified is None
    assert "unverified" in result.headline()


def test_random_pass_leaves_high_entropy_data(tmp_path, safe_policy):
    from sanctum.core.hashing import shannon_entropy

    image = _target(tmp_path / "r.img", size=64 * 1024)
    result = DriveEraser().run(image, "random1", policy=safe_policy,
                               verify=True, verify_mode=VerifyMode.FULL)

    assert result.success
    assert shannon_entropy(open(image.path, "rb").read()) > 7.0


# -- the pattern-phase regression -----------------------------------------

def test_cycling_pattern_stays_in_phase_across_chunk_boundaries(tmp_path, safe_policy):
    """
    End-to-end guard for a bug that a naive implementation has and hides.

    The Gutmann scheme's passes are 3-byte sequences. CHUNK_SIZE is 1 MiB, which
    is not a multiple of 3, so tiling the sequence per chunk shifts its phase
    after the first megabyte: the media stops holding the pattern the standard
    names, while the report still claims compliance. Verification would not
    catch it either, because the checker made the same assumption.

    This writes a cycling pass to a target larger than one chunk and reads the
    bytes back against a single continuous run of the sequence.
    """
    spec = PassSpec(PatternKind.CYCLE, sequence=b"\x92\x49\x24")
    size = CHUNK_SIZE + 5000
    image = _target(tmp_path / "phase.img", size=size)

    result = DriveEraser().run(image, _single_pass_standard(spec), policy=safe_policy,
                               verify=True, verify_mode=VerifyMode.FULL)

    assert result.success
    assert result.verified is True

    on_disk = open(image.path, "rb").read()
    assert on_disk == spec.build_buffer(size)


def _single_pass_standard(spec: PassSpec):
    """Wrap a bare PassSpec so the engine can be pointed at it directly."""
    from sanctum.core.standards import EraseStandard

    return EraseStandard(
        id="test-cycle",
        name="Test cycling pass",
        description="Single cycling pass used by the phase-continuity test.",
        passes=(PassSpec(spec.kind, sequence=spec.sequence, verify=True),),
        compliance=(),
    )


# -- failure handling ------------------------------------------------------

def test_a_failed_verification_aborts_before_the_next_pass(tmp_path, safe_policy, monkeypatch):
    """
    Continuing after a failed verification would overwrite the evidence of the
    failure. The run must stop and say so.
    """
    image = _target(tmp_path / "f.img", size=16 * 1024)

    def always_fails(*args, **kwargs):
        return VerifyOutcome(passed=False, mode=VerifyMode.FULL, windows_checked=1,
                             bytes_checked=16 * 1024)

    monkeypatch.setattr("sanctum.erase.drive.verify_pass", always_fails)

    result = DriveEraser().run(image, "dod3", policy=safe_policy,
                               verify=True, verify_mode=VerifyMode.FULL)

    assert not result.success
    assert result.aborted
    assert result.total_passes == 1  # stopped after the first pass
    assert "failed verification" in result.error
    assert "VERIFICATION FAILURES" in result.headline()


def test_cancellation_before_the_first_pass_aborts_cleanly(image, safe_policy):
    token = CancelToken()
    token.cancel()

    result = DriveEraser().run(image, "dod3", policy=safe_policy, cancel=token)

    assert result.aborted
    assert not result.success
    assert "Cancelled" in result.error


# -- policy enforcement ----------------------------------------------------

def test_a_nonexistent_target_is_refused(tmp_path, safe_policy):
    """A policy refusal is an error, not a completed job with a sad face."""
    target = describe_target(str(tmp_path / "missing.img"), kind=TargetKind.DISK_IMAGE)
    with pytest.raises(SafetyViolation, match="does not exist"):
        DriveEraser().run(target, "zero1", policy=safe_policy)


def test_a_read_only_target_is_refused(tmp_path, safe_policy):
    import os
    import stat as stat_module

    path = tmp_path / "readonly.img"
    path.write_bytes(b"\x00" * 4096)
    target = describe_target(str(path), kind=TargetKind.DISK_IMAGE)
    os.chmod(path, stat_module.S_IREAD)

    try:
        with pytest.raises(SafetyViolation):
            DriveEraser().run(target, "zero1", policy=safe_policy)
    finally:
        os.chmod(path, stat_module.S_IWRITE | stat_module.S_IREAD)


def test_an_unexpected_engine_error_becomes_a_result_not_a_crash(
    tmp_path, safe_policy, monkeypatch
):
    """
    An engine bug must surface in the report and the audit trail, not as a
    traceback that leaves the operator unsure whether anything was written.
    """
    image = _target(tmp_path / "boom.img", size=4096)

    class Exploding:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise OSError("simulated hardware fault")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr("sanctum.erase.drive.TargetWriter", Exploding)

    result = DriveEraser().run(image, "zero1", policy=safe_policy)

    assert not result.success
    assert "simulated hardware fault" in result.error
    assert "FAILED" in result.headline()


def test_confirmation_token_is_required_when_policy_demands_it(image, safe_policy):
    policy = SafetyPolicy(dry_run=False, allow_raw_devices=False,
                          require_confirmation_token=True)
    with pytest.raises(SafetyViolation, match="Confirmation token mismatch"):
        DriveEraser().run(image, "zero1", policy=policy, confirmation="WRONG")

    # The correct token is accepted.
    result = DriveEraser().run(image, "zero1", policy=policy,
                               confirmation=image.confirmation_token())
    assert result.success


def test_refusal_is_audited_as_denied(tmp_path, image):
    chain = AuditChain(tmp_path / "audit.jsonl")
    with pytest.raises(SafetyViolation):
        DriveEraser(chain).run(image, "zero1",
                               policy=SafetyPolicy(dry_run=False, allow_raw_devices=False),
                               confirmation="")

    entries = chain.entries()
    assert entries[-1].action == "erasure_refused"
    assert entries[-1].outcome == AuditOutcome.DENIED.value
    assert chain.verify().ok


# -- audit -----------------------------------------------------------------

def test_a_completed_run_is_bracketed_in_the_audit_chain(tmp_path, safe_policy):
    chain = AuditChain(tmp_path / "audit.jsonl")
    image = _target(tmp_path / "a.img", size=16 * 1024)

    result = DriveEraser(chain).run(image, "zero1", policy=safe_policy)

    actions = [entry.action for entry in chain.entries()]
    assert actions == ["drive_erase_started", "drive_erase_finished"]
    assert chain.entries()[-1].outcome == AuditOutcome.SUCCESS.value
    assert result.audit_range == (1, 2)
    assert chain.verify().ok


def test_a_dry_run_is_audited_too(tmp_path, dry_policy):
    """An operation that was *not* performed is still part of the record."""
    chain = AuditChain(tmp_path / "audit.jsonl")
    image = _target(tmp_path / "d.img", size=4096)
    DriveEraser(chain).run(image, "dod3", policy=dry_policy)

    assert [entry.action for entry in chain.entries()] == [
        "drive_erase_started", "drive_erase_finished"
    ]


def test_an_aborted_run_is_audited_as_a_failure(tmp_path, safe_policy):
    chain = AuditChain(tmp_path / "audit.jsonl")
    image = _target(tmp_path / "c.img", size=4096)
    token = CancelToken()
    token.cancel()

    DriveEraser(chain).run(image, "dod3", policy=safe_policy, cancel=token)
    assert chain.entries()[-1].outcome == AuditOutcome.FAILURE.value


# -- media honesty ---------------------------------------------------------

def test_flash_media_produces_a_wear_levelling_warning(tmp_path, safe_policy):
    """
    An overwrite is not a purge on flash. The engine must say so rather than
    let the report imply otherwise.
    """
    path = tmp_path / "flash.img"
    path.write_bytes(b"\x00" * 4096)
    target = EraseTarget(
        path=str(path), kind=TargetKind.DISK_IMAGE, size_bytes=4096,
        media_type=MediaType.SSD, is_system=False,
    )

    result = DriveEraser().run(target, "zero1", policy=safe_policy)

    assert any("wear-levelling" in w for w in result.warnings)
    assert any("SANITIZE" in w for w in result.warnings)


def test_magnetic_media_produces_no_such_warning(tmp_path, safe_policy):
    path = tmp_path / "hdd.img"
    path.write_bytes(b"\x00" * 4096)
    target = EraseTarget(
        path=str(path), kind=TargetKind.DISK_IMAGE, size_bytes=4096,
        media_type=MediaType.HDD, is_system=False,
    )

    result = DriveEraser().run(target, "zero1", policy=safe_policy)
    assert not any("wear-levelling" in w for w in result.warnings)


# -- reporting -------------------------------------------------------------

def test_result_serialises_for_the_report(tmp_path, safe_policy):
    image = _target(tmp_path / "s.img", size=8192)
    data = DriveEraser().run(image, "zero1", policy=safe_policy,
                             verify=True, verify_mode=VerifyMode.FULL).as_dict()

    assert data["operation"] == "drive_erase"
    assert data["standard"]["id"] == "zero1"
    assert data["target"]["kind"] == TargetKind.DISK_IMAGE.value
    assert data["passes"][0]["verification"]["passed"] is True
    assert data["bytes_total"] == 8192


def test_elapsed_and_throughput_are_recorded(tmp_path, safe_policy):
    image = _target(tmp_path / "t.img", size=256 * 1024)
    result = DriveEraser().run(image, "zero1", policy=safe_policy)

    assert result.elapsed_seconds > 0
    assert result.throughput_mbps > 0
    assert result.finished_at


def test_progress_is_reported_for_each_phase(tmp_path, safe_policy):
    image = _target(tmp_path / "p.img", size=64 * 1024)
    seen: list = []
    DriveEraser().run(image, "zero1", policy=safe_policy,
                      progress=seen.append)

    phases = {update.phase for update in seen}
    assert any(phase.startswith("Pass 1/1") for phase in phases)
    assert seen[-1].completed == 64 * 1024
