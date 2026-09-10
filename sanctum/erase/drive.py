"""
Secure Drive Eraser engine.

Executes a standard's pass sequence over a whole device or disk image, with
optional verification after each pass and a sealed audit record of everything
that happened.

The engine is deliberately generic: it walks whatever pass list the standard
declares (see :mod:`sanctum.core.standards`), so a new regulatory scheme never
requires touching this file.

Two operating modes share the same code path:

* **Image mode** (default) - the target is a ``.img``/``.dd`` file. Every pass,
  verification and report works identically, but the operation is repeatable and
  cannot destroy real data. This is what the demo and the test suite exercise.
* **Device mode** - the target is a physical drive. Requires the raw-device
  policy flag *and* the environment unlock *and* a typed confirmation token,
  and the running system's own drive is refused outright.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sanctum.config import CHUNK_SIZE, SafetyPolicy
from sanctum.core import hashing
from sanctum.core.audit import AuditCategory, AuditChain, AuditOutcome
from sanctum.core.progress import CancelToken, OperationCancelled, ProgressReporter, ProgressUpdate
from sanctum.core.standards import EraseStandard, PassSpec, PatternKind, get_standard
from sanctum.core.targets import (
    EraseTarget,
    MediaType,
    SafetyViolation,
    TargetWriter,
    validate_for_erasure,
    verify_confirmation,
)
from sanctum.erase.verify import VerifyMode, VerifyOutcome, verify_pass


@dataclass
class PassResult:
    """Outcome of one overwrite pass."""

    index: int
    label: str
    bytes_written: int
    duration_seconds: float
    verification: VerifyOutcome | None = None

    @property
    def verified(self) -> bool | None:
        """True/False if verification ran, None if it was skipped."""
        return self.verification.passed if self.verification else None

    def as_dict(self) -> dict:
        data = {
            "pass": self.index,
            "pattern": self.label,
            "bytes_written": self.bytes_written,
            "duration_seconds": round(self.duration_seconds, 3),
            "verified": self.verified,
        }
        if self.verification:
            data["verification"] = {
                "mode": self.verification.mode.value,
                "windows_checked": self.verification.windows_checked,
                "bytes_checked": self.verification.bytes_checked,
                "passed": self.verification.passed,
                "first_mismatch_offset": self.verification.first_mismatch_offset,
            }
        return data


@dataclass
class EraseResult:
    """Complete record of a drive sanitization run."""

    target: EraseTarget
    standard: EraseStandard
    started_at: str
    finished_at: str = ""
    passes: list[PassResult] = field(default_factory=list)
    success: bool = False
    aborted: bool = False
    cancelled: bool = False
    dry_run: bool = False
    bytes_total: int = 0
    elapsed_seconds: float = 0.0
    throughput_mbps: float = 0.0
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    audit_range: tuple[int, int] = (0, 0)

    @property
    def verified(self) -> bool | None:
        """True only if every verified pass passed; None if nothing was verified."""
        checks = [p.verification for p in self.passes if p.verification]
        if not checks:
            return None
        return all(check.passed for check in checks)

    @property
    def total_passes(self) -> int:
        return len(self.passes)

    def headline(self) -> str:
        if self.dry_run:
            return "Dry run - no data was written"
        if self.cancelled:
            # Deliberately distinct from ABORTED. A run stopped by the operator
            # and a run stopped because verification failed are opposite
            # findings, and a report that renders both as "ABORTED" invites the
            # reader to assume the worse one.
            return "CANCELLED by operator - target is partially written"
        if self.aborted:
            # Only two things set ``aborted``: the operator cancelling, which is
            # handled above, and a pass failing verification. So reaching here
            # means verification failed - the finding a reader most needs, and
            # the one a bare "ABORTED" hides behind a word that could equally
            # mean a device error or a bad sector. The two call for opposite
            # responses: a verification failure means data may still be on the
            # media and the target must not be reused, whereas an I/O abort says
            # nothing about what survived. The reason is carried through so the
            # headline alone is enough to act on.
            return (
                f"ABORTED - VERIFICATION FAILURES: {self.error}" if self.error else "ABORTED"
            )
        if self.error:
            return f"FAILED: {self.error}"
        if self.verified is False:
            return "Completed with VERIFICATION FAILURES"
        return "Completed and verified" if self.verified else "Completed (unverified)"

    def as_dict(self) -> dict:
        return {
            "operation": "drive_erase",
            "dry_run": self.dry_run,
            "success": self.success,
            "aborted": self.aborted,
            "cancelled": self.cancelled,
            "headline": self.headline(),
            "error": self.error,
            "warnings": self.warnings,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "throughput_mbps": round(self.throughput_mbps, 2),
            "bytes_total": self.bytes_total,
            "target": {
                "path": self.target.path,
                "kind": self.target.kind.value,
                "media_type": self.target.media_type.value,
                "size_bytes": self.target.size_bytes,
                "model": self.target.model,
                "serial": self.target.serial,
                "is_system": self.target.is_system,
            },
            "standard": {
                "id": self.standard.id,
                "name": self.standard.name,
                "passes": self.standard.pass_count,
                "compliance": list(self.standard.compliance),
            },
            "passes": [p.as_dict() for p in self.passes],
            "verified": self.verified,
            "audit_range": list(self.audit_range),
        }


#: Media where an overwrite is not a genuine purge, and the operator must be told.
_WARN_OVERWRITE_MEDIA = {
    MediaType.SSD,
    MediaType.NVME,
    MediaType.USB_FLASH,
    MediaType.SD_CARD,
}


class DriveEraser:
    """
    Multi-pass sanitization engine for whole devices and disk images.

    Example - wiping a disk image with the 3-pass DoD scheme::

        target = describe_target("evidence/scratch.img", kind=TargetKind.DISK_IMAGE)
        result = DriveEraser().run(target, "dod3", policy=SafetyPolicy(dry_run=False))
        print(result.headline())
    """

    def __init__(self, audit: AuditChain | None = None) -> None:
        self.audit = audit

    # -- public API --------------------------------------------------------

    def run(
        self,
        target: EraseTarget,
        standard: EraseStandard | str,
        *,
        policy: SafetyPolicy | None = None,
        confirmation: str = "",
        verify: bool | None = None,
        verify_mode: VerifyMode = VerifyMode.SAMPLE,
        progress: Callable[[ProgressUpdate], None] | None = None,
        cancel: CancelToken | None = None,
        confirm: Callable[[str], bool] | None = None,
    ) -> EraseResult:
        """
        Execute the standard against the target.

        Raises :class:`SafetyViolation` if policy refuses the operation - an
        explicit exception rather than a result object, because a refusal is a
        programming or policy error, not a job outcome.
        """
        policy = policy or SafetyPolicy()
        if isinstance(standard, str):
            standard = get_standard(standard)

        reporter = ProgressReporter(progress)
        cancel = cancel or CancelToken()

        result = EraseResult(
            target=target,
            standard=standard,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            dry_run=policy.dry_run,
            bytes_total=target.size_bytes,
        )

        # ---- policy gate -------------------------------------------------
        try:
            validate_for_erasure(target, policy)
        except SafetyViolation as violation:
            self._audit_refusal(violation, target, standard, policy)
            raise

        # ---- confirmation gate -------------------------------------------
        if policy.require_confirmation_token and not policy.dry_run:
            try:
                verify_confirmation(target, confirmation)
            except SafetyViolation as violation:
                self._audit_refusal(violation, target, standard, policy)
                raise

        self._audit_start(target, standard, policy)

        if policy.dry_run:
            result.success = True
            result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            result.warnings.append("Dry run - pass sequence was not executed.")
            self._audit_finish(result)
            return result

        # ---- execute ------------------------------------------------------
        started = time.monotonic()
        try:
            self._execute(target, standard, result, reporter, cancel, verify, verify_mode)
            result.success = all(p.verified is not False for p in result.passes) and not result.aborted
        except OperationCancelled:
            result.aborted = True
            result.cancelled = True
            result.error = "Cancelled by operator"
            result.warnings.append(
                "The operator stopped this run. Passes already completed were "
                "written and verified as recorded above; the target as a whole "
                "does not meet the selected standard and must not be reported "
                "as if it did."
            )
        except SafetyViolation:
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced into the report
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.elapsed_seconds = time.monotonic() - started
            if result.elapsed_seconds > 0 and result.bytes_total:
                written = sum(p.bytes_written for p in result.passes)
                result.throughput_mbps = (written / (1024 * 1024)) / result.elapsed_seconds
            result.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._audit_finish(result)

        return result

    # -- execution ---------------------------------------------------------

    def _execute(
        self,
        target: EraseTarget,
        standard: EraseStandard,
        result: EraseResult,
        reporter: ProgressReporter,
        cancel: CancelToken,
        verify: bool | None,
        verify_mode: VerifyMode,
    ) -> None:
        passes = standard.effective_passes(verify)

        if verify_mode is VerifyMode.NONE:
            passes = standard.effective_passes(False)

        self._append_media_warnings(target, result)

        with TargetWriter(target, writable=True) as writer:
            for index, pass_spec in enumerate(passes, start=1):
                cancel.check()
                pass_result = self._run_pass(
                    writer, target, pass_spec, index, len(passes), reporter, cancel, verify_mode
                )
                result.passes.append(pass_result)

                # A failed verification is a hard stop: continuing to the next
                # pass would erase the evidence of the failure.
                if pass_result.verified is False:
                    result.error = (
                        f"Pass {index} ({pass_spec.describe()}) failed verification; "
                        "aborting before further passes overwrite the evidence."
                    )
                    result.aborted = True
                    break

            writer.flush()

    def _run_pass(
        self,
        writer: TargetWriter,
        target: EraseTarget,
        pass_spec: PassSpec,
        index: int,
        total_passes: int,
        reporter: ProgressReporter,
        cancel: CancelToken,
        verify_mode: VerifyMode,
    ) -> PassResult:
        phase = f"Pass {index}/{total_passes} [{pass_spec.describe()}]"
        started = time.monotonic()
        total = target.size_bytes
        written = 0

        reporter.start(phase, total, pass_spec.describe())

        # Build one chunk of the pattern and reuse it for every non-random
        # write; only RANDOM regenerates per chunk, which is the whole point
        # of a random pass. The chunk is sized to a whole number of pattern
        # periods so a repeating sequence keeps its phase across the device.
        chunk = CHUNK_SIZE
        static_buffer: bytes | None = None
        if pass_spec.kind is not PatternKind.RANDOM:
            chunk = pass_spec.aligned_size(CHUNK_SIZE)
            static_buffer = pass_spec.build_buffer(chunk)

        handle = writer.handle
        handle.seek(0)

        while written < total:
            cancel.check()
            remaining = total - written
            size = min(chunk, remaining)
            if pass_spec.kind is PatternKind.RANDOM:
                payload = pass_spec.build_buffer(size)
            else:
                payload = static_buffer if size == chunk else static_buffer[:size]  # type: ignore[index]
            handle.write(payload)
            written += len(payload)
            reporter.update(phase, written, total)

        writer.flush()
        duration = time.monotonic() - started

        verification: VerifyOutcome | None = None
        if pass_spec.verify and verify_mode is not VerifyMode.NONE:
            with TargetWriter(target, writable=False) as reader:
                verification = verify_pass(
                    reader.handle,
                    total,
                    pass_spec,
                    mode=verify_mode,
                    progress=reporter,
                    cancel=cancel,
                    phase=f"Verify pass {index}/{total_passes}",
                )

        reporter.finish(phase, total, f"{hashing.human_bytes(written)} written")

        return PassResult(
            index=index,
            label=pass_spec.describe(),
            bytes_written=written,
            duration_seconds=duration,
            verification=verification,
        )

    def _append_media_warnings(self, target: EraseTarget, result: EraseResult) -> None:
        """Tell the operator when an overwrite is the wrong tool for the media."""
        if target.media_type in _WARN_OVERWRITE_MEDIA:
            result.warnings.append(
                f"{target.media_type.value} media uses wear-levelling and block "
                "remapping: an overwrite is NOT a guaranteed purge. For this device "
                "use the firmware sanitize command (ATA SANITIZE / SECURITY ERASE "
                "UNIT, NVMe Format/Sanitize, or TCG Opal crypto erase)."
            )
        if target.is_removable:
            result.warnings.append(
                "Removable media: confirm the correct device was selected before "
                "committing this operation."
            )

    # -- audit -------------------------------------------------------------

    def _audit_start(self, target: EraseTarget, standard: EraseStandard, policy: SafetyPolicy) -> None:
        if self.audit is None:
            return
        entry = self.audit.log(
            AuditCategory.ERASE,
            "drive_erase_started",
            outcome=AuditOutcome.INFO,
            target=target.path,
            details={
                "standard": standard.id,
                "standard_name": standard.name,
                "passes": standard.pass_count,
                "compliance": list(standard.compliance),
                "size_bytes": target.size_bytes,
                "media_type": target.media_type.value,
                "target_kind": target.kind.value,
                "policy": policy.summary(),
                "dry_run": policy.dry_run,
            },
        )
        self._start_seq = entry.seq

    def _audit_finish(self, result: EraseResult) -> None:
        if self.audit is None:
            return
        outcome = AuditOutcome.SUCCESS if result.success else AuditOutcome.FAILURE
        if result.aborted:
            outcome = AuditOutcome.FAILURE
        entry = self.audit.log(
            AuditCategory.ERASE,
            "drive_erase_finished",
            outcome=outcome,
            target=result.target.path,
            details={
                "standard": result.standard.id,
                "headline": result.headline(),
                "passes_executed": result.total_passes,
                "verified": result.verified,
                "elapsed_seconds": round(result.elapsed_seconds, 3),
                "throughput_mbps": round(result.throughput_mbps, 2),
                "error": result.error,
                "warnings": result.warnings,
            },
        )
        result.audit_range = (getattr(self, "_start_seq", 0), entry.seq)

    def _audit_refusal(
        self,
        violation: SafetyViolation,
        target: EraseTarget,
        standard: EraseStandard,
        policy: SafetyPolicy,
    ) -> None:
        if self.audit is None:
            return
        self.audit.log(
            AuditCategory.SAFETY,
            "erasure_refused",
            outcome=AuditOutcome.DENIED,
            target=target.path,
            details={
                "reason": violation.reason,
                "standard": standard.id,
                "policy": policy.summary(),
                "is_system": target.is_system,
            },
        )
