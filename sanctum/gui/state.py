"""
Application state shared across views.

One object holds the working context - open case, safety policy, session
results - so views stay stateless and a change made in Settings is immediately
visible everywhere it matters. It emits Qt signals on change so the dashboard
and status bar refresh without polling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

from sanctum.cases import Case, CaseManager
from sanctum.config import SafetyPolicy, ensure_layout, runtime_allows_raw_devices
from sanctum.core.audit import AuditChain, VerifyReport
from sanctum.core.devices import platform_summary
from sanctum.core.hashing import human_bytes
from sanctum.recover.native import capabilities


def _describe(result) -> tuple[str, str]:
    """
    The ``(kind, one-line summary)`` pair to file against a case.

    Engine results are dataclasses that expose ``as_dict()``; they are not
    mappings. Reading one as a mapping therefore matches nothing and yields two
    empty strings - which files a blank entry against the case rather than
    raising, so the case operation log quietly fills with records that look
    corrupted instead of looking like a caller bug. Everything is taken through
    ``as_dict()`` first for that reason.

    The summary comes from ``headline()`` where the result defines one, or from
    the ``headline`` key where ``as_dict()`` supplies it. Carving results do
    neither - they carry counts - so their line is composed here.
    """
    if hasattr(result, "as_dict"):
        data = dict(result.as_dict())
    elif isinstance(result, dict):
        data = dict(result)
    else:
        return "", ""

    kind = data.get("operation", "")

    if hasattr(result, "headline"):
        return kind, result.headline()
    if data.get("headline"):
        return kind, data["headline"]
    if kind == "file_carving":
        return kind, (
            f"{data.get('recovered_count', 0)} artefact(s), "
            f"{human_bytes(data.get('recovered_bytes', 0))} recovered"
        )
    return kind, data.get("error", "")


@dataclass
class SessionResults:
    """Everything produced this session, for report assembly."""

    operations: list[dict] = field(default_factory=list)

    def add(self, result) -> None:
        if hasattr(result, "as_dict"):
            self.operations.append(result.as_dict())
        elif isinstance(result, dict):
            self.operations.append(result)

    @property
    def count(self) -> int:
        return len(self.operations)

    def clear(self) -> None:
        self.operations.clear()


class AppState(QObject):
    """Mutable application state with change notifications."""

    case_changed = pyqtSignal(object)     # Case | None
    policy_changed = pyqtSignal(object)   # SafetyPolicy
    results_changed = pyqtSignal()
    audit_changed = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        ensure_layout()
        self.case_manager = CaseManager()
        self.case: Case | None = None
        self._adhoc_audit: AuditChain | None = None
        self.policy = SafetyPolicy(dry_run=True)
        self.results = SessionResults()
        self.capabilities = capabilities()
        self.environment = platform_summary()

    # -- case --------------------------------------------------------------

    def create_case(self, name: str, examiner: str = "", description: str = "") -> Case:
        self.case = self.case_manager.create(name, examiner, description)
        self.case_changed.emit(self.case)
        self.audit_changed.emit()
        return self.case

    def open_case(self, case_id: str) -> Case:
        self.case = self.case_manager.open(case_id)
        self.case_changed.emit(self.case)
        self.audit_changed.emit()
        return self.case

    def close_case(self) -> None:
        self.case = None
        self.case_changed.emit(None)
        self.audit_changed.emit()

    @property
    def case_label(self) -> str:
        return self.case.name if self.case else "No case open (ad-hoc session)"

    # -- audit -------------------------------------------------------------

    def audit(self) -> AuditChain:
        """
        The audit chain to record into.

        Operations without an open case still get recorded: an unlogged
        destructive action is worse than an untidy one. Ad-hoc records land in
        the application log directory so they can still be exported.
        """
        if self.case is not None:
            return self.case.audit()
        if self._adhoc_audit is None:
            from sanctum.config import LOGS_DIR

            self._adhoc_audit = AuditChain(LOGS_DIR / "adhoc_audit.jsonl", actor="operator")
        return self._adhoc_audit

    def audit_verification(self) -> VerifyReport:
        try:
            return self.audit().verify()
        except OSError as exc:
            return VerifyReport(ok=False, entries=0, reason=str(exc))

    # -- policy ------------------------------------------------------------

    def update_policy(self, **changes) -> SafetyPolicy:
        current = {
            "allow_raw_devices": self.policy.allow_raw_devices,
            "allow_system_targets": self.policy.allow_system_targets,
            "require_confirmation_token": self.policy.require_confirmation_token,
            "dry_run": self.policy.dry_run,
        }
        current.update(changes)
        self.policy = SafetyPolicy(**current)
        self.policy_changed.emit(self.policy)
        return self.policy

    @property
    def raw_devices_armed(self) -> bool:
        """True only when both the policy flag and the environment unlock are set."""
        return self.policy.allow_raw_devices and runtime_allows_raw_devices()

    # -- results -----------------------------------------------------------

    def record(self, result) -> None:
        self.results.add(result)
        if self.case is not None:
            kind, summary = _describe(result)
            self.case.record_operation(kind, summary, {"recorded": True})
            self.case.save()
        self.results_changed.emit()

    def clear_results(self) -> None:
        self.results.clear()
        self.results_changed.emit()

    # -- paths -------------------------------------------------------------

    @property
    def artifacts_dir(self) -> Path:
        """Where recovered files go: inside the case when there is one."""
        if self.case is not None:
            return self.case.artifacts_dir
        from sanctum.config import BASE_DIR

        target = BASE_DIR / "artifacts"
        target.mkdir(parents=True, exist_ok=True)
        return target

    @property
    def reports_dir(self) -> Path:
        if self.case is not None:
            return self.case.reports_dir
        from sanctum.config import BASE_DIR

        target = BASE_DIR / "reports"
        target.mkdir(parents=True, exist_ok=True)
        return target
