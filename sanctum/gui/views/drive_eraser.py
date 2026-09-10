"""
Secure Drive Eraser view.

The most dangerous screen in the application, and therefore the most
deliberately tedious one. Selecting a target, choosing a standard and pressing
Run is not enough: the operator must also arm raw-device access, set the policy
out of dry-run, and retype a confirmation token derived from the target's own
identity. Each of those is an independent failure that must occur before real
data is destroyed.

The screen also refuses to let the operator believe something it cannot
support: if the selected media is flash-based, the warning that an overwrite is
not a guaranteed purge is shown before the operation starts, not buried in the
report afterwards.
"""

from __future__ import annotations

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.config import runtime_allows_raw_devices
from sanctum.core.hashing import human_bytes
from sanctum.core.standards import STANDARDS
from sanctum.core.targets import (
    EraseTarget,
    MediaType,
    SafetyViolation,
    TargetKind,
    describe_target,
    validate_for_erasure,
)
from sanctum.erase.drive import DriveEraser
from sanctum.erase.verify import VerifyMode
from sanctum.gui import theme
from sanctum.gui.widgets import Card, FieldRow, LogPane, PageHeader, ProgressPanel
from sanctum.gui.workers import Job

#: Media where an overwrite is the wrong instrument, and the operator is told so
#: before committing rather than after.
_FLASH_MEDIA = {
    MediaType.SSD,
    MediaType.NVME,
    MediaType.USB_FLASH,
    MediaType.SD_CARD,
}

_VERIFY_MODES = [
    ("Sampled verification (64 windows)", VerifyMode.SAMPLE),
    ("Full verification (byte-for-byte)", VerifyMode.FULL),
    ("No verification", VerifyMode.NONE),
]


class DriveEraserView(QWidget):
    """Whole-device and disk-image sanitization."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.target: EraseTarget | None = None
        self.job: Job | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header = PageHeader(
            "Secure Drive Eraser",
            "Sanitize a whole device or disk image using a recognised overwrite "
            "standard, with per-pass verification and a sealed audit record.",
        )
        layout.addWidget(header)

        columns = QHBoxLayout()
        columns.setSpacing(12)

        # ---- left: target + standard ------------------------------------
        left = QVBoxLayout()
        left.setSpacing(12)

        target_card = Card("Target")
        self.kind_combo = QComboBox()
        self.kind_combo.addItem("Disk image file (.img / .dd / .raw / .iso)", TargetKind.DISK_IMAGE)
        self.kind_combo.addItem("Physical device (requires administrator)", TargetKind.BLOCK_DEVICE)
        self.kind_combo.currentIndexChanged.connect(self._on_kind_changed)

        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("No target selected")
        self.path_edit.setReadOnly(True)
        self.browse_button = QPushButton("Browse image...")
        self.browse_button.clicked.connect(self._browse_image)
        path_row = QHBoxLayout()
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.browse_button)

        self.device_combo = QComboBox()
        self.device_combo.setVisible(False)
        self.device_combo.currentIndexChanged.connect(self._on_device_selected)
        self.refresh_button = QPushButton("Rescan devices")
        self.refresh_button.clicked.connect(self.refresh_devices)
        self.refresh_button.setVisible(False)
        device_row = QHBoxLayout()
        device_row.addWidget(self.device_combo, 1)
        device_row.addWidget(self.refresh_button)

        target_card.add(self.kind_combo)
        target_card.add_layout(path_row)
        target_card.add_layout(device_row)

        self.target_summary = QLabel("No target selected.")
        self.target_summary.setObjectName("muted")
        self.target_summary.setWordWrap(True)
        target_card.add(self.target_summary)

        self.media_warning = QLabel("")
        self.media_warning.setWordWrap(True)
        self.media_warning.setVisible(False)
        target_card.add(self.media_warning)

        left.addWidget(target_card)

        standard_card = Card("Standard")
        self.standard_combo = QComboBox()
        for standard in STANDARDS:
            self.standard_combo.addItem(
                f"{standard.name}  ({standard.pass_count} pass"
                f"{'es' if standard.pass_count != 1 else ''})",
                standard.id,
            )
        self.standard_combo.currentIndexChanged.connect(self._on_standard_changed)
        standard_card.add(self.standard_combo)

        self.standard_detail = QLabel("")
        self.standard_detail.setObjectName("muted")
        self.standard_detail.setWordWrap(True)
        standard_card.add(self.standard_detail)

        self.verify_combo = QComboBox()
        for label, mode in _VERIFY_MODES:
            self.verify_combo.addItem(label, mode)
        standard_card.add(FieldRow("Verification", self.verify_combo))

        left.addWidget(standard_card)
        left.addStretch(1)

        # ---- right: policy + confirmation --------------------------------
        right = QVBoxLayout()
        right.setSpacing(12)

        policy_card = Card("Policy")
        self.dry_run_check = QCheckBox("Dry run (no data is written)")
        self.dry_run_check.setChecked(True)
        self.dry_run_check.toggled.connect(self._on_policy_changed)

        self.raw_check = QCheckBox("Allow writing to physical devices")
        self.raw_check.setChecked(False)
        self.raw_check.toggled.connect(self._on_policy_changed)

        self.raw_note = QLabel("")
        self.raw_note.setObjectName("hint")
        self.raw_note.setWordWrap(True)

        policy_card.add(self.dry_run_check)
        policy_card.add(self.raw_check)
        policy_card.add(self.raw_note)
        right.addWidget(policy_card)

        confirm_card = Card("Confirmation")
        # What the operator is about to spend, stated in the same card as the
        # token they must type. The pass count is the whole cost model: a
        # standard writes a multiple of the target's size equal to its number of
        # passes, so the difference between one hour and most of a day is a
        # dropdown two cards above. That is not something to discover after
        # starting, and it is a fact - size times passes - rather than an
        # estimate, so it can be stated without hedging.
        self.confirm_impact = QLabel("")
        self.confirm_impact.setObjectName("muted")
        self.confirm_impact.setWordWrap(True)
        confirm_card.add(self.confirm_impact)
        self.token_label = QLabel("-")
        self.token_label.setStyleSheet(
            f"font-family: Consolas, monospace; font-size: 18px; color: {theme.WARN};"
        )
        confirm_card.add(FieldRow("Type this token", self.token_label))
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText("Confirmation token")
        self.confirm_edit.textChanged.connect(self._update_run_state)
        confirm_card.add(self.confirm_edit)
        self.confirm_hint = QLabel(
            "The token is derived from the target's path, size and serial, so a "
            "token shown for one device never validates for another."
        )
        self.confirm_hint.setObjectName("hint")
        self.confirm_hint.setWordWrap(True)
        confirm_card.add(self.confirm_hint)
        right.addWidget(confirm_card)

        self.run_button = QPushButton("Start erasure")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self._start)
        self.run_button.setEnabled(False)
        right.addWidget(self.run_button)
        right.addStretch(1)

        columns.addLayout(left, 1)
        columns.addLayout(right, 1)
        layout.addLayout(columns)

        # ---- progress ----------------------------------------------------
        self.progress = ProgressPanel()
        self.progress.cancelled.connect(self._cancel)
        layout.addWidget(self.progress)

        self.log = LogPane()
        self.log.setMinimumHeight(140)
        layout.addWidget(self.log, 1)

        self.results = QTableWidget(0, 5)
        self.results.setHorizontalHeaderLabels(
            ["Pass", "Pattern", "Bytes written", "Duration", "Verification"]
        )
        self.results.verticalHeader().setVisible(False)
        self.results.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.results.setMaximumHeight(160)
        layout.addWidget(self.results)

        self._on_standard_changed()
        self._on_kind_changed()
        self.refresh_interlocks()

    # -- target selection --------------------------------------------------

    def on_shown(self) -> None:
        """
        Called when the page becomes visible.

        Re-checks the environment (the operator may have exported the unlock
        variable in another terminal) but does *not* re-enumerate devices: a
        rescan would silently discard a target the operator had already selected
        and inspected, which is the last thing this screen should do.
        """
        self.refresh_interlocks()
        if self.kind_combo.currentData() is TargetKind.BLOCK_DEVICE and self.device_combo.count() == 0:
            self.refresh_devices()

    def _on_kind_changed(self) -> None:
        is_device = self.kind_combo.currentData() is TargetKind.BLOCK_DEVICE
        self.device_combo.setVisible(is_device)
        self.refresh_button.setVisible(is_device)
        self.path_edit.setVisible(not is_device)
        self.browse_button.setVisible(not is_device)
        if is_device and self.device_combo.count() == 0:
            self.refresh_devices()
        elif not is_device:
            self._set_target(None)

    def _browse_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a disk image",
            "",
            "Disk images (*.img *.dd *.raw *.iso *.001);;All files (*)",
        )
        if not path:
            return
        try:
            target = describe_target(path, kind=TargetKind.DISK_IMAGE)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Could not describe target", str(exc))
            return
        self.path_edit.setText(path)
        self._set_target(target)

    def refresh_devices(self) -> None:
        """Enumerate storage. Runs off the GUI thread; it shells out on Windows."""
        self.refresh_button.setEnabled(False)
        self.device_combo.clear()
        self.device_combo.addItem("Scanning devices...", None)

        from sanctum.core.devices import enumerate_devices

        job = Job(
            lambda progress=None, cancel=None: enumerate_devices(),
            label="Enumerating storage devices",
        )
        job.signals.completed.connect(self._on_devices)
        job.signals.failed.connect(self._on_device_scan_failed)
        job.finished.connect(lambda: self.refresh_button.setEnabled(True))
        job.start()
        self._device_job = job  # keep a reference so it is not collected

    def _on_devices(self, devices) -> None:
        self.device_combo.clear()
        if not devices:
            self.device_combo.addItem("No devices found", None)
            return
        for device in devices:
            label = device.summary()
            if not device.accessible and device.kind is TargetKind.BLOCK_DEVICE:
                label += "  - needs elevation"
            self.device_combo.addItem(label, device)

    def _on_device_scan_failed(self, message: str, _traceback: str) -> None:
        self.device_combo.clear()
        self.device_combo.addItem(f"Enumeration failed: {message}", None)

    def _on_device_selected(self) -> None:
        device = self.device_combo.currentData()
        if device is None:
            self._set_target(None)
            return
        target = EraseTarget(
            path=device.path,
            kind=device.kind,
            size_bytes=device.size_bytes,
            display_name=device.name,
            media_type=device.media_type,
            model=device.model,
            serial=device.serial,
            bus=device.bus,
            is_system=device.is_system,
            is_removable=device.is_removable,
            mountpoints=list(device.mountpoints),
            notes=[device.note] if device.note else [],
        )
        self._set_target(target)

    def _set_target(self, target: EraseTarget | None) -> None:
        self.target = target
        if target is None:
            self.target_summary.setText("No target selected.")
            self.target_summary.setStyleSheet(f"color: {theme.MUTED};")
            self.token_label.setText("-")
            self.media_warning.setVisible(False)
            self._update_impact()
            self._update_run_state()
            return

        self.target_summary.setText(
            f"{target.display_name}  |  {target.kind.value}  |  "
            f"{target.media_type.value}  |  {human_bytes(target.size_bytes)}"
            + (f"  |  serial {target.serial}" if target.serial else "")
            + ("  |  SYSTEM DRIVE" if target.is_system else "")
        )
        self.target_summary.setStyleSheet(
            f"color: {theme.BAD if target.is_system else theme.INK};"
        )
        self.token_label.setText(target.confirmation_token())
        self._update_impact()

        if target.media_type in _FLASH_MEDIA:
            self.media_warning.setText(
                f"{target.media_type.value} media uses wear-levelling and block "
                "remapping. An overwrite is NOT a guaranteed purge on this device - "
                "the controller may retain previous physical pages. The firmware "
                "sanitize command (ATA SANITIZE, NVMe Format/Sanitize, TCG Opal "
                "crypto erase) is the correct instrument for this media."
            )
            self.media_warning.setStyleSheet(f"color: {theme.WARN};")
            self.media_warning.setVisible(True)
        elif target.is_removable:
            self.media_warning.setText(
                "Removable media selected. Confirm this is the intended device "
                "before committing."
            )
            self.media_warning.setStyleSheet(f"color: {theme.WARN};")
            self.media_warning.setVisible(True)
        else:
            self.media_warning.setVisible(False)

        self._update_run_state()

    # -- standard / policy -------------------------------------------------

    def _on_standard_changed(self) -> None:
        standard_id = self.standard_combo.currentData()
        standard = next((s for s in STANDARDS if s.id == standard_id), None)
        if standard is None:
            return
        parts = [standard.description]
        if standard.compliance:
            parts.append("Compliance: " + "; ".join(standard.compliance))
        if standard.notes:
            parts.append(standard.notes)
        parts.append(
            f"Recommended for {standard.recommended_for}. "
            f"Verification is {'on' if standard.verify_default else 'off'} by default."
        )
        self.standard_detail.setText(" ".join(parts))
        self._update_impact()
        self._update_run_state()

    def _update_impact(self) -> None:
        """
        State exactly what the pending operation will write.

        Bytes written is ``size x passes`` and nothing else, so it is reported
        as a figure rather than an estimate. ``EraseStandard.effective_passes``
        is deliberately not consulted: it changes which passes are verified, not
        how many run, so using it here would understate the work on any standard
        whose last pass is the only verified one.
        """
        standard = next(
            (s for s in STANDARDS if s.id == self.standard_combo.currentData()), None
        )
        if self.target is None or standard is None:
            self.confirm_impact.setText("")
            return

        passes = standard.pass_count
        total = self.target.size_bytes * passes
        self.confirm_impact.setText(
            f"Will write {human_bytes(total)} over {passes} pass"
            f"{'es' if passes != 1 else ''} across "
            f"{human_bytes(self.target.size_bytes)} of media "
            f"({passes}x the target)."
        )

    def _on_policy_changed(self) -> None:
        self.state.update_policy(
            dry_run=self.dry_run_check.isChecked(),
            allow_raw_devices=self.raw_check.isChecked(),
        )
        self._refresh_raw_note()
        self._update_run_state()

    def refresh_interlocks(self) -> None:
        if not runtime_allows_raw_devices():
            self.raw_note.setText(
                f"The {self.state_raw_env()} environment variable is not set, so raw "
                "device access is locked regardless of this checkbox. This two-key "
                "design means an accidental click cannot reach bare metal."
            )
            self.raw_note.setStyleSheet(f"color: {theme.WARN};")
        else:
            self.raw_note.setText(
                "Raw-device unlock is present in the environment. The running "
                "system's own drive is still refused unconditionally."
            )
            self.raw_note.setStyleSheet(f"color: {theme.MUTED};")

    @staticmethod
    def state_raw_env() -> str:
        from sanctum.config import ALLOW_RAW_DEVICE_ENV

        return ALLOW_RAW_DEVICE_ENV

    # -- run gating --------------------------------------------------------

    def _blocking_reason(self) -> str:
        """Why Start is disabled, as a short human-readable phrase."""
        if self.target is None:
            return "Select a target"
        if self.job is not None and self.job.isRunning():
            return "An operation is already running"
        policy = self.state.policy
        if policy.dry_run:
            return ""
        if self.target.is_system:
            return "The running operating system's drive is refused unconditionally"
        if policy.allow_raw_devices and not runtime_allows_raw_devices():
            return "Raw device access requires the environment unlock"
        if policy.require_confirmation_token:
            if self.confirm_edit.text().strip().upper() != self.target.confirmation_token():
                return "Type the confirmation token to proceed"
        return ""

    def _update_run_state(self) -> None:
        reason = self._blocking_reason()
        self.run_button.setEnabled(not reason)
        if reason:
            self.run_button.setToolTip(reason)
        else:
            self.run_button.setToolTip(
                "Dry run" if self.state.policy.dry_run else "This will overwrite the target"
            )

    # -- execution ---------------------------------------------------------

    def _start(self) -> None:
        if self.target is None:
            return
        standard_id = self.standard_combo.currentData()
        verify_mode: VerifyMode = self.verify_combo.currentData()
        policy = self.state.policy

        # Belt and braces: re-run the engine's own gate here so a refusal is
        # reported in the UI rather than as a worker-thread traceback.
        try:
            validate_for_erasure(self.target, policy)
        except SafetyViolation as violation:
            QMessageBox.critical(self, "Refused by policy", violation.reason)
            self.state.audit().log(
                "SAFETY", "erasure_refused",
                outcome="DENIED", target=self.target.path,
                details={"reason": violation.reason, "policy": policy.summary()},
            )
            self.log.append_line(f"REFUSED: {violation.reason}", "bad")
            return

        if not policy.dry_run:
            confirmed = QMessageBox.warning(
                self,
                "Confirm sanitization",
                f"About to overwrite:\n\n{self.target.display_name}\n"
                f"{self.target.path}\n{human_bytes(self.target.size_bytes)}\n\n"
                "This cannot be undone. Proceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirmed is not QMessageBox.StandardButton.Yes:
                return

        self.results.setRowCount(0)
        self.log.rule(f"Drive erasure - {standard_id} on {self.target.short_name}")
        self.progress.begin("Starting...")
        self.log.append_line(f"Target : {self.target.path}", "muted")
        self.log.append_line(f"Policy : {policy.summary()}", "muted")

        eraser = DriveEraser(self.state.audit())
        job = Job(
            eraser.run,
            self.target,
            standard_id,
            policy=policy,
            confirmation=self.confirm_edit.text().strip(),
            verify_mode=verify_mode,
            label=f"Sanitizing {self.target.short_name}",
        )
        job.signals.progress.connect(self.progress.on_progress)
        job.signals.completed.connect(self._on_complete)
        job.signals.failed.connect(self._on_failed)
        job.finished.connect(self._on_job_finished)
        self.job = job
        job.start()
        self._update_run_state()

    def _cancel(self) -> None:
        if self.job is not None:
            self.job.cancel()
            self.log.append_line("Cancellation requested.", "warn")

    def _on_complete(self, result) -> None:
        tone = "ok"
        if result.dry_run:
            tone = "info"
        elif result.cancelled:
            # The operator stopped this themselves. The engine already recorded
            # it in the audit chain and appended the caveat that the target does
            # not meet the standard, so it is reported, not raised as an error.
            tone = "warn"
        elif result.aborted or result.error:
            tone = "bad"
        elif result.verified is False:
            tone = "bad"
        elif not result.verified:
            tone = "warn"

        self.progress.finish(result.headline(), tone)
        self.log.append_line(f"Result: {result.headline()}", tone)
        self.log.append_line(
            f"{result.total_passes} pass(es), "
            f"{human_bytes(result.bytes_total)} target, "
            f"{result.elapsed_seconds:.1f}s, {result.throughput_mbps:.1f} MB/s",
            "muted",
        )
        for warning in result.warnings:
            self.log.append_line(f"NOTE: {warning}", "warn")
        if result.error:
            self.log.append_line(f"ERROR: {result.error}", "bad")

        self._fill_passes(result)
        self.state.record(result)

    def _fill_passes(self, result) -> None:
        self.results.setRowCount(0)
        for row in result.passes:
            index = self.results.rowCount()
            self.results.insertRow(index)
            verified = row.verified
            if verified is True:
                verdict, tone = "verified", theme.OK
            elif verified is False:
                verdict, tone = "FAILED", theme.BAD
            else:
                verdict, tone = "not requested", theme.MUTED

            cells = [
                str(row.index),
                row.label,
                f"{row.bytes_written:,}",
                f"{row.duration_seconds:.2f}s",
                verdict,
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 4:
                    item.setForeground(QColor(tone))
                self.results.setItem(index, column, item)

    def _on_failed(self, message: str, trace: str) -> None:
        self.progress.finish("Failed", "bad")
        self.log.append_line(f"FAILED: {message}", "bad")
        self.log.append_line(trace, "muted")
        QMessageBox.critical(self, "Operation failed", message)

    def _on_job_finished(self) -> None:
        self.job = None
        self.confirm_edit.clear()
        self._update_run_state()
