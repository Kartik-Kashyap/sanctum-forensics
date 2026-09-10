"""
Secure File & Folder Eraser view.

Two distinct operations share this screen because they solve the same problem
from different directions:

* **Selective deletion** removes named files and folder trees - content
  overwritten in place, directory entry renamed to an uninformative name of the
  same length, then unlinked.
* **Free-space sweep** attacks what selective deletion cannot reach: the bytes
  of previously-deleted files still sitting in unallocated clusters.

The screen states plainly what neither can do. Journal records and filesystem
table entries can retain filename fragments beyond user-space reach, and an
operator who is not told that will overstate what they have achieved.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.core.hashing import human_bytes
from sanctum.core.standards import STANDARDS
from sanctum.core.targets import SafetyViolation, is_filesystem_root, is_inside_sanctum_home, is_os_directory
from sanctum.erase.file import FileEraser
from sanctum.gui import theme
from sanctum.gui.widgets import Card, FieldRow, LogPane, PageHeader, ProgressPanel
from sanctum.gui.workers import Job

#: Typed verbatim to arm a real (non-dry-run) deletion. Deliberately a word
#: rather than a token: this operation's risk is misjudging *which* files were
#: selected, so a word that names the action is the right speed bump.
_CONFIRM_WORD = "DELETE"


class FileEraserView(QWidget):
    """Selective secure deletion and free-space sanitization."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.job: Job | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Secure File & Folder Eraser",
                "Overwrite selected files in place, cleanse their directory "
                "entries, and sweep the volume's free space to remove the residue "
                "of files deleted earlier.",
            )
        )

        columns = QHBoxLayout()
        columns.setSpacing(12)

        # ---- left: selection ---------------------------------------------
        left = QVBoxLayout()
        left.setSpacing(12)

        selection = Card("Selection")
        self.path_list = QListWidget()
        self.path_list.setMinimumHeight(180)
        self.path_list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection
        )
        selection.add(self.path_list)

        buttons = QHBoxLayout()
        for label, slot in (
            ("Add files...", self._add_files),
            ("Add folder...", self._add_folder),
            ("Remove", self._remove_selected),
            ("Clear", self._clear),
        ):
            button = QPushButton(label)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        selection.add_layout(buttons)

        self.selection_note = QLabel("No files selected.")
        self.selection_note.setObjectName("muted")
        selection.add(self.selection_note)
        left.addWidget(selection)

        sweep = Card("Free-space sweep")
        self.sweep_edit = QLineEdit()
        self.sweep_edit.setPlaceholderText("Volume or folder to sweep (e.g. D:\\ or C:\\Users\\me\\Temp)")
        sweep_browse = QPushButton("Browse...")
        sweep_browse.clicked.connect(self._browse_sweep)
        sweep_row = QHBoxLayout()
        sweep_row.addWidget(self.sweep_edit, 1)
        sweep_row.addWidget(sweep_browse)
        sweep.add_layout(sweep_row)

        self.sweep_standard = QComboBox()
        for standard in STANDARDS:
            self.sweep_standard.addItem(f"{standard.name}", standard.id)
        default = next(
            (i for i, s in enumerate(STANDARDS) if s.id == "random1"), 0
        )
        self.sweep_standard.setCurrentIndex(default)
        sweep.add(FieldRow("Pattern", self.sweep_standard))

        self.sweep_button = QPushButton("Sweep free space")
        self.sweep_button.clicked.connect(self._start_sweep)
        sweep.add(self.sweep_button)

        sweep_note = QLabel(
            "Free-space sweeping writes only to unallocated clusters, so it "
            "cannot destroy live data - which is why it is permitted on a system "
            "volume. It does not sanitize slack space inside existing files, nor "
            "journal records."
        )
        sweep_note.setObjectName("hint")
        sweep_note.setWordWrap(True)
        sweep.add(sweep_note)
        left.addWidget(sweep)
        left.addStretch(1)

        # ---- right: options ----------------------------------------------
        right = QVBoxLayout()
        right.setSpacing(12)

        options = Card("Standard and options")
        self.standard_combo = QComboBox()
        for standard in STANDARDS:
            self.standard_combo.addItem(
                f"{standard.name}  ({standard.pass_count} pass"
                f"{'es' if standard.pass_count != 1 else ''})",
                standard.id,
            )
        self.standard_combo.setCurrentIndex(
            next((i for i, s in enumerate(STANDARDS) if s.id == "dod3"), 0)
        )
        self.standard_combo.currentIndexChanged.connect(self._on_standard_changed)
        options.add(self.standard_combo)

        self.standard_detail = QLabel("")
        self.standard_detail.setObjectName("muted")
        self.standard_detail.setWordWrap(True)
        options.add(self.standard_detail)

        self.cleanse_check = QCheckBox("Cleanse metadata (rename, truncate, remove ADS)")
        self.cleanse_check.setChecked(True)
        options.add(self.cleanse_check)

        self.recursive_check = QCheckBox("Recurse into subfolders")
        self.recursive_check.setChecked(True)
        options.add(self.recursive_check)

        self.dry_run_check = QCheckBox("Dry run (nothing is deleted)")
        self.dry_run_check.setChecked(True)
        self.dry_run_check.toggled.connect(self._on_policy_changed)
        options.add(self.dry_run_check)
        right.addWidget(options)

        confirm = Card("Confirmation")
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setPlaceholderText(f"Type {_CONFIRM_WORD} to arm deletion")
        self.confirm_edit.textChanged.connect(self._update_run_state)
        confirm.add(self.confirm_edit)
        self.confirm_hint = QLabel(
            "Selective deletion is irreversible. The audit chain records every "
            "path, its size and the standard applied."
        )
        self.confirm_hint.setObjectName("hint")
        self.confirm_hint.setWordWrap(True)
        confirm.add(self.confirm_hint)
        right.addWidget(confirm)

        self.run_button = QPushButton("Delete selected paths")
        self.run_button.setObjectName("danger")
        self.run_button.clicked.connect(self._start_delete)
        self.run_button.setEnabled(False)
        right.addWidget(self.run_button)

        self.journal_note = QLabel(
            "Limitation: filesystem journals and table records (NTFS $UsnJrnl, "
            "$LogFile, MFT; ext3/4 journal) may retain filename and timestamp "
            "fragments outside user-space reach. A rename reduces this but does "
            "not eliminate it. Only whole-media sanitization removes it."
        )
        self.journal_note.setObjectName("hint")
        self.journal_note.setWordWrap(True)
        right.addWidget(self.journal_note)
        right.addStretch(1)

        columns.addLayout(left, 3)
        columns.addLayout(right, 2)
        layout.addLayout(columns)

        self.progress = ProgressPanel()
        self.progress.cancelled.connect(self._cancel)
        layout.addWidget(self.progress)

        self.log = LogPane()
        self.log.setMinimumHeight(130)
        layout.addWidget(self.log, 1)

        self.results = QTableWidget(0, 4)
        self.results.setHorizontalHeaderLabels(["Path", "Outcome", "Bytes", "Removed"])
        self.results.verticalHeader().setVisible(False)
        self.results.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.results.setMaximumHeight(150)
        layout.addWidget(self.results)

        self._on_standard_changed()

    # -- selection ---------------------------------------------------------

    def _add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files to delete")
        self._add_paths(paths)

    def _add_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select a folder to delete")
        if path:
            self._add_paths([path])

    def _add_paths(self, paths) -> None:
        existing = {self.path_list.item(i).text() for i in range(self.path_list.count())}
        for path in paths:
            if path not in existing:
                self.path_list.addItem(path)
        self._refresh_selection_note()

    def _remove_selected(self) -> None:
        for item in self.path_list.selectedItems():
            self.path_list.takeItem(self.path_list.row(item))
        self._refresh_selection_note()

    def _clear(self) -> None:
        self.path_list.clear()
        self._refresh_selection_note()

    def selected_paths(self) -> list[str]:
        return [self.path_list.item(i).text() for i in range(self.path_list.count())]

    def _refresh_selection_note(self) -> None:
        paths = self.selected_paths()
        if not paths:
            self.selection_note.setText("No files selected.")
            self.selection_note.setStyleSheet(f"color: {theme.MUTED};")
        else:
            total = 0
            for path in paths:
                target = Path(path)
                try:
                    if target.is_file():
                        total += target.stat().st_size
                    elif target.is_dir():
                        for child in target.rglob("*"):
                            if child.is_file():
                                total += child.stat().st_size
                except OSError:
                    pass
            self.selection_note.setText(
                f"{len(paths)} path(s) selected, {human_bytes(total)} total."
            )
            self.selection_note.setStyleSheet(f"color: {theme.INK};")
        self._update_run_state()

    def _browse_sweep(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select a volume or folder to sweep")
        if path:
            self.sweep_edit.setText(path)

    # -- options -----------------------------------------------------------

    def _on_standard_changed(self) -> None:
        standard_id = self.standard_combo.currentData()
        standard = next((s for s in STANDARDS if s.id == standard_id), None)
        if standard is None:
            return
        self.standard_detail.setText(
            f"{standard.description} "
            + (f"Compliance: {'; '.join(standard.compliance)}. " if standard.compliance else "")
            + f"Recommended for {standard.recommended_for}."
        )

    def _on_policy_changed(self) -> None:
        self.state.update_policy(dry_run=self.dry_run_check.isChecked())
        self._update_run_state()

    # -- gating ------------------------------------------------------------

    def _update_run_state(self) -> None:
        paths = self.selected_paths()
        if self.job is not None and self.job.isRunning():
            self.run_button.setEnabled(False)
            self.run_button.setToolTip("An operation is already running")
            return

        blocked: list[str] = []
        for path in paths:
            if is_inside_sanctum_home(path):
                blocked.append(f"{path} is inside SANCTUM's own data directory")
            elif is_filesystem_root(path):
                blocked.append(f"{path} is a whole filesystem root - use the Drive Eraser")
            elif is_os_directory(path):
                blocked.append(f"{path} is an operating-system directory")

        if not paths:
            self.run_button.setEnabled(False)
            self.run_button.setToolTip("Select at least one path")
            return
        if blocked:
            self.run_button.setEnabled(False)
            self.run_button.setToolTip(blocked[0])
            self.confirm_hint.setText("Refused: " + "; ".join(blocked))
            self.confirm_hint.setStyleSheet(f"color: {theme.BAD};")
            return

        self.confirm_hint.setStyleSheet(f"color: {theme.MUTED};")
        if not self.state.policy.dry_run and self.confirm_edit.text().strip().upper() != _CONFIRM_WORD:
            self.run_button.setEnabled(False)
            self.run_button.setToolTip(f"Type {_CONFIRM_WORD} to arm deletion")
            return

        self.run_button.setEnabled(True)
        self.run_button.setToolTip(
            "Dry run" if self.state.policy.dry_run else "This will delete the selected paths"
        )

    # -- execution ---------------------------------------------------------

    def _start_delete(self) -> None:
        paths = self.selected_paths()
        if not paths:
            return
        policy = self.state.policy

        if not policy.dry_run:
            preview = "\n".join(paths[:12])
            if len(paths) > 12:
                preview += f"\n... and {len(paths) - 12} more"
            confirmed = QMessageBox.warning(
                self,
                "Confirm deletion",
                f"Permanently delete the following?\n\n{preview}\n\n"
                "This cannot be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirmed is not QMessageBox.StandardButton.Yes:
                return

        self.results.setRowCount(0)
        self.log.rule(f"Secure deletion - {len(paths)} path(s)")
        self.progress.begin("Starting...")

        eraser = FileEraser(self.state.audit())
        job = Job(
            eraser.secure_delete_paths,
            paths,
            self.standard_combo.currentData(),
            policy=policy,
            recursive=self.recursive_check.isChecked(),
            label="Secure deletion",
        )
        job.signals.progress.connect(self.progress.on_progress)
        job.signals.completed.connect(self._on_delete_complete)
        job.signals.failed.connect(self._on_failed)
        job.finished.connect(self._on_job_finished)
        self.job = job
        job.start()
        self._update_run_state()

    def _start_sweep(self) -> None:
        root = self.sweep_edit.text().strip()
        if not root:
            QMessageBox.information(self, "No target", "Choose a volume or folder to sweep.")
            return
        policy = self.state.policy

        if not policy.dry_run:
            confirmed = QMessageBox.warning(
                self,
                "Confirm free-space sweep",
                f"Sweep free space on:\n\n{root}\n\n"
                "This fills the volume's unallocated space with pattern data and "
                "deletes it. Live files are untouched, but the volume will be "
                "nearly full for the duration.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if confirmed is not QMessageBox.StandardButton.Yes:
                return

        self.log.rule(f"Free-space sweep - {root}")
        self.progress.begin("Starting...")

        eraser = FileEraser(self.state.audit())
        job = Job(
            eraser.wipe_free_space,
            root,
            self.sweep_standard.currentData(),
            policy=policy,
            label=f"Sweeping free space on {root}",
        )
        job.signals.progress.connect(self.progress.on_progress)
        job.signals.completed.connect(self._on_sweep_complete)
        job.signals.failed.connect(self._on_failed)
        job.finished.connect(self._on_job_finished)
        self.job = job
        job.start()
        self.sweep_button.setEnabled(False)

    def _cancel(self) -> None:
        if self.job is not None:
            self.job.cancel()
            self.log.append_line("Cancellation requested.", "warn")

    def _on_delete_complete(self, batch) -> None:
        tone = "ok" if batch.failed == 0 else "bad"
        if batch.cancelled:
            # The operator stopped it, and the engine counted the paths it never
            # reached - so this is reported as a partial run, not a failure and
            # not a success.
            tone = "warn"
        headline = batch.headline()
        self.progress.finish(headline, tone)
        self.log.append_line(headline, tone)

        self.results.setRowCount(0)
        for result in batch.results:
            index = self.results.rowCount()
            self.results.insertRow(index)
            if result.success:
                tone_cell = theme.OK
            elif result.dry_run:
                tone_cell = theme.MUTED
            else:
                tone_cell = theme.BAD
            cells = [
                result.path,
                result.headline(),
                f"{result.size_bytes:,}",
                "yes" if result.verified else ("no" if result.verified is False else "-"),
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 1:
                    item.setForeground(QColor(tone_cell))
                self.results.setItem(index, column, item)

        for result in batch.results:
            if result.error and not result.cancelled:
                self.log.append_line(f"{result.path}: {result.error}", "bad")
            elif result.cancelled:
                self.log.append_line(f"{result.path}: {result.headline()}", "warn")

        # The journal caveat is the same for every file; state it once.
        seen: set[str] = set()
        for warning in list(batch.warnings) + [
            w for result in batch.results for w in result.warnings
        ]:
            if warning not in seen:
                seen.add(warning)
                self.log.append_line(f"NOTE: {warning}", "warn")

        self.state.record(batch)
        self.path_list.clear()
        self._refresh_selection_note()

    def _on_sweep_complete(self, result) -> None:
        tone = "info" if result.dry_run else ("ok" if result.success else "bad")
        if result.cancelled:
            tone = "warn"
        self.progress.finish(result.headline(), tone)
        self.log.append_line(result.headline(), tone)
        if result.error and not result.cancelled:
            self.log.append_line(f"ERROR: {result.error}", "bad")
        for warning in result.warnings:
            self.log.append_line(f"NOTE: {warning}", "warn")
        self.state.record(result)

    def _on_failed(self, message: str, trace: str) -> None:
        self.progress.finish("Failed", "bad")
        self.log.append_line(f"FAILED: {message}", "bad")
        self.log.append_line(trace, "muted")
        QMessageBox.critical(self, "Operation failed", message)

    def _on_job_finished(self) -> None:
        self.job = None
        self.sweep_button.setEnabled(True)
        self.confirm_edit.clear()
        self._update_run_state()
