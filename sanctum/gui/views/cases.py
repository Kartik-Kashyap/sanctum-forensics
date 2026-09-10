"""
Case Management view.

A forensic tool's output has to be defensible months later by someone who was
not present when the work was done. A case is what makes that possible: it binds
a named investigation to its own audit chain, its own evidence register and its
own report directory, so "what did we do, to what, and when" has an answer that
does not depend on anyone's memory.

Evidence is hashed at intake. That digest is what a later report is checked
against, and it is the only thing that makes a chain-of-custody claim mean
anything.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.core.hashing import human_bytes
from sanctum.gui import theme
from sanctum.gui.widgets import Card, FieldRow, LogPane, PageHeader
from sanctum.gui.workers import Job

_CASE_COLUMNS = ["Case ID", "Name", "Examiner", "Evidence", "Operations", "Updated"]
_EVIDENCE_COLUMNS = ["Path", "Description", "Bytes", "SHA-256", "Registered"]


class CasesView(QWidget):
    """Create, open and maintain cases and their evidence registers."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.job: Job | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header = PageHeader(
            "Cases & Evidence",
            "A case binds an investigation to its audit chain, evidence register "
            "and report directory. Evidence is hashed at intake so a later report "
            "can be checked against it.",
        )
        close_button = QPushButton("Close case")
        close_button.clicked.connect(self._close_case)
        header.add_action(close_button)
        layout.addWidget(header)

        self.current_label = QLabel("")
        self.current_label.setWordWrap(True)
        layout.addWidget(self.current_label)

        columns = QHBoxLayout()
        columns.setSpacing(12)

        # ---- left: case list ---------------------------------------------
        left = QVBoxLayout()
        left.setSpacing(12)
        listing = Card("Cases on this system")
        self.case_table = QTableWidget(0, len(_CASE_COLUMNS))
        self.case_table.setHorizontalHeaderLabels(_CASE_COLUMNS)
        self.case_table.verticalHeader().setVisible(False)
        self.case_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.case_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.case_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.case_table.doubleClicked.connect(lambda _index: self._open_selected())
        listing.add(self.case_table)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        open_button = QPushButton("Open selected")
        open_button.setObjectName("primary")
        open_button.clicked.connect(self._open_selected)
        row.addWidget(refresh)
        row.addWidget(open_button)
        row.addStretch(1)
        listing.add_layout(row)
        left.addWidget(listing)

        create = Card("New case")
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Case name, e.g. Operation Falcon")
        self.examiner_edit = QLineEdit()
        self.examiner_edit.setPlaceholderText("Examiner name")
        self.description_edit = QPlainTextEdit()
        self.description_edit.setPlaceholderText("Scope and authorisation notes")
        self.description_edit.setMaximumHeight(70)
        create.add(FieldRow("Name", self.name_edit))
        create.add(FieldRow("Examiner", self.examiner_edit))
        create.add(self.description_edit)
        create_button = QPushButton("Create case")
        create_button.setObjectName("primary")
        create_button.clicked.connect(self._create_case)
        create.add(create_button)
        left.addWidget(create)
        left.addStretch(1)

        # ---- right: evidence ---------------------------------------------
        right = QVBoxLayout()
        right.setSpacing(12)
        evidence = Card("Evidence register")
        self.evidence_table = QTableWidget(0, len(_EVIDENCE_COLUMNS))
        self.evidence_table.setHorizontalHeaderLabels(_EVIDENCE_COLUMNS)
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        evidence.add(self.evidence_table)

        evidence_row = QHBoxLayout()
        add_evidence = QPushButton("Register evidence...")
        add_evidence.clicked.connect(self._register_evidence)
        verify_evidence = QPushButton("Re-hash and compare")
        verify_evidence.clicked.connect(self._verify_evidence)
        evidence_row.addWidget(add_evidence)
        evidence_row.addWidget(verify_evidence)
        evidence_row.addStretch(1)
        evidence.add_layout(evidence_row)

        self.evidence_note = QLabel(
            "Re-hashing a registered item and comparing against the digest taken "
            "at intake is what demonstrates the item has not changed since."
        )
        self.evidence_note.setObjectName("hint")
        self.evidence_note.setWordWrap(True)
        evidence.add(self.evidence_note)
        right.addWidget(evidence)

        self.log = LogPane()
        self.log.setMinimumHeight(140)
        right.addWidget(self.log, 1)

        columns.addLayout(left, 3)
        columns.addLayout(right, 2)
        layout.addLayout(columns)

        self.state.case_changed.connect(lambda _case: self._refresh_current())
        self.refresh()

    # -- cases -------------------------------------------------------------

    def refresh(self) -> None:
        self.case_table.setRowCount(0)
        for summary in self.state.case_manager.list_cases():
            row = self.case_table.rowCount()
            self.case_table.insertRow(row)
            cells = [
                summary.get("case_id", ""),
                summary.get("name", ""),
                summary.get("examiner", ""),
                str(summary.get("evidence_count", 0)),
                str(summary.get("operation_count", 0)),
                summary.get("updated_at", ""),
            ]
            for column, text in enumerate(cells):
                self.case_table.setItem(row, column, QTableWidgetItem(text))
        self._refresh_current()

    def _refresh_current(self) -> None:
        case = self.state.case
        if case is None:
            self.current_label.setText(
                "No case open. Operations still run and are still audited, but "
                "they are recorded against an ad-hoc session chain rather than a "
                "named case."
            )
            self.current_label.setStyleSheet(f"color: {theme.WARN};")
            self.evidence_table.setRowCount(0)
            return

        self.current_label.setText(
            f"Open case: {case.name}  |  {case.case_id}  |  "
            f"examiner {case.examiner or 'not recorded'}  |  "
            f"{len(case.evidence)} evidence item(s)  |  {len(case.operations)} operation(s)"
        )
        self.current_label.setStyleSheet(f"color: {theme.OK};")
        self._fill_evidence(case)

    def _fill_evidence(self, case) -> None:
        self.evidence_table.setRowCount(0)
        for item in case.evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            cells = [
                item.path,
                item.description,
                f"{item.size_bytes:,}",
                item.sha256,
                item.registered_at,
            ]
            for column, text in enumerate(cells):
                self.evidence_table.setItem(row, column, QTableWidgetItem(text))

    def _selected_case_id(self) -> str:
        rows = self.case_table.selectionModel().selectedRows()
        if not rows:
            return ""
        item = self.case_table.item(rows[0].row(), 0)
        return item.text() if item else ""

    def _open_selected(self) -> None:
        case_id = self._selected_case_id()
        if not case_id:
            QMessageBox.information(self, "No selection", "Select a case first.")
            return
        try:
            case = self.state.open_case(case_id)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not open case", str(exc))
            return
        self.log.append_line(f"Opened case {case.name} ({case.case_id})", "ok")

    def _close_case(self) -> None:
        if self.state.case is None:
            return
        self.state.close_case()
        self.log.append_line("Case closed. Subsequent operations record to the ad-hoc chain.", "warn")

    def _create_case(self) -> None:
        name = self.name_edit.text().strip()
        if not name:
            QMessageBox.information(self, "Name required", "Give the case a name.")
            return
        try:
            case = self.state.create_case(
                name,
                self.examiner_edit.text().strip(),
                self.description_edit.toPlainText().strip(),
            )
        except OSError as exc:
            QMessageBox.warning(self, "Could not create case", str(exc))
            return
        self.log.append_line(f"Created case {case.name} at {case.path}", "ok")
        self.name_edit.clear()
        self.examiner_edit.clear()
        self.description_edit.clear()
        self.refresh()

    # -- evidence ----------------------------------------------------------

    def _register_evidence(self) -> None:
        case = self.state.case
        if case is None:
            QMessageBox.information(
                self,
                "No case open",
                "Open or create a case before registering evidence. Registration "
                "records the digest into the case's own audit chain.",
            )
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Select an evidence file to register"
        )
        if not path:
            return

        # Hashing a multi-gigabyte image takes real time; do it off the GUI
        # thread so the window stays responsive.
        self.log.append_line(f"Hashing {path} for intake...", "muted")

        def work(progress=None, cancel=None):
            return case.register_evidence(path, source="intake")

        job = Job(work, label=f"Hashing {Path(path).name}")
        job.signals.completed.connect(self._on_evidence_registered)
        job.signals.failed.connect(
            lambda message, _trace: QMessageBox.warning(self, "Registration failed", message)
        )
        self.job = job
        job.start()

    def _on_evidence_registered(self, item) -> None:
        self.log.append_line(
            f"Registered {Path(item.path).name} ({human_bytes(item.size_bytes)}) "
            f"SHA-256 {item.sha256[:16]}...",
            "ok",
        )
        self.state.case.save()
        self.state.audit().log(
            "CASE", "evidence_registered",
            outcome="SUCCESS", target=item.path,
            details={"sha256": item.sha256, "size_bytes": item.size_bytes},
        )
        self._refresh_current()
        self.refresh()

    def _verify_evidence(self) -> None:
        case = self.state.case
        if case is None or not case.evidence:
            QMessageBox.information(self, "Nothing to verify", "No evidence registered.")
            return

        from sanctum.core import hashing

        self.log.rule("Evidence re-verification")
        intact = 0
        for item in case.evidence:
            target = Path(item.path)
            if not target.exists():
                self.log.append_line(f"MISSING: {item.path}", "bad")
                continue
            try:
                digests = hashing.hash_file(target)
            except OSError as exc:
                self.log.append_line(f"UNREADABLE: {item.path} ({exc})", "bad")
                continue
            if digests.get("sha256") == item.sha256:
                intact += 1
                self.log.append_line(f"MATCH: {item.path}", "ok")
            else:
                self.log.append_line(
                    f"CHANGED: {item.path}\n"
                    f"  recorded {item.sha256}\n"
                    f"  current  {digests.get('sha256')}",
                    "bad",
                )
                self.state.audit().log(
                    "INTEGRITY", "evidence_digest_mismatch",
                    outcome="FAILURE", target=item.path,
                    details={"recorded": item.sha256, "current": digests.get("sha256", "")},
                )
        self.log.append_line(
            f"{intact}/{len(case.evidence)} item(s) unchanged.", "muted"
        )
