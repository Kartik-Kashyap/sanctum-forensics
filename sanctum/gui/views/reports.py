"""
Reporting view.

Assembles the deliverable that leaves the tool: a report an investigator can
hand to a reviewer, a court or an auditor. It covers the operations performed,
the exact parameters, the evidence handled, the results, the integrity state of
the audit chain, and the limitations of what was done.

The limitations section is shown on this screen *before* the report is written,
so the operator cannot be surprised by what it says. Generating a report is also
the moment the audit chain is re-verified, because a report asserting integrity
should have just checked it.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox,
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

from sanctum import __product_name__, __version__
from sanctum.gui import theme
from sanctum.gui.widgets import Card, FieldRow, LogPane, PageHeader
from sanctum.report.builder import ReportBuilder, ReportContext

_OP_COLUMNS = ["Include", "Operation", "Summary"]

_TITLES = {
    "drive_erase": "Drive erasure",
    "file_erase": "File/folder deletion",
    "free_space_wipe": "Free-space sanitization",
    "file_carving": "File carving",
}


class ReportsView(QWidget):
    """Generate HTML, JSON and CSV reports from the session's operations."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Reporting & Audit Management",
                f"Assemble a defensible record of the work performed. The audit "
                f"chain is re-verified at generation time and its state is written "
                f"into the report.",
            )
        )

        columns = QHBoxLayout()
        columns.setSpacing(12)

        # ---- left: context + operations ----------------------------------
        left = QVBoxLayout()
        left.setSpacing(12)

        context = Card("Report context")
        self.case_name = QLineEdit()
        self.examiner = QLineEdit()
        self.description = QPlainTextEdit()
        self.description.setMaximumHeight(70)
        context.add(FieldRow("Case name", self.case_name))
        context.add(FieldRow("Examiner", self.examiner))
        context.add(self.description)
        left.addWidget(context)

        operations = Card("Operations to include")
        self.op_table = QTableWidget(0, len(_OP_COLUMNS))
        self.op_table.setHorizontalHeaderLabels(_OP_COLUMNS)
        self.op_table.verticalHeader().setVisible(False)
        self.op_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.op_table.itemChanged.connect(lambda _item: self._refresh_limitations())
        operations.add(self.op_table)

        op_row = QHBoxLayout()
        select_all = QPushButton("Select all")
        select_all.clicked.connect(lambda: self._set_all(True))
        select_none = QPushButton("Select none")
        select_none.clicked.connect(lambda: self._set_all(False))
        op_row.addWidget(select_all)
        op_row.addWidget(select_none)
        op_row.addStretch(1)
        operations.add_layout(op_row)
        left.addWidget(operations, 1)

        # ---- right: output + limitations ---------------------------------
        right = QVBoxLayout()
        right.setSpacing(12)

        output = Card("Output")
        self.html_check = QCheckBox("HTML (self-contained, print-ready)")
        self.html_check.setChecked(True)
        self.json_check = QCheckBox("JSON (structured, for re-analysis)")
        self.json_check.setChecked(True)
        self.csv_check = QCheckBox("CSV (artefact inventory)")
        self.csv_check.setChecked(False)
        output.add(self.html_check)
        output.add(self.json_check)
        output.add(self.csv_check)

        self.stem_edit = QLineEdit("sanctum_report")
        output.add(FieldRow("Filename stem", self.stem_edit))

        self.destination = QLabel("")
        self.destination.setObjectName("muted")
        self.destination.setWordWrap(True)
        output.add(self.destination)

        self.generate_button = QPushButton("Generate report")
        self.generate_button.setObjectName("primary")
        self.generate_button.clicked.connect(self.generate)
        output.add(self.generate_button)

        self.open_button = QPushButton("Open generated report")
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self._open_report)
        output.add(self.open_button)
        right.addWidget(output)

        self.limitations = QPlainTextEdit()
        self.limitations.setReadOnly(True)
        self.limitations.setPlaceholderText(
            "Limitations applying to the selected operations appear here before "
            "the report is written."
        )
        right.addWidget(self.limitations, 2)
        right.addStretch(1)

        columns.addLayout(left, 3)
        columns.addLayout(right, 2)
        layout.addLayout(columns)

        self.log = LogPane()
        self.log.setMaximumHeight(130)
        layout.addWidget(self.log)

        self._last_html: Path | None = None
        self.state.results_changed.connect(self.refresh)
        self.state.case_changed.connect(lambda _case: self._sync_context())
        self.refresh()
        self._sync_context()

    # -- data --------------------------------------------------------------

    def _sync_context(self) -> None:
        case = self.state.case
        if case is not None:
            self.case_name.setText(case.name)
            self.examiner.setText(case.examiner)
            self.description.setPlainText(case.description)
        self.destination.setText(f"Reports are written to:\n{self.state.reports_dir}")

    def refresh(self) -> None:
        operations = self.state.results.operations
        # Suppress itemChanged while populating, or every inserted cell would
        # trigger a limitations recomputation against a half-built table.
        self.op_table.blockSignals(True)
        self.op_table.setRowCount(0)
        for index, op in enumerate(operations):
            row = self.op_table.rowCount()
            self.op_table.insertRow(row)

            check = QTableWidgetItem()
            check.setFlags(check.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            check.setCheckState(Qt.CheckState.Checked)
            check.setData(Qt.ItemDataRole.UserRole, index)
            self.op_table.setItem(row, 0, check)

            kind = op.get("operation", "unknown")
            self.op_table.setItem(
                row, 1, QTableWidgetItem(_TITLES.get(kind, kind.replace("_", " ").title()))
            )
            self.op_table.setItem(row, 2, QTableWidgetItem(op.get("headline", "")))
        self.op_table.blockSignals(False)

        if not operations:
            self.log.append_line(
                "No operations recorded yet this session. Perform an erasure or "
                "recovery, then return here.",
                "muted",
            )
        self._refresh_limitations()

    def _set_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.op_table.rowCount()):
            item = self.op_table.item(row, 0)
            if item:
                item.setCheckState(state)
        self._refresh_limitations()

    def selected_operations(self) -> list[dict]:
        chosen: list[dict] = []
        for row in range(self.op_table.rowCount()):
            item = self.op_table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                index = item.data(Qt.ItemDataRole.UserRole)
                if 0 <= index < len(self.state.results.operations):
                    chosen.append(self.state.results.operations[index])
        return chosen

    def _build(self) -> ReportBuilder:
        case = self.state.case
        builder = ReportBuilder(
            ReportContext(
                case_name=self.case_name.text().strip() or "Ad-hoc session",
                case_id=case.case_id if case else "",
                examiner=self.examiner.text().strip(),
                description=self.description.toPlainText().strip(),
            )
        )
        for op in self.selected_operations():
            builder.add_operation(op)
        if case is not None:
            for item in case.evidence:
                builder.add_evidence(item)
        # Verifying at generation time is the point: a report that asserts
        # integrity should have checked it, not repeated a claim from earlier.
        builder.attach_audit(self.state.audit())
        return builder

    def _refresh_limitations(self) -> None:
        try:
            builder = self._build()
        except Exception as exc:  # noqa: BLE001 - never block the UI on this
            self.limitations.setPlainText(f"Could not compute limitations: {exc}")
            return
        notes = builder.limitations()
        self.limitations.setPlainText(
            "\n\n".join(f"- {note}" for note in notes)
            if notes
            else "No operations selected."
        )

    # -- generation --------------------------------------------------------

    def generate(self) -> None:
        if not self.selected_operations():
            QMessageBox.information(
                self,
                "Nothing to report",
                "Select at least one operation to include in the report.",
            )
            return

        formats: list[str] = []
        if self.html_check.isChecked():
            formats.append("html")
        if self.json_check.isChecked():
            formats.append("json")
        if self.csv_check.isChecked():
            formats.append("csv")
        if not formats:
            QMessageBox.information(
                self, "No format selected", "Choose at least one output format."
            )
            return

        stem = self.stem_edit.text().strip() or "sanctum_report"
        destination = self.state.reports_dir

        builder = self._build()
        try:
            written = builder.write(destination, stem=stem, formats=tuple(formats))
        except OSError as exc:
            QMessageBox.critical(self, "Could not write report", str(exc))
            return

        self.log.rule("Report generated")
        for name, path in written.items():
            self.log.append_line(f"{name.upper():5} {path}", "ok")

        verification = builder.context.audit_verification
        if verification and verification.ok:
            self.log.append_line(
                f"Audit chain verified at generation: {verification.entries} record(s) intact.",
                "ok",
            )
        elif verification:
            self.log.append_line(
                f"AUDIT CHAIN BROKEN at {verification.broken_at}: {verification.reason}",
                "bad",
            )

        self._last_html = written.get("html") or next(iter(written.values()))
        self.open_button.setEnabled(True)

        self.state.audit().log(
            "REPORT", "report_generated",
            outcome="SUCCESS", target=stem,
            details={"formats": formats, "operations": len(builder.context.operations)},
        )

        if self.state.case is not None:
            self.state.case.record_operation(
                "report", f"{stem} ({', '.join(formats)})",
                {"files": {k: str(v) for k, v in written.items()}},
            )
            self.state.case.save()

        QMessageBox.information(
            self,
            "Report generated",
            f"{__product_name__} v{__version__}\n\n"
            + "\n".join(str(p) for p in written.values()),
        )

    def _open_report(self) -> None:
        if self._last_html is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._last_html)))
