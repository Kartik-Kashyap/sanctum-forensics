"""
Audit Management view.

The point of this screen is to make the integrity claim checkable rather than
merely asserted. It shows the chain, its verification state, and - when
verification fails - the exact sequence number where integrity first breaks.

A **Verify chain** button re-derives every digest from the file on disk. If a
record was edited, reordered or removed since it was written, the verification
fails at that point and says so. That is the whole value of the design: not
that the log cannot be touched, but that touching it cannot go unnoticed.
"""

from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.gui import theme
from sanctum.gui.widgets import Card, LogPane, NumericItem, PageHeader
from sanctum.report.builder import LIMITATION_AUDIT

_OUTCOME_TONE = {
    "SUCCESS": theme.OK,
    "INFO": theme.ACCENT,
    "DENIED": theme.WARN,
    "FAILURE": theme.BAD,
}

_COLUMNS = ["Seq", "Timestamp (UTC)", "Category", "Action", "Outcome", "Actor", "Target"]


class AuditView(QWidget):
    """Browse, verify and export the tamper-evident audit chain."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header = PageHeader(
            "Audit Management",
            "Every destructive and recovery operation is recorded in a hash-chained "
            "log. Each entry commits to its predecessor's digest and carries an "
            "HMAC, so modification, reordering or deletion is detectable.",
        )
        verify_button = QPushButton("Verify chain")
        verify_button.setObjectName("primary")
        verify_button.clicked.connect(self.verify)
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.refresh)
        export_button = QPushButton("Export...")
        export_button.clicked.connect(self.export)
        header.add_action(refresh_button)
        header.add_action(export_button)
        header.add_action(verify_button)
        layout.addWidget(header)

        self.verdict = QLabel("Chain not yet verified.")
        self.verdict.setWordWrap(True)
        self.verdict.setStyleSheet(f"color: {theme.MUTED};")
        layout.addWidget(self.verdict)

        self.limitation = QLabel(LIMITATION_AUDIT)
        self.limitation.setObjectName("hint")
        self.limitation.setWordWrap(True)
        layout.addWidget(self.limitation)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        # Chain order, which is the order ``verify`` walks and the order the
        # sequence numbers mean. Left alone the default is Qt's - column 0,
        # descending - which on a chain of 1..n shows the newest record first
        # and reads as a log rather than as a chain. Either is defensible; the
        # point is that it is chosen here rather than inherited.
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemSelectionChanged.connect(self._on_selected)
        layout.addWidget(self.table, 3)

        detail = QHBoxLayout()
        detail.setSpacing(12)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a record to inspect its full payload.")
        detail.addWidget(self.detail, 1)

        self.log = LogPane()
        self.log.setPlaceholderText("Verification output appears here.")
        detail.addWidget(self.log, 1)
        layout.addLayout(detail, 2)

        self.refresh()

    # -- data --------------------------------------------------------------

    def refresh(self) -> None:
        try:
            chain = self.state.audit()
            entries = chain.entries()
        except OSError as exc:
            self.verdict.setText(f"Could not read the audit chain: {exc}")
            self.verdict.setStyleSheet(f"color: {theme.BAD};")
            return

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self._entries = entries
        for position, entry in enumerate(entries):
            row = self.table.rowCount()
            self.table.insertRow(row)
            cells = [
                str(entry.seq),
                entry.timestamp,
                entry.category,
                entry.action,
                entry.outcome,
                entry.actor,
                entry.target,
            ]
            for column, text in enumerate(cells):
                # The sequence number is the chain's ordering, so it has to
                # sort as a number. Left as text - which is what it was, the
                # cell showing "10" before "9" - an examiner ordering the chain
                # by sequence got a list in no order at all.
                item = (
                    NumericItem(text, entry.seq) if column == 0
                    else QTableWidgetItem(text)
                )
                if column == 0:
                    # Which record this row *is*, as opposed to what it reads
                    # as. Sorting permutes the rows, so the position in the
                    # table says nothing about the position in the chain.
                    item.setData(Qt.ItemDataRole.UserRole, position)
                if column == 4:
                    item.setForeground(
                        QColor(_OUTCOME_TONE.get(entry.outcome, theme.MUTED))
                    )
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)

        source = "case chain" if self.state.case else "ad-hoc session chain"
        self.verdict.setText(
            f"{len(entries)} record(s) in the {source}. Press Verify chain to "
            "re-derive every digest from the file on disk."
        )
        self.verdict.setStyleSheet(f"color: {theme.MUTED};")

    def verify(self) -> None:
        try:
            report = self.state.audit().verify()
        except OSError as exc:
            self.verdict.setText(f"Verification could not run: {exc}")
            self.verdict.setStyleSheet(f"color: {theme.BAD};")
            return

        self.log.rule("Chain verification")
        if report.ok:
            self.verdict.setText(
                f"INTACT - all {report.entries} record(s) verified. Every entry's "
                "digest and back-link are consistent and its HMAC is valid. No "
                "modification, reordering or deletion was detected."
            )
            self.verdict.setStyleSheet(f"color: {theme.OK}; font-weight: 600;")
            self.log.append_line(report.summary(), "ok")
        else:
            self.verdict.setText(
                f"BROKEN at record {report.broken_at} - {report.reason}. The chain "
                "has been altered and results derived from it cannot be relied upon."
            )
            self.verdict.setStyleSheet(f"color: {theme.BAD}; font-weight: 600;")
            self.log.append_line(report.summary(), "bad")
            QMessageBox.critical(
                self,
                "Audit chain integrity failure",
                f"{report.summary()}\n\nRecords from sequence {report.broken_at} "
                "onward cannot be trusted.",
            )

    def export(self) -> None:
        default = str(self.state.reports_dir / "audit_export.jsonl")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export audit chain", default, "JSON Lines (*.jsonl)"
        )
        if not path:
            return
        try:
            written = self.state.audit().export_json(path)
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        self.log.append_line(f"Exported chain to {written}", "ok")

    # -- detail ------------------------------------------------------------

    def _on_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self.detail.clear()
            return
        seq_item = self.table.item(rows[0].row(), 0)
        if seq_item is None:
            return
        # The stored position, not the displayed sequence number. Reading the
        # DisplayRole here yields the cell's *text*, and comparing that against
        # an integer ``entry.seq`` matches nothing - so every click selected
        # nothing and the pane stayed empty, silently, on a table that looked
        # perfectly healthy. The row's identity is kept in UserRole instead.
        position = seq_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(position, int) or not 0 <= position < len(self._entries):
            return
        entry = self._entries[position]
        self.detail.setPlainText(
            json.dumps(entry.payload(), indent=2, sort_keys=True, default=str)
            + "\n\n"
            + f"entry_hash : {entry.entry_hash}\n"
            + f"hmac       : {entry.hmac}\n"
            + f"prev_hash  : {entry.prev_hash}\n"
        )
