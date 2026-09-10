"""
Advanced File Carving and Recovery view.

Recovers files from media where the filesystem no longer helps. The screen is
built around the two decisions that actually determine whether a carve is worth
anything:

* **Where to scan.** Carving a whole device finds live files as well as deleted
  ones. Restricting the scan to a filesystem's *unallocated* extents is what
  makes a result set mean "these were deleted" - and it requires the native
  backend. When that backend is unavailable the screen says so loudly rather
  than silently scanning everything and letting the operator assume otherwise.
* **What to trust.** Every artefact carries a confidence score with its full
  derivation, shown in the detail pane. A reviewer can see exactly why a
  candidate was rated High and disagree with the weighting if they want to.

Carving is read-only by construction: it opens the source for reading and
writes only into the designated output directory.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.core.hashing import human_bytes
from sanctum.gui import theme
from sanctum.gui.widgets import (
    Card,
    FieldRow,
    LogPane,
    NumericItem,
    PageHeader,
    ProgressPanel,
)
from sanctum.gui.workers import Job
from sanctum.recover.carver import SignatureCarver
from sanctum.recover.image import DiskImage, detect_container
from sanctum.recover.signatures import SIGNATURES, categories, signatures_for_category

_ARTIFACT_COLUMNS = [
    "File", "Category", "Offset", "Bytes", "Confidence", "SHA-256",
]


class RecoveryView(QWidget):
    """Signature, structure and fragment based file recovery."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.job: Job | None = None
        self.artifacts: list = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Advanced File Carving & Recovery",
                "Recover files from formatted, corrupted or damaged media by "
                "content alone - signature matching confirmed by structural "
                "validation, with a scored and auditable confidence result.",
            )
        )

        columns = QHBoxLayout()
        columns.setSpacing(12)

        # ---- left: source + filters --------------------------------------
        left = QVBoxLayout()
        left.setSpacing(12)

        source = Card("Source")
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Evidence image or device (read-only)")
        self.source_edit.setReadOnly(True)
        browse = QPushButton("Open image...")
        browse.clicked.connect(self._browse_source)
        row = QHBoxLayout()
        row.addWidget(self.source_edit, 1)
        row.addWidget(browse)
        source.add_layout(row)

        self.source_info = QLabel("No source selected.")
        self.source_info.setObjectName("muted")
        self.source_info.setWordWrap(True)
        source.add(self.source_info)

        self.scope_combo = QComboBox()
        self.scope_combo.addItem("Whole source", "whole")
        self.scope_combo.addItem("Unallocated space only (native backend required)", "unallocated")
        self.scope_combo.currentIndexChanged.connect(self._refresh_scope_note)
        source.add(FieldRow("Scan scope", self.scope_combo))

        self.scope_note = QLabel("")
        self.scope_note.setObjectName("hint")
        self.scope_note.setWordWrap(True)
        source.add(self.scope_note)
        left.addWidget(source)

        filters = Card("Format filter")
        self.category_list = QListWidget()
        self.category_list.setMaximumHeight(150)
        for category in categories():
            item = QListWidgetItem(
                f"{category}  ({len(signatures_for_category(category))} formats)"
            )
            item.setData(Qt.ItemDataRole.UserRole, category)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.category_list.addItem(item)
        self.category_list.itemChanged.connect(self._refresh_filter_note)
        filters.add(self.category_list)

        selection_row = QHBoxLayout()
        all_button = QPushButton("All")
        all_button.clicked.connect(lambda: self._set_all_categories(True))
        none_button = QPushButton("None")
        none_button.clicked.connect(lambda: self._set_all_categories(False))
        selection_row.addWidget(all_button)
        selection_row.addWidget(none_button)
        selection_row.addStretch(1)
        filters.add_layout(selection_row)

        self.filter_note = QLabel("")
        self.filter_note.setObjectName("muted")
        self.filter_note.setWordWrap(True)
        filters.add(self.filter_note)
        left.addWidget(filters)
        left.addStretch(1)

        # ---- right: parameters -------------------------------------------
        right = QVBoxLayout()
        right.setSpacing(12)

        params = Card("Recovery parameters")
        self.min_confidence = QDoubleSpinBox()
        self.min_confidence.setRange(0.0, 100.0)
        self.min_confidence.setSingleStep(5.0)
        self.min_confidence.setValue(0.0)
        self.min_confidence.setSuffix(" / 100")
        params.add(
            FieldRow(
                "Minimum confidence",
                self.min_confidence,
                "0 keeps every candidate, including low-confidence ones, and lets "
                "the report rank them. Raising this narrows output to findings "
                "the scorer is more sure about.",
            )
        )

        self.max_artifacts = QSpinBox()
        self.max_artifacts.setRange(1, 100_000)
        self.max_artifacts.setValue(5000)
        params.add(FieldRow("Maximum artefacts", self.max_artifacts))

        self.require_validation = QCheckBox("Require structural validation")
        self.require_validation.setChecked(True)
        self.require_validation.setToolTip(
            "Reject candidates whose bytes match a header but fail the format's "
            "structural parse. This is what suppresses coincidental matches."
        )
        params.add(self.require_validation)

        self.write_files = QCheckBox("Write recovered files to disk")
        self.write_files.setChecked(True)
        params.add(self.write_files)

        self.advanced_fragments = QCheckBox("Attempt fragment reassembly (JPEG)")
        self.advanced_fragments.setChecked(False)
        self.advanced_fragments.setToolTip(
            "Splices fragments by validating the JPEG marker chain. Structural "
            "validity does not prove the extents are in their original order - "
            "treat reassembled artefacts as provisional."
        )
        params.add(self.advanced_fragments)
        right.addWidget(params)

        output = Card("Output")
        self.output_edit = QLineEdit()
        self.output_edit.setText(str(self.state.artifacts_dir))
        out_browse = QPushButton("Change...")
        out_browse.clicked.connect(self._browse_output)
        out_row = QHBoxLayout()
        out_row.addWidget(self.output_edit, 1)
        out_row.addWidget(out_browse)
        output.add_layout(out_row)
        self.output_note = QLabel(
            "Recovered files are written here with digests recorded in the report. "
            "Nothing is ever written to the source."
        )
        self.output_note.setObjectName("hint")
        self.output_note.setWordWrap(True)
        output.add(self.output_note)
        right.addWidget(output)

        self.run_button = QPushButton("Start recovery")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self._start)
        self.run_button.setEnabled(False)
        right.addWidget(self.run_button)
        right.addStretch(1)

        columns.addLayout(left, 1)
        columns.addLayout(right, 1)
        layout.addLayout(columns)

        self.progress = ProgressPanel()
        self.progress.cancelled.connect(self._cancel)
        layout.addWidget(self.progress)

        # ---- results ------------------------------------------------------
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, len(_ARTIFACT_COLUMNS))
        self.table.setHorizontalHeaderLabels(_ARTIFACT_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        # Initial order is the carver's own: ascending offset, which is the
        # order the media was scanned and the order the results arrive in.
        # Without this the default is whatever Qt picked when sorting was
        # switched on - column 0, descending - so the table opened showing the
        # finds in reverse filename order. That agreed with nothing: not the
        # engine's ordering, not confidence, not scan order. An examiner had to
        # re-sort on arrival to see the results the tool had actually ranked.
        self.table.sortByColumn(2, Qt.SortOrder.AscendingOrder)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemSelectionChanged.connect(self._on_artifact_selected)
        splitter.addWidget(self.table)

        detail_split = QSplitter(Qt.Orientation.Horizontal)
        self.explanation = QPlainTextEdit()
        self.explanation.setReadOnly(True)
        self.explanation.setPlaceholderText(
            "Select an artefact to see how its confidence score was derived."
        )
        self.log = LogPane()
        detail_split.addWidget(self.explanation)
        detail_split.addWidget(self.log)
        splitter.addWidget(detail_split)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

        self._refresh_scope_note()
        self._refresh_filter_note()
        self._refresh_source_info()

    # -- source ------------------------------------------------------------

    def _browse_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select an evidence image",
            "",
            "Disk images (*.img *.dd *.raw *.iso *.001 *.E01 *.e01);;All files (*)",
        )
        if not path:
            return
        self.source_edit.setText(path)
        self._refresh_source_info()

    def _refresh_source_info(self) -> None:
        path = self.source_edit.text().strip()
        if not path:
            self.source_info.setText("No source selected.")
            self.run_button.setEnabled(False)
            return
        target = Path(path)
        if not target.exists():
            self.source_info.setText("Source does not exist.")
            self.source_info.setStyleSheet(f"color: {theme.BAD};")
            self.run_button.setEnabled(False)
            return

        container = detect_container(target)
        size = target.stat().st_size
        text = f"{container}  |  {human_bytes(size)}"
        if container == "ewf":
            text += "  (EnCase image - requires the pyewf native backend)"
        self.source_info.setText(text)
        self.source_info.setStyleSheet(f"color: {theme.MUTED};")
        self.run_button.setEnabled(True)

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose an output directory")
        if path:
            self.output_edit.setText(path)

    def _refresh_scope_note(self) -> None:
        if self.scope_combo.currentData() != "unallocated":
            self.scope_note.setText(
                "Scanning the whole source recovers live files as well as deleted "
                "ones - the result set is not evidence of deletion on its own."
            )
            self.scope_note.setStyleSheet(f"color: {theme.MUTED};")
        elif not self.state.capabilities.any:
            self.scope_note.setText(
                "The native backend (pytsk3) is not available, so filesystem "
                "extents cannot be resolved. Recovery will fall back to scanning "
                "the whole source - which is not the same thing, and is recorded "
                "as such in the report."
            )
            self.scope_note.setStyleSheet(f"color: {theme.WARN};")
        else:
            self.scope_note.setText(
                "Only extents the filesystem reports as unallocated are scanned. "
                "This is what makes the result set meaningful as evidence of "
                "deletion, and it is substantially faster."
            )
            self.scope_note.setStyleSheet(f"color: {theme.OK};")

    # -- filters -----------------------------------------------------------

    def _set_all_categories(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.category_list.blockSignals(True)
        for index in range(self.category_list.count()):
            self.category_list.item(index).setCheckState(state)
        self.category_list.blockSignals(False)
        self._refresh_filter_note()

    def selected_categories(self) -> list[str]:
        return [
            self.category_list.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self.category_list.count())
            if self.category_list.item(i).checkState() == Qt.CheckState.Checked
        ]

    def _refresh_filter_note(self) -> None:
        chosen = self.selected_categories()
        count = sum(len(signatures_for_category(c)) for c in chosen)
        if not chosen:
            self.filter_note.setText("No formats selected - nothing will be scanned.")
            self.filter_note.setStyleSheet(f"color: {theme.BAD};")
        else:
            self.filter_note.setText(
                f"{count} of {len(SIGNATURES)} signatures across "
                f"{len(chosen)} categor{'ies' if len(chosen) != 1 else 'y'}."
            )
            self.filter_note.setStyleSheet(f"color: {theme.MUTED};")

    # -- execution ---------------------------------------------------------

    def _start(self) -> None:
        source = self.source_edit.text().strip()
        if not source:
            return
        chosen = self.selected_categories()
        if not chosen:
            QMessageBox.information(
                self, "No formats selected", "Choose at least one file category."
            )
            return

        output = self.output_edit.text().strip() or str(self.state.artifacts_dir)
        Path(output).mkdir(parents=True, exist_ok=True)

        regions = None
        if self.scope_combo.currentData() == "unallocated":
            try:
                with DiskImage(source) as image:
                    regions = image.unallocated_regions()
            except Exception as exc:  # noqa: BLE001 - reported, not crashed on
                QMessageBox.warning(
                    self,
                    "Could not resolve unallocated space",
                    f"{type(exc).__name__}: {exc}\n\nFalling back to a whole-source scan. "
                    "The report will record that the scope was widened.",
                )
                regions = None

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.artifacts = []
        self.explanation.clear()
        self.log.rule(f"Carving {Path(source).name}")
        self.log.append_line(f"Categories: {', '.join(chosen)}", "muted")
        self.log.append_line(
            f"Scope: {'unallocated extents' if regions else 'whole source'}", "muted"
        )
        self.progress.begin("Scanning...")

        carver = SignatureCarver(self.state.audit())
        job = Job(
            carver.carve,
            source,
            output,
            categories_filter=chosen,
            regions=regions,
            min_confidence=self.min_confidence.value(),
            max_artifacts=self.max_artifacts.value(),
            require_validation=self.require_validation.isChecked(),
            write_files=self.write_files.isChecked(),
            label=f"Carving {Path(source).name}",
        )
        job.signals.progress.connect(self.progress.on_progress)
        job.signals.completed.connect(self._on_complete)
        job.signals.failed.connect(self._on_failed)
        job.finished.connect(self._on_job_finished)
        self.job = job
        job.start()
        self.run_button.setEnabled(False)

    def _cancel(self) -> None:
        if self.job is not None:
            self.job.cancel()
            self.log.append_line("Cancellation requested.", "warn")

    def _on_complete(self, result) -> None:
        tone = "bad" if result.error else ("warn" if result.cancelled else "ok")
        headline = (
            f"{result.recovered_count} artefact(s), "
            f"{human_bytes(result.recovered_bytes)} recovered"
        )
        self.progress.finish(result.error or headline, tone)
        self.log.append_line(headline, tone)
        self.log.append_line(
            f"Scanned {human_bytes(result.bytes_scanned)} across "
            f"{result.regions_scanned} region(s) using "
            f"{result.signatures_used} signature(s) in "
            f"{result.elapsed_seconds:.1f}s",
            "muted",
        )
        summary = result.summary()
        labels = summary.get("by_confidence", {})
        self.log.append_line(
            f"High {labels.get('High', 0)}  Medium {labels.get('Medium', 0)}  "
            f"Low {labels.get('Low', 0)}  |  mean confidence "
            f"{summary.get('mean_confidence', 0):.1f}/100",
            "muted",
        )
        for warning in result.warnings:
            self.log.append_line(f"NOTE: {warning}", "warn")
        if result.error:
            self.log.append_line(f"ERROR: {result.error}", "bad")

        self.artifacts = list(result.artifacts)
        self._fill_table()
        self.state.record(result)

    def _fill_table(self) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for artifact in self.artifacts:
            index = self.table.rowCount()
            self.table.insertRow(index)
            tone = theme.CONFIDENCE_TONE.get(artifact.confidence_label, theme.MUTED)
            cells = [
                # (display text, numeric sort key). The keys are what stop the
                # offset column ordering 0x1000 before 0x200 and the length
                # column ordering 9 before 10.
                (artifact.name, None),
                (artifact.category, None),
                (f"0x{artifact.offset:X}", artifact.offset),
                (f"{artifact.length:,}", artifact.length),
                (f"{artifact.confidence:.0f} {artifact.confidence_label}",
                 artifact.confidence),
                (artifact.digests.get("sha256", ""), None),
            ]
            for column, (text, sort_key) in enumerate(cells):
                item = (
                    QTableWidgetItem(text) if sort_key is None
                    else NumericItem(text, sort_key)
                )
                if column == 0:
                    # Which artefact this row shows, by position in
                    # ``self.artifacts``. Sorting permutes the rows, so the row
                    # number is not the artefact number; matching on the
                    # displayed name and offset instead would work only while
                    # those happen to be unique and unformatted. Storing the
                    # index is a fact the cell carries rather than a property
                    # inferred back out of its rendering.
                    item.setData(Qt.ItemDataRole.UserRole, self.artifacts.index(artifact))
                if column == 4:
                    item.setForeground(QColor(tone))
                self.table.setItem(index, column, item)
        self.table.setSortingEnabled(True)

    def _on_artifact_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            self.explanation.clear()
            return
        artifact = self._artifact_for_row(rows[0].row())
        if artifact is None:
            return
        self.explanation.setPlainText(self._explain(artifact))

    def _artifact_for_row(self, row: int):
        """
        Map a view row back to its artefact.

        The row number is the position *on screen*, which sorting permutes, so
        the artefact's index is read back out of the cell that stored it rather
        than inferred from the text being displayed. Inferring it from the
        rendered name and offset is what this used to do, and it stopped working
        the moment those cells were given a sort key: the offset cell displays
        ``0x1000`` while the artefact holds the integer, so no row ever matched
        and the confidence derivation pane stayed empty no matter what was
        clicked.
        """
        name_item = self.table.item(row, 0)
        if name_item is None:
            return None
        stored = name_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(stored, int) or not 0 <= stored < len(self.artifacts):
            return None
        return self.artifacts[stored]

    @staticmethod
    def _explain(artifact) -> str:
        """
        Render the full derivation of a confidence score.

        Every factor is shown with its weight so a reviewer can recompute the
        total under a different weighting and see whether the ranking would
        change. An opaque score would be unusable as evidence.
        """
        lines = [
            f"{artifact.name}",
            f"{'=' * len(artifact.name)}",
            f"Category      : {artifact.category}",
            f"Signature     : {artifact.signature_id}",
            f"Offset        : 0x{artifact.offset:X} - 0x{artifact.end_offset:X}",
            f"Length        : {artifact.length:,} bytes",
            f"Confidence    : {artifact.confidence:.1f}/100 ({artifact.confidence_label})",
            f"Validated     : {'yes' if artifact.validated else 'no'}",
            f"Terminator    : {'found' if artifact.footer_found else 'not found'}",
            f"Truncated     : {'yes' if artifact.truncated else 'no'}",
            "",
            "SHA-256       : " + artifact.digests.get("sha256", ""),
            "MD5           : " + artifact.digests.get("md5", ""),
            "",
            "Score derivation",
            "-" * 16,
        ]
        total = 0.0
        for factor in artifact.factors:
            weight = factor.get("weight", 0.0)
            total += weight
            sign = "+" if weight >= 0 else ""
            lines.append(
                f"  {sign}{weight:>6.1f}  {factor.get('factor', '')}"
                + (f": {factor['detail']}" if factor.get("detail") else "")
            )
        lines.append(f"  {'-' * 6}")
        lines.append(f"  {total:>6.1f}  total (clamped to 0-100)")
        if artifact.warnings:
            lines.append("")
            lines.append("Warnings")
            lines.append("-" * 8)
            lines.extend(f"  ! {w}" for w in artifact.warnings)
        if artifact.output_path:
            lines.append("")
            lines.append(f"Written to: {artifact.output_path}")
        if artifact.extraction_error:
            lines.append(f"Extraction error: {artifact.extraction_error}")
        return "\n".join(lines)

    def _on_failed(self, message: str, trace: str) -> None:
        self.progress.finish("Failed", "bad")
        self.log.append_line(f"FAILED: {message}", "bad")
        self.log.append_line(trace, "muted")
        QMessageBox.critical(self, "Recovery failed", message)

    def _on_job_finished(self) -> None:
        self.job = None
        self.run_button.setEnabled(bool(self.source_edit.text().strip()))
