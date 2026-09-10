"""
Dashboard.

The first screen, and the one that has to answer "is this tool in a state where
I can trust what it tells me?" before anything else. It reports the runtime
environment, which optional backends are actually available, the state of the
audit chain, and what has been done this session.

Two things here are deliberate choices rather than decoration:

* The **capability card tells the truth about degradation.** If the native
  filesystem backend is not installed, the dashboard says so, because it changes
  what a recovery result means.
* The **integrity card is not a green tick by default.** The chain is verified
  on load and the result - intact or broken - is shown as found.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sanctum import __product_name__, __tagline__, __version__
from sanctum.core.hashing import human_bytes
from sanctum.gui import theme
from sanctum.gui.widgets import Card, PageHeader, StatRow


class DashboardView(QWidget):
    """Session overview: environment, capabilities, integrity, activity."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        header = PageHeader(
            f"{__product_name__} {__version__}",
            __tagline__,
        )
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        header.add_action(self.refresh_button)
        layout.addWidget(header)

        self.stats = StatRow(
            [
                ("Case", "none", "warn"),
                ("Operations", "0", "info"),
                ("Artefacts", "0", "info"),
                ("Data recovered", "0 B", "info"),
                ("Audit chain", "unverified", "muted"),
            ]
        )
        layout.addWidget(self.stats)

        columns = QHBoxLayout()
        columns.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(12)

        self.integrity_card = Card("Integrity")
        self.integrity_text = QLabel("")
        self.integrity_text.setWordWrap(True)
        self.integrity_card.add(self.integrity_text)
        self.verify_button = QPushButton("Verify audit chain now")
        self.verify_button.clicked.connect(self.verify_audit)
        self.integrity_card.add(self.verify_button)
        left.addWidget(self.integrity_card)

        self.capability_card = Card("Capabilities")
        self.capability_text = QLabel("")
        self.capability_text.setWordWrap(True)
        self.capability_text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.capability_card.add(self.capability_text)
        left.addWidget(self.capability_card)

        self.environment_card = Card("Environment")
        self.environment_text = QLabel("")
        self.environment_text.setWordWrap(True)
        self.environment_text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.environment_card.add(self.environment_text)
        left.addWidget(self.environment_card)
        left.addStretch(1)

        right = QVBoxLayout()
        right.setSpacing(12)

        overview = Card("What this tool does")
        overview_text = QLabel(
            "Three modules over one audited core.\n\n"
            "• Secure Drive Eraser — whole devices and disk images, using NIST "
            "SP 800-88, DoD 5220.22-M, Gutmann, Schneier, VSITR and HMG Infosec "
            "Standard 5, with per-pass verification.\n\n"
            "• Secure File & Folder Eraser — selective deletion that overwrites "
            "content in place, cleanses the directory entry, and sweeps free "
            "space to remove residue of files deleted earlier.\n\n"
            "• Advanced File Carving & Recovery — signature, structure and "
            "fragment based recovery with a scored, auditable confidence result.\n\n"
            "Every operation lands in a hash-chained audit log whose integrity "
            "can be re-verified at any time."
        )
        overview_text.setWordWrap(True)
        overview_text.setObjectName("muted")
        overview.add(overview_text)
        right.addWidget(overview)

        self.activity_card = Card("This session")
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setPlaceholderText("Operations performed this session appear here.")
        self.activity_card.add(self.activity)
        right.addWidget(self.activity_card, 1)

        columns.addLayout(left, 1)
        columns.addLayout(right, 1)
        layout.addLayout(columns, 1)

        self.state.results_changed.connect(self.refresh)
        self.state.case_changed.connect(lambda _case: self.refresh())
        self.refresh()
        # Verify on load rather than asserting a default: the operator should see
        # the chain's actual state, not a green tick that was never checked.
        self.verify_audit()

    # -- refresh -----------------------------------------------------------

    def refresh(self) -> None:
        state = self.state

        self.stats.update("Case", state.case.name if state.case else "none",
                          "ok" if state.case else "warn")

        operations = state.results.operations
        self.stats.update("Operations", str(len(operations)))

        artifacts = [
            artifact
            for op in operations
            for artifact in (op.get("artifacts") or [])
        ]
        self.stats.update("Artefacts", f"{len(artifacts):,}")
        recovered = sum(a.get("length", 0) for a in artifacts)
        self.stats.update("Data recovered", human_bytes(recovered))

        self._refresh_capabilities()
        self._refresh_environment()
        self._refresh_activity(operations)

    def _refresh_capabilities(self) -> None:
        capabilities = self.state.capabilities
        lines: list[str] = []

        if capabilities.any:
            lines.append(
                "Native forensic backend ACTIVE. Filesystem-aware recovery is "
                "available: deleted-entry enumeration, and carving restricted to "
                "the extents the filesystem reports as unallocated."
            )
        else:
            lines.append(
                "Native forensic backend NOT AVAILABLE (pytsk3 / pyewf not "
                "installed). Recovery still works — the carving engine, signature "
                "database, structural validation and confidence scoring are all "
                "pure Python and need no third-party package — but two things "
                "change:"
            )
            lines.append(
                "   • carving cannot be restricted to unallocated extents, so a "
                "scan covers live files as well as deleted ones;"
            )
            lines.append(
                "   • original filenames and timestamps cannot be recovered, "
                "since those live in filesystem metadata."
            )
            lines.append(
                "Reports record which mode was in force, so a result is never "
                "silently overstated."
            )

        lines.append("")
        lines.append(capabilities.summary())
        self.capability_text.setText("\n".join(lines))
        # A missing backend is a warning, not an error: the tool still works,
        # but what a result means has changed, so the colour says "read this".
        self.capability_text.setStyleSheet(
            f"color: {theme.INK if capabilities.any else theme.WARN};"
        )

    def _refresh_environment(self) -> None:
        env = self.state.environment
        elevated = env.get("elevated")
        lines = [
            f"Platform    : {env.get('platform', '')}",
            f"Machine     : {env.get('machine', '')}",
            f"Python      : {env.get('python', '')}",
            f"Privileges  : {'elevated (administrator/root)' if elevated else 'standard user'}",
        ]
        if not elevated:
            lines.append(
                "  Raw physical device enumeration and writes need elevation; "
                "image-backed work does not."
            )
        lines.append(f"Data dir    : {self.state.case_manager.base_dir.parent}")
        lines.append(f"Cases dir   : {self.state.case_manager.base_dir}")
        lines.append(f"Policy      : {self.state.policy.summary()}")
        self.environment_text.setText("\n".join(lines))

    def _refresh_activity(self, operations: list[dict]) -> None:
        if not operations:
            self.activity.setPlainText(
                "No operations yet this session.\n\n"
                "Start with the Drive Eraser against a disk image — it exercises "
                "the whole pipeline safely and repeatably, with no risk to real "
                "data."
            )
            return
        lines: list[str] = []
        for index, op in enumerate(operations, start=1):
            kind = op.get("operation", "operation")
            headline = op.get("headline", "")
            lines.append(f"{index:>3}. {kind:<16} {headline}")
            if kind == "file_carving":
                lines.append(
                    f"     {op.get('recovered_count', 0)} artefact(s), "
                    f"{human_bytes(op.get('recovered_bytes', 0))}, "
                    f"{op.get('elapsed_seconds', 0):.1f}s"
                )
            elif kind == "drive_erase":
                lines.append(
                    f"     {op.get('standard', {}).get('name', '')}, "
                    f"{human_bytes(op.get('bytes_total', 0))}, "
                    f"{op.get('throughput_mbps', 0):.1f} MB/s"
                )
        self.activity.setPlainText("\n".join(lines))

    # -- actions -----------------------------------------------------------

    def verify_audit(self) -> None:
        report = self.state.audit_verification()
        if report.ok:
            self.integrity_text.setText(
                f"INTACT — {report.entries} record(s) verified. Every entry's "
                "digest and back-link are consistent and its HMAC is valid; no "
                "modification, reordering or deletion was detected."
            )
            self.integrity_text.setStyleSheet(f"color: {theme.OK};")
            self.stats.update("Audit chain", "intact", "ok")
        else:
            self.integrity_text.setText(
                f"BROKEN at record {report.broken_at} — {report.reason}. The audit "
                "log has been altered and results derived from it cannot be relied "
                "upon."
            )
            self.integrity_text.setStyleSheet(f"color: {theme.BAD}; font-weight: 600;")
            self.stats.update("Audit chain", "BROKEN", "bad")
