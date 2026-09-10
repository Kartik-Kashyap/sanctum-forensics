"""
Main window and application entry point.

The shell is intentionally thin. It owns the sidebar, the status bar, and the
shared :class:`AppState`, and swaps pages in and out of a stack. All the
behaviour lives in the views and, below them, in the engines - which is what
keeps the GUI honest: it cannot do anything the tested code paths cannot do.
"""

from __future__ import annotations

import sys

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from sanctum import __product_name__, __tagline__, __version__
from sanctum.gui import theme
from sanctum.gui.state import AppState
from sanctum.gui.views import (
    AuditView,
    CasesView,
    DashboardView,
    DriveEraserView,
    FileEraserView,
    RecoveryView,
    ReportsView,
    SettingsView,
)

#: Sidebar entries, in workflow order: look, then act, then account for it.
_NAVIGATION = [
    ("Dashboard", DashboardView, "Session overview, capabilities and integrity"),
    ("Drive Eraser", DriveEraserView, "Sanitize a whole device or disk image"),
    ("File Eraser", FileEraserView, "Selective secure deletion and free-space sweep"),
    ("Recovery", RecoveryView, "Carve and recover files from damaged media"),
    ("Reports", ReportsView, "Generate the report and audit record"),
    ("Audit", AuditView, "Browse and verify the tamper-evident chain"),
    ("Cases", CasesView, "Cases, evidence register and chain of custody"),
    ("Settings", SettingsView, "Safety policy and runtime configuration"),
]


class MainWindow(QMainWindow):
    """The application shell."""

    def __init__(self, state: AppState | None = None) -> None:
        """
        Build the shell around ``state``.

        The state is injectable so a caller - a test, or a future entry point
        that restores a session - can supply one. Left out, the window makes its
        own, which is what ``run()`` does.
        """
        super().__init__()
        self.setWindowTitle(f"{__product_name__} — {__tagline__}")
        self.resize(1360, 880)
        self.setMinimumSize(1040, 680)

        self.state = state if state is not None else AppState()

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ---- sidebar -----------------------------------------------------
        sidebar = QWidget()
        sidebar.setFixedWidth(216)
        sidebar_layout = QHBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.currentRowChanged.connect(self._on_nav_changed)

        brand = QLabel(f"  {__product_name__}")
        brand.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        brand.setStyleSheet(
            f"color: {theme.ACCENT}; padding: 14px 4px 10px 10px;"
        )

        version = QLabel(f"  v{__version__}")
        version.setStyleSheet(
            f"color: {theme.MUTED}; font-size: 11px; padding: 0 0 6px 12px;"
        )

        nav_column = QVBoxLayout()
        nav_column.setContentsMargins(0, 0, 0, 0)
        nav_column.setSpacing(0)
        nav_column.addWidget(brand)
        nav_column.addWidget(version)
        nav_column.addWidget(self.nav, 1)
        sidebar_layout.addLayout(nav_column)
        layout.addWidget(sidebar)

        # ---- pages -------------------------------------------------------
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, 1)

        for title, view_class, hint in _NAVIGATION:
            item = QListWidgetItem(title)
            item.setToolTip(hint)
            self.nav.addItem(item)
            self.pages.addWidget(view_class(self.state))

        self.setCentralWidget(central)

        # ---- status bar --------------------------------------------------
        status = QStatusBar()
        self.setStatusBar(status)
        self.case_status = QLabel("")
        self.policy_status = QLabel("")
        status.addWidget(self.case_status, 1)
        status.addPermanentWidget(self.policy_status)

        self.state.case_changed.connect(lambda _case: self._refresh_status())
        self.state.policy_changed.connect(lambda _policy: self._refresh_status())
        self.state.results_changed.connect(self._refresh_status)
        self._refresh_status()

        self.nav.setCurrentRow(0)

    # -- navigation --------------------------------------------------------

    def _on_nav_changed(self, row: int) -> None:
        if not (0 <= row < self.pages.count()):
            return
        self.pages.setCurrentIndex(row)
        page = self.pages.currentWidget()
        # Several views cache session state; refresh on entry so a page is never
        # showing a stale view of what has happened since it was last visible.
        if hasattr(page, "refresh"):
            page.refresh()
        elif hasattr(page, "on_shown"):
            page.on_shown()

    # -- status ------------------------------------------------------------

    def _refresh_status(self) -> None:
        state = self.state

        self.case_status.setText(f"  Case: {state.case_label}")
        self.case_status.setStyleSheet(
            f"color: {theme.OK if state.case else theme.WARN};"
        )

        parts = [f"Dry run: {'ON' if state.policy.dry_run else 'off'}"]
        if state.policy.dry_run:
            tone = theme.MUTED
        else:
            tone = theme.ACCENT
        if state.raw_devices_armed:
            parts.append("Raw devices: ARMED")
            tone = theme.WARN
        elif state.policy.allow_raw_devices:
            parts.append("Raw devices: locked by environment")
            tone = theme.WARN
        else:
            parts.append("Raw devices: disabled")
        parts.append(f"{state.results.count} operation(s) this session")

        self.policy_status.setText("  |  ".join(parts) + "  ")
        self.policy_status.setStyleSheet(f"color: {tone};")

    # -- lifecycle ---------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        from PyQt6.QtWidgets import QMessageBox

        running = [
            widget for widget in (self.pages.widget(i) for i in range(self.pages.count()))
            if getattr(widget, "job", None) is not None and widget.job.isRunning()
        ]
        if running:
            answer = QMessageBox.question(
                self,
                "An operation is still running",
                "An erasure or recovery is in progress. Closing now will request "
                "cancellation; the engine stops at its next safe point and the "
                "audit chain records the interruption.\n\nClose anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer is not QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            for widget in running:
                widget.job.cancel()
                widget.job.wait(4000)

        if self.state.case is not None:
            try:
                self.state.case.save()
            except OSError:
                pass
        event.accept()


def run(argv: list[str] | None = None) -> int:
    """Launch the desktop application. Returns the process exit code."""
    argv = list(argv if argv is not None else sys.argv)
    app = QApplication(argv)
    app.setApplicationName(__product_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Team Sanchay")
    app.setStyleSheet(theme.STYLESHEET)

    window = MainWindow()
    window.show()
    return app.exec()
