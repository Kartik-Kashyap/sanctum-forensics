"""
Dashboard views.

Each view is a self-contained page: it collects parameters, launches a worker
job, and renders the result object the engine returns. No view reimplements
engine logic, so behaviour is identical whether an operation is driven from the
GUI, the CLI, or a test.
"""

from sanctum.gui.views.audit import AuditView
from sanctum.gui.views.cases import CasesView
from sanctum.gui.views.dashboard import DashboardView
from sanctum.gui.views.drive_eraser import DriveEraserView
from sanctum.gui.views.file_eraser import FileEraserView
from sanctum.gui.views.recovery import RecoveryView
from sanctum.gui.views.reports import ReportsView
from sanctum.gui.views.settings import SettingsView

__all__ = [
    "DashboardView",
    "DriveEraserView",
    "FileEraserView",
    "RecoveryView",
    "ReportsView",
    "AuditView",
    "CasesView",
    "SettingsView",
]
