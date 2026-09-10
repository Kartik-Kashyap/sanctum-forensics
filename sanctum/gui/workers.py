"""
Background job execution.

Erasure and carving are long, blocking, and progress-reporting. Running them on
the GUI thread would freeze the window and, worse, prevent the operator from
cancelling a destructive operation once it had started.

Every engine accepts ``progress`` and ``cancel`` keyword arguments. This module
supplies both, so a view can launch any operation with one line and get
progress and completion back as Qt signals.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from sanctum.core.progress import CancelToken


class JobSignals(QObject):
    """Qt signals for a running job."""

    progress = pyqtSignal(object)   # ProgressUpdate
    completed = pyqtSignal(object)  # the engine's result object
    failed = pyqtSignal(str, str)   # message, traceback
    started = pyqtSignal(str)       # job label


class Job(QThread):
    """
    Runs one engine call on a worker thread.

    The callable is invoked with ``progress=`` and ``cancel=`` injected, which
    matches every engine's signature::

        job = Job(carver.carve, str(image), str(outdir), signature_ids=["jpeg"])
        job.signals.progress.connect(self.on_progress)
        job.signals.completed.connect(self.on_done)
        job.start()
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        /,
        *args: Any,
        label: str = "Operation",
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.label = label
        self.signals = JobSignals()
        self.cancel_token = CancelToken()

    def run(self) -> None:  # noqa: D102 - QThread entry point
        self.signals.started.emit(self.label)
        try:
            result = self._fn(
                *self._args,
                progress=self.signals.progress.emit,
                cancel=self.cancel_token,
                **self._kwargs,
            )
            self.signals.completed.emit(result)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI, not swallowed
            self.signals.failed.emit(
                f"{type(exc).__name__}: {exc}", traceback.format_exc()
            )

    # -- control -----------------------------------------------------------

    def cancel(self) -> None:
        """Request cancellation; engines stop at their next safe point."""
        self.cancel_token.cancel()

    @property
    def cancelled(self) -> bool:
        return self.cancel_token.cancelled
