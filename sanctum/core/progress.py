"""
Progress reporting and cooperative cancellation.

Long operations - a 35-pass Gutmann wipe of a 500 GB image, a multi-gigabyte
carve - run on worker threads. They need to report progress without blocking,
and they need to stop promptly when the operator hits Cancel. Rather than let
each engine invent its own convention, both primitives live here.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from sanctum.core.hashing import human_bytes


class OperationCancelled(Exception):
    """Raised inside an engine when the operator cancels the running job."""


class ProgressCallback(Protocol):
    """Anything that can receive progress updates."""

    def __call__(self, update: "ProgressUpdate") -> None:  # pragma: no cover
        ...


@dataclass
class ProgressUpdate:
    """A single progress sample."""

    phase: str
    completed: int
    total: int
    message: str = ""
    rate_bytes_per_sec: float = 0.0
    eta_seconds: float | None = None
    detail: dict = field(default_factory=dict)

    @property
    def fraction(self) -> float:
        if self.total <= 0:
            return 0.0
        return min(1.0, max(0.0, self.completed / self.total))

    @property
    def percent(self) -> float:
        return self.fraction * 100.0

    def summary(self) -> str:
        parts = [f"{self.phase}: {self.percent:5.1f}%"]
        if self.total:
            parts.append(f"{human_bytes(self.completed)} / {human_bytes(self.total)}")
        if self.rate_bytes_per_sec:
            parts.append(f"{human_bytes(self.rate_bytes_per_sec)}/s")
        if self.eta_seconds is not None and self.eta_seconds > 0:
            parts.append(f"ETA {_format_duration(self.eta_seconds)}")
        if self.message:
            parts.append(self.message)
        return "  |  ".join(parts)


def _format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


#: Public alias - the UI formats ETA strings the same way the engine does, and
#: should not have to reach for a private name to do it.
format_duration = _format_duration


class CancelToken:
    """
    A thread-safe cancellation flag.

    Deliberately a plain event rather than an exception raised across threads:
    engines poll :meth:`check` at safe points, so a cancel can never leave a
    device half-written outside a controlled code path.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def reset(self) -> None:
        self._event.clear()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        """Raise :class:`OperationCancelled` if cancellation was requested."""
        if self._event.is_set():
            raise OperationCancelled("Operation cancelled by operator")


class ProgressReporter:
    """
    Wraps a user callback with rate limiting and rate/ETA estimation.

    Emitting a progress event for every 1 MiB chunk of a terabyte image would
    flood the GUI event loop and make the app feel slower than the work it is
    reporting on, so updates are throttled by wall-clock interval.
    """

    def __init__(
        self,
        callback: Callable[[ProgressUpdate], None] | None,
        *,
        min_interval: float = 0.08,
    ) -> None:
        self.callback = callback
        self.min_interval = min_interval
        self._start = time.monotonic()
        self._last_emit = 0.0
        self._started = self._start

    def start(self, phase: str, total: int, message: str = "") -> None:
        self._started = time.monotonic()
        self._last_emit = 0.0
        self._emit(ProgressUpdate(phase, 0, total, message), force=True)

    def update(
        self,
        phase: str,
        completed: int,
        total: int,
        message: str = "",
        *,
        force: bool = False,
        **detail,
    ) -> None:
        update = ProgressUpdate(
            phase=phase,
            completed=completed,
            total=total,
            message=message,
            rate_bytes_per_sec=self._rate(completed),
            eta_seconds=self._eta(completed, total),
            detail=detail,
        )
        self._emit(update, force=force)

    def finish(self, phase: str, total: int, message: str = "done") -> None:
        self._emit(
            ProgressUpdate(phase, total, total, message, self._rate(total), 0.0),
            force=True,
        )

    # -- internals ---------------------------------------------------------

    def _rate(self, completed: int) -> float:
        elapsed = time.monotonic() - self._started
        if elapsed <= 0:
            return 0.0
        return completed / elapsed

    def _eta(self, completed: int, total: int) -> float | None:
        if completed <= 0 or total <= 0 or completed >= total:
            return None
        rate = self._rate(completed)
        if rate <= 0:
            return None
        return (total - completed) / rate

    def _emit(self, update: ProgressUpdate, *, force: bool = False) -> None:
        if self.callback is None:
            return
        now = time.monotonic()
        if not force and (now - self._last_emit) < self.min_interval:
            return
        self._last_emit = now
        self.callback(update)
