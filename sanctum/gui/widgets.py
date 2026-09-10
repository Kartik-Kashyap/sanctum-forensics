"""
Reusable interface components.

Small, dumb widgets shared by the views: a page header, a stat card, a log
pane, and a progress panel that any long-running job can drive. Keeping them
here means every page reports progress and status the same way, which matters
when one of those pages is asking an operator to confirm the destruction of a
drive.
"""

from __future__ import annotations

from typing import Iterable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from sanctum.core.hashing import human_bytes
from sanctum.core.progress import format_duration
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sanctum.gui import theme


class NumericItem(QTableWidgetItem):
    """
    A table cell that *reads* as formatted text but *sorts* by a number.

    Byte offsets, file lengths and confidence scores are all displayed in a
    shape that does not sort correctly as a string - ``"0x1000"`` precedes
    ``"0x200"`` alphabetically, and ``"9"`` follows ``"10"``. Sorting those
    columns as text puts the largest offset in the middle of the table, which
    is worse than not sorting at all, because the header arrow says it is
    sorted.

    The obvious trick - ``setData(DisplayRole, value)`` followed by
    ``setText(...)`` - does not work, and fails quietly: ``setText`` writes the
    DisplayRole, so it overwrites the number that was just stored there. The
    cell then displays the formatted string *and* sorts by it, which is the
    behaviour the call was meant to prevent. It also silently breaks any code
    that reads the cell's data expecting the number.

    So the sort key is kept somewhere ``setText`` cannot reach and the
    comparison is overridden. PyQt routes QTableWidget's sorting through
    ``__lt__`` on the item, so this is what the view actually uses.
    """

    #: Where the numeric sort key lives. A role of our own, so nothing Qt does
    #: to the display or edit data can disturb it.
    SORT_ROLE = Qt.ItemDataRole.UserRole + 1

    def __init__(self, text: str, sort_key: float) -> None:
        super().__init__(text)
        self.setData(self.SORT_ROLE, sort_key)

    @property
    def sort_key(self) -> float:
        value = self.data(self.SORT_ROLE)
        # An item built by Qt rather than by this class - a corner-header item,
        # for instance - has no sort key. Sorting must not raise on it.
        return float(value) if value is not None else 0.0

    def __lt__(self, other) -> bool:  # noqa: D105 - Qt's sorting protocol
        if isinstance(other, NumericItem):
            return self.sort_key < other.sort_key
        return super().__lt__(other)


class PageHeader(QWidget):
    """Title, one-line explanation, and an optional right-aligned action row."""

    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        text = QVBoxLayout()
        text.setSpacing(2)
        self.title = QLabel(title)
        self.title.setObjectName("pageTitle")
        self.subtitle = QLabel(subtitle)
        self.subtitle.setObjectName("pageSub")
        self.subtitle.setWordWrap(True)
        text.addWidget(self.title)
        text.addWidget(self.subtitle)
        layout.addLayout(text, 1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(8)
        layout.addLayout(self.actions)

    def add_action(self, widget: QWidget) -> None:
        self.actions.addWidget(widget)

    def set_subtitle(self, text: str) -> None:
        self.subtitle.setText(text)


class Card(QFrame):
    """A titled panel - the standard container for a group of controls."""

    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(16, 14, 16, 16)
        self._outer.setSpacing(10)

        if title:
            label = QLabel(title.upper())
            label.setObjectName("statLabel")
            self._outer.addWidget(label)

        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        self._outer.addLayout(self.body)

    def add(self, widget: QWidget) -> None:
        self.body.addWidget(widget)

    def add_layout(self, layout) -> None:
        self.body.addLayout(layout)


class StatCard(QFrame):
    """A single headline number with a label and optional tone."""

    def __init__(self, label: str, value: str = "-", tone: str = "info",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(2)

        self.value = QLabel(value)
        self.value.setObjectName("statValue")
        self.value.setStyleSheet(f"color: {theme.TONE.get(tone, theme.ACCENT)};")
        self.label = QLabel(label.upper())
        self.label.setObjectName("statLabel")
        self.label.setWordWrap(True)

        layout.addWidget(self.value)
        layout.addWidget(self.label)

    def set_value(self, value: str, tone: str | None = None) -> None:
        self.value.setText(value)
        if tone:
            self.value.setStyleSheet(f"color: {theme.TONE.get(tone, theme.ACCENT)};")


class StatRow(QWidget):
    """A horizontal strip of :class:`StatCard`."""

    def __init__(self, specs: Iterable[tuple[str, str, str]] = (), parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(10)
        self.cards: dict[str, StatCard] = {}
        for label, value, tone in specs:
            self.add(label, value, tone)

    def add(self, label: str, value: str = "-", tone: str = "info") -> StatCard:
        card = StatCard(label, value, tone)
        self.cards[label] = card
        self._layout.addWidget(card)
        return card

    def update(self, label: str, value: str, tone: str | None = None) -> None:
        card = self.cards.get(label)
        if card:
            card.set_value(value, tone)


class LogPane(QPlainTextEdit):
    """
    Append-only operation log shown beneath a progress bar.

    Capped at a fixed block count: an operator may leave a carve running for an
    hour, and an unbounded text widget would consume memory steadily for no
    benefit.
    """

    MAX_BLOCKS = 2000

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(self.MAX_BLOCKS)
        self.setFont(QFont("Cascadia Mono, Consolas, monospace", 9))
        self.setPlaceholderText("Operation output appears here.")

    def append_line(self, text: str, tone: str | None = None) -> None:
        if tone:
            colour = theme.TONE.get(tone, theme.INK)
            self.appendHtml(
                f'<span style="color:{colour}">{_escape(text)}</span>'
            )
        else:
            self.appendPlainText(text)

    def rule(self, title: str) -> None:
        self.append_line(f"\n--- {title} ---", "muted")


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace(" ", "&nbsp;")
    )


class ProgressPanel(QFrame):
    """
    Progress bar, status line, and a Cancel button.

    The cancel button is not decoration. Whole-device sanitization can run for
    hours; an operator who realises they selected the wrong target must be able
    to stop it, and the engines poll a cancellation token at safe points
    precisely so that stopping is always available.
    """

    cancelled = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        self.phase = QLabel("Idle")
        self.phase.setObjectName("muted")
        self.detail = QLabel("")
        self.detail.setObjectName("muted")
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("danger")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._on_cancel)
        top.addWidget(self.phase, 1)
        top.addWidget(self.detail)
        top.addWidget(self.cancel_button)

        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        self.bar.setFormat("%p%")

        layout.addLayout(top)
        layout.addWidget(self.bar)
        self._active = False

    # -- lifecycle ---------------------------------------------------------

    def begin(self, label: str = "Working") -> None:
        self._active = True
        self.phase.setText(label)
        self.detail.setText("")
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText("Cancel")

    def finish(self, message: str = "Done", tone: str = "ok") -> None:
        self._active = False
        self.phase.setText(message)
        self.phase.setStyleSheet(f"color: {theme.TONE.get(tone, theme.MUTED)};")
        self.detail.setText("")
        self.cancel_button.setEnabled(False)
        self.bar.setValue(1000)

    def reset(self) -> None:
        self._active = False
        self.phase.setText("Idle")
        self.phase.setStyleSheet(f"color: {theme.MUTED};")
        self.detail.setText("")
        self.bar.setValue(0)
        self.cancel_button.setEnabled(False)

    def on_progress(self, update) -> None:
        """
        Slot for a ``ProgressUpdate`` from any engine.

        The bar is determinate whenever the engine knows a total, and
        indeterminate otherwise - guessing a percentage for an unbounded scan
        would be worse than admitting there isn't one.
        """
        if update.total > 0:
            self.bar.setRange(0, 1000)
            self.bar.setValue(int(update.fraction * 1000))
            self.bar.setFormat(f"{update.percent:.0f}%")
        else:
            self.bar.setRange(0, 0)  # indeterminate
            self.bar.setFormat("")

        self.phase.setText(update.phase or "Working")
        self.phase.setStyleSheet(f"color: {theme.ACCENT};")

        parts: list[str] = []
        if update.total:
            parts.append(
                f"{human_bytes(update.completed)} / {human_bytes(update.total)}"
            )
        if update.rate_bytes_per_sec:
            parts.append(f"{human_bytes(update.rate_bytes_per_sec)}/s")
        if update.eta_seconds:
            parts.append(f"ETA {format_duration(update.eta_seconds)}")
        if update.message:
            parts.append(update.message)
        self.detail.setText("  |  ".join(parts))

    def _on_cancel(self) -> None:
        self.cancel_button.setEnabled(False)
        self.cancel_button.setText("Cancelling...")
        self.phase.setText("Cancelling - stopping at the next safe point")
        self.phase.setStyleSheet(f"color: {theme.WARN};")
        self.cancelled.emit()

    @property
    def active(self) -> bool:
        return self._active


class FieldRow(QWidget):
    """A label and a widget, laid out consistently."""

    def __init__(self, label: str, widget: QWidget, hint: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setColumnStretch(1, 1)
        name = QLabel(label)
        name.setObjectName("muted")
        grid.addWidget(name, 0, 0)
        grid.addWidget(widget, 0, 1)
        if hint:
            hint_label = QLabel(hint)
            hint_label.setObjectName("hint")
            hint_label.setWordWrap(True)
            grid.addWidget(hint_label, 1, 1)


class Badge(QLabel):
    """A small toned label for a status word."""

    def __init__(self, text: str, tone: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        colour = theme.TONE.get(tone, theme.ACCENT)
        self.setStyleSheet(
            f"color: {colour}; border: 1px solid {colour}; border-radius: 9px;"
            f"padding: 1px 9px; font-size: 11px;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
