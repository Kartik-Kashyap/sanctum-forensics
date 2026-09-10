"""
Settings.

This screen is where the safety model becomes visible, and it is written to make
the model legible rather than to hide it behind a single switch.

Touching a real physical device requires three independent things to be true at
once: the policy flag here, the ``SANCTUM_ALLOW_RAW_DEVICE`` environment
variable, and a confirmation token typed at the moment of use. The screen shows
the state of all three, including the ones it cannot change - so an operator who
wonders why the Run button is disabled has an answer on screen instead of a
support ticket.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sanctum.config import (
    ALLOW_RAW_DEVICE_ENV,
    BASE_DIR,
    CASES_DIR,
    LOGS_DIR,
    runtime_allows_raw_devices,
)
from sanctum.gui import theme
from sanctum.gui.widgets import Card, PageHeader


class SettingsView(QWidget):
    """Safety policy and runtime configuration."""

    def __init__(self, state, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Settings",
                "Safety policy, runtime paths, and the state of every interlock "
                "that stands between this tool and irreversible data loss.",
            )
        )

        columns = QHBoxLayout()
        columns.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(12)

        policy = Card("Safety policy")
        self.dry_run_check = QCheckBox("Dry run — never write to a target")
        self.dry_run_check.setChecked(self.state.policy.dry_run)
        self.dry_run_check.setToolTip(
            "With dry run on, every module plans the operation in full, writes "
            "audit records, and reports what it would have done — without "
            "touching the target. This is the default."
        )
        self.dry_run_check.toggled.connect(self._on_changed)

        self.raw_check = QCheckBox("Allow writing to physical (raw) devices")
        self.raw_check.setChecked(self.state.policy.allow_raw_devices)
        self.raw_check.toggled.connect(self._on_changed)

        self.token_check = QCheckBox("Require a typed confirmation token")
        self.token_check.setChecked(self.state.policy.require_confirmation_token)
        self.token_check.setToolTip(
            "Derived from the target's path, size and serial, so a token shown "
            "for one device never validates for another."
        )
        self.token_check.toggled.connect(self._on_changed)

        policy.add(self.dry_run_check)
        policy.add(self.raw_check)
        policy.add(self.token_check)
        left.addWidget(policy)

        interlock = Card("Raw-device interlocks")
        self.interlock_text = QLabel("")
        self.interlock_text.setWordWrap(True)
        interlock.add(self.interlock_text)

        refresh_interlock = QPushButton("Re-check environment")
        refresh_interlock.clicked.connect(self.refresh)
        interlock.add(refresh_interlock)
        left.addWidget(interlock)

        left.addStretch(1)

        right = QVBoxLayout()
        right.setSpacing(12)

        paths = Card("Runtime paths")
        self.paths_text = QLabel("")
        self.paths_text.setWordWrap(True)
        self.paths_text.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        paths.add(self.paths_text)
        right.addWidget(paths)

        env = Card("Environment override")
        env_text = QLabel(
            f"Set {ALLOW_RAW_DEVICE_ENV}=1 before launching SANCTUM to satisfy the "
            "runtime half of the raw-device interlock. If it is not set, the "
            "checkbox above is recorded in the audit chain but cannot authorise a "
            "write to bare metal.\n\n"
            "This is deliberate. A misclick should not be sufficient to destroy a "
            "disk, and an environment variable cannot be set by a misclick."
        )
        env_text.setWordWrap(True)
        env_text.setObjectName("muted")
        env.add(env_text)
        right.addWidget(env)

        self.policy_text = QPlainTextEdit()
        self.policy_text.setReadOnly(True)
        right.addWidget(self.policy_text, 1)

        columns.addLayout(left, 1)
        columns.addLayout(right, 1)
        layout.addLayout(columns, 1)

        self.refresh()

    # -- behaviour ---------------------------------------------------------

    def _on_changed(self) -> None:
        self.state.update_policy(
            dry_run=self.dry_run_check.isChecked(),
            allow_raw_devices=self.raw_check.isChecked(),
            require_confirmation_token=self.token_check.isChecked(),
        )
        self.refresh()

    def refresh(self) -> None:
        env_unlock = runtime_allows_raw_devices()
        policy_flag = self.state.policy.allow_raw_devices

        lines = [
            f"1. Policy flag (this screen)          : "
            f"{'SET' if policy_flag else 'not set'}",
            f"2. {ALLOW_RAW_DEVICE_ENV} environment : "
            f"{'SET' if env_unlock else 'not set'}",
            "3. Confirmation token (at point of use): "
            f"{'required' if self.state.policy.require_confirmation_token else 'NOT required'}",
            "",
        ]
        if policy_flag and env_unlock:
            lines.append(
                "All interlocks satisfied. Raw devices can be targeted — but the "
                "running operating system's own drive is still refused "
                "unconditionally, and SANCTUM's own data directory can never be a "
                "target."
            )
            tone = theme.WARN
        else:
            missing = []
            if not policy_flag:
                missing.append("the policy flag above")
            if not env_unlock:
                missing.append(f"the {ALLOW_RAW_DEVICE_ENV} environment variable")
            lines.append(
                "Raw devices are locked. Missing: " + " and ".join(missing) + "."
            )
            tone = theme.OK
        self.interlock_text.setText("\n".join(lines))
        self.interlock_text.setStyleSheet(f"color: {tone};")

        base = os.environ.get("SANCTUM_HOME")
        self.paths_text.setText(
            f"Data directory : {BASE_DIR}\n"
            f"Cases          : {CASES_DIR}\n"
            f"Logs           : {LOGS_DIR}\n"
            f"SANCTUM_HOME   : {base if base else '(not set — using the platform default)'}"
        )

        self.policy_text.setPlainText(
            "Effective policy\n"
            "----------------\n"
            + self.state.policy.summary()
            + "\n\n"
            "This exact string is written into the audit chain at the start of "
            "every destructive operation, so a reviewer can reconstruct which "
            "policy was in force when the work was done.\n\n"
            "Refusals are audited too. A denied operation is recorded with "
            "outcome DENIED and the specific reason, because an attempt that was "
            "blocked is as much a part of the record as one that succeeded."
        )
