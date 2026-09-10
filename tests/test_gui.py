"""
GUI smoke tests.

The interface is a thin shell over the engines, so what these check is that it
loads, that every page can be constructed and shown, and that the worker thread
delivers results and failures without wedging the event loop. Those are the
failures that make a demo die on stage, and they are invisible to every other
test module.

Skipped entirely when PyQt6 is not installed, because the tool is required to
work without it.
"""

from __future__ import annotations

import os
import time

import pytest

#: Headless rendering: there is no display in CI, and the widgets are being
#: exercised rather than looked at.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI is optional; the engines are not")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _wait_for(condition, timeout: float = 15.0) -> bool:
    """Pump the event loop until ``condition`` holds, so queued signals arrive."""
    app = QApplication.instance()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    return False


# -- imports ---------------------------------------------------------------

def test_every_engine_module_imports_without_qt():
    """
    The GUI must be optional. If a non-GUI module has grown a Qt import, the
    command-line and test paths break on a machine without PyQt6.
    """
    import importlib

    for module in (
        "sanctum.config", "sanctum.cases",
        "sanctum.core.audit", "sanctum.core.hashing", "sanctum.core.progress",
        "sanctum.core.standards", "sanctum.core.targets", "sanctum.core.devices",
        "sanctum.erase.drive", "sanctum.erase.file", "sanctum.erase.verify",
        "sanctum.recover.carver", "sanctum.recover.classify",
        "sanctum.recover.image", "sanctum.recover.native", "sanctum.recover.signatures",
        "sanctum.report.builder",
    ):
        assert importlib.import_module(module) is not None, module


def test_the_gui_package_imports(qapp):
    from sanctum.gui import app, state, widgets, workers  # noqa: F401
    from sanctum.gui.views import (  # noqa: F401
        AuditView, CasesView, DashboardView, DriveEraserView, FileEraserView,
        RecoveryView, ReportsView, SettingsView,
    )


# -- state -----------------------------------------------------------------

def test_app_state_starts_in_dry_run(qapp):
    """The default must be the one that cannot destroy anything."""
    from sanctum.gui.state import AppState

    assert AppState().policy.dry_run is True


def test_policy_updates_are_reflected_and_announced(qapp):
    from sanctum.gui.state import AppState

    state = AppState()
    seen: list = []
    state.policy_changed.connect(seen.append)

    state.update_policy(dry_run=False)

    assert state.policy.dry_run is False
    assert seen


def test_raw_devices_are_only_armed_with_both_keys(qapp, monkeypatch):
    from sanctum.config import ALLOW_RAW_DEVICE_ENV
    from sanctum.gui.state import AppState

    state = AppState()
    monkeypatch.delenv(ALLOW_RAW_DEVICE_ENV, raising=False)
    state.update_policy(allow_raw_devices=True)
    assert state.raw_devices_armed is False

    monkeypatch.setenv(ALLOW_RAW_DEVICE_ENV, "1")
    assert state.raw_devices_armed is True


def test_results_accumulate_and_clear(qapp):
    from sanctum.gui.state import AppState

    state = AppState()
    state.record({"operation": "drive_erase", "success": True})
    state.record({"operation": "file_carving", "recovered_count": 3})

    assert state.results.count == 2
    state.clear_results()
    assert state.results.count == 0


def test_results_accept_objects_exposing_as_dict(qapp):
    from sanctum.gui.state import AppState

    class Result:
        def as_dict(self):
            return {"operation": "drive_erase"}

    state = AppState()
    state.record(Result())
    assert state.results.operations[0]["operation"] == "drive_erase"


# -- workers ---------------------------------------------------------------

def test_a_job_delivers_a_result(qapp):
    from sanctum.gui.workers import Job

    job = Job(lambda *, progress, cancel: 6 * 7, label="Test")
    delivered: list = []
    job.signals.completed.connect(delivered.append)

    job.start()
    assert _wait_for(lambda: delivered), "the job never reported completion"
    assert delivered[0] == 42
    job.wait(5000)


def test_a_job_reports_progress(qapp):
    from sanctum.gui.workers import Job

    def work(*, progress, cancel):
        for index in range(3):
            progress(_update(index))
        return "done"

    def _update(index):
        from sanctum.core.progress import ProgressUpdate
        return ProgressUpdate("Phase", index, 3)

    job = Job(work)
    updates: list = []
    job.signals.progress.connect(updates.append)

    job.start()
    assert _wait_for(lambda: len(updates) == 3)
    job.wait(5000)


def test_a_failing_job_reports_the_error_instead_of_crashing(qapp):
    """
    An engine exception must arrive at the UI as a message. A traceback on a
    worker thread with no handler takes the whole application down.
    """
    from sanctum.gui.workers import Job

    def explode(*, progress, cancel):
        raise ValueError("engine refused")

    job = Job(explode)
    failures: list = []
    job.signals.failed.connect(lambda message, trace: failures.append(message))

    job.start()
    assert _wait_for(lambda: failures)
    assert "engine refused" in failures[0]
    assert "ValueError" in failures[0]
    job.wait(5000)


def test_a_job_can_be_cancelled(qapp):
    from sanctum.gui.workers import Job

    def long_running(*, progress, cancel):
        for _ in range(1000):
            cancel.check()
            time.sleep(0.005)
        return "finished"

    job = Job(long_running)
    job.start()
    job.cancel()

    assert job.wait(10000)
    assert job.cancelled


# -- widgets ---------------------------------------------------------------

def test_log_pane_appends_and_caps_its_history(qapp):
    from sanctum.gui.widgets import LogPane

    pane = LogPane()
    for index in range(LogPane.MAX_BLOCKS + 50):
        pane.append_line(f"line {index}")

    assert pane.blockCount() <= LogPane.MAX_BLOCKS + 2


def test_log_pane_escapes_markup_from_media_content(qapp):
    """
    Log lines can contain filenames taken from the media under examination.
    Rendering them as rich text would execute a suspect's markup in the
    examiner's session.
    """
    from sanctum.gui.widgets import LogPane

    pane = LogPane()
    pane.append_line("<b>not bold</b>")
    assert "<b>not bold</b>" in pane.toPlainText()


def test_progress_panel_handles_a_determinate_update(qapp):
    from sanctum.core.progress import ProgressUpdate
    from sanctum.gui.widgets import ProgressPanel

    panel = ProgressPanel()
    panel.begin("Working")
    panel.on_progress(ProgressUpdate("Pass 1/3", 50, 100, rate_bytes_per_sec=1024.0))
    assert panel.bar.value() == 500

    panel.on_progress(ProgressUpdate("Pass 1/3", 100, 100))
    panel.finish("done")


def test_progress_panel_handles_an_indeterminate_update(qapp):
    """A phase with no known total must not divide by zero."""
    from sanctum.core.progress import ProgressUpdate
    from sanctum.gui.widgets import ProgressPanel

    panel = ProgressPanel()
    panel.on_progress(ProgressUpdate("Enumerating devices", 0, 0))
    assert panel.bar.maximum() == 0  # busy indicator


def test_progress_panel_emits_a_cancel_request(qapp):
    from sanctum.gui.widgets import ProgressPanel

    panel = ProgressPanel()
    seen: list = []
    panel.cancelled.connect(lambda: seen.append(True))
    panel._on_cancel()
    assert seen


def test_a_numeric_item_sorts_by_its_number_not_its_text(qapp):
    """
    ``"0x1000"`` sorts before ``"0x200"`` as text, which puts the largest
    offset in the middle of the table while the header arrow claims otherwise.
    """
    from sanctum.gui.widgets import NumericItem

    low = NumericItem("0x200", 0x200)
    high = NumericItem("0x1000", 0x1000)
    assert low < high
    assert not high < low
    # The displayed text is still what the examiner needs to read.
    assert low.text() == "0x200"
    assert low.data(NumericItem.SORT_ROLE) == 0x200


def test_a_numeric_item_compared_against_a_plain_item_does_not_raise(qapp):
    """Qt builds some items itself; sorting must survive meeting one."""
    from PyQt6.QtWidgets import QTableWidgetItem

    from sanctum.gui.widgets import NumericItem

    # Either ordering is defensible; raising is not. The assertion is that the
    # comparison returns a bool at all.
    assert isinstance(NumericItem("1,024", 1024) < QTableWidgetItem("zzz"), bool)


def test_the_recovery_table_sorts_offsets_and_lengths_numerically(qapp):
    """
    The end-to-end version of the rule above, through the real view.

    A string sort here would reorder the artefacts into an order that looks
    sorted and is not - the failure mode is silent, because the table still
    renders.
    """
    from sanctum.gui.state import AppState
    from sanctum.gui.views.recovery import RecoveryView

    class _Fake:
        """Only the attributes the table and the detail pane read."""

        def __init__(self, name, offset, length, confidence):
            self.name = name
            self.category = "Image"
            self.signature_id = "jpeg"
            self.offset = offset
            self.end_offset = offset + length
            self.length = length
            self.confidence = confidence
            self.confidence_label = "High"
            self.validated = True
            self.footer_found = True
            self.truncated = False
            self.digests = {"sha256": "0" * 64, "md5": "0" * 32}
            self.factors = []
            self.warnings = []
            self.output_path = None
            self.extraction_error = None

    view = RecoveryView(AppState())
    # Deliberately inserted in an order that a string sort would scramble.
    view.artifacts = [
        _Fake("b.jpg", 0x1000, 900, 90.0),
        _Fake("a.jpg", 0x200, 10000, 70.0),
        _Fake("c.jpg", 0x30, 2048, 80.0),
    ]
    view._fill_table()

    view.table.sortItems(2)  # offset
    shown = [view.table.item(row, 0).text() for row in range(view.table.rowCount())]
    assert shown == ["c.jpg", "a.jpg", "b.jpg"], shown

    view.table.sortItems(3)  # length
    shown = [view.table.item(row, 0).text() for row in range(view.table.rowCount())]
    assert shown == ["b.jpg", "c.jpg", "a.jpg"], shown


def test_selecting_a_sorted_row_shows_that_artefacts_derivation(qapp):
    """
    The row index is a screen position, not an artefact index.

    Sorting permutes the rows, so a lookup that assumes row *n* holds artefact
    *n* shows the wrong file's confidence breakdown - or, as it did, nothing at
    all. The derivation is the evidence for the ranking, so showing another
    file's is worse than showing none.
    """
    from sanctum.gui.state import AppState
    from sanctum.gui.views.recovery import RecoveryView

    class _Fake:
        def __init__(self, name, offset, confidence):
            self.name = name
            self.category = "Image"
            self.signature_id = "jpeg"
            self.offset = offset
            self.end_offset = offset + 512
            self.length = 512
            self.confidence = confidence
            self.confidence_label = "High"
            self.validated = True
            self.footer_found = True
            self.truncated = False
            self.digests = {"sha256": "ab" * 32, "md5": "cd" * 16}
            self.factors = []
            self.warnings = []
            self.output_path = None
            self.extraction_error = None

    view = RecoveryView(AppState())
    view.artifacts = [
        _Fake("first.jpg", 0x10, 99.0),
        _Fake("second.jpg", 0x20, 61.0),
    ]
    view._fill_table()

    view.table.sortItems(0, Qt.SortOrder.AscendingOrder)
    view.table.selectRow(0)
    qapp.processEvents()
    assert "first.jpg" in view.explanation.toPlainText()

    # Reverse the display order, then select the top row again. It is now the
    # other artefact, and the pane must say so.
    view.table.sortItems(0, Qt.SortOrder.DescendingOrder)
    view.table.selectRow(0)
    qapp.processEvents()
    text = view.explanation.toPlainText()
    assert "second.jpg" in text
    assert "first.jpg" not in text


def test_the_recovery_table_opens_in_the_carvers_order(qapp):
    """
    Filling the table must not silently re-sort it.

    Switching sorting on applies whatever the header's indicator says, which is
    a default Qt chose rather than one this view did - so the results opened in
    reverse filename order, agreeing with neither the engine's ranking nor
    scan order. The initial state is the carver's ordering, and the only column
    that can express it is the offset.
    """
    from sanctum.gui.state import AppState
    from sanctum.gui.views.recovery import RecoveryView

    view = RecoveryView(AppState())
    header = view.table.horizontalHeader()
    assert header.sortIndicatorSection() == 2
    assert header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder


# -- the main window -------------------------------------------------------

def test_main_window_builds_and_every_page_opens(qapp, tmp_path, monkeypatch):
    """
    The integration check that matters: a typo in any view's refresh path is
    invisible until someone clicks that tab, which is exactly when a demo is
    being given.
    """
    from sanctum.gui.app import MainWindow, _NAVIGATION
    from sanctum.gui.state import AppState

    window = MainWindow(AppState())
    try:
        assert window.nav.count() == len(_NAVIGATION)
        for row in range(window.nav.count()):
            window.nav.setCurrentRow(row)
            qapp.processEvents()
            assert window.pages.currentIndex() == row
    finally:
        window.close()


def test_main_window_opens_a_case_and_reflects_it(qapp, tmp_path):
    from sanctum.cases import CaseManager
    from sanctum.gui.app import MainWindow
    from sanctum.gui.state import AppState

    state = AppState()
    state.case_manager = CaseManager(base_dir=tmp_path / "cases")
    case = state.case_manager.create("GUI test case", examiner="Examiner")

    window = MainWindow(state)
    try:
        state.open_case(case.case_id)
        qapp.processEvents()
        assert "GUI test case" in state.case_label
    finally:
        window.close()


# -- a real engine result, through the real view ---------------------------

def test_a_carve_runs_through_the_recovery_view_and_reaches_the_table(
    qapp, tmp_path, monkeypatch
):
    """
    Press the button, not just construct the page.

    Every other GUI test builds a view and looks at it; this one drives an
    engine through the worker and checks the result arrives. It is the check
    that would have caught the selection defect recorded in the validation
    document, because a table that renders eleven rows and refuses to show any
    of them is indistinguishable from a working one until an examiner clicks.
    """
    from sanctum.gui.state import AppState
    from sanctum.gui.views.recovery import RecoveryView
    from tools.make_test_media import build_all

    # The view writes its artefacts and audit chain under the application's own
    # directories; redirect them so the test leaves nothing behind.
    monkeypatch.setenv("SANCTUM_HOME", str(tmp_path / "home"))

    media = tmp_path / "media"
    manifest = build_all(media, quiet=True)
    source = media / manifest["scenarios"]["deleted_files"]["image"]

    view = RecoveryView(AppState())
    view.source_edit.setText(str(source))
    view.output_edit.setText(str(tmp_path / "out"))

    view._start()
    assert view.job is not None, "the view did not start a job"
    assert not view.run_button.isEnabled(), "the run button stayed live during a carve"
    assert view.job.wait(120_000), "the carve did not finish"

    # The worker delivers on its own thread; pump the loop so the queued
    # signals are handled before the assertions read the widgets.
    assert _wait_for(lambda: view.table.rowCount() > 0), "no artefacts reached the table"
    qapp.processEvents()

    assert view.artifacts, "the view kept no artefacts"
    assert view.table.rowCount() == len(view.artifacts)
    assert view.run_button.isEnabled(), "the run button was left disabled"
    assert "artefact" in view.log.toPlainText().lower()

    # And the detail pane works on a row the carve actually produced.
    view.table.selectRow(0)
    qapp.processEvents()
    text = view.explanation.toPlainText()
    assert "Confidence" in text, text[:200]
    assert "Score derivation" in text


def test_the_audit_table_orders_the_chain_by_sequence(qapp, tmp_path):
    """
    The sequence column is the chain's ordering, and it must sort as a number.

    It was left as text, so a chain of ten or more records displayed in the
    order 1, 10, 2, 9 - a list in no order, in the one view whose entire subject
    is the order records were written in. The view also had no opinion about its
    initial order, so it opened on whatever Qt's default indicator said.
    """
    from sanctum.core.audit import AuditCategory, AuditChain
    from sanctum.gui.state import AppState
    from sanctum.gui.views.audit import AuditView

    chain = AuditChain(tmp_path / "chain.jsonl")
    # Enough records that a text sort visibly differs from a numeric one.
    for index in range(12):
        chain.log(AuditCategory.SYSTEM, "test_event", details={"index": index})

    class _State(AppState):
        def audit(self):
            return chain

    view = AuditView(_State())
    view.refresh()
    qapp.processEvents()

    assert view.table.rowCount() == len(chain.entries())

    view.table.sortItems(0, Qt.SortOrder.AscendingOrder)
    shown = [view.table.item(row, 0).text() for row in range(view.table.rowCount())]
    assert shown == [str(n) for n in range(1, 13)], shown


def test_selecting_an_audit_record_shows_its_payload(qapp, tmp_path):
    """
    Clicking a record must show that record's payload, on a sorted table.

    This is the second appearance of one defect. The sequence cell was made a
    :class:`NumericItem` so the column would sort as numbers - and the selection
    handler was left reading ``item.data(0)``, the DisplayRole, which on that
    cell is the *text* "3". Comparing it against an integer ``entry.seq``
    matched nothing, so every click selected nothing and the detail pane stayed
    empty. Nothing raised, nothing looked wrong, and the payload pane simply
    never populated.

    The test sorts the table first, because the obvious way to find the record
    for a row - its position - is only correct in the unsorted case, and the
    bug is invisible until the rows have moved.
    """
    from sanctum.core.audit import AuditCategory, AuditChain
    from sanctum.gui.state import AppState
    from sanctum.gui.views.audit import AuditView

    chain = AuditChain(tmp_path / "chain.jsonl")
    for index in range(12):
        chain.log(AuditCategory.SYSTEM, "test_event", details={"index": index})

    class _State(AppState):
        def audit(self):
            return chain

    view = AuditView(_State())
    view.refresh()
    qapp.processEvents()

    # Descending, so row 0 is the *last* record and a handler that trusted the
    # row number would show the wrong one.
    view.table.sortItems(0, Qt.SortOrder.DescendingOrder)
    qapp.processEvents()

    view.table.selectRow(0)
    qapp.processEvents()

    text = view.detail.toPlainText()
    assert text, "selecting a record showed nothing"
    assert '"seq": 12' in text, text[:300]
    assert "entry_hash" in text and "hmac" in text


def test_the_audit_table_opens_in_chain_order(qapp):
    from sanctum.gui.state import AppState
    from sanctum.gui.views.audit import AuditView

    # Held in a name: a table that is only reachable through a temporary view
    # is collected along with it, and its header goes with it.
    view = AuditView(AppState())
    header = view.table.horizontalHeader()
    assert header.sortIndicatorSection() == 0
    assert header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder


def test_the_confirmation_states_the_bytes_the_operation_will_write(qapp, tmp_path):
    """
    The pass count is the entire cost model, and it lives in a dropdown.

    A standard writes a multiple of the target's size equal to its number of
    passes, so the difference between one pass and Gutmann's thirty-five is the
    difference between minutes and most of a day - chosen two cards above the
    token an operator has to type to commit. The figure is size times passes,
    which is exact, so it is stated as a number rather than an estimate.
    """
    from sanctum.core.targets import TargetKind, describe_target
    from sanctum.gui.state import AppState
    from sanctum.gui.views.drive_eraser import DriveEraserView

    image = tmp_path / "target.img"
    with open(image, "wb") as handle:
        handle.truncate(1024 * 1024 * 1024)  # 1 GiB

    view = DriveEraserView(AppState())
    assert view.confirm_impact.text() == "", "impact stated with no target selected"

    view._set_target(describe_target(str(image), kind=TargetKind.DISK_IMAGE))

    def impact_for(standard_id: str) -> str:
        index = next(
            i for i in range(view.standard_combo.count())
            if view.standard_combo.itemData(i) == standard_id
        )
        view.standard_combo.setCurrentIndex(index)
        qapp.processEvents()
        return view.confirm_impact.text()

    assert "1 pass" in impact_for("zero1")
    assert "3 passes" in impact_for("dod3")
    assert "35 passes" in impact_for("gutmann")
    # And the arithmetic, not just the wording: 35 passes over 1 GiB is 35 GiB.
    assert "35.00 GB" in impact_for("gutmann")
