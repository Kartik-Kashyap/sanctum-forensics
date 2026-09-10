"""
Desktop user interface.

The GUI is a thin shell over the same engines the CLI and tests drive. No
business logic lives here: a view collects parameters, hands them to a worker
thread, and renders the result object it gets back. That keeps behaviour
identical however the tool is invoked, and means a bug fixed in an engine is
fixed everywhere.
"""

from sanctum.gui.app import MainWindow, run

__all__ = ["MainWindow", "run"]
