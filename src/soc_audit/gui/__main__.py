"""Entry point for launching the SOC Audit GUI.

This module enables running the GUI via:
    python -m soc_audit.gui

It provides a main() function that instantiates the MainWindow
and starts the Tkinter event loop.
"""
from soc_audit.gui.main_window import MainWindow


def main() -> None:
    """Launch the SOC Audit GUI application."""
    app = MainWindow()
    app.run()


if __name__ == "__main__":
    main()
