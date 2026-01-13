"""Entry point for launching the SOC Audit GUI.

This module enables running the GUI via:
    python -m soc_audit.gui

It instantiates the MainWindow and starts the Tkinter event loop.
"""
from soc_audit.gui.main_window import MainWindow

if __name__ == "__main__":
    app = MainWindow()
    app.run()
