"""Main application window for the SOC Audit GUI.

This module provides the primary application window for the SOC Audit Framework's
graphical user interface. It serves as the foundation for all GUI components,
establishing the layout, menu structure, and status bar.

The MainWindow class creates a Tkinter-based window that will host scanner
configuration, findings display, and report export views in future commits.
This module focuses solely on GUI scaffold - no business logic, engine execution,
or data processing occurs here.

Architecture:
    The GUI follows a thin-wrapper design where all security scanning and
    analysis logic remains in the core engine. This window provides the
    visual shell that will eventually interact with the engine through
    the cli_bridge module.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox


class MainWindow:
    """
    Main application window for the SOC Audit Framework GUI.

    This class creates and manages the primary application window, including
    the menu bar, main content area, and status bar. It serves as the container
    for all GUI views and handles top-level window events.

    The window is designed to host future components:
    - Scanner view for configuring and running scans
    - Findings view for displaying security findings
    - Report export functionality

    Attributes:
        root: The Tkinter root window instance.
        main_frame: The central frame for hosting content views.
        status_var: StringVar for the status bar text.
        status_bar: Label widget displaying status messages.

    Example usage:
        app = MainWindow()
        app.run()
    """

    # Window dimensions
    DEFAULT_WIDTH = 1000
    DEFAULT_HEIGHT = 700
    MIN_WIDTH = 800
    MIN_HEIGHT = 500

    def __init__(self) -> None:
        """
        Initialize the main application window.

        Creates the Tkinter root window, sets up the menu bar, main content
        frame, and status bar. The window is configured with default and
        minimum sizes.
        """
        # Create root window
        self.root = tk.Tk()
        self.root.title("SOC Audit Framework")

        # Set window size and constraints
        self.root.geometry(f"{self.DEFAULT_WIDTH}x{self.DEFAULT_HEIGHT}")
        self.root.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)

        # Configure root grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Build UI components
        self._create_menu_bar()
        self._create_main_frame()
        self._create_status_bar()

    def _create_menu_bar(self) -> None:
        """
        Create the application menu bar.

        Sets up the File, View, and Help menus with their respective
        menu items. Currently implements Exit and About functionality,
        with placeholder items for future features.
        """
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self._on_exit)

        # View menu
        view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", state=tk.DISABLED)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

    def _create_main_frame(self) -> None:
        """
        Create the main content frame.

        This frame serves as the container for scanner, findings, and
        other views that will be added in future commits. Currently
        empty but configured for flexible layout.
        """
        self.main_frame = tk.Frame(self.root)
        self.main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Configure main frame for future child widgets
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=1)

    def _create_status_bar(self) -> None:
        """
        Create the status bar at the bottom of the window.

        The status bar displays application state and messages.
        The status_var attribute can be updated to change the
        displayed text.
        """
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padx=10,
            pady=5,
        )
        self.status_bar.grid(row=1, column=0, sticky="ew")

    def set_status(self, message: str) -> None:
        """
        Update the status bar text.

        Args:
            message: The status message to display.
        """
        self.status_var.set(message)

    def _on_exit(self) -> None:
        """Handle the File > Exit menu action."""
        self.root.quit()

    def _on_about(self) -> None:
        """Handle the Help > About menu action."""
        messagebox.showinfo(
            "About SOC Audit Framework",
            "SOC Audit Framework\n\n"
            "A modular security auditing tool for SOC analysts.\n\n"
            "Version: 1.0.0",
        )

    def run(self) -> None:
        """
        Start the application main loop.

        This method blocks until the window is closed. Call this
        method after creating the MainWindow instance to display
        the GUI and begin processing user events.
        """
        self.root.mainloop()
