"""Main application window for the SOC Audit GUI.

This module provides the primary application window for the SOC Audit Framework's
graphical user interface. It serves as the foundation for all GUI components,
establishing the layout, menu structure, and status bar.

The MainWindow class creates a Tkinter-based window that hosts the SOC dashboard,
scanner configuration, and findings display views with view switching support.

Architecture:
    The GUI follows a thin-wrapper design where all security scanning and
    analysis logic remains in the core engine. This window provides the
    visual shell that interacts with the engine through the cli_bridge module.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from soc_audit.gui.dashboard_view import DashboardView
from soc_audit.gui.findings_view import FindingsView
from soc_audit.gui.report_export import ReportExportView
from soc_audit.gui.scanner_view import ScannerView

if TYPE_CHECKING:
    from soc_audit.core.engine import EngineResult


class MainWindow:
    """
    Main application window for the SOC Audit Framework GUI.

    This class creates and manages the primary application window, including
    the menu bar, main content area (with multiple switchable views), and
    status bar. It serves as the container for all GUI views and handles
    top-level window events.

    Views:
    - Dashboard: SOC-style dashboard with metrics, alerts, and entities
    - Scan Configuration: Scanner configuration and execution
    - Findings: Detailed findings table and analysis

    Attributes:
        root: The Tkinter root window instance.
        content_frame: Frame containing the active view.
        dashboard_view: The DashboardView instance.
        scanner_view: The ScannerView instance.
        findings_view: The FindingsView instance.
        latest_result: The most recent EngineResult, or None.
        status_var: StringVar for the status bar text.
        status_bar: Label widget displaying status messages.
        current_view: Name of the currently displayed view.

    Example usage:
        app = MainWindow()
        app.run()
    """

    # Window dimensions
    DEFAULT_WIDTH = 1100
    DEFAULT_HEIGHT = 800
    MIN_WIDTH = 900
    MIN_HEIGHT = 600

    def __init__(self) -> None:
        """
        Initialize the main application window.

        Creates the Tkinter root window, sets up the menu bar, main content
        area with dashboard view, and status bar. Dashboard is shown by default.
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

        # Initialize state
        self.latest_result: EngineResult | None = None
        self.current_view: str = "dashboard"

        # Build UI components
        self._create_menu_bar()
        self._create_content_frame()
        self._create_views()
        self._create_status_bar()

        # Show dashboard by default
        self._show_view("dashboard")
        self.set_status("Dashboard loaded (wireframe)")

    def _create_menu_bar(self) -> None:
        """
        Create the application menu bar.

        Sets up the File, View, and Help menus with their respective
        menu items including view switching options.
        """
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        # File menu
        self.file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(
            label="Export Report...",
            command=self._on_export_report,
            state=tk.DISABLED,
        )
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self._on_exit)

        # View menu with view switching
        self.view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Dashboard", command=self._on_show_dashboard)
        self.view_menu.add_command(label="Scan Configuration", command=self._on_show_scanner)
        self.view_menu.add_command(label="Findings", command=self._on_show_findings)
        self.view_menu.add_separator()
        self.view_menu.add_command(label="Clear Findings", command=self._on_clear_findings)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

    def _create_content_frame(self) -> None:
        """Create the main content frame that holds all views."""
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.rowconfigure(0, weight=1)

    def _create_views(self) -> None:
        """Create all view instances."""
        # Dashboard view (default)
        self.dashboard_view = DashboardView(self.content_frame)

        # Scanner view with paned layout
        self.scanner_paned = ttk.PanedWindow(self.content_frame, orient=tk.VERTICAL)

        scanner_frame = ttk.Frame(self.scanner_paned)
        self.scanner_view = ScannerView(
            scanner_frame,
            self.set_status,
            on_scan_complete=self._on_scan_complete,
        )
        self.scanner_view.pack(fill=tk.X, padx=5, pady=5)
        self.scanner_paned.add(scanner_frame, weight=0)

        # Findings view (part of scanner pane)
        self.findings_view = FindingsView(self.scanner_paned)
        self.scanner_paned.add(self.findings_view, weight=1)

        # Standalone findings view for dedicated findings page
        self.findings_standalone = FindingsView(self.content_frame)

    def _create_status_bar(self) -> None:
        """
        Create the status bar at the bottom of the window.

        The status bar displays application state and messages.
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

    def _show_view(self, view_name: str) -> None:
        """
        Switch to the specified view.

        Args:
            view_name: Name of the view to show ('dashboard', 'scanner', 'findings').
        """
        # Hide all views
        self.dashboard_view.grid_forget()
        self.scanner_paned.grid_forget()
        self.findings_standalone.grid_forget()

        # Show the requested view
        if view_name == "dashboard":
            self.dashboard_view.grid(row=0, column=0, sticky="nsew")
            self.set_status("Dashboard loaded (wireframe)")
        elif view_name == "scanner":
            self.scanner_paned.grid(row=0, column=0, sticky="nsew")
            self.set_status("Scan Configuration")
        elif view_name == "findings":
            self.findings_standalone.grid(row=0, column=0, sticky="nsew")
            self.set_status("Findings View")

        self.current_view = view_name

    def _on_show_dashboard(self) -> None:
        """Handle View > Dashboard menu action."""
        self._show_view("dashboard")

    def _on_show_scanner(self) -> None:
        """Handle View > Scan Configuration menu action."""
        self._show_view("scanner")

    def _on_show_findings(self) -> None:
        """Handle View > Findings menu action."""
        self._show_view("findings")

    def set_status(self, message: str) -> None:
        """
        Update the status bar text.

        Args:
            message: The status message to display.
        """
        self.status_var.set(message)

    def _on_scan_complete(self, engine_result: object) -> None:
        """
        Handle scan completion by updating findings views and enabling export.

        Args:
            engine_result: The EngineResult from the scan.
        """
        # Import here to avoid circular import at module level
        from soc_audit.core.engine import EngineResult

        if isinstance(engine_result, EngineResult):
            self.latest_result = engine_result
            # Update both findings views
            self.findings_view.set_results(engine_result)
            self.findings_standalone.set_results(engine_result)
            # Enable export menu item
            self.file_menu.entryconfig("Export Report...", state=tk.NORMAL)

    def _on_export_report(self) -> None:
        """Handle the File > Export Report menu action."""
        if self.latest_result is None:
            messagebox.showwarning(
                "No Results",
                "No scan results available to export.\nRun a scan first.",
            )
            return

        # Create modal export dialog
        export_dialog = tk.Toplevel(self.root)
        export_dialog.title("Export Report")
        export_dialog.geometry("300x150")
        export_dialog.resizable(False, False)
        export_dialog.transient(self.root)
        export_dialog.grab_set()

        # Center the dialog on the main window
        export_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 300) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 150) // 2
        export_dialog.geometry(f"+{x}+{y}")

        # Add export view
        export_view = ReportExportView(export_dialog, self.latest_result)
        export_view.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _on_clear_findings(self) -> None:
        """Handle the View > Clear Findings menu action."""
        self.findings_view.clear()
        self.findings_standalone.clear()
        self.latest_result = None
        self.file_menu.entryconfig("Export Report...", state=tk.DISABLED)
        self.set_status("Findings cleared")

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
