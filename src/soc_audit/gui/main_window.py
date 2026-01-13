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
from pathlib import Path
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING

from soc_audit.gui.dashboard_view import DashboardView
from soc_audit.gui.findings_view import FindingsView
from soc_audit.gui.report_export import ReportExportView
from soc_audit.gui.scanner_view import ScannerView
from soc_audit.gui.theme import apply_dark_theme

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
    - Dashboard: SOC-style dashboard with live metrics, alerts, and entities
    - Scan Configuration: Scanner configuration and execution
    - Findings: Detailed findings table and analysis

    Attributes:
        root: The Tkinter root window instance.
        content_frame: Frame containing the active view.
        dashboard_view: The DashboardView instance with live metrics.
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
        area with dashboard view, and status bar. Dashboard is shown by default
        with live metrics auto-refresh enabled.
        """
        # Create root window
        self.root = tk.Tk()
        self.root.title("SOC Audit Framework")

        # Set window size and constraints
        self.root.geometry(f"{self.DEFAULT_WIDTH}x{self.DEFAULT_HEIGHT}")
        self.root.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)

        # Set application icon
        self._set_app_icon()

        # Apply dark theme for eye-friendly appearance
        # To revert: comment out or remove this line
        apply_dark_theme(self.root)

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

        # Show dashboard by default and start metrics refresh
        self._show_view("dashboard")
        self.dashboard_view.start()

        # Bind window close to cleanup
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

    def _create_menu_bar(self) -> None:
        """
        Create the application menu bar.

        Sets up the File, View, and Help menus with their respective
        menu items including view switching and metrics refresh options.
        """
        # Dark menu colors
        menu_bg = "#1e1e1e"
        menu_fg = "#d4d4d4"
        menu_active_bg = "#3e3e42"
        menu_disabled_fg = "#666666"
        
        menu_bar = tk.Menu(
            self.root, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#ffffff",
            disabledforeground=menu_disabled_fg
        )
        self.root.config(menu=menu_bar)

        # File menu
        self.file_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#ffffff",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(
            label="Export Report...",
            command=self._on_export_report,
            state=tk.DISABLED,
        )
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self._on_window_close)

        # View menu with view switching
        self.view_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#ffffff",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Dashboard", command=self._on_show_dashboard)
        self.view_menu.add_command(label="Scan Configuration", command=self._on_show_scanner)
        self.view_menu.add_command(label="Findings", command=self._on_show_findings)
        self.view_menu.add_separator()
        self.view_menu.add_command(label="Refresh Metrics", command=self._on_refresh_metrics)
        self.view_menu.add_command(label="Stop Alert Stream", command=self._on_stop_streaming)
        self.view_menu.add_command(label="Clear Findings", command=self._on_clear_findings)

        # Help menu
        help_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#ffffff",
            disabledforeground=menu_disabled_fg
        )
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
        # Dashboard view (default) with status callback for live metrics
        self.dashboard_view = DashboardView(
            self.content_frame,
            on_status=self.set_status,
            refresh_ms=1000,
        )

        # Scanner view with fixed layout (no resizable divider - eliminates jitter)
        self.scanner_container = ttk.Frame(self.content_frame)

        # Scanner config section (top) - fixed height
        scanner_frame = tk.Frame(self.scanner_container, bg="#1e1e1e", height=120)
        scanner_frame.pack(side=tk.TOP, fill=tk.X)
        scanner_frame.pack_propagate(False)  # Keep fixed height
        
        self.scanner_view = ScannerView(
            scanner_frame,
            self.set_status,
            on_scan_complete=self._on_scan_complete,
        )
        self.scanner_view.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Findings view (fills remaining space)
        self.findings_view = FindingsView(self.scanner_container)
        self.findings_view.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

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
            bg="#1e1e1e",  # Dark background
            fg="#d4d4d4",  # Light text
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
        self.scanner_container.grid_forget()
        self.findings_standalone.grid_forget()

        # Show the requested view
        if view_name == "dashboard":
            self.dashboard_view.grid(row=0, column=0, sticky="nsew")
        elif view_name == "scanner":
            self.scanner_container.grid(row=0, column=0, sticky="nsew")
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

    def _on_refresh_metrics(self) -> None:
        """Handle View > Refresh Metrics menu action."""
        self.dashboard_view.refresh_now()
        self.set_status("Metrics refreshed")

    def _on_stop_streaming(self) -> None:
        """Handle View > Stop Alert Stream menu action."""
        if self.dashboard_view.is_streaming():
            self.dashboard_view.stop_streaming()
            self.set_status("Alert streaming stopped")
        else:
            self.set_status("No stream in progress")

    def set_status(self, message: str) -> None:
        """
        Update the status bar text.

        Args:
            message: The status message to display.
        """
        self.status_var.set(message)

    def _on_scan_complete(self, engine_result: object) -> None:
        """
        Handle scan completion by streaming to dashboard and updating findings.

        This method:
        1. Switches to the dashboard view
        2. Streams findings one-by-one for SOC-style visualization
        3. Updates the findings views with complete results
        4. Enables report export

        Args:
            engine_result: The EngineResult from the scan.
        """
        # Import here to avoid circular import at module level
        from soc_audit.core.engine import EngineResult

        if isinstance(engine_result, EngineResult):
            self.latest_result = engine_result
            
            # Update findings views with complete results
            self.findings_view.set_results(engine_result)
            self.findings_standalone.set_results(engine_result)
            
            # Enable export menu item
            self.file_menu.entryconfig("Export Report...", state=tk.NORMAL)
            
            # Switch to dashboard and stream findings for SOC-style presentation
            self._show_view("dashboard")
            self.dashboard_view.stream_engine_result(engine_result, delay_ms=350)

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
        # Stop any ongoing streaming
        self.dashboard_view.stop_streaming()
        # Clear all views
        self.dashboard_view.clear_findings()
        self.findings_view.clear()
        self.findings_standalone.clear()
        self.latest_result = None
        self.file_menu.entryconfig("Export Report...", state=tk.DISABLED)
        self.set_status("Findings cleared")

    def _on_window_close(self) -> None:
        """Handle window close event with cleanup."""
        # Stop dashboard metrics refresh
        self.dashboard_view.stop()
        # Destroy the window
        self.root.quit()

    def _set_app_icon(self) -> None:
        """Set the application icon for window and taskbar."""
        try:
            import ctypes
            
            # Set unique App ID for Windows taskbar (prevents grouping with Python)
            app_id = "SOCAudit.Framework.GUI.1.0"
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
            
            # Set dark title bar on Windows 10/11
            self.root.update()  # Ensure window is created
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10/11)
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(value), ctypes.sizeof(value)
            )
            
            # DWMWA_CAPTION_COLOR = 35 (Windows 11) - set title bar to dark grey
            DWMWA_CAPTION_COLOR = 35
            # Color is in BGR format: 0x001E1E1E = RGB(30, 30, 30)
            color = ctypes.c_int(0x001E1E1E)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_CAPTION_COLOR,
                ctypes.byref(color), ctypes.sizeof(color)
            )
            
            # DWMWA_TEXT_COLOR = 36 (Windows 11) - set title text to light grey
            DWMWA_TEXT_COLOR = 36
            text_color = ctypes.c_int(0x00D4D4D4)  # BGR for #D4D4D4
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_TEXT_COLOR,
                ctypes.byref(text_color), ctypes.sizeof(text_color)
            )
        except (ImportError, AttributeError, OSError):
            pass  # Not on Windows or API not available
        
        # Look for icon in assets folder
        icon_path = Path(__file__).parent / "assets" / "icon.ico"
        
        if icon_path.exists():
            try:
                self.root.iconbitmap(default=str(icon_path))
            except tk.TclError:
                pass  # Icon format not supported, continue without icon
        
        # Also set iconphoto for better cross-platform support
        png_path = Path(__file__).parent / "assets" / "icon.png"
        if png_path.exists():
            try:
                icon_image = tk.PhotoImage(file=str(png_path))
                self.root.iconphoto(True, icon_image)
                self._icon_image = icon_image  # Keep reference to prevent garbage collection
            except tk.TclError:
                pass  # Continue without icon

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
