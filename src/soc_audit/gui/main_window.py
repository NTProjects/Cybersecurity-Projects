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

import json
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any

from soc_audit.core.config import load_config
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
        
        # Load config (with defaults)
        self.config: dict[str, Any] = {}
        try:
            default_config_path = Path("config/default.json")
            if default_config_path.exists():
                self.config = load_config(str(default_config_path))
        except Exception:
            pass  # Use empty config if load fails

        # Build UI components
        self._create_menu_bar()
        self._create_content_frame()
        self._create_views()
        self._create_status_bar()

        # Show dashboard by default and start metrics refresh
        self._show_view("dashboard")
        self.dashboard_view.start()
        
        # Phase 6.2: Wire role update callback and update UI
        self.dashboard_view.on_role_update = self._update_role_based_ui
        self._update_role_based_ui()

        # Bind window close to cleanup
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)

    def _create_menu_bar(self) -> None:
        """
        Create the application menu bar.

        Sets up the File, View, and Help menus with their respective
        menu items including view switching and metrics refresh options.
        """
        # Light grey menu colors
        menu_bg = "#d3d3d3"
        menu_fg = "#1e1e1e"
        menu_active_bg = "#b0b0b0"
        menu_disabled_fg = "#1e1e1e"  # Match normal text color
        
        menu_bar = tk.Menu(
            self.root, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        self.root.config(menu=menu_bar)

        # File menu
        self.file_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(
            label="Export Report...",
            command=self._on_export_report,
            state=tk.DISABLED,
        )
        self.file_menu.add_separator()
        # Phase 5.5: Export options
        self.file_menu.add_command(label="Export Timeline...", command=self._on_export_timeline)
        self.file_menu.add_command(label="Export Incidents...", command=self._on_export_incidents)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self._on_window_close)

        # View menu with view switching
        self.view_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="Dashboard", command=self._on_show_dashboard)
        self.view_menu.add_command(label="Scan Configuration", command=self._on_show_scanner)
        self.view_menu.add_command(label="Findings", command=self._on_show_findings)
        self.view_menu.add_separator()
        self.view_menu.add_separator()
        self.view_menu.add_command(label="Refresh Metrics", command=self._on_refresh_metrics)
        self.view_menu.add_command(label="Stop Alert Stream", command=self._on_stop_streaming)
        self.view_menu.add_command(label="Clear Findings", command=self._on_clear_findings)
        self.view_menu.add_separator()
        # Collectors toggle
        self._collectors_enabled = tk.BooleanVar(value=self.config.get("collectors", {}).get("enabled", True))
        self.view_menu.add_checkbutton(
            label="Live Collectors",
            command=self._on_toggle_collectors,
            variable=self._collectors_enabled,
        )
        # Phase 5.5: Show suppressed toggle
        self._show_suppressed = tk.BooleanVar(value=False)
        self.view_menu.add_checkbutton(
            label="Show Suppressed",
            command=self._on_toggle_show_suppressed,
            variable=self._show_suppressed,
        )
        # Phase 6: Backend status
        self.view_menu.add_separator()
        self.view_menu.add_command(label="Backend Status", command=self._on_backend_status)
        # Phase 7.3: Host scope
        self.view_menu.add_command(label="Host Scope…", command=self._on_host_scope, state=tk.DISABLED)
        self._host_scope_menu_item = self.view_menu.index("Host Scope…")
        
        # Phase 5.5: Alerts menu
        self.alerts_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="Alerts", menu=self.alerts_menu)
        self.alerts_menu.add_command(label="Acknowledge Alert", command=self._on_ack_alert)
        self.alerts_menu.add_command(label="Suppress Similar...", command=self._on_suppress_similar)
        
        # Phase 5.5: Incidents menu
        self.incidents_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="Incidents", menu=self.incidents_menu)
        self.incidents_menu.add_command(label="Close Incident", command=self._on_close_incident)
        self.incidents_menu.add_command(label="Add Note...", command=self._on_add_incident_note)
        
        # Phase 6.2: Store menu items for role-based enabling/disabling
        self._incident_close_item = self.incidents_menu.index("Close Incident")
        self._incident_note_item = self.incidents_menu.index("Add Note...")
        
        # Phase 6.2: Backend menu
        self.backend_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
            disabledforeground=menu_disabled_fg
        )
        menu_bar.add_cascade(label="Backend", menu=self.backend_menu)
        self.backend_menu.add_command(label="Authentication...", command=self._on_backend_auth)
        # Phase 7.3: Host status
        self.backend_menu.add_command(label="Hosts…", command=self._on_host_status, state=tk.DISABLED)
        self._host_status_menu_item = self.backend_menu.index("Hosts…")

        # Help menu
        help_menu = tk.Menu(
            menu_bar, tearoff=0, bg=menu_bg, fg=menu_fg,
            activebackground=menu_active_bg, activeforeground="#000000",
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
            config=self.config,
        )
        # Phase 6.2: Wire role update callback
        if hasattr(self.dashboard_view, "_backend_client"):
            # Callback will be set after backend client is initialized
            pass

        # Scanner view with fixed layout (no resizable divider - eliminates jitter)
        self.scanner_container = ttk.Frame(self.content_frame)

        # Scanner config section (top) - fixed height
        scanner_frame = tk.Frame(self.scanner_container, bg="#1e1e1e", height=150)
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
            self.dashboard_view.start()  # Ensure dashboard is started when shown
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

    def _on_toggle_collectors(self) -> None:
        """Handle View > Live Collectors toggle."""
        enabled = self._collectors_enabled.get()
        # Update config
        if "collectors" not in self.config:
            self.config["collectors"] = {}
        self.config["collectors"]["enabled"] = enabled
        
        # Update dashboard (it will handle start/stop internally)
        if enabled:
            collectors_config = self.config.get("collectors", {})
            self.dashboard_view._start_collectors(collectors_config)
            self.set_status("Live collectors enabled")
        else:
            self.dashboard_view._stop_collectors()
            self.set_status("Live collectors disabled")
    
    def _on_toggle_show_suppressed(self) -> None:
        """Handle View > Show Suppressed toggle."""
        show = self._show_suppressed.get()
        self.dashboard_view.toggle_show_suppressed(show)
        self.set_status("Show suppressed: " + ("ON" if show else "OFF"))
    
    def _on_backend_status(self) -> None:
        """Handle View > Backend Status menu action."""
        backend_config = self.config.get("backend", {})
        enabled = backend_config.get("enabled", False)
        
        if not enabled:
            messagebox.showinfo(
                "Backend Status",
                "Backend mode is disabled.\n\n"
                "To enable, set 'backend.enabled' to true in config/default.json"
            )
            return
        
        # Get backend client status
        backend_client = getattr(self.dashboard_view, "_backend_client", None)
        if backend_client:
            status = backend_client.status
            api_url = backend_config.get("api_url", "N/A")
            ws_url = backend_config.get("ws_url", "N/A")
            use_ws = backend_config.get("use_websocket", False)
            
            status_msg = (
                f"Backend Status: {status.upper()}\n\n"
                f"API URL: {api_url}\n"
                f"WebSocket URL: {ws_url if use_ws else 'Not used'}\n"
                f"Poll Interval: {backend_config.get('poll_interval_seconds', 5.0)}s\n"
            )
            
            # Phase 6.2: Show role
            if backend_client.backend_role:
                status_msg += f"Role: {backend_client.backend_role.capitalize()}\n"
            else:
                status_msg += "Role: Unauthenticated\n"
            
            if backend_client.last_error:
                status_msg += f"\nLast Error: {backend_client.last_error}"
            
            messagebox.showinfo("Backend Status", status_msg)
        else:
            messagebox.showwarning(
                "Backend Status",
                "Backend client not initialized.\n\n"
                "Check configuration and restart the application."
            )
    
    def _on_backend_auth(self) -> None:
        """Handle Backend > Authentication menu action (Phase 6.2)."""
        backend_config = self.config.get("backend", {})
        enabled = backend_config.get("enabled", False)
        
        if not enabled:
            messagebox.showinfo(
                "Backend Authentication",
                "Backend mode is disabled.\n\n"
                "Enable backend in config to use authentication."
            )
            return
        
        # Create auth dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Backend Authentication")
        dialog.geometry("400x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 400) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 200) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # API Key input
        ttk.Label(dialog, text="API Key:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(dialog, textvariable=api_key_var, show="*", width=40)
        api_key_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        dialog.columnconfigure(1, weight=1)
        
        # Pre-fill if backend client has key
        backend_client = getattr(self.dashboard_view, "_backend_client", None)
        if backend_client and backend_client.api_key:
            api_key_var.set(backend_client.api_key)
        
        # Remember checkbox (session only, not saved to disk)
        remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Remember for this session", variable=remember_var).grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="w")
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        def save_auth():
            api_key = api_key_var.get().strip()
            if not api_key:
                messagebox.showwarning("Invalid Key", "Please enter an API key.")
                return
            
            # Update backend client
            if backend_client:
                backend_client.set_api_key(api_key)
                messagebox.showinfo("Authentication", "API key updated for this session.")
            else:
                messagebox.showerror("Error", "Backend client not available.")
            
            dialog.destroy()
        
        def clear_auth():
            if backend_client:
                backend_client.set_api_key(None)
                messagebox.showinfo("Authentication", "API key cleared.")
            dialog.destroy()
        
        ttk.Button(button_frame, text="Save", command=save_auth).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=clear_auth).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    # Phase 7.3: Host scoping and status
    def _on_host_scope(self) -> None:
        """Handle View > Host Scope… menu action."""
        backend_config = self.config.get("backend", {})
        if not backend_config.get("enabled", False):
            messagebox.showinfo(
                "Host Scope",
                "Backend mode is disabled.\n\n"
                "Enable backend in config to use host scoping."
            )
            return
        
        # Get hosts from backend
        hosts = self.dashboard_view.get_hosts()
        if not hosts:
            messagebox.showinfo(
                "Host Scope",
                "No hosts found.\n\n"
                "Ensure agents are registered with the backend server."
            )
            return
        
        # Get current host scope
        current_host_id = getattr(self.dashboard_view, "current_host_id", None)
        
        # Show host scope dialog
        from soc_audit.gui.dialogs.host_scope_dialog import HostScopeDialog
        
        def on_confirm(host_id: str | None):
            self.dashboard_view._on_host_scope_change(host_id)
        
        HostScopeDialog(self.root, hosts, current_host_id, on_confirm)
    
    def _on_host_status(self) -> None:
        """Handle Backend > Hosts… menu action."""
        backend_config = self.config.get("backend", {})
        if not backend_config.get("enabled", False):
            messagebox.showinfo(
                "Host Status",
                "Backend mode is disabled.\n\n"
                "Enable backend in config to view host status."
            )
            return
        
        # Get hosts from backend
        hosts = self.dashboard_view.get_hosts()
        if not hosts:
            messagebox.showinfo(
                "Host Status",
                "No hosts found.\n\n"
                "Ensure agents are registered with the backend server."
            )
            return
        
        # Get heartbeat interval from config
        heartbeat_interval = backend_config.get("poll_interval_seconds", 10)
        
        # Show host status dialog
        from soc_audit.gui.dialogs.host_status_dialog import HostStatusDialog
        
        HostStatusDialog(self.root, hosts, int(heartbeat_interval * 2))
    
    def _update_role_based_ui(self) -> None:
        """Update UI elements based on backend role (Phase 6.2)."""
        backend_config = self.config.get("backend", {})
        backend_enabled = backend_config.get("enabled", False)
        
        backend_client = getattr(self.dashboard_view, "_backend_client", None)
        backend_connected = backend_client is not None
        
        # Phase 7.3: Enable/disable host menu items based on backend connection
        if backend_enabled and backend_connected:
            self.view_menu.entryconfig(self._host_scope_menu_item, state=tk.NORMAL)
            self.backend_menu.entryconfig(self._host_status_menu_item, state=tk.NORMAL)
        else:
            self.view_menu.entryconfig(self._host_scope_menu_item, state=tk.DISABLED)
            self.backend_menu.entryconfig(self._host_status_menu_item, state=tk.DISABLED)
        
        if not backend_enabled:
            # Backend disabled - all actions available (local mode)
            return
        
        if not backend_client:
            return
        
        role = backend_client.backend_role
        
        # Phase 6.2: Gate incident actions based on role
        if role == "admin":
            # Admin: all actions enabled
            self.incidents_menu.entryconfig("Close Incident", state=tk.NORMAL)
            self.incidents_menu.entryconfig("Add Note...", state=tk.NORMAL)
        elif role == "analyst":
            # Analyst: can add notes, cannot close
            self.incidents_menu.entryconfig("Close Incident", state=tk.DISABLED)
            self.incidents_menu.entryconfig("Add Note...", state=tk.NORMAL)
        else:
            # Unauthenticated or unknown: disable admin actions
            self.incidents_menu.entryconfig("Close Incident", state=tk.DISABLED)
            self.incidents_menu.entryconfig("Add Note...", state=tk.DISABLED)
    
    # Phase 5.5: Alert actions
    def _on_ack_alert(self) -> None:
        """Handle Alerts > Acknowledge Alert."""
        # Get selected alert from dashboard (simplified - in production, track selection)
        messagebox.showinfo("Acknowledge Alert", "Right-click on an alert and select 'Acknowledge' to acknowledge it.")
    
    def _on_suppress_similar(self) -> None:
        """Handle Alerts > Suppress Similar..."""
        # Simple dialog for suppression rule
        dialog = tk.Toplevel(self.root)
        dialog.title("Suppress Similar Alerts")
        dialog.geometry("400x200")
        
        tk.Label(dialog, text="Module:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        module_var = tk.StringVar()
        tk.Entry(dialog, textvariable=module_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Title contains:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        title_var = tk.StringVar()
        tk.Entry(dialog, textvariable=title_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        def save_suppression():
            from soc_audit.core.suppression import SuppressionRule, load_suppressions, save_suppressions, upsert_rule
            import uuid
            
            module = module_var.get().strip()
            title_keywords = [t.strip() for t in title_var.get().split(",") if t.strip()]
            
            if not module and not title_keywords:
                messagebox.showwarning("Invalid Rule", "Please specify at least module or title keywords.")
                return
            
            # Load existing rules
            persistence_config = self.config.get("persistence", {})
            suppressions_path = persistence_config.get("suppressions_path", "config/suppressions.json")
            rules = load_suppressions(suppressions_path)
            
            # Create new rule
            rule = SuppressionRule(
                id=str(uuid.uuid4()),
                name=f"Suppress: {module or 'all'} - {title_keywords[0] if title_keywords else 'any'}",
                enabled=True,
                match_module=module if module else None,
                match_title_contains=title_keywords,
            )
            
            upsert_rule(rules, rule)
            save_suppressions(suppressions_path, rules)
            
            # Reload in dashboard (simplified - would need to reload)
            messagebox.showinfo("Suppression Rule Created", f"Rule created: {rule.name}")
            dialog.destroy()
        
        tk.Button(dialog, text="Create Rule", command=save_suppression).grid(row=2, column=1, padx=5, pady=10, sticky="e")
        tk.Button(dialog, text="Cancel", command=dialog.destroy).grid(row=2, column=0, padx=5, pady=10, sticky="w")
    
    # Phase 5.5: Incident actions
    def _on_close_incident(self) -> None:
        """Handle Incidents > Close Incident."""
        messagebox.showinfo("Close Incident", "Select an incident from the dashboard to close it.")
    
    def _on_add_incident_note(self) -> None:
        """Handle Incidents > Add Note..."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Incident Note")
        dialog.geometry("400x200")
        
        tk.Label(dialog, text="Incident ID:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        incident_id_var = tk.StringVar()
        tk.Entry(dialog, textvariable=incident_id_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(dialog, text="Note:").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        note_text = tk.Text(dialog, width=30, height=5)
        note_text.grid(row=1, column=1, padx=5, pady=5)
        
        def save_note():
            incident_id = incident_id_var.get().strip()
            note = note_text.get("1.0", tk.END).strip()
            
            if not incident_id or not note:
                messagebox.showwarning("Invalid Input", "Please provide both incident ID and note.")
                return
            
            engine = self.dashboard_view.get_incident_engine()
            if engine:
                engine.add_note(incident_id, note)
                # Save to storage
                storage = self.dashboard_view.get_storage()
                if storage:
                    incident = engine.get_incident(incident_id)
                    if incident:
                        storage.save_incident(incident)
                messagebox.showinfo("Note Added", "Note added to incident.")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Incident engine not available.")
        
        tk.Button(dialog, text="Add Note", command=save_note).grid(row=2, column=1, padx=5, pady=10, sticky="e")
        tk.Button(dialog, text="Cancel", command=dialog.destroy).grid(row=2, column=0, padx=5, pady=10, sticky="w")
    
    # Phase 5.5: Export actions
    def _on_export_timeline(self) -> None:
        """Handle File > Export Timeline..."""
        from tkinter import filedialog
        from soc_audit.reporting.timeline_export import export_timeline_json, export_timeline_text
        
        storage = self.dashboard_view.get_storage()
        if not storage:
            messagebox.showwarning("No Storage", "Persistence is not enabled. Enable it in config to export timeline.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export Timeline",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
        )
        
        if file_path:
            try:
                if file_path.endswith(".txt"):
                    export_timeline_text(storage, file_path)
                else:
                    export_timeline_json(storage, file_path)
                messagebox.showinfo("Export Complete", f"Timeline exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export timeline:\n{e}")
    
    def _on_export_incidents(self) -> None:
        """Handle File > Export Incidents..."""
        from tkinter import filedialog
        from soc_audit.reporting.timeline_export import export_incidents_json
        
        storage = self.dashboard_view.get_storage()
        if not storage:
            messagebox.showwarning("No Storage", "Persistence is not enabled. Enable it in config to export incidents.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export Incidents",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        
        if file_path:
            try:
                export_incidents_json(storage, file_path)
                messagebox.showinfo("Export Complete", f"Incidents exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export incidents:\n{e}")

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
            
            # Set light grey title bar on Windows 10/11
            self.root.update()  # Ensure window is created
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10/11) - disable dark mode
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(0)  # 0 = light mode
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(value), ctypes.sizeof(value)
            )
            
            # DWMWA_CAPTION_COLOR = 35 (Windows 11) - set title bar to light grey
            DWMWA_CAPTION_COLOR = 35
            # Color is in BGR format: 0x00D3D3D3 = RGB(211, 211, 211) - light grey
            color = ctypes.c_int(0x00D3D3D3)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_CAPTION_COLOR,
                ctypes.byref(color), ctypes.sizeof(color)
            )
            
            # DWMWA_TEXT_COLOR = 36 (Windows 11) - set title text to dark
            DWMWA_TEXT_COLOR = 36
            text_color = ctypes.c_int(0x001E1E1E)  # BGR for #1E1E1E - dark text
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
