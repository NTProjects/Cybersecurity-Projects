"""Dialog for displaying host status information."""
from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
from tkinter import messagebox, ttk
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from soc_audit.gui.backend.client import BackendClient


class HostStatusDialog:
    """Dialog displaying registered hosts and their status."""

    def __init__(self, parent: tk.Widget, backend_client: BackendClient, heartbeat_interval: int = 10):
        """
        Initialize the host status dialog.

        Args:
            parent: Parent widget.
            backend_client: BackendClient instance for fetching hosts.
            heartbeat_interval: Heartbeat interval in seconds for ONLINE/OFFLINE calculation.
        """
        self.parent = parent
        self.backend_client = backend_client
        self.heartbeat_interval = heartbeat_interval

        self._show_dialog()

    def _show_dialog(self) -> None:
        """Show the dialog."""
        # Phase 9.4: Fetch hosts at open-time from backend client
        try:
            hosts = self.backend_client.get_hosts()
            # Use cache if available, otherwise use fresh fetch
            if not hosts and hasattr(self.backend_client, "hosts_cache"):
                hosts = self.backend_client.hosts_cache
        except Exception as e:
            print(f"[GUI] Error fetching hosts in dialog: {e}")
            hosts = []
        
        # Guard: If hosts list is empty, show info and return early
        if not hosts or len(hosts) == 0:
            messagebox.showinfo(
                "Host Status",
                "No hosts found.\n\n"
                "Ensure agents are registered with the backend server."
            )
            return
        
        print(f"[GUI] Host dialogs populated with {len(hosts)} hosts")
        self.hosts = hosts
        
        # Create dialog window
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Host Status")
        self.dialog.geometry("800x400")
        self.dialog.resizable(True, True)
        self.dialog.transient(self.parent)

        # Configure grid
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)

        # Create treeview with scrollbar
        frame = ttk.Frame(self.dialog)
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Treeview columns
        columns = ("host_id", "host_name", "first_seen", "last_seen", "status")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        # Configure column headings
        tree.heading("host_id", text="Host ID")
        tree.heading("host_name", text="Host Name")
        tree.heading("first_seen", text="First Seen")
        tree.heading("last_seen", text="Last Seen")
        tree.heading("status", text="Status")

        # Configure column widths
        tree.column("host_id", width=150)
        tree.column("host_name", width=200)
        tree.column("first_seen", width=150)
        tree.column("last_seen", width=150)
        tree.column("status", width=100)

        # Populate treeview
        now = datetime.now(timezone.utc)
        threshold_seconds = 2 * self.heartbeat_interval

        for host in self.hosts:
            host_id = host.get("host_id", "")
            host_name = host.get("host_name") or "(unnamed)"
            first_seen_ts = host.get("first_seen_ts", "")
            last_seen_ts = host.get("last_seen_ts", "")

            # Parse last_seen timestamp
            status = "UNKNOWN"
            try:
                if last_seen_ts:
                    last_seen = datetime.fromisoformat(last_seen_ts.replace("Z", "+00:00"))
                    if last_seen.tzinfo is None:
                        last_seen = last_seen.replace(tzinfo=timezone.utc)
                    
                    elapsed = (now - last_seen).total_seconds()
                    status = "ONLINE" if elapsed < threshold_seconds else "OFFLINE"
            except Exception:
                status = "UNKNOWN"

            # Format timestamps for display
            first_seen_display = self._format_timestamp(first_seen_ts)
            last_seen_display = self._format_timestamp(last_seen_ts)

            # Phase 8.2: Status indicator with color
            status_display = f"● {status}"
            
            item = tree.insert("", tk.END, values=(host_id, host_name, first_seen_display, last_seen_display, status_display))
            
            # Phase 8.2: Apply color tags based on status
            if status == "ONLINE":
                tree.set(item, "status", "● ONLINE")
                tree.item(item, tags=("online",))
            elif status == "OFFLINE":
                tree.set(item, "status", "● OFFLINE")
                tree.item(item, tags=("offline",))
            else:
                tree.set(item, "status", "● UNKNOWN")
                tree.item(item, tags=("unknown",))

        # Phase 8.2: Configure status color tags
        tree.tag_configure("online", foreground="#00aa00")  # Green
        tree.tag_configure("offline", foreground="#aa0000")  # Red
        tree.tag_configure("unknown", foreground="#666666")  # Gray
        
        tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scrollbar.set)

        # Close button
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        button_frame.columnconfigure(0, weight=1)

        close_button = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_button.grid(row=0, column=0)

        # Focus on dialog
        self.dialog.focus_set()

    def _format_timestamp(self, ts: str) -> str:
        """Format ISO timestamp for display."""
        if not ts:
            return "(unknown)"
        
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            
            # Format as YYYY-MM-DD HH:MM:SS
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts[:19] if len(ts) >= 19 else ts
