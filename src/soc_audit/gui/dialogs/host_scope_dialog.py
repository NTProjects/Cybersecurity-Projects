"""Dialog for selecting host scope in the GUI."""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from soc_audit.gui.backend.client import BackendClient


class HostScopeDialog:
    """Dialog for selecting host scope (All Hosts or specific host)."""

    def __init__(
        self,
        parent: tk.Widget,
        backend_client: BackendClient,
        current_host_id: str | None,
        on_confirm: Callable[[str | None], None],
    ):
        """
        Initialize the host scope dialog.

        Args:
            parent: Parent widget.
            backend_client: BackendClient instance for fetching hosts.
            current_host_id: Currently selected host_id (None = All Hosts).
            on_confirm: Callback invoked with selected host_id (None = All Hosts).
        """
        self.parent = parent
        self.backend_client = backend_client
        self.current_host_id = current_host_id
        self.on_confirm = on_confirm
        self.selected_host_id: str | None = None

        self._show_dialog()

    def _show_dialog(self) -> None:
        """Show the dialog."""
        # Guard: Check if backend is authenticated (analyst/admin role required)
        if not self.backend_client.api_key:
            messagebox.showwarning(
                "Not Authenticated",
                "Please authenticate with the backend first.\n\n"
                "Go to Backend → Authentication... and enter your API key."
            )
            return
        
        if self.backend_client.backend_role not in ["analyst", "admin"]:
            messagebox.showwarning(
                "Insufficient Permissions",
                "Host listing requires analyst or admin role.\n\n"
                "Please authenticate with an appropriate API key."
            )
            return
        
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
                "Host Scope",
                "No hosts found.\n\n"
                "Ensure agents are registered with the backend server.\n"
                "Hosts appear after agents send heartbeats."
            )
            return
        
        print(f"[GUI] Host dialogs populated with {len(hosts)} hosts")
        self.hosts = hosts
        
        # Create dialog window
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Select Host Scope")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()

        # Configure grid
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(1, weight=1)

        # Label
        label = ttk.Label(
            self.dialog,
            text="Select the host scope for filtering alerts, incidents, and timeline:",
            padding=10,
        )
        label.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))

        # Frame for radio buttons
        radio_frame = ttk.Frame(self.dialog)
        radio_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        radio_frame.columnconfigure(0, weight=1)

        # Radio button variable
        self.var = tk.StringVar(value="all" if self.current_host_id is None else self.current_host_id)

        # "All Hosts" radio button
        all_radio = ttk.Radiobutton(
            radio_frame,
            text="All Hosts",
            variable=self.var,
            value="all",
            command=self._on_selection_change,
        )
        all_radio.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        # Host-specific radio buttons
        row = 1
        for host in self.hosts:
            host_id = host.get("host_id", "")
            host_name = host.get("host_name") or host_id
            label_text = f"{host_name} ({host_id})"

            host_radio = ttk.Radiobutton(
                radio_frame,
                text=label_text,
                variable=self.var,
                value=host_id,
                command=self._on_selection_change,
            )
            host_radio.grid(row=row, column=0, sticky="w", padx=10, pady=2)
            row += 1

        # Buttons frame
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        # OK button
        ok_button = ttk.Button(button_frame, text="OK", command=self._on_ok)
        ok_button.grid(row=0, column=0, padx=(0, 5), sticky="ew")

        # Cancel button
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self._on_cancel)
        cancel_button.grid(row=0, column=1, padx=(5, 0), sticky="ew")

        # Focus on dialog
        self.dialog.focus_set()

    def _on_selection_change(self) -> None:
        """Handle radio button selection change."""
        value = self.var.get()
        self.selected_host_id = None if value == "all" else value

    def _on_ok(self) -> None:
        """Handle OK button click."""
        value = self.var.get()
        host_id = None if value == "all" else value
        self.on_confirm(host_id)
        self.dialog.destroy()

    def _on_cancel(self) -> None:
        """Handle Cancel button click."""
        self.dialog.destroy()
