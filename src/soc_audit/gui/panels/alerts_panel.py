"""Alerts panel for the SOC dashboard.

This module provides a panel displaying security alerts and notable
events in a Splunk ES-style format.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable


class AlertsPanel(ttk.LabelFrame):
    """
    Panel displaying alerts and notable events.

    Shows a table of security alerts with severity, module, title, and time.
    Supports row selection with callback notification.

    Attributes:
        tree: Treeview widget displaying alerts.
        on_select: Optional callback invoked when an alert is selected.
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_select: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """
        Initialize the alerts panel.

        Args:
            parent: Parent widget.
            on_select: Optional callback invoked with selected row data.
        """
        super().__init__(parent, text="Alerts / Notable Events", padding=10)
        self.on_select = on_select
        self._build_ui()
        self.set_placeholder_data()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Create treeview
        columns = ("severity", "module", "title", "time")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")

        # Configure columns
        self.tree.heading("severity", text="Severity")
        self.tree.heading("module", text="Module")
        self.tree.heading("title", text="Title")
        self.tree.heading("time", text="Time")

        self.tree.column("severity", width=70, minwidth=50)
        self.tree.column("module", width=120, minwidth=80)
        self.tree.column("title", width=250, minwidth=150)
        self.tree.column("time", width=60, minwidth=40)

        self.tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _on_tree_select(self, event: tk.Event) -> None:
        """Handle treeview selection."""
        selection = self.tree.selection()
        if not selection:
            return

        item = self.tree.item(selection[0])
        values = item.get("values", [])
        if values and self.on_select:
            data = {
                "severity": values[0] if len(values) > 0 else "",
                "module": values[1] if len(values) > 1 else "",
                "title": values[2] if len(values) > 2 else "",
                "time": values[3] if len(values) > 3 else "",
            }
            self.on_select(data)

    def set_placeholder_data(self) -> None:
        """Set placeholder alert data for demonstration."""
        self.clear()

        placeholder_alerts = [
            ("High", "firewall_analyzer", "Overly permissive firewall rule", "Now"),
            ("High", "log_analyzer", "Repeated SSH failures", "Now"),
            ("Medium", "port_risk_analyzer", "SSH exposed", "Now"),
            ("Medium", "port_risk_analyzer", "HTTP exposed", "1m ago"),
        ]

        for alert in placeholder_alerts:
            self.tree.insert("", tk.END, values=alert)

    def clear(self) -> None:
        """Clear all alerts from the table."""
        for item in self.tree.get_children():
            self.tree.delete(item)
