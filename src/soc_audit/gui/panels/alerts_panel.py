"""Alerts panel for the SOC dashboard.

This module provides a panel displaying security alerts and notable
events in a Splunk ES-style format with live streaming support.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from soc_audit.core.interfaces import Finding


# Severity color mapping for visual distinction
SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff6b6b",
    "medium": "#ffa726",
    "low": "#42a5f5",
    "info": "#78909c",
}


class AlertsPanel(ttk.LabelFrame):
    """
    Panel displaying alerts and notable events with streaming support.

    Shows a table of security alerts with severity, module, title, and time.
    Supports incremental alert insertion for live streaming effect.

    Attributes:
        tree: Treeview widget displaying alerts.
        on_select: Optional callback invoked when an alert is selected.
        findings_cache: List of Finding objects for drill-down.
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
        self.findings_cache: list[Any] = []  # Store Finding objects for drill-down
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Configure tag colors for severity highlighting
        style = ttk.Style()
        
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

        # Configure severity tags for row coloring
        self.tree.tag_configure("critical", background="#4a1a1a")
        self.tree.tag_configure("high", background="#4a2a2a")
        self.tree.tag_configure("medium", background="#4a3a1a")
        self.tree.tag_configure("low", background="#1a2a4a")
        self.tree.tag_configure("info", background="#2a2a2a")

        self.tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _on_tree_select(self, event: tk.Event) -> None:
        """Handle treeview selection."""
        selection = self.tree.selection()
        if not selection:
            return

        item_id = selection[0]
        item = self.tree.item(item_id)
        values = item.get("values", [])
        
        # Get the index to retrieve the cached Finding
        children = self.tree.get_children()
        idx = children.index(item_id) if item_id in children else -1
        
        if values and self.on_select:
            data = {
                "severity": values[0] if len(values) > 0 else "",
                "module": values[1] if len(values) > 1 else "",
                "title": values[2] if len(values) > 2 else "",
                "time": values[3] if len(values) > 3 else "",
            }
            # Include the Finding object if available for drill-down
            if 0 <= idx < len(self.findings_cache):
                data["finding"] = self.findings_cache[idx]
            self.on_select(data)

    def append_finding(self, finding: Finding, module_name: str, timestamp: str = "Now") -> None:
        """
        Append a single finding to the alerts table (streaming mode).

        Args:
            finding: The Finding object to append.
            module_name: Name of the module that produced the finding.
            timestamp: Display timestamp (default: "Now").
        """
        severity = finding.severity.lower()
        tag = severity if severity in SEVERITY_COLORS else "info"
        
        # Cache the finding for drill-down
        self.findings_cache.append(finding)
        
        # Insert at the top for newest-first ordering
        self.tree.insert(
            "",
            0,  # Insert at top
            values=(finding.severity.capitalize(), module_name, finding.title, timestamp),
            tags=(tag,),
        )
        
        # Auto-scroll to show newest (top)
        children = self.tree.get_children()
        if children:
            self.tree.see(children[0])

    def set_placeholder_data(self) -> None:
        """Set placeholder alert data for demonstration."""
        self.clear()

        placeholder_alerts = [
            ("High", "firewall_analyzer", "Overly permissive firewall rule", "Now", "high"),
            ("High", "log_analyzer", "Repeated SSH failures", "Now", "high"),
            ("Medium", "port_risk_analyzer", "SSH exposed", "Now", "medium"),
            ("Medium", "port_risk_analyzer", "HTTP exposed", "1m ago", "medium"),
        ]

        for severity, module, title, time, tag in placeholder_alerts:
            self.tree.insert("", tk.END, values=(severity, module, title, time), tags=(tag,))

    def clear(self) -> None:
        """Clear all alerts from the table."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.findings_cache.clear()
