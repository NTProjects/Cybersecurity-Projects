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
        self.findings_cache: list[Any] = []  # Store Finding/AlertEvent objects for drill-down
        self.alert_events_cache: dict[str, Any] = {}  # alert_id -> AlertEvent
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Configure tag colors for severity highlighting
        style = ttk.Style()
        
        # Create treeview with RBA/MITRE/Source/Ack/Suppressed/Incident columns
        columns = ("severity", "rba", "module", "title", "mitre", "time", "source", "acked", "suppressed", "incident")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")

        # Configure columns
        self.tree.heading("severity", text="Severity")
        self.tree.heading("rba", text="RBA")
        self.tree.heading("module", text="Module")
        self.tree.heading("title", text="Title")
        self.tree.heading("mitre", text="MITRE")
        self.tree.heading("time", text="Time")
        self.tree.heading("source", text="Source")
        self.tree.heading("acked", text="Ack")
        self.tree.heading("suppressed", text="Supp")
        self.tree.heading("incident", text="Incident")

        self.tree.column("severity", width=70, minwidth=50)
        self.tree.column("rba", width=50, minwidth=40)
        self.tree.column("module", width=100, minwidth=80)
        self.tree.column("title", width=180, minwidth=150)
        self.tree.column("mitre", width=80, minwidth=60)
        self.tree.column("time", width=60, minwidth=40)
        self.tree.column("source", width=70, minwidth=50)
        self.tree.column("acked", width=40, minwidth=30)
        self.tree.column("suppressed", width=40, minwidth=30)
        self.tree.column("incident", width=60, minwidth=40)

        # Configure severity tags for row coloring
        self.tree.tag_configure("critical", background="#4a1a1a")
        self.tree.tag_configure("high", background="#4a2a2a")
        self.tree.tag_configure("medium", background="#4a3a1a")
        self.tree.tag_configure("low", background="#1a2a4a")
        self.tree.tag_configure("info", background="#2a2a2a")
        
        # RBA-based highlighting
        self.tree.tag_configure("rba_high", background="#5a1a1a")  # RBA >= 80
        self.tree.tag_configure("rba_medium", background="#5a2a1a")  # RBA 50-79
        # Suppressed alerts styling
        self.tree.tag_configure("suppressed", foreground="#666666")

        self.tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        
        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Acknowledge", command=self._on_ack)
        self.context_menu.add_command(label="Unacknowledge", command=self._on_unack)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Suppress Similar...", command=self._on_suppress_similar)
        self.context_menu.add_command(label="View Incident", command=self._on_view_incident)
        
        self.tree.bind("<Button-3>", self._on_right_click)  # Right-click on Windows
        self.tree.bind("<Button-2>", self._on_right_click)  # Right-click on macOS/Linux
        
        # Callbacks for actions
        self.on_ack: Callable[[str], None] | None = None
        self.on_suppress: Callable[[str, dict], None] | None = None
        self.on_view_incident: Callable[[str], None] | None = None

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
                "rba": values[1] if len(values) > 1 else "",
                "module": values[2] if len(values) > 2 else "",
                "title": values[3] if len(values) > 3 else "",
                "mitre": values[4] if len(values) > 4 else "",
                "time": values[5] if len(values) > 5 else "",
                "source": values[6] if len(values) > 6 else "",
                "acked": values[7] if len(values) > 7 else "",
                "suppressed": values[8] if len(values) > 8 else "",
                "incident": values[9] if len(values) > 9 else "",
            }
            # Include the Finding/AlertEvent object if available for drill-down
            if 0 <= idx < len(self.findings_cache):
                data["finding"] = self.findings_cache[idx]
            # Try to get AlertEvent by ID from item tags or stored ID
            item_tags = item.get("tags", [])
            if item_tags:
                # Store alert_id in tags if available
                pass
            self.on_select(data)

    def append_finding(
        self,
        finding: Finding | Any,  # Can be Finding or AlertEvent
        module_name: str,
        timestamp: str = "Now",
        source: str = "engine",
        alert_event: Any | None = None,  # Optional AlertEvent
    ) -> None:
        """
        Append a single finding to the alerts table (streaming mode).

        Args:
            finding: The Finding object to append.
            module_name: Name of the module that produced the finding.
            timestamp: Display timestamp (default: "Now").
            source: Source of the finding ("engine", "metrics", "logs", etc.).
        """
        severity = finding.severity.lower()
        tag = severity if severity in SEVERITY_COLORS else "info"
        
        # RBA-based highlighting
        rba_score = getattr(finding, "rba_score", None) or 0
        if rba_score >= 80:
            tag = "rba_high"
        elif rba_score >= 50:
            tag = "rba_medium" if tag == "info" else tag
        
        # Format RBA score
        rba_display = str(rba_score) if rba_score is not None and rba_score > 0 else "-"
        
        # Format MITRE IDs (truncate if long)
        mitre_ids = getattr(finding, "mitre_ids", None) or []
        mitre_display = ",".join(mitre_ids[:3]) if mitre_ids else "-"
        if len(mitre_ids) > 3:
            mitre_display += "…"
        
        # Get ack/suppressed/incident from AlertEvent if available
        acked = getattr(alert_event, "acked", False) if alert_event else False
        suppressed = getattr(alert_event, "suppressed", False) if alert_event else False
        incident_id = getattr(alert_event, "incident_id", None) if alert_event else None
        alert_id = getattr(alert_event, "id", None) if alert_event else None
        
        # Format incident display (short ID)
        incident_display = incident_id[:8] + "..." if incident_id else "-"
        
        # Apply suppressed styling
        if suppressed:
            tag = "suppressed"
        
        # Cache the finding/event for drill-down
        self.findings_cache.append(finding)
        if alert_event and alert_id:
            self.alert_events_cache[alert_id] = alert_event
        
        # Insert at the top for newest-first ordering
        item_id = self.tree.insert(
            "",
            0,  # Insert at top
            values=(
                finding.severity.capitalize(),
                rba_display,
                module_name,
                finding.title,
                mitre_display,
                timestamp,
                source,
                "Y" if acked else "N",
                "Y" if suppressed else "N",
                incident_display,
            ),
            tags=(tag,),
        )
        
        # Store alert_id in item for context menu
        if alert_id:
            self.tree.set(item_id, "alert_id", alert_id)
        
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
        self.alert_events_cache.clear()
    
    def _on_right_click(self, event: tk.Event) -> None:
        """Handle right-click to show context menu."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()
    
    def _on_ack(self) -> None:
        """Handle acknowledge action."""
        selection = self.tree.selection()
        if selection and self.on_ack:
            item = self.tree.item(selection[0])
            alert_id = self.tree.set(selection[0], "alert_id")
            if alert_id:
                self.on_ack(alert_id)
    
    def _on_unack(self) -> None:
        """Handle unacknowledge action."""
        selection = self.tree.selection()
        if selection and self.on_ack:
            item = self.tree.item(selection[0])
            alert_id = self.tree.set(selection[0], "alert_id")
            if alert_id:
                self.on_ack(alert_id)  # Toggle - same callback
    
    def _on_suppress_similar(self) -> None:
        """Handle suppress similar action."""
        selection = self.tree.selection()
        if selection and self.on_suppress:
            item = self.tree.item(selection[0])
            values = item.get("values", [])
            alert_id = self.tree.set(selection[0], "alert_id")
            if alert_id and values:
                # Extract module and title for suppression rule
                module = values[2] if len(values) > 2 else ""
                title = values[3] if len(values) > 3 else ""
                self.on_suppress(alert_id, {"module": module, "title": title})
    
    def _on_view_incident(self) -> None:
        """Handle view incident action."""
        selection = self.tree.selection()
        if selection and self.on_view_incident:
            item = self.tree.item(selection[0])
            values = item.get("values", [])
            incident_id = values[9] if len(values) > 9 else None
            if incident_id and incident_id != "-":
                # Extract full incident ID from alert_event if available
                alert_id = self.tree.set(selection[0], "alert_id")
                if alert_id and alert_id in self.alert_events_cache:
                    event = self.alert_events_cache[alert_id]
                    if event.incident_id:
                        self.on_view_incident(event.incident_id)
    
    def update_alert_ack(self, alert_id: str, acked: bool) -> None:
        """Update ack status for an alert in the table."""
        for item in self.tree.get_children():
            if self.tree.set(item, "alert_id") == alert_id:
                values = list(self.tree.item(item)["values"])
                if len(values) > 7:
                    values[7] = "Y" if acked else "N"
                    self.tree.item(item, values=values)
                break
    
    def update_alert_suppressed(self, alert_id: str, suppressed: bool) -> None:
        """Update suppressed status for an alert in the table."""
        for item in self.tree.get_children():
            if self.tree.set(item, "alert_id") == alert_id:
                values = list(self.tree.item(item)["values"])
                if len(values) > 8:
                    values[8] = "Y" if suppressed else "N"
                    tags = list(self.tree.item(item)["tags"])
                    if suppressed and "suppressed" not in tags:
                        tags.append("suppressed")
                    elif not suppressed and "suppressed" in tags:
                        tags.remove("suppressed")
                    self.tree.item(item, values=values, tags=tags)
                break
