"""Alerts panel for the SOC dashboard.

This module provides a panel displaying security alerts and notable
events in a Splunk ES-style format with live streaming support.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
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
        
        # Phase 6.1: Filter state
        self._filter_source: str = "All"  # All, Local, Backend
        self._filter_severity: str = "All"  # All, Low, Medium, High, Critical
        self._filter_rba_min: int = 0
        self._filter_show_suppressed: bool = False
        self._filter_host_id: str | None = None
        
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)  # Treeview row
        
        # Phase 6.1: Filter toolbar
        filter_frame = ttk.Frame(self)
        filter_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        filter_frame.columnconfigure(0, weight=0)
        filter_frame.columnconfigure(1, weight=0)
        filter_frame.columnconfigure(2, weight=0)
        filter_frame.columnconfigure(3, weight=0)
        filter_frame.columnconfigure(4, weight=0)
        filter_frame.columnconfigure(5, weight=0)
        filter_frame.columnconfigure(6, weight=0)
        filter_frame.columnconfigure(7, weight=1)
        
        # Source filter
        ttk.Label(filter_frame, text="Source:").grid(row=0, column=0, padx=(0, 5))
        self.source_var = tk.StringVar(value="All")
        source_combo = ttk.Combobox(filter_frame, textvariable=self.source_var, values=["All", "Local", "Backend"], state="readonly", width=10)
        source_combo.grid(row=0, column=1, padx=(0, 10))
        source_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())
        
        # Severity filter
        ttk.Label(filter_frame, text="Severity:").grid(row=0, column=2, padx=(0, 5))
        self.severity_var = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.severity_var, values=["All", "Low", "Medium", "High", "Critical"], state="readonly", width=10)
        severity_combo.grid(row=0, column=3, padx=(0, 10))
        severity_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())
        
        # RBA threshold
        ttk.Label(filter_frame, text="RBA ≥").grid(row=0, column=4, padx=(0, 5))
        self.rba_var = tk.IntVar(value=0)
        rba_scale = ttk.Scale(filter_frame, from_=0, to=100, variable=self.rba_var, orient=tk.HORIZONTAL, length=100)
        rba_scale.grid(row=0, column=5, padx=(0, 5))
        self.rba_label = ttk.Label(filter_frame, text="0")
        self.rba_label.grid(row=0, column=6, padx=(0, 10))
        rba_scale.configure(command=lambda v: (self.rba_label.config(text=str(int(float(v)))), self._apply_filters()))
        
        # Show suppressed checkbox
        self.show_suppressed_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_frame, text="Show Suppressed", variable=self.show_suppressed_var, command=self._apply_filters).grid(row=0, column=7, padx=(0, 5))

        # Configure tag colors for severity highlighting
        style = ttk.Style()
        
        # Create treeview with alert_id (hidden) + RBA/MITRE/Source/Ack/Suppressed/Incident columns
        columns = ("alert_id", "severity", "rba", "module", "title", "mitre", "time", "source", "acked", "suppressed", "incident")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", selectmode="browse")

        # Configure columns
        # Hide alert_id column (internal use only)
        self.tree.column("alert_id", width=0, stretch=False)
        self.tree.heading("alert_id", text="")
        
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

        # Performance: Disable auto-resize to prevent expensive column recalculation on every update
        self.tree.column("severity", width=70, minwidth=50, stretch=False)
        self.tree.column("rba", width=50, minwidth=40, stretch=False)
        self.tree.column("module", width=100, minwidth=80, stretch=False)
        self.tree.column("title", width=180, minwidth=150, stretch=True)  # Only title can stretch
        self.tree.column("mitre", width=80, minwidth=60, stretch=False)
        self.tree.column("time", width=60, minwidth=40, stretch=False)
        self.tree.column("source", width=70, minwidth=50, stretch=False)
        self.tree.column("acked", width=40, minwidth=30, stretch=False)
        self.tree.column("suppressed", width=40, minwidth=30, stretch=False)
        self.tree.column("incident", width=60, minwidth=40, stretch=False)

        # Configure severity tags for row coloring
        self.tree.tag_configure("critical", background="#4a1a1a")
        self.tree.tag_configure("high", background="#4a2a2a")
        self.tree.tag_configure("medium", background="#4a3a1a")
        self.tree.tag_configure("low", background="#1a2a4a")
        self.tree.tag_configure("info", background="#2a2a2a")
        
        # Phase 9.1: Severity column cell colors (foreground)
        self.tree.tag_configure("severity_critical", foreground="#ff4444")  # Dark red
        self.tree.tag_configure("severity_high", foreground="#ff6b6b")  # Red
        self.tree.tag_configure("severity_medium", foreground="#ffa726")  # Amber/yellow
        self.tree.tag_configure("severity_low", foreground="#42a5f5")  # Blue/gray
        self.tree.tag_configure("severity_info", foreground="#78909c")  # Gray
        
        # RBA-based highlighting
        self.tree.tag_configure("rba_high", background="#5a1a1a")  # RBA >= 80
        self.tree.tag_configure("rba_medium", background="#5a2a1a")  # RBA 50-79
        # Suppressed alerts styling
        self.tree.tag_configure("suppressed", foreground="#666666")
        
        # Phase 8.2: Host status styling (OFFLINE hosts dimmed)
        self.tree.tag_configure("host_offline", foreground="#888888")  # Dimmed gray
        
        # Phase 9.1: SLA risk indicators
        self.tree.tag_configure("sla_warning", foreground="#ffa726")  # Amber for warning
        self.tree.tag_configure("sla_breach", foreground="#ff4444")  # Red for breach

        self.tree.grid(row=1, column=0, sticky="nsew")

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.scrollbar.grid(row=1, column=1, sticky="ns")
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

    def _on_tree_select(self, event: tk.Event | None = None) -> None:
        """Handle treeview selection."""
        # Guard against empty selection
        selection = self.tree.selection()
        if not selection:
            return

        item_id = selection[0]
        if not item_id:
            return
        
        # Guard against missing item
        if not self.tree.exists(item_id):
            return
        
        item = self.tree.item(item_id)
        values = item.get("values", [])
        
        # Guard against empty values
        if not values or len(values) == 0:
            return
        
        # Extract alert_id FIRST before any usage
        alert_id = values[0] if len(values) > 0 else None
        if not alert_id:
            # Try to get from tree.set as fallback
            alert_id = self.tree.set(item_id, "alert_id")
            if not alert_id:
                return
        
        # Get the index to retrieve the cached Finding
        children = self.tree.get_children()
        idx = children.index(item_id) if item_id in children else -1
        
        if self.on_select:
            data = {
                "alert_id": alert_id,
                "severity": values[1] if len(values) > 1 else "",
                "rba": values[2] if len(values) > 2 else "",
                "module": values[3] if len(values) > 3 else "",
                "title": values[4] if len(values) > 4 else "",
                "mitre": values[5] if len(values) > 5 else "",
                "time": values[6] if len(values) > 6 else "",
                "source": values[7] if len(values) > 7 else "",
                "acked": values[8] if len(values) > 8 else "",
                "suppressed": values[9] if len(values) > 9 else "",
                "incident": values[10] if len(values) > 10 else "",
            }
            # Include the Finding/AlertEvent object if available for drill-down
            if 0 <= idx < len(self.findings_cache):
                data["finding"] = self.findings_cache[idx]
            # Phase 9.1: Include alert_event for age/SLA calculation
            alert_event = None
            if alert_id:
                alert_event = self.alert_events_cache.get(alert_id)
            if alert_event:
                data["alert_event"] = alert_event
            
            self.on_select(data)

    def append_finding(
        self,
        finding: Finding | Any,  # Can be Finding or AlertEvent
        module_name: str,
        timestamp: str = "Now",
        source: str = "engine",
        alert_event: Any | None = None,  # Optional AlertEvent
        host_status: str | None = None,  # Phase 8.2: "ONLINE", "OFFLINE", "UNKNOWN"
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
        
        # Performance: Cache string formatting to reduce operations
        rba_display = str(rba_score) if rba_score and rba_score > 0 else "-"
        
        # Format MITRE IDs (truncate if long) - cache result
        mitre_ids = getattr(finding, "mitre_ids", None) or []
        if mitre_ids:
            mitre_display = ",".join(mitre_ids[:3])
            if len(mitre_ids) > 3:
                mitre_display += "…"
        else:
            mitre_display = "-"
        
        # Performance: Cache attribute lookups to reduce getattr calls
        if alert_event:
            acked = getattr(alert_event, "acked", False)
            suppressed = getattr(alert_event, "suppressed", False)
            incident_id = getattr(alert_event, "incident_id", None)
            alert_id = getattr(alert_event, "id", None)
        else:
            acked = False
            suppressed = False
            incident_id = None
            alert_id = None
        
        # Format incident display (short ID) - cache result
        if incident_id:
            incident_display = incident_id[:8] + "..."
        else:
            incident_display = "-"
        
        # Apply suppressed styling
        if suppressed:
            tag = "suppressed"
        
        # Phase 8.2: Apply host status styling (OFFLINE hosts dimmed)
        tags_list = [tag] if tag else []
        if host_status == "OFFLINE" and source == "backend":
            tags_list.append("host_offline")
        
        # Phase 9.1: Add severity column color tag
        severity_tag = f"severity_{severity}" if severity in ["critical", "high", "medium", "low", "info"] else "severity_info"
        tags_list.append(severity_tag)
        
        # Phase 9.1: Calculate age and SLA status
        alert_age_seconds = None
        sla_status = None
        if alert_event:
            alert_timestamp = getattr(alert_event, "timestamp", None)
            if alert_timestamp and isinstance(alert_timestamp, datetime):
                now = datetime.now(timezone.utc) if alert_timestamp.tzinfo else datetime.utcnow()
                if alert_timestamp.tzinfo:
                    now = now.replace(tzinfo=timezone.utc)
                alert_age_seconds = (now - alert_timestamp).total_seconds()
                
                # SLA thresholds (GUI-only constants)
                sla_thresholds = {
                    "critical": 15 * 60,  # 15 minutes
                    "high": 60 * 60,  # 1 hour
                    "medium": 4 * 60 * 60,  # 4 hours
                    "low": 24 * 60 * 60,  # 24 hours
                    "info": 24 * 60 * 60,  # 24 hours
                }
                
                sla_threshold = sla_thresholds.get(severity, sla_thresholds["info"])
                
                # Skip SLA if acked or suppressed
                if not acked and not suppressed:
                    if alert_age_seconds > sla_threshold:
                        sla_status = "breach"
                        tags_list.append("sla_breach")
                    elif alert_age_seconds > 0.75 * sla_threshold:
                        sla_status = "warning"
                        tags_list.append("sla_warning")
        
        # Phase 9.1: Add ⚠ prefix to title if SLA breach
        title_display = finding.title
        if sla_status == "breach" and not acked and not suppressed:
            title_display = f"⚠ {finding.title}"
        
        # Cache the finding/event for drill-down
        self.findings_cache.append(finding)
        if alert_event and alert_id:
            self.alert_events_cache[alert_id] = alert_event
        
        # Performance: Limit alerts panel to 100 items max (treeview insert at 0 is O(n)!)
        MAX_ALERTS = 100
        children = self.tree.get_children()
        if len(children) >= MAX_ALERTS:
            # Remove oldest item (last in list) to make room
            oldest_item = children[-1]
            # Get alert_id before deleting
            oldest_alert_id = self.tree.set(oldest_item, "alert_id")
            self.tree.delete(oldest_item)
            # Remove from caches to prevent memory leak
            if len(self.findings_cache) > 0:
                self.findings_cache.pop()
            if oldest_alert_id and oldest_alert_id in self.alert_events_cache:
                del self.alert_events_cache[oldest_alert_id]
        
        # Insert at the top for newest-first ordering
        # Note: alert_id is first column (hidden), then visible columns
        item_id = self.tree.insert(
            "",
            0,  # Insert at top
            values=(
                alert_id or "",  # alert_id column (hidden)
                finding.severity.capitalize(),
                rba_display,
                module_name,
                title_display,
                mitre_display,
                timestamp,
                source,
                "Y" if acked else "N",
                "Y" if suppressed else "N",
                incident_display,
            ),
            tags=tuple(tags_list),
        )
        
        # Ensure alert_id is set (in case it was None in values)
        if alert_id:
            self.tree.set(item_id, "alert_id", alert_id)
        
        # Performance: Only auto-scroll if user hasn't manually scrolled
        # (Check if selection is at top - if so, likely user wants to see newest)
        # Disabled auto-scroll to reduce lag - user can manually scroll to top if needed
        # children = self.tree.get_children()
        # if children:
        #     self.tree.see(children[0])

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
    
    def _apply_filters(self) -> None:
        """Apply filters to the alerts table (client-side filtering)."""
        # Update filter state
        self._filter_source = self.source_var.get()
        self._filter_severity = self.severity_var.get()
        self._filter_rba_min = self.rba_var.get()
        self._filter_show_suppressed = self.show_suppressed_var.get()
        
        # Show/hide items based on filters
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if len(values) < 11:
                continue
            
            # Extract values
            severity = values[1] if len(values) > 1 else ""
            rba_str = values[2] if len(values) > 2 else "0"
            source = values[7] if len(values) > 7 else ""
            suppressed_str = values[9] if len(values) > 9 else "N"
            
            # Parse RBA
            try:
                rba = int(rba_str) if rba_str and rba_str != "-" else 0
            except (ValueError, TypeError):
                rba = 0
            
            # Apply filters
            show = True
            
            # Source filter
            if self._filter_source != "All":
                if self._filter_source == "Local" and source == "backend":
                    show = False
                elif self._filter_source == "Backend" and source != "backend":
                    show = False
            
            # Severity filter
            if show and self._filter_severity != "All":
                severity_map = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical", "info": "Low"}
                alert_severity = severity_map.get(severity.lower(), "Low")
                if alert_severity != self._filter_severity:
                    show = False
            
            # RBA filter
            if show and rba < self._filter_rba_min:
                show = False
            
            # Suppressed filter
            if show and not self._filter_show_suppressed and suppressed_str == "Y":
                show = False
            
            # Phase 7.3: Host filter
            if show and self._filter_host_id is not None:
                # Get host_id from alert_event cache
                alert_id = self.tree.set(item, "alert_id")
                if alert_id:
                    alert_event = self.alert_events_cache.get(alert_id)
                    if alert_event:
                        alert_host_id = getattr(alert_event, "host_id", None)
                        if alert_host_id != self._filter_host_id:
                            show = False
            
            # Show/hide item using detach/reattach
            if show:
                # Reattach if detached
                if not self.tree.exists(item):
                    # Item was detached, need to reattach (simplified: just skip for now)
                    pass
            else:
                # Detach to hide
                if self.tree.exists(item):
                    self.tree.detach(item)
    
    def set_host_filter(self, host_id: str | None) -> None:
        """Set host filter (called from dashboard)."""
        self._filter_host_id = host_id
        self._apply_filters()
    
    def should_show_alert(self, source: str, severity: str, rba: int, suppressed: bool, host_id: str | None = None) -> bool:
        """Check if alert should be shown based on current filters (for new alerts)."""
        # Source filter
        if self._filter_source != "All":
            if self._filter_source == "Local" and source == "backend":
                return False
            elif self._filter_source == "Backend" and source != "backend":
                return False
        
        # Severity filter
        if self._filter_severity != "All":
            severity_map = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical", "info": "Low"}
            alert_severity = severity_map.get(severity.lower(), "Low")
            if alert_severity != self._filter_severity:
                return False
        
        # RBA filter
        if rba < self._filter_rba_min:
            return False
        
        # Suppressed filter
        if not self._filter_show_suppressed and suppressed:
            return False
        
        # Phase 7.3: Host filter
        if self._filter_host_id is not None:
            if host_id != self._filter_host_id:
                return False
        
        return True
    
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
        if not selection or not self.on_ack:
            return
        
        item_id = selection[0]
        if not item_id or not self.tree.exists(item_id):
            return
        
        alert_id = self.tree.set(item_id, "alert_id")
        if alert_id:
            try:
                self.on_ack(alert_id)
            except Exception as e:
                print(f"[GUI] Error in acknowledge callback: {e}")
    
    def _on_unack(self) -> None:
        """Handle unacknowledge action."""
        selection = self.tree.selection()
        if not selection or not self.on_ack:
            return
        
        item_id = selection[0]
        if not item_id or not self.tree.exists(item_id):
            return
        
        alert_id = self.tree.set(item_id, "alert_id")
        if alert_id:
            try:
                self.on_ack(alert_id)  # Toggle - same callback
            except Exception as e:
                print(f"[GUI] Error in unacknowledge callback: {e}")
    
    def _on_suppress_similar(self) -> None:
        """Handle suppress similar action."""
        selection = self.tree.selection()
        if not selection or not self.on_suppress:
            return
        
        item_id = selection[0]
        if not item_id or not self.tree.exists(item_id):
            return
        
        item = self.tree.item(item_id)
        values = item.get("values", [])
        if not values:
            return
        
        alert_id = self.tree.set(item_id, "alert_id")
        if alert_id and values:
            try:
                # Extract module and title for suppression rule (alert_id is index 0)
                module = values[3] if len(values) > 3 else ""  # module is index 3
                title = values[4] if len(values) > 4 else ""  # title is index 4
                self.on_suppress(alert_id, {"module": module, "title": title})
            except Exception as e:
                print(f"[GUI] Error in suppress callback: {e}")
    
    def _on_view_incident(self) -> None:
        """Handle view incident action."""
        selection = self.tree.selection()
        if not selection or not self.on_view_incident:
            return
        
        item_id = selection[0]
        if not item_id or not self.tree.exists(item_id):
            return
        
        item = self.tree.item(item_id)
        values = item.get("values", [])
        if not values:
            return
        
        incident_id = values[10] if len(values) > 10 else None  # incident is index 10
        if incident_id and incident_id != "-":
            try:
                # Extract full incident ID from alert_event if available
                alert_id = self.tree.set(item_id, "alert_id")
                if alert_id and alert_id in self.alert_events_cache:
                    event = self.alert_events_cache[alert_id]
                    if event and hasattr(event, "incident_id") and event.incident_id:
                        self.on_view_incident(event.incident_id)
                elif incident_id:
                    # Fallback: use the displayed incident ID
                    self.on_view_incident(incident_id)
            except Exception as e:
                print(f"[GUI] Error in view incident callback: {e}")
    
    def update_alert_ack(self, alert_id: str, acked: bool) -> None:
        """Update ack status for an alert in the table."""
        for item in self.tree.get_children():
            if self.tree.set(item, "alert_id") == alert_id:
                values = list(self.tree.item(item)["values"])
                if len(values) > 8:  # alert_id is index 0, acked is index 8
                    values[8] = "Y" if acked else "N"
                    self.tree.item(item, values=values)
                break
    
    def update_alert_suppressed(self, alert_id: str, suppressed: bool) -> None:
        """Update suppressed status for an alert in the table."""
        for item in self.tree.get_children():
            if self.tree.set(item, "alert_id") == alert_id:
                values = list(self.tree.item(item)["values"])
                if len(values) > 9:  # alert_id is index 0, suppressed is index 9
                    values[9] = "Y" if suppressed else "N"
                    tags = list(self.tree.item(item)["tags"])
                    if suppressed and "suppressed" not in tags:
                        tags.append("suppressed")
                    elif not suppressed and "suppressed" in tags:
                        tags.remove("suppressed")
                    self.tree.item(item, values=values, tags=tags)
                break
