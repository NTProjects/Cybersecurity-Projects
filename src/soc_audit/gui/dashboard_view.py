"""SOC Dashboard view for the SOC Audit GUI.

This module provides a Splunk ES-style dashboard layout serving as the
default landing view for SOC analysts. It displays live system metrics,
alerts, timeline, top entities, and details in an organized layout.

The dashboard supports:
- Periodic refresh of live metrics using Tkinter's after() mechanism
- Streaming of findings with simulated delays for SOC-style presentation
- Live aggregation of entities (IPs, users, ports) from findings
"""
from __future__ import annotations

import queue
import tkinter as tk
from dataclasses import replace
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

from soc_audit.core.collectors import CollectorManager, TelemetryEvent
from soc_audit.core.incidents import IncidentEngine
from soc_audit.core.mitre import load_mitre_mapping, map_finding_to_mitre
from soc_audit.core.models import AlertEvent, Incident, normalize_event_from_finding, normalize_event_from_telemetry
from soc_audit.core.rba import compute_rba_score
from soc_audit.core.storage import JSONStorage, SQLiteStorage, Storage
from soc_audit.core.suppression import event_is_suppressed, load_suppressions
from soc_audit.gui.backend.client import BackendClient
from soc_audit.gui.metrics import get_system_metrics
from soc_audit.gui.panels import (
    AlertsPanel,
    DetailsPanel,
    LiveMetricsPanel,
    TimelinePanel,
    TopEntitiesPanel,
)

if TYPE_CHECKING:
    from soc_audit.core.engine import EngineResult
    from soc_audit.core.interfaces import Finding


class DashboardView(ttk.Frame):
    """
    SOC Dashboard view with Splunk ES-style layout and live streaming.

    Layout structure:
    - Top Row: LiveMetricsPanel (left) | AlertsPanel (right)
    - Middle: TimelinePanel (full width)
    - Bottom Row: TopEntitiesPanel (left) | DetailsPanel (right)

    The dashboard supports:
    - Periodic refresh of system metrics
    - Streaming findings one-by-one with configurable delays
    - Live entity aggregation from streamed findings

    Attributes:
        metrics_panel: Panel showing live system metrics.
        alerts_panel: Panel showing security alerts.
        timeline_panel: Panel showing activity timeline.
        entities_panel: Panel showing top entities.
        details_panel: Panel showing selected item details.
        refresh_ms: Refresh interval in milliseconds.
        on_status: Optional callback for status messages.
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_status: Callable[[str], None] | None = None,
        refresh_ms: int = 1000,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize the dashboard view.

        Args:
            parent: Parent widget.
            on_status: Optional callback for status bar updates.
            refresh_ms: Metrics refresh interval in milliseconds (default: 1000).
            config: Optional configuration dict for collectors/MITRE/RBA.
        """
        super().__init__(parent)
        self.on_status = on_status
        self.refresh_ms = refresh_ms
        self.config = config or {}
        self._after_id: str | None = None
        self._stream_after_id: str | None = None
        self._collector_after_id: str | None = None
        self._last_error: str | None = None
        self._streaming: bool = False
        self._stream_queue: list[tuple[Any, str]] = []  # (finding, module_name)
        self._stream_delay_ms: int = 300
        
        # Collectors setup
        self._collector_queue: queue.Queue[TelemetryEvent] = queue.Queue()
        self._collector_manager: CollectorManager | None = None
        self._mitre_mappings = None
        self._rba_weights = self.config.get("rba", {}).get("severity_weights")
        
        # Load MITRE mappings
        try:
            mitre_config = self.config.get("mitre", {})
            mapping_file = mitre_config.get("mapping_file", "rules/mitre-mapping.yaml")
            self._mitre_mappings = load_mitre_mapping(mapping_file)
        except Exception:
            self._mitre_mappings = []
        
        # Phase 5.5: Storage, incidents, suppression
        self._storage: Storage | None = None
        self._incident_engine: IncidentEngine | None = None
        self._suppression_rules: list[Any] = []
        self._show_suppressed = False  # Toggle for showing suppressed alerts
        
        # Initialize persistence if enabled
        persistence_config = self.config.get("persistence", {})
        if persistence_config.get("enabled", True):
            try:
                backend = persistence_config.get("backend", "sqlite")
                if backend == "sqlite":
                    db_path = persistence_config.get("sqlite_path", "data/soc_audit.db")
                    self._storage = SQLiteStorage(db_path)
                    self._storage.init()
                else:
                    json_path = persistence_config.get("json_path", "data/soc_audit_store.json")
                    self._storage = JSONStorage(json_path)
                    self._storage.init()
            except Exception:
                # Fallback to JSON if SQLite fails
                try:
                    json_path = persistence_config.get("json_path", "data/soc_audit_store.json")
                    self._storage = JSONStorage(json_path)
                    self._storage.init()
                except Exception:
                    self._storage = None
        
        # Initialize incident engine
        incidents_config = self.config.get("incidents", {})
        group_window = incidents_config.get("group_window_seconds", 300)
        self._incident_engine = IncidentEngine(group_window_seconds=group_window)
        
        # Load suppression rules
        if persistence_config.get("enabled", True):
            suppressions_path = persistence_config.get("suppressions_path", "config/suppressions.json")
            try:
                self._suppression_rules = load_suppressions(suppressions_path)
            except Exception:
                self._suppression_rules = []
        
        # Phase 6: Backend client (optional)
        self._backend_client: BackendClient | None = None
        self._backend_alert_ids: set[str] = set()  # Track backend alerts for deduplication
        
        # Phase 7.3: Host scope state
        self.current_host_id: str | None = None  # None = All Hosts
        self._hosts_list: list[dict[str, Any]] = []  # Cached host list
        backend_config = self.config.get("backend", {})
        if backend_config.get("enabled", False):
            try:
                api_url = backend_config.get("api_url", "http://127.0.0.1:8001")
                ws_url = backend_config.get("ws_url")
                api_key = backend_config.get("api_key")
                poll_interval = backend_config.get("poll_interval_seconds", 5.0)
                use_ws = backend_config.get("use_websocket", True)
                
                self._backend_client = BackendClient(
                    api_url=api_url,
                    ws_url=ws_url,
                    api_key=api_key,
                    poll_interval_seconds=poll_interval,
                    use_websocket=use_ws,
                    on_alert=self._process_backend_alert,
                    on_incident=self._process_backend_incident,
                    on_status=self._on_backend_status,
                )
            except Exception as e:
                if self.on_status:
                    self.on_status(f"Backend client init error: {e}")
                self._backend_client = None
        
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the dashboard layout."""
        # Configure grid for main frame
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=0)  # Top row
        self.rowconfigure(1, weight=0)  # Timeline
        self.rowconfigure(2, weight=1)  # Bottom row

        # === Top Row: Metrics + Alerts ===
        top_frame = ttk.Frame(self)
        top_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        top_frame.columnconfigure(0, weight=1)
        top_frame.columnconfigure(1, weight=2)
        top_frame.rowconfigure(0, weight=1)

        # Live Metrics Panel (left)
        self.metrics_panel = LiveMetricsPanel(top_frame)
        self.metrics_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Alerts Panel (right)
        self.alerts_panel = AlertsPanel(top_frame, on_select=self._on_alert_select)
        self.alerts_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        # Wire callbacks for Phase 5.5 actions
        self.alerts_panel.on_ack = self.ack_alert
        self.alerts_panel.on_suppress = self.suppress_alert
        self.alerts_panel.on_view_incident = self._on_view_incident

        # === Middle: Timeline ===
        self.timeline_panel = TimelinePanel(self)
        self.timeline_panel.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        # === Bottom Row: Entities + Details ===
        bottom_frame = ttk.Frame(self)
        bottom_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        bottom_frame.columnconfigure(0, weight=1)
        bottom_frame.columnconfigure(1, weight=1)
        bottom_frame.rowconfigure(0, weight=1)

        # Top Entities Panel (left)
        self.entities_panel = TopEntitiesPanel(bottom_frame)
        self.entities_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Details Panel (right)
        self.details_panel = DetailsPanel(bottom_frame)
        self.details_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

    def _on_alert_select(self, alert_data: dict[str, Any]) -> None:
        """
        Handle alert selection from the alerts panel.

        Args:
            alert_data: Dictionary containing selected alert information.
        """
        self.details_panel.show_alert_details(alert_data)

    def set_status(self, message: str) -> None:
        """
        Update the status bar via callback.

        Args:
            message: Status message to display.
        """
        if self.on_status:
            self.on_status(message)

    # ==================== Metrics Refresh ====================

    def start(self) -> None:
        """Start periodic metrics refresh, collectors, and backend client."""
        if self._after_id is None:
            self._tick()
        
        # Start collectors if enabled
        collectors_config = self.config.get("collectors", {})
        if collectors_config.get("enabled", True):
            self._start_collectors(collectors_config)
        
        # Start collector event polling
        if self._collector_after_id is None:
            self._poll_collector_events()
        
        # Start backend client if enabled
        if self._backend_client:
            try:
                self._backend_client.start()
                if self.on_status:
                    self.on_status("Backend client started")
            except Exception as e:
                if self.on_status:
                    self.on_status(f"Backend start error: {e}")

    def stop(self) -> None:
        """Stop periodic metrics refresh, streaming, collectors, and backend client."""
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        if self._collector_after_id is not None:
            self.after_cancel(self._collector_after_id)
            self._collector_after_id = None
        self.stop_streaming()
        self._stop_collectors()
        
        # Stop backend client
        if self._backend_client:
            try:
                self._backend_client.stop()
            except Exception:
                pass
            self._backend_client = None

    def refresh_now(self) -> None:
        """Perform an immediate metrics refresh."""
        self._update_metrics()

    def _tick(self) -> None:
        """Internal tick function for periodic refresh."""
        self._update_metrics()
        self._after_id = self.after(self.refresh_ms, self._tick)

    def _update_metrics(self) -> None:
        """Fetch and update live metrics."""
        metrics = get_system_metrics()
        self.metrics_panel.update_metrics(metrics)

        # Only update status bar if error state changed (avoid spam)
        error = metrics.get("error")
        if error != self._last_error:
            self._last_error = error
            if error:
                self.set_status(f"Metrics: {error}")
            elif not self._streaming:
                self.set_status("Dashboard - Live metrics active")

    # ==================== Finding Streaming ====================

    def stream_engine_result(
        self,
        result: EngineResult,
        delay_ms: int = 300,
    ) -> None:
        """
        Stream all findings from an EngineResult with visual delays.

        This creates a SOC-style "live" experience where alerts appear
        one at a time with a configurable delay between each.

        Args:
            result: The EngineResult containing module results and findings.
            delay_ms: Delay in milliseconds between each finding (default: 300).
        """
        # Stop any existing stream
        self.stop_streaming()

        # Clear panels for fresh display
        self.clear_findings()

        # Build the queue of findings with MITRE+RBA enrichment
        self._stream_queue = []
        for module_result in result.module_results:
            for finding in module_result.findings:
                # Enrich finding with MITRE and RBA
                enriched_finding = self._enrich_finding(finding, module_result.module_name)
                self._stream_queue.append((enriched_finding, module_result.module_name))

        if not self._stream_queue:
            self.set_status("Scan complete - No findings")
            return

        # Start streaming
        self._stream_delay_ms = delay_ms
        self._streaming = True
        self.set_status(f"Streaming {len(self._stream_queue)} findings...")
        self._stream_next()

    def _stream_next(self) -> None:
        """Process the next finding in the stream queue."""
        if not self._stream_queue:
            self._streaming = False
            self.set_status("Dashboard - Stream complete")
            return

        # Get next finding
        finding, module_name = self._stream_queue.pop(0)

        # Update all panels
        self._process_finding(finding, module_name)

        # Update status with remaining count
        remaining = len(self._stream_queue)
        if remaining > 0:
            self.set_status(f"Streaming alerts... ({remaining} remaining)")

        # Schedule next
        self._stream_after_id = self.after(self._stream_delay_ms, self._stream_next)

    def _process_finding(self, finding: Finding, module_name: str) -> None:
        """
        Process a single finding - normalize, suppress, group, persist, display.

        Args:
            finding: The Finding to process.
            module_name: Name of the source module.
        """
        # Phase 5.5: Normalize to AlertEvent
        alert_event = normalize_event_from_finding(finding, module_name, source="engine")
        
        # Apply suppression rules
        if self._suppression_rules:
            suppressed = event_is_suppressed(alert_event, self._suppression_rules)
            alert_event.suppressed = suppressed
        
        # Incident grouping
        if self._incident_engine:
            alert_event, incident = self._incident_engine.ingest_event(alert_event)
            if incident and self._storage:
                self._storage.save_incident(incident)
        
        # Persist alert
        if self._storage:
            self._storage.save_alert(alert_event)
            # Append to timeline
            self._storage.append_timeline(
                alert_event.timestamp,
                f"Alert: {alert_event.title}",
                alert_event.severity,
                alert_event.source,
                alert_event.module,
                alert_id=alert_event.id,
                incident_id=alert_event.incident_id,
            )
        
        # Display if not suppressed or if show_suppressed is True
        if not alert_event.suppressed or self._show_suppressed:
            timestamp = alert_event.timestamp
            time_display = self._format_time_ago(timestamp)
            
            # Update Alerts panel (Notable Events)
            self.alerts_panel.append_finding(
                finding, module_name, time_display, source="engine", alert_event=alert_event
            )
            
            # Update Timeline
            self.timeline_panel.append_event(finding, module_name, timestamp)
            
            # Update Entity aggregation
            self.entities_panel.update_from_finding(finding)

    def _format_time_ago(self, timestamp: datetime) -> str:
        """
        Format a timestamp for display (e.g., 'Now', '1m ago').

        Args:
            timestamp: The datetime to format.

        Returns:
            Human-readable time string.
        """
        # For streaming, always show "Now" since events are being processed live
        return "Now"

    def stop_streaming(self) -> None:
        """Stop any ongoing finding stream."""
        if self._stream_after_id is not None:
            self.after_cancel(self._stream_after_id)
            self._stream_after_id = None
        self._streaming = False
        self._stream_queue.clear()

    def is_streaming(self) -> bool:
        """Check if streaming is in progress."""
        return self._streaming

    # ==================== Clear / Placeholder ====================

    def clear_findings(self) -> None:
        """Clear findings from alerts, timeline, and entities panels."""
        self.alerts_panel.clear()
        self.timeline_panel.clear()
        self.entities_panel.clear()
        self.details_panel.clear()

    def set_placeholder_data(self) -> None:
        """Set placeholder data in all panels."""
        self.metrics_panel.set_placeholder_data()
        self.alerts_panel.set_placeholder_data()
        self.timeline_panel.set_placeholder_data()
        self.entities_panel.set_placeholder_data()
        self.details_panel.set_placeholder_text()

    def clear(self) -> None:
        """Clear all panels and stop streaming."""
        self.stop_streaming()
        self.metrics_panel.clear()
        self.alerts_panel.clear()
        self.timeline_panel.clear()
        self.entities_panel.clear()
        self.details_panel.clear()

    # ==================== MITRE + RBA Enrichment ====================

    def _enrich_finding(self, finding: Finding, module_name: str) -> Finding:
        """
        Enrich a finding with MITRE ATT&CK mappings and RBA score.

        Args:
            finding: The finding to enrich.
            module_name: Name of the module that produced the finding.

        Returns:
            Enriched Finding with MITRE and RBA fields set.
        """
        # Create a finding-like object for MITRE mapping
        class FindingForMapping:
            def __init__(self, finding: Finding, module_name: str):
                self.title = finding.title
                self.module_name = module_name

        mapping_obj = FindingForMapping(finding, module_name)
        tactics, techniques, ids = map_finding_to_mitre(mapping_obj, self._mitre_mappings)

        # Compute RBA score
        rba_score, rba_breakdown = compute_rba_score(
            finding.severity,
            finding.risk_score,
            ids if ids else None,
            severity_weights=self._rba_weights,
        )

        # Create enriched finding (since Finding is frozen, use replace)
        timestamp_iso = datetime.utcnow().isoformat()
        return replace(
            finding,
            mitre_tactics=tactics if tactics else None,
            mitre_techniques=techniques if techniques else None,
            mitre_ids=ids if ids else None,
            rba_score=rba_score,
            timestamp=timestamp_iso,
        )

    # ==================== Collectors ====================

    def _start_collectors(self, collectors_config: dict[str, Any]) -> None:
        """Start the collector manager."""
        if self._collector_manager is not None:
            return

        def metrics_callback(metrics: dict[str, Any]) -> None:
            """Callback to update metrics panel directly."""
            try:
                self.metrics_panel.update_metrics(metrics)
            except Exception:
                pass

        try:
            self._collector_manager = CollectorManager(
                self._collector_queue,
                collectors_config,
                metrics_callback=metrics_callback,
            )
            self._collector_manager.start()
        except Exception:
            pass  # Non-fatal

    def _stop_collectors(self) -> None:
        """Stop the collector manager."""
        if self._collector_manager:
            try:
                self._collector_manager.stop()
            except Exception:
                pass
            self._collector_manager = None

    def _poll_collector_events(self) -> None:
        """Poll collector event queue and process events (Tkinter-safe)."""
        # Drain queue (non-blocking)
        processed = 0
        while processed < 10:  # Limit per tick
            try:
                event = self._collector_queue.get_nowait()
                self._process_collector_event(event)
                processed += 1
            except queue.Empty:
                break

        # Schedule next poll
        self._collector_after_id = self.after(500, self._poll_collector_events)  # Poll every 500ms

    def _process_collector_event(self, event: TelemetryEvent) -> None:
        """Process a collector telemetry event."""
        # Phase 5.5: Normalize to AlertEvent
        alert_event = normalize_event_from_telemetry(event)
        
        # Apply suppression rules
        if self._suppression_rules:
            suppressed = event_is_suppressed(alert_event, self._suppression_rules)
            alert_event.suppressed = suppressed
        
        # Incident grouping
        if self._incident_engine:
            alert_event, incident = self._incident_engine.ingest_event(alert_event)
            if incident and self._storage:
                self._storage.save_incident(incident)
        
        # Persist alert
        if self._storage:
            self._storage.save_alert(alert_event)
            # Append to timeline
            self._storage.append_timeline(
                alert_event.timestamp,
                f"Alert: {alert_event.title}",
                alert_event.severity,
                alert_event.source,
                alert_event.module,
                alert_id=alert_event.id,
                incident_id=alert_event.incident_id,
            )
        
        # Convert to Finding for display
        from soc_audit.core.interfaces import Finding
        
        finding = Finding(
            title=event.title,
            description=f"Telemetry event from {event.source}",
            severity=event.severity,
            evidence=event.evidence,
            mitre_tactics=event.mitre_tactics,
            mitre_techniques=event.mitre_techniques,
            mitre_ids=event.mitre_ids,
            rba_score=event.rba_score,
            timestamp=event.timestamp.isoformat(),
        )
        
        # Display if not suppressed or if show_suppressed is True
        if not alert_event.suppressed or self._show_suppressed:
            # Add to alerts panel
            time_display = event.timestamp.strftime("%H:%M:%S")
            self.alerts_panel.append_finding(finding, event.module, time_display, source=event.source, alert_event=alert_event)
            
            # Add to timeline
            self.timeline_panel.append_event(finding, event.module, event.timestamp)
            
            # Update entities if applicable
            if event.source == "logs" and event.evidence:
                # Extract IP and username from log events
                source_ip = event.evidence.get("source_ip")
                username = event.evidence.get("username")
                if source_ip:
                    self.entities_panel.increment_entity("IPs", source_ip)
                if username:
                    self.entities_panel.increment_entity("Users", username)
    
    # ==================== Phase 6: Backend Event Processing ====================
    
    def _process_backend_alert(self, alert_event: AlertEvent) -> None:
        """
        Process an alert event received from the backend.
        
        Args:
            alert_event: AlertEvent from backend API.
        """
        # Deduplicate by alert_id
        if alert_event.id in self._backend_alert_ids:
            return
        self._backend_alert_ids.add(alert_event.id)
        
        # Phase 7.3: Apply host scope filter
        if self.current_host_id is not None:
            alert_host_id = getattr(alert_event, "host_id", None)
            if alert_host_id != self.current_host_id:
                return  # Filter out alerts from other hosts
        
        # Ensure source is "backend" for display
        alert_event.source = "backend"
        
        # Convert to Finding for display
        from soc_audit.core.interfaces import Finding
        
        finding = Finding(
            title=alert_event.title,
            description=f"Alert from backend: {alert_event.module}",
            severity=alert_event.severity,
            evidence=alert_event.evidence,
            mitre_ids=alert_event.mitre_ids,
            rba_score=alert_event.rba_score,
            timestamp=alert_event.timestamp.isoformat(),
        )
        
        # Display if not suppressed or if show_suppressed is True
        if not alert_event.suppressed or self._show_suppressed:
            time_display = self._format_time_ago(alert_event.timestamp)
            
            # Update Alerts panel
            self.alerts_panel.append_finding(
                finding, alert_event.module, time_display, source="backend", alert_event=alert_event
            )
            
            # Phase 7.3: Update Timeline with [host_id] prefix
            host_id = getattr(alert_event, "host_id", None)
            if host_id:
                # Prefix timeline entry with [host_id]
                finding_with_prefix = Finding(
                    title=f"[{host_id}] {alert_event.title}",
                    description=finding.description,
                    severity=finding.severity,
                    evidence=finding.evidence,
                    mitre_ids=finding.mitre_ids,
                    rba_score=finding.rba_score,
                    timestamp=finding.timestamp,
                )
                self.timeline_panel.append_event(finding_with_prefix, alert_event.module, alert_event.timestamp)
            else:
                self.timeline_panel.append_event(finding, alert_event.module, alert_event.timestamp)
            
            # Update Entity aggregation
            self.entities_panel.update_from_finding(finding)
    
    def _process_backend_incident(self, incident: Incident) -> None:
        """
        Process an incident received from the backend.
        
        Args:
            incident: Incident from backend API.
        """
        # For MVP, incidents are displayed via alerts panel
        # Future: could add incidents panel or update existing incidents display
        pass
    
    def _on_backend_status(self, status: str, message: str) -> None:
        """
        Handle backend status updates.
        
        Args:
            status: Status string ("connected", "polling", "disconnected", "error").
            message: Status message.
        """
        if self.on_status:
            self.on_status(f"Backend: {message}")
        
        # Phase 6.2: Include role in timeline message if available
        role_info = ""
        if self._backend_client and self._backend_client.backend_role:
            role_info = f" (Role: {self._backend_client.backend_role.capitalize()})"
        
        # Add to timeline (use append_event with a simple Finding-like object)
        from soc_audit.core.interfaces import Finding
        finding = Finding(
            title=f"Backend {status}{role_info}",
            description=message,
            severity="info" if status in ("connected", "polling") else "warning",
        )
        self.timeline_panel.append_event(finding, "backend", datetime.utcnow())
    
    # ==================== Phase 7.3: Host Scoping ====================
    
    def _on_host_scope_change(self, host_id: str | None) -> None:
        """
        Handle host scope change.
        
        Args:
            host_id: Selected host_id (None = All Hosts).
        """
        self.current_host_id = host_id
        self._apply_host_filter()
        
        # Update status
        if self.on_status:
            scope_name = f"Host: {host_id}" if host_id else "All Hosts"
            self.on_status(f"Host scope: {scope_name}")
    
    def _apply_host_filter(self) -> None:
        """Apply host filter to alerts panel."""
        if self.alerts_panel:
            # Update alerts panel filter
            self.alerts_panel.set_host_filter(self.current_host_id)
            
            # Refresh alerts panel to reapply filters
            # Note: The alerts panel already has filtering logic from Phase 6.1
            # We just need to update the host_id filter
    
    def get_hosts(self) -> list[dict[str, Any]]:
        """
        Get list of hosts from backend (with caching).
        
        Returns:
            List of host dicts.
        """
        if not self._backend_client:
            return []
        
        try:
            hosts = self._backend_client.get_hosts()
            self._hosts_list = hosts
            return hosts
        except Exception:
            return self._hosts_list  # Return cached list on error
    
    # ==================== Phase 5.5: SOC Workflow Actions ====================
    
    def ack_alert(self, alert_id: str) -> None:
        """Acknowledge an alert."""
        # Check if alert is from backend
        is_backend_alert = alert_id in self._backend_alert_ids
        
        if is_backend_alert and self._backend_client:
            # Update via backend API
            try:
                # For MVP, toggle (assume current state is opposite)
                self._backend_client.ack_alert(alert_id, True)  # Acknowledge
                # Update UI
                self.alerts_panel.update_alert_ack(alert_id, True)
                if self.on_status:
                    self.on_status(f"Alert {alert_id} acknowledged via backend")
            except Exception as e:
                if self.on_status:
                    self.on_status(f"Backend ack error: {e}")
            return
        
        # Local alert handling
        if self._storage:
            # Load alert to check current state
            alerts = self._storage.load_recent_alerts(limit=1000)
            for alert in alerts:
                if alert.id == alert_id:
                    alert.acked = not alert.acked  # Toggle
                    self._storage.update_ack(alert_id, alert.acked)
                    self._storage.append_timeline(
                        datetime.utcnow(),
                        f"Alert {'acknowledged' if alert.acked else 'unacknowledged'}: {alert.title}",
                        "info",
                        "user",
                        "dashboard",
                        alert_id=alert_id,
                    )
                    # Update UI
                    self.alerts_panel.update_alert_ack(alert_id, alert.acked)
                    break
    
    def suppress_alert(self, alert_id: str, rule_data: dict[str, Any]) -> None:
        """Create suppression rule and suppress alert."""
        # Check if alert is from backend
        is_backend_alert = alert_id in self._backend_alert_ids
        
        if is_backend_alert and self._backend_client:
            # Update via backend API
            try:
                self._backend_client.suppress_alert(alert_id, True)
                # Update UI
                self.alerts_panel.update_alert_suppressed(alert_id, True)
                if self.on_status:
                    self.on_status(f"Alert {alert_id} suppressed via backend")
            except Exception as e:
                if self.on_status:
                    self.on_status(f"Backend suppress error: {e}")
            return
        
        # Local alert handling
        # This would create a suppression rule - simplified for now
        if self._storage:
            self._storage.set_suppressed(alert_id, True)
            self._storage.append_timeline(
                datetime.utcnow(),
                f"Alert suppressed: {rule_data.get('title', 'Unknown')}",
                "info",
                "user",
                "dashboard",
                alert_id=alert_id,
            )
            self.alerts_panel.update_alert_suppressed(alert_id, True)
    
    def get_storage(self) -> Storage | None:
        """Get the storage instance (for export)."""
        return self._storage
    
    def get_incident_engine(self) -> IncidentEngine | None:
        """Get the incident engine instance."""
        return self._incident_engine
    
    def toggle_show_suppressed(self, show: bool) -> None:
        """Toggle showing suppressed alerts."""
        self._show_suppressed = show
    
    def _on_view_incident(self, incident_id: str) -> None:
        """Handle view incident action (placeholder - can be extended)."""
        if self.on_status:
            self.on_status(f"Viewing incident: {incident_id[:8]}...")
