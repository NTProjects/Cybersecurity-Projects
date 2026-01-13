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

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING, Any, Callable

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
    ) -> None:
        """
        Initialize the dashboard view.

        Args:
            parent: Parent widget.
            on_status: Optional callback for status bar updates.
            refresh_ms: Metrics refresh interval in milliseconds (default: 1000).
        """
        super().__init__(parent)
        self.on_status = on_status
        self.refresh_ms = refresh_ms
        self._after_id: str | None = None
        self._stream_after_id: str | None = None
        self._last_error: str | None = None
        self._streaming: bool = False
        self._stream_queue: list[tuple[Any, str]] = []  # (finding, module_name)
        self._stream_delay_ms: int = 300
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
        """Start periodic metrics refresh."""
        if self._after_id is None:
            self._tick()

    def stop(self) -> None:
        """Stop periodic metrics refresh and streaming."""
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None
        self.stop_streaming()

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

        # Build the queue of findings
        self._stream_queue = []
        for module_result in result.module_results:
            for finding in module_result.findings:
                self._stream_queue.append((finding, module_result.module_name))

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
        Process a single finding - update all panels.

        Args:
            finding: The Finding to process.
            module_name: Name of the source module.
        """
        timestamp = datetime.now()

        # Format time display
        time_display = self._format_time_ago(timestamp)

        # Update Alerts panel (Notable Events)
        self.alerts_panel.append_finding(finding, module_name, time_display)

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
