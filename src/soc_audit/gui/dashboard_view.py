"""SOC Dashboard view for the SOC Audit GUI.

This module provides a Splunk ES-style dashboard layout serving as the
default landing view for SOC analysts. It displays live system metrics,
alerts, timeline, top entities, and details in an organized layout.

The dashboard supports periodic refresh of live metrics using Tkinter's
after() mechanism (no threading required).
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from soc_audit.gui.metrics import get_system_metrics
from soc_audit.gui.panels import (
    AlertsPanel,
    DetailsPanel,
    LiveMetricsPanel,
    TimelinePanel,
    TopEntitiesPanel,
)


class DashboardView(ttk.Frame):
    """
    SOC Dashboard view with Splunk ES-style layout and live metrics.

    Layout structure:
    - Top Row: LiveMetricsPanel (left) | AlertsPanel (right)
    - Middle: TimelinePanel (full width)
    - Bottom Row: TopEntitiesPanel (left) | DetailsPanel (right)

    The dashboard supports periodic refresh of system metrics using
    Tkinter's after() mechanism for non-blocking updates.

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
        self._last_error: str | None = None
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

    def start(self) -> None:
        """Start periodic metrics refresh."""
        if self._after_id is None:
            self._tick()

    def stop(self) -> None:
        """Stop periodic metrics refresh."""
        if self._after_id is not None:
            self.after_cancel(self._after_id)
            self._after_id = None

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
            else:
                self.set_status("Dashboard - Live metrics active")

    def set_placeholder_data(self) -> None:
        """Set placeholder data in all panels."""
        self.metrics_panel.set_placeholder_data()
        self.alerts_panel.set_placeholder_data()
        self.timeline_panel.set_placeholder_data()
        self.entities_panel.set_placeholder_data()
        self.details_panel.set_placeholder_text()

    def clear(self) -> None:
        """Clear all panels."""
        self.metrics_panel.clear()
        self.alerts_panel.clear()
        self.timeline_panel.clear()
        self.entities_panel.clear()
        self.details_panel.clear()
