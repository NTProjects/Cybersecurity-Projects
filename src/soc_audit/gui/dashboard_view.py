"""SOC Dashboard view for the SOC Audit GUI.

This module provides a Splunk ES-style dashboard layout serving as the
default landing view for SOC analysts. It displays system metrics,
alerts, timeline, top entities, and details in an organized layout.

Currently uses placeholder data for demonstration purposes.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from soc_audit.gui.panels import (
    AlertsPanel,
    DetailsPanel,
    LiveMetricsPanel,
    TimelinePanel,
    TopEntitiesPanel,
)


class DashboardView(ttk.Frame):
    """
    SOC Dashboard view with Splunk ES-style layout.

    Layout structure:
    - Top Row: LiveMetricsPanel (left) | AlertsPanel (right)
    - Middle: TimelinePanel (full width)
    - Bottom Row: TopEntitiesPanel (left) | DetailsPanel (right)

    Attributes:
        metrics_panel: Panel showing live system metrics.
        alerts_panel: Panel showing security alerts.
        timeline_panel: Panel showing activity timeline.
        entities_panel: Panel showing top entities.
        details_panel: Panel showing selected item details.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the dashboard view.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
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
