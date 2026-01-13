"""Dashboard panel components for the SOC Audit GUI.

This package contains the individual panel widgets used in the
SOC dashboard view, following a Splunk ES-style layout.
"""
from soc_audit.gui.panels.alerts_panel import AlertsPanel
from soc_audit.gui.panels.details_panel import DetailsPanel
from soc_audit.gui.panels.live_metrics_panel import LiveMetricsPanel
from soc_audit.gui.panels.timeline_panel import TimelinePanel
from soc_audit.gui.panels.top_entities_panel import TopEntitiesPanel

__all__ = [
    "AlertsPanel",
    "DetailsPanel",
    "LiveMetricsPanel",
    "TimelinePanel",
    "TopEntitiesPanel",
]
