"""Live system metrics panel for the SOC dashboard.

This module provides a panel displaying real-time system metrics
in a Splunk ES-style format. Supports both placeholder and live data.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any


class LiveMetricsPanel(ttk.LabelFrame):
    """
    Panel displaying live system metrics.

    Shows CPU usage, memory usage, network I/O, and active connections
    using progress bars and labels. Supports live updates from system
    telemetry when available.

    Attributes:
        cpu_var: StringVar for CPU percentage display.
        memory_var: StringVar for memory percentage display.
        network_in_var: StringVar for network input rate.
        network_out_var: StringVar for network output rate.
        connections_var: StringVar for active connection count.
        status_var: StringVar for status message.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the live metrics panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Live System Metrics", padding=10)
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(1, weight=1)

        row = 0

        # CPU Usage
        ttk.Label(self, text="CPU Usage:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.cpu_progress = ttk.Progressbar(self, length=150, mode="determinate")
        self.cpu_progress.grid(row=row, column=1, sticky="ew", padx=5, pady=3)
        self.cpu_var = tk.StringVar(value="N/A")
        ttk.Label(self, textvariable=self.cpu_var, width=6).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        # Memory Usage
        ttk.Label(self, text="Memory Usage:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.memory_progress = ttk.Progressbar(self, length=150, mode="determinate")
        self.memory_progress.grid(row=row, column=1, sticky="ew", padx=5, pady=3)
        self.memory_var = tk.StringVar(value="N/A")
        ttk.Label(self, textvariable=self.memory_var, width=6).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        # Network In
        ttk.Label(self, text="Network In:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.network_in_var = tk.StringVar(value="N/A")
        ttk.Label(self, textvariable=self.network_in_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Network Out
        ttk.Label(self, text="Network Out:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.network_out_var = tk.StringVar(value="N/A")
        ttk.Label(self, textvariable=self.network_out_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Active Connections
        ttk.Label(self, text="Active Connections:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.connections_var = tk.StringVar(value="N/A")
        ttk.Label(self, textvariable=self.connections_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Status note
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=3, sticky="ew", pady=8)
        row += 1
        self.status_var = tk.StringVar(value="Waiting for data...")
        self.status_label = ttk.Label(self, textvariable=self.status_var, font=("TkDefaultFont", 8, "italic"))
        self.status_label.grid(row=row, column=0, columnspan=3, pady=3)

    def update_metrics(self, metrics: dict[str, Any]) -> None:
        """
        Update the panel with live metrics data.

        Args:
            metrics: Dictionary from get_system_metrics() containing:
                - cpu_percent: float | None
                - memory_percent: float | None
                - net_in_bps: int | None
                - net_out_bps: int | None
                - active_conns: int | None
                - error: str | None
        """
        # Import here to avoid circular import
        from soc_audit.gui.metrics import format_bytes_rate

        # CPU
        cpu = metrics.get("cpu_percent")
        if cpu is not None:
            self.cpu_progress["value"] = cpu
            self.cpu_var.set(f"{cpu:.0f}%")
        else:
            self.cpu_progress["value"] = 0
            self.cpu_var.set("N/A")

        # Memory
        mem = metrics.get("memory_percent")
        if mem is not None:
            self.memory_progress["value"] = mem
            self.memory_var.set(f"{mem:.0f}%")
        else:
            self.memory_progress["value"] = 0
            self.memory_var.set("N/A")

        # Network In
        net_in = metrics.get("net_in_bps")
        self.network_in_var.set(format_bytes_rate(net_in))

        # Network Out
        net_out = metrics.get("net_out_bps")
        self.network_out_var.set(format_bytes_rate(net_out))

        # Active Connections
        conns = metrics.get("active_conns")
        if conns is not None:
            self.connections_var.set(str(conns))
        else:
            self.connections_var.set("N/A")

        # Status
        error = metrics.get("error")
        if error:
            self.status_var.set(f"Warning: {error}")
        else:
            self.status_var.set("Live data")

    def set_placeholder_data(self) -> None:
        """Set placeholder values for demonstration."""
        self.cpu_progress["value"] = 35
        self.cpu_var.set("35%")

        self.memory_progress["value"] = 62
        self.memory_var.set("62%")

        self.network_in_var.set("120 KB/s")
        self.network_out_var.set("90 KB/s")

        self.connections_var.set("42")
        self.status_var.set("Placeholder data")

    def clear(self) -> None:
        """Clear all metrics to N/A."""
        self.cpu_progress["value"] = 0
        self.cpu_var.set("N/A")
        self.memory_progress["value"] = 0
        self.memory_var.set("N/A")
        self.network_in_var.set("N/A")
        self.network_out_var.set("N/A")
        self.connections_var.set("N/A")
        self.status_var.set("Cleared")
