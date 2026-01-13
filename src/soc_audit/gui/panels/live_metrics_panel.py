"""Live system metrics panel for the SOC dashboard.

This module provides a panel displaying real-time system metrics
in a Splunk ES-style format. Currently uses placeholder data.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class LiveMetricsPanel(ttk.LabelFrame):
    """
    Panel displaying live system metrics.

    Shows CPU usage, memory usage, network I/O, and active connections
    using progress bars and labels. Currently displays placeholder values.

    Attributes:
        cpu_var: StringVar for CPU percentage display.
        memory_var: StringVar for memory percentage display.
        network_in_var: StringVar for network input rate.
        network_out_var: StringVar for network output rate.
        connections_var: StringVar for active connection count.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the live metrics panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Live System Metrics", padding=10)
        self._build_ui()
        self.set_placeholder_data()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(1, weight=1)

        row = 0

        # CPU Usage
        ttk.Label(self, text="CPU Usage:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.cpu_progress = ttk.Progressbar(self, length=150, mode="determinate")
        self.cpu_progress.grid(row=row, column=1, sticky="ew", padx=5, pady=3)
        self.cpu_var = tk.StringVar(value="0%")
        ttk.Label(self, textvariable=self.cpu_var, width=6).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        # Memory Usage
        ttk.Label(self, text="Memory Usage:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.memory_progress = ttk.Progressbar(self, length=150, mode="determinate")
        self.memory_progress.grid(row=row, column=1, sticky="ew", padx=5, pady=3)
        self.memory_var = tk.StringVar(value="0%")
        ttk.Label(self, textvariable=self.memory_var, width=6).grid(row=row, column=2, padx=5, pady=3)
        row += 1

        # Network In
        ttk.Label(self, text="Network In:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.network_in_var = tk.StringVar(value="0 KB/s")
        ttk.Label(self, textvariable=self.network_in_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Network Out
        ttk.Label(self, text="Network Out:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.network_out_var = tk.StringVar(value="0 KB/s")
        ttk.Label(self, textvariable=self.network_out_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Active Connections
        ttk.Label(self, text="Active Connections:").grid(row=row, column=0, sticky="w", padx=5, pady=3)
        self.connections_var = tk.StringVar(value="0")
        ttk.Label(self, textvariable=self.connections_var).grid(row=row, column=1, sticky="w", padx=5, pady=3)
        row += 1

        # Placeholder note
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(row=row, column=0, columnspan=3, sticky="ew", pady=8)
        row += 1
        note_label = ttk.Label(self, text="Live data placeholder", font=("TkDefaultFont", 8, "italic"))
        note_label.grid(row=row, column=0, columnspan=3, pady=3)

    def set_placeholder_data(self) -> None:
        """Set placeholder values for demonstration."""
        self.cpu_progress["value"] = 35
        self.cpu_var.set("35%")

        self.memory_progress["value"] = 62
        self.memory_var.set("62%")

        self.network_in_var.set("120 KB/s in")
        self.network_out_var.set("90 KB/s out")

        self.connections_var.set("42")

    def clear(self) -> None:
        """Clear all metrics to zero."""
        self.cpu_progress["value"] = 0
        self.cpu_var.set("0%")
        self.memory_progress["value"] = 0
        self.memory_var.set("0%")
        self.network_in_var.set("0 KB/s")
        self.network_out_var.set("0 KB/s")
        self.connections_var.set("0")
