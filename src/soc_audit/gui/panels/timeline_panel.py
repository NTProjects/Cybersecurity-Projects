"""Timeline panel for the SOC dashboard.

This module provides a panel for displaying activity timeline
visualization in a Splunk ES-style format.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class TimelinePanel(ttk.LabelFrame):
    """
    Panel displaying activity timeline visualization.

    Currently shows a placeholder for future timeline chart implementation.

    Attributes:
        canvas: Canvas widget for timeline visualization.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the timeline panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Activity Timeline", padding=10)
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Placeholder canvas
        self.canvas = tk.Canvas(self, bg="#2b2b2b", height=120)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        # Draw placeholder text
        self._draw_placeholder()

    def _draw_placeholder(self) -> None:
        """Draw placeholder content on the canvas."""
        self.canvas.delete("all")

        # Get canvas dimensions after it's been drawn
        self.canvas.update_idletasks()
        width = self.canvas.winfo_width() or 400
        height = self.canvas.winfo_height() or 120

        # Draw placeholder text
        self.canvas.create_text(
            width // 2,
            height // 2,
            text="Timeline visualization will appear here",
            fill="#888888",
            font=("TkDefaultFont", 10, "italic"),
            anchor="center",
        )

        # Draw placeholder timeline line
        y_mid = height // 2 + 20
        self.canvas.create_line(20, y_mid, width - 20, y_mid, fill="#555555", width=2)

        # Draw some placeholder points
        for i, x_offset in enumerate([0.2, 0.4, 0.6, 0.8]):
            x = int(20 + (width - 40) * x_offset)
            self.canvas.create_oval(x - 4, y_mid - 4, x + 4, y_mid + 4, fill="#4a90d9", outline="")

    def clear(self) -> None:
        """Clear the timeline visualization."""
        self.canvas.delete("all")
        self._draw_placeholder()

    def set_placeholder_data(self) -> None:
        """Reset to placeholder state."""
        self._draw_placeholder()
