"""Details panel for the SOC dashboard.

This module provides a panel for displaying detailed information
about selected alerts or entities.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any


class DetailsPanel(ttk.LabelFrame):
    """
    Panel displaying detailed information about selected items.

    Shows a read-only text widget with details about the currently
    selected alert or entity.

    Attributes:
        text: Text widget for displaying details.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the details panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Details", padding=10)
        self._build_ui()
        self.set_placeholder_text()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Text widget with scrollbar
        self.text = tk.Text(
            self,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("TkFixedFont", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
        )
        self.text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=scrollbar.set)

    def set_placeholder_text(self) -> None:
        """Set placeholder text."""
        self.set_content("Select an alert to view details")

    def set_content(self, content: str) -> None:
        """
        Set the text content of the details panel.

        Args:
            content: Text to display.
        """
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", content)
        self.text.config(state=tk.DISABLED)

    def show_alert_details(self, alert_data: dict[str, Any]) -> None:
        """
        Display details for a selected alert.

        Args:
            alert_data: Dictionary containing alert information.
        """
        lines = []
        lines.append("=" * 40)
        lines.append("ALERT DETAILS")
        lines.append("=" * 40)
        lines.append("")

        if alert_data.get("severity"):
            lines.append(f"Severity:  {alert_data['severity']}")
        if alert_data.get("module"):
            lines.append(f"Module:    {alert_data['module']}")
        if alert_data.get("title"):
            lines.append(f"Title:     {alert_data['title']}")
        if alert_data.get("time"):
            lines.append(f"Time:      {alert_data['time']}")

        lines.append("")
        lines.append("-" * 40)
        lines.append("Additional details will appear here")
        lines.append("when integrated with live data.")

        self.set_content("\n".join(lines))

    def clear(self) -> None:
        """Clear the details panel."""
        self.set_placeholder_text()
