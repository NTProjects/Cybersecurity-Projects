"""Timeline panel for the SOC dashboard.

This module provides a panel for displaying activity timeline
in a Splunk ES-style format with scrolling event entries.
"""
from __future__ import annotations

import tkinter as tk
from datetime import datetime
from tkinter import ttk
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_audit.core.interfaces import Finding


# Severity color mapping for timeline entries
SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff6b6b",
    "medium": "#ffa726",
    "low": "#42a5f5",
    "info": "#78909c",
}


class TimelinePanel(ttk.LabelFrame):
    """
    Panel displaying activity timeline with scrolling event log.

    Shows timestamped event entries as they occur, maintaining
    chronological order with auto-scroll to newest.

    Attributes:
        text: Text widget for timeline entries.
        max_events: Maximum number of events to retain (default: 100).
        event_count: Current count of events displayed.
    """

    def __init__(self, parent: tk.Widget, max_events: int = 500) -> None:
        """
        Initialize the timeline panel.

        Args:
            parent: Parent widget.
            max_events: Maximum number of events to retain (default: 500).
        """
        super().__init__(parent, text="Activity Timeline", padding=10)
        self.max_events = max_events  # Performance: Increased from 100 to 500
        self.event_count = 0
        self._text_state_normal = False  # Track state to reduce toggles
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Create text widget for timeline
        self.text = tk.Text(
            self,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            height=6,
            padx=8,
            pady=5,
        )
        self.text.grid(row=0, column=0, sticky="nsew")

        # Configure severity tags for colored text
        self.text.tag_configure("timestamp", foreground="#888888")
        self.text.tag_configure("module", foreground="#4ec9b0")
        self.text.tag_configure("arrow", foreground="#666666")
        self.text.tag_configure("critical", foreground="#ff4444")
        self.text.tag_configure("high", foreground="#ff6b6b")
        self.text.tag_configure("medium", foreground="#ffa726")
        self.text.tag_configure("low", foreground="#42a5f5")
        self.text.tag_configure("info", foreground="#78909c")

        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=scrollbar.set)

        # Show initial placeholder
        self._show_placeholder()

    def _show_placeholder(self) -> None:
        """Show placeholder text when no events."""
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, "Waiting for events...\n", "info")
        self.text.config(state=tk.DISABLED)

    def append_event(
        self,
        finding: Finding,
        module_name: str,
        timestamp: datetime | None = None,
    ) -> None:
        """
        Append an event entry to the timeline (optimized for performance).

        Args:
            finding: The Finding object to display.
            module_name: Name of the module that produced the finding.
            timestamp: Event timestamp (default: current time).
        """
        if timestamp is None:
            timestamp = datetime.now()

        time_str = timestamp.strftime("%H:%M:%S")
        severity = finding.severity.lower()
        severity_tag = severity if severity in SEVERITY_COLORS else "info"

        # Performance: Only toggle state if needed (reduce expensive state changes)
        if not self._text_state_normal:
            self.text.config(state=tk.NORMAL)
            self._text_state_normal = True

        # Clear placeholder on first event
        if self.event_count == 0:
            self.text.delete("1.0", tk.END)

        # Build the entry line
        self.text.insert(tk.END, f"[{time_str}] ", "timestamp")
        self.text.insert(tk.END, f"{module_name}", "module")
        self.text.insert(tk.END, " → ", "arrow")
        self.text.insert(tk.END, f"{finding.title}\n", severity_tag)

        self.event_count += 1

        # Trim old events if exceeding max
        if self.event_count > self.max_events:
            # Delete the first line
            self.text.delete("1.0", "2.0")
            self.event_count -= 1

        # Performance: Disable auto-scroll to reduce lag (user can manually scroll)
        # Only scroll on every 10th event or at end to reduce redraws
        # if self.event_count % 10 == 0 or self.event_count == 1:
        #     self.text.see(tk.END)
    
    def flush(self) -> None:
        """Flush pending updates and restore text widget state if needed."""
        if self._text_state_normal:
            self.text.config(state=tk.DISABLED)
            self._text_state_normal = False

    def clear(self) -> None:
        """Clear the timeline and show placeholder."""
        if not self._text_state_normal:
            self.text.config(state=tk.NORMAL)
            self._text_state_normal = True
        self.text.delete("1.0", tk.END)
        self.text.config(state=tk.DISABLED)
        self._text_state_normal = False
        self.event_count = 0
        self._show_placeholder()

    def set_placeholder_data(self) -> None:
        """Show placeholder data for demonstration."""
        self.clear()
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)

        # Sample timeline entries
        entries = [
            ("10:01:04", "firewall_analyzer", "Overly permissive rule detected", "high"),
            ("10:01:06", "log_analyzer", "Repeated SSH failures", "high"),
            ("10:01:08", "port_risk_analyzer", "SSH exposed on port 22", "medium"),
            ("10:01:10", "port_risk_analyzer", "HTTP exposed on port 80", "medium"),
        ]

        for time_str, module, title, severity in entries:
            self.text.insert(tk.END, f"[{time_str}] ", "timestamp")
            self.text.insert(tk.END, f"{module}", "module")
            self.text.insert(tk.END, " → ", "arrow")
            self.text.insert(tk.END, f"{title}\n", severity)

        self.text.config(state=tk.DISABLED)
        self.event_count = len(entries)
