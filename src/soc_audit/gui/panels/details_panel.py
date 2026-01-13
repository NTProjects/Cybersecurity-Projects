"""Details panel for the SOC dashboard.

This module provides a panel for displaying detailed information
about selected alerts or entities with full incident drill-down.
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from soc_audit.core.interfaces import Finding


class DetailsPanel(ttk.LabelFrame):
    """
    Panel displaying detailed information about selected items.

    Shows a read-only text widget with comprehensive details about
    the currently selected alert, including evidence and recommendations.

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
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
            padx=8,
            pady=5,
        )
        self.text.grid(row=0, column=0, sticky="nsew")

        # Configure tags for colored text
        self.text.tag_configure("header", foreground="#569cd6", font=("Consolas", 10, "bold"))
        self.text.tag_configure("label", foreground="#9cdcfe")
        self.text.tag_configure("value", foreground="#ce9178")
        self.text.tag_configure("critical", foreground="#ff4444")
        self.text.tag_configure("high", foreground="#ff6b6b")
        self.text.tag_configure("medium", foreground="#ffa726")
        self.text.tag_configure("low", foreground="#42a5f5")
        self.text.tag_configure("separator", foreground="#444444")
        self.text.tag_configure("evidence", foreground="#6a9955")
        self.text.tag_configure("recommendation", foreground="#dcdcaa")

        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=scrollbar.set)

    def set_placeholder_text(self) -> None:
        """Set placeholder text."""
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, "Select an alert to view details\n", "label")
        self.text.config(state=tk.DISABLED)

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
            alert_data: Dictionary containing alert information,
                       optionally including a 'finding' key with the Finding object.
        """
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)

        # Header
        self.text.insert(tk.END, "═" * 42 + "\n", "separator")
        self.text.insert(tk.END, "  INCIDENT DETAILS\n", "header")
        self.text.insert(tk.END, "═" * 42 + "\n\n", "separator")

        # Basic info
        severity = alert_data.get("severity", "Unknown")
        severity_tag = severity.lower() if severity.lower() in ["critical", "high", "medium", "low"] else "label"
        
        self.text.insert(tk.END, "Severity:    ", "label")
        self.text.insert(tk.END, f"{severity}\n", severity_tag)
        
        if alert_data.get("module"):
            self.text.insert(tk.END, "Module:      ", "label")
            self.text.insert(tk.END, f"{alert_data['module']}\n", "value")
        
        if alert_data.get("title"):
            self.text.insert(tk.END, "Title:       ", "label")
            self.text.insert(tk.END, f"{alert_data['title']}\n", "value")
        
        if alert_data.get("time"):
            self.text.insert(tk.END, "Time:        ", "label")
            self.text.insert(tk.END, f"{alert_data['time']}\n", "value")

        # Check if we have the full Finding object for drill-down
        finding = alert_data.get("finding")
        if finding:
            self._show_finding_details(finding)
        else:
            self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, "Full details available after scan\n", "label")

        self.text.config(state=tk.DISABLED)

    def _show_finding_details(self, finding: Finding) -> None:
        """
        Display full finding details including evidence and recommendation.

        Args:
            finding: The Finding object to display.
        """
        # Description
        self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
        self.text.insert(tk.END, "DESCRIPTION\n", "header")
        self.text.insert(tk.END, "─" * 42 + "\n", "separator")
        self.text.insert(tk.END, f"{finding.description}\n", "value")

        # Risk Score (if present)
        if finding.risk_score is not None:
            self.text.insert(tk.END, "\n")
            self.text.insert(tk.END, "Risk Score:  ", "label")
            self.text.insert(tk.END, f"{finding.risk_score}/100\n", "value")

        # Compliance (if present)
        if finding.control_ids:
            self.text.insert(tk.END, "Control IDs: ", "label")
            self.text.insert(tk.END, f"{', '.join(finding.control_ids)}\n", "value")
        
        if finding.compliance_status:
            self.text.insert(tk.END, "Compliance:  ", "label")
            self.text.insert(tk.END, f"{finding.compliance_status}\n", "value")

        # Evidence
        if finding.evidence:
            self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, "EVIDENCE\n", "header")
            self.text.insert(tk.END, "─" * 42 + "\n", "separator")
            try:
                evidence_str = json.dumps(dict(finding.evidence), indent=2, default=str)
                self.text.insert(tk.END, f"{evidence_str}\n", "evidence")
            except (TypeError, ValueError):
                self.text.insert(tk.END, f"{finding.evidence}\n", "evidence")

        # Recommendation
        if finding.recommendation:
            self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, "RECOMMENDATION\n", "header")
            self.text.insert(tk.END, "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, f"{finding.recommendation}\n", "recommendation")

    def show_finding(self, finding: Finding, module_name: str) -> None:
        """
        Display a Finding object directly.

        Args:
            finding: The Finding object to display.
            module_name: Name of the module that produced the finding.
        """
        alert_data = {
            "severity": finding.severity.capitalize(),
            "module": module_name,
            "title": finding.title,
            "time": "Now",
            "finding": finding,
        }
        self.show_alert_details(alert_data)

    def clear(self) -> None:
        """Clear the details panel."""
        self.set_placeholder_text()
