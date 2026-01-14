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
        
        # Phase 5.5: Ack and Suppressed status
        if alert_data.get("acked"):
            acked_val = alert_data["acked"]
            self.text.insert(tk.END, "Acknowledged: ", "label")
            self.text.insert(tk.END, f"{acked_val}\n", "value" if acked_val == "Y" else "label")
        
        if alert_data.get("suppressed"):
            suppressed_val = alert_data["suppressed"]
            self.text.insert(tk.END, "Suppressed:   ", "label")
            self.text.insert(tk.END, f"{suppressed_val}\n", "value" if suppressed_val == "Y" else "label")
        
        if alert_data.get("incident"):
            incident_val = alert_data["incident"]
            if incident_val and incident_val != "-":
                self.text.insert(tk.END, "Incident:    ", "label")
                self.text.insert(tk.END, f"{incident_val}\n", "value")

        # Check if we have the full Finding object for drill-down
        finding = alert_data.get("finding")
        if finding:
            self._show_finding_details(finding, alert_data)
        else:
            self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, "Full details available after scan\n", "label")

        self.text.config(state=tk.DISABLED)

    def _show_finding_details(self, finding: Finding, alert_data: dict[str, Any] | None = None) -> None:
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

        # RBA Score and Breakdown (Phase 5.4)
        rba_score = getattr(finding, "rba_score", None)
        if rba_score is not None:
            self.text.insert(tk.END, "\n")
            self.text.insert(tk.END, "RBA Score:   ", "label")
            self.text.insert(tk.END, f"{rba_score}/100\n", "value")
            
            # Try to get breakdown from finding, or compute it
            rba_breakdown = getattr(finding, "rba_breakdown", None)
            if not rba_breakdown:
                # Compute breakdown on-demand
                try:
                    from soc_audit.core.rba import compute_rba_score
                    mitre_ids = getattr(finding, "mitre_ids", None)
                    _, rba_breakdown = compute_rba_score(
                        finding.severity,
                        finding.risk_score,
                        mitre_ids,
                    )
                except Exception:
                    rba_breakdown = None
            
            if rba_breakdown:
                self.text.insert(tk.END, "\nRBA Breakdown:\n", "label")
                self.text.insert(tk.END, f"  Base Severity: {rba_breakdown.get('base_severity', 0)}\n", "value")
                self.text.insert(tk.END, f"  MITRE Bonus:   +{rba_breakdown.get('mitre_bonus', 0)}\n", "value")
                self.text.insert(tk.END, f"  Risk Bonus:    +{rba_breakdown.get('risk_bonus', 0)}\n", "value")

        # MITRE ATT&CK (Phase 5.4)
        mitre_tactics = getattr(finding, "mitre_tactics", None)
        mitre_techniques = getattr(finding, "mitre_techniques", None)
        mitre_ids = getattr(finding, "mitre_ids", None)
        
        if mitre_tactics or mitre_techniques or mitre_ids:
            self.text.insert(tk.END, "\n" + "─" * 42 + "\n", "separator")
            self.text.insert(tk.END, "MITRE ATT&CK\n", "header")
            self.text.insert(tk.END, "─" * 42 + "\n", "separator")
            
            if mitre_tactics:
                self.text.insert(tk.END, "Tactics:     ", "label")
                self.text.insert(tk.END, f"{', '.join(mitre_tactics)}\n", "value")
            
            if mitre_techniques:
                self.text.insert(tk.END, "Techniques:  ", "label")
                self.text.insert(tk.END, f"{', '.join(mitre_techniques)}\n", "value")
            
            if mitre_ids:
                self.text.insert(tk.END, "Technique IDs: ", "label")
                self.text.insert(tk.END, f"{', '.join(mitre_ids)}\n", "value")

        # Phase 5.5: Incident link (if available)
        if alert_data:
            incident_id = alert_data.get("incident")
            if incident_id and incident_id != "-":
                self.text.insert(tk.END, "\n")
                self.text.insert(tk.END, "Incident ID: ", "label")
                self.text.insert(tk.END, f"{incident_id}\n", "value")
        
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
