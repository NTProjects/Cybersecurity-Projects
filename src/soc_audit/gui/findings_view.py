"""Findings display view for the SOC Audit GUI.

This module provides a table-based interface for viewing, filtering, and
sorting security findings returned by the scan engine. It includes a details
panel for examining individual findings.

The FindingsView is designed to receive EngineResult objects and display
their contents in an interactive, user-friendly format.
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Any

from soc_audit.core.engine import EngineResult
from soc_audit.core.interfaces import Finding


# Custom severity order for sorting (higher priority = lower sort value)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingsView(ttk.Frame):
    """
    Findings display view with filtering, sorting, and details panel.

    This view displays scan findings in a table format with:
    - Module and severity filtering
    - Text search across title, description, and evidence
    - Sortable columns (severity uses custom order)
    - Details panel showing full finding information

    Attributes:
        findings_data: List of (module_name, Finding) tuples from results.
        tree: Treeview widget displaying findings table.
        details_text: Text widget showing selected finding details.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the findings view.

        Args:
            parent: Parent widget (typically a pane in MainWindow).
        """
        super().__init__(parent)
        self.findings_data: list[tuple[str, Finding]] = []
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the findings view UI components."""
        # Configure grid weights for resizing
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)  # Table gets more space
        self.rowconfigure(2, weight=1)  # Details panel

        # === Top controls row ===
        controls_frame = ttk.Frame(self)
        controls_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        controls_frame.columnconfigure(4, weight=1)  # Search entry expands

        # Title label
        title_label = ttk.Label(
            controls_frame,
            text="Findings",
            font=("TkDefaultFont", 11, "bold"),
        )
        title_label.grid(row=0, column=0, padx=(5, 15), sticky="w")

        # Module filter
        ttk.Label(controls_frame, text="Module:").grid(row=0, column=1, padx=(5, 2))
        self.module_var = tk.StringVar(value="All")
        self.module_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.module_var,
            values=["All"],
            state="readonly",
            width=18,
        )
        self.module_combo.grid(row=0, column=2, padx=(0, 10))
        self.module_combo.bind("<<ComboboxSelected>>", self._on_filter_change)

        # Severity filter
        ttk.Label(controls_frame, text="Severity:").grid(row=0, column=3, padx=(5, 2))
        self.severity_var = tk.StringVar(value="All")
        self.severity_combo = ttk.Combobox(
            controls_frame,
            textvariable=self.severity_var,
            values=["All", "critical", "high", "medium", "low", "info"],
            state="readonly",
            width=12,
        )
        self.severity_combo.grid(row=0, column=4, padx=(0, 10), sticky="w")
        self.severity_combo.bind("<<ComboboxSelected>>", self._on_filter_change)

        # Search entry
        ttk.Label(controls_frame, text="Search:").grid(row=0, column=5, padx=(10, 2))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            controls_frame,
            textvariable=self.search_var,
            width=25,
        )
        self.search_entry.grid(row=0, column=6, padx=(0, 5), sticky="ew")
        self.search_var.trace_add("write", self._on_filter_change)

        # === Table (Treeview) ===
        table_frame = ttk.Frame(self)
        table_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        # Define columns
        columns = ("module", "severity", "title", "risk_score", "compliance_status")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        # Configure column headings and widths
        self.tree.heading("module", text="Module", command=lambda: self._sort_column("module"))
        self.tree.heading("severity", text="Severity", command=lambda: self._sort_column("severity"))
        self.tree.heading("title", text="Title", command=lambda: self._sort_column("title"))
        self.tree.heading("risk_score", text="Risk Score", command=lambda: self._sort_column("risk_score"))
        self.tree.heading("compliance_status", text="Compliance", command=lambda: self._sort_column("compliance_status"))

        self.tree.column("module", width=120, minwidth=80)
        self.tree.column("severity", width=80, minwidth=60)
        self.tree.column("title", width=300, minwidth=150)
        self.tree.column("risk_score", width=80, minwidth=60)
        self.tree.column("compliance_status", width=100, minwidth=80)

        self.tree.grid(row=0, column=0, sticky="nsew")

        # Vertical scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Track sort state
        self._sort_column_name = ""
        self._sort_reverse = False

        # === Details panel ===
        details_frame = ttk.LabelFrame(self, text="Details")
        details_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)

        # Details text widget with scrollbar (dark theme)
        self.details_text = tk.Text(
            details_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=8,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
            selectbackground="#3e3e42",
            selectforeground="#ffffff",
        )
        self.details_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        details_scrollbar = ttk.Scrollbar(
            details_frame,
            orient=tk.VERTICAL,
            command=self.details_text.yview,
        )
        details_scrollbar.grid(row=0, column=1, sticky="ns", pady=5)
        self.details_text.configure(yscrollcommand=details_scrollbar.set)

    def set_results(self, engine_result: EngineResult) -> None:
        """
        Populate the view with findings from an EngineResult.

        Args:
            engine_result: The result object from engine.run().
        """
        # Extract all findings with their module names
        self.findings_data = []
        modules_seen: set[str] = set()
        severities_seen: set[str] = set()

        for module_result in engine_result.module_results:
            module_name = module_result.module_name
            modules_seen.add(module_name)
            for finding in module_result.findings:
                self.findings_data.append((module_name, finding))
                severities_seen.add(finding.severity.lower())

        # Update filter dropdowns
        module_values = ["All"] + sorted(modules_seen)
        self.module_combo["values"] = module_values

        # Build severity list with standard order first
        severity_values = ["All"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severities_seen:
                severity_values.append(sev)
                severities_seen.discard(sev)
        # Add any non-standard severities
        severity_values.extend(sorted(severities_seen))
        self.severity_combo["values"] = severity_values

        # Reset filters and render
        self.module_var.set("All")
        self.severity_var.set("All")
        self.search_var.set("")
        self._render_table()

    def clear(self) -> None:
        """Clear all findings from the view."""
        self.findings_data = []
        self.module_combo["values"] = ["All"]
        self.severity_combo["values"] = ["All", "critical", "high", "medium", "low", "info"]
        self.module_var.set("All")
        self.severity_var.set("All")
        self.search_var.set("")
        self._render_table()
        self._clear_details()

    def _render_table(self) -> None:
        """Render the table based on current filters and sort settings."""
        # Clear existing rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Get filter values
        module_filter = self.module_var.get()
        severity_filter = self.severity_var.get().lower()
        search_text = self.search_var.get().lower().strip()

        # Filter findings
        filtered: list[tuple[int, str, Finding]] = []
        for idx, (module_name, finding) in enumerate(self.findings_data):
            # Module filter
            if module_filter != "All" and module_name != module_filter:
                continue

            # Severity filter
            if severity_filter != "all" and finding.severity.lower() != severity_filter:
                continue

            # Search filter
            if search_text:
                searchable = (
                    finding.title.lower()
                    + " "
                    + finding.description.lower()
                    + " "
                    + self._evidence_to_string(finding.evidence).lower()
                )
                if search_text not in searchable:
                    continue

            filtered.append((idx, module_name, finding))

        # Sort if needed
        if self._sort_column_name:
            filtered = self._apply_sort(filtered)

        # Insert rows
        for idx, module_name, finding in filtered:
            risk_score = finding.risk_score if finding.risk_score is not None else ""
            compliance_status = finding.compliance_status or ""

            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    module_name,
                    finding.severity.lower(),
                    finding.title,
                    risk_score,
                    compliance_status,
                ),
            )

    def _apply_sort(
        self, data: list[tuple[int, str, Finding]]
    ) -> list[tuple[int, str, Finding]]:
        """Apply current sort settings to filtered data."""
        col = self._sort_column_name
        reverse = self._sort_reverse

        def sort_key(item: tuple[int, str, Finding]) -> Any:
            idx, module_name, finding = item
            if col == "module":
                return module_name.lower()
            elif col == "severity":
                sev = finding.severity.lower()
                return SEVERITY_ORDER.get(sev, 99)
            elif col == "title":
                return finding.title.lower()
            elif col == "risk_score":
                # None treated as -infinity (sorts to end when ascending)
                return finding.risk_score if finding.risk_score is not None else -float("inf")
            elif col == "compliance_status":
                return (finding.compliance_status or "").lower()
            return idx

        return sorted(data, key=sort_key, reverse=reverse)

    def _sort_column(self, col: str) -> None:
        """Handle column header click for sorting."""
        if self._sort_column_name == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column_name = col
            self._sort_reverse = False
        self._render_table()

    def _on_filter_change(self, *args: Any) -> None:
        """Handle filter change events."""
        self._render_table()

    def _on_select(self, event: tk.Event) -> None:
        """Handle table row selection."""
        selection = self.tree.selection()
        if not selection:
            self._clear_details()
            return

        # Get the finding by index
        idx = int(selection[0])
        if 0 <= idx < len(self.findings_data):
            module_name, finding = self.findings_data[idx]
            self._show_details(module_name, finding)

    def _show_details(self, module_name: str, finding: Finding) -> None:
        """Display finding details in the details panel."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)

        lines: list[str] = []
        lines.append(f"Module: {module_name}")
        lines.append(f"Title: {finding.title}")
        lines.append(f"Severity: {finding.severity}")

        if finding.risk_score is not None:
            lines.append(f"Risk Score: {finding.risk_score}")

        lines.append("")
        lines.append(f"Description:\n{finding.description}")

        if finding.recommendation:
            lines.append("")
            lines.append(f"Recommendation:\n{finding.recommendation}")

        if finding.evidence:
            lines.append("")
            lines.append(f"Evidence:\n{self._evidence_to_string(finding.evidence)}")

        if finding.control_ids:
            lines.append("")
            lines.append(f"Control IDs: {', '.join(finding.control_ids)}")

        if finding.compliance_status:
            lines.append(f"Compliance Status: {finding.compliance_status}")

        self.details_text.insert("1.0", "\n".join(lines))
        self.details_text.config(state=tk.DISABLED)

    def _clear_details(self) -> None:
        """Clear the details panel."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.config(state=tk.DISABLED)

    @staticmethod
    def _evidence_to_string(evidence: Any) -> str:
        """Convert evidence to a readable string."""
        if not evidence:
            return ""
        if isinstance(evidence, dict):
            try:
                return json.dumps(evidence, indent=2, default=str)
            except (TypeError, ValueError):
                return str(evidence)
        return str(evidence)
