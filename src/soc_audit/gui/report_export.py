"""Report export view for the SOC Audit GUI.

This module provides an interface for exporting scan results to
JSON or text file formats. It uses the core ReportRenderer to
generate output, ensuring consistency with CLI report generation.
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from soc_audit.reporting.reporter import ReportRenderer

if TYPE_CHECKING:
    from soc_audit.core.engine import EngineResult


class ReportExportView(ttk.Frame):
    """
    Report export view with JSON and text export options.

    This view provides buttons to export scan results in different formats.
    It uses the core ReportRenderer to generate output, ensuring the
    exported content matches what the CLI would produce.

    Attributes:
        engine_result: The EngineResult to export.
        renderer: ReportRenderer instance for generating output.
    """

    def __init__(
        self,
        parent: tk.Widget,
        engine_result: EngineResult,
    ) -> None:
        """
        Initialize the report export view.

        Args:
            parent: Parent widget (typically a modal dialog).
            engine_result: The scan result to export.
        """
        super().__init__(parent)
        self.engine_result = engine_result
        self.renderer = ReportRenderer()
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the export view UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        # Title label
        title_label = ttk.Label(
            self,
            text="Export Report",
            font=("TkDefaultFont", 12, "bold"),
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(15, 20))

        # Description label
        desc_label = ttk.Label(
            self,
            text="Select export format:",
        )
        desc_label.grid(row=1, column=0, columnspan=2, pady=(0, 15))

        # Export as JSON button
        json_button = ttk.Button(
            self,
            text="Export as JSON",
            command=self._export_json,
            width=18,
        )
        json_button.grid(row=2, column=0, padx=10, pady=10)

        # Export as Text button
        text_button = ttk.Button(
            self,
            text="Export as Text",
            command=self._export_text,
            width=18,
        )
        text_button.grid(row=2, column=1, padx=10, pady=10)

    def _export_json(self) -> None:
        """Export the report as JSON."""
        file_path = filedialog.asksaveasfilename(
            title="Export Report as JSON",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
            initialfile="soc_audit_report.json",
        )

        if not file_path:
            # User cancelled
            return

        try:
            # Render JSON using ReportRenderer
            json_data = self.renderer.render_json(self.engine_result)

            # Write to file
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, default=str)

            messagebox.showinfo(
                "Export Successful",
                f"Report exported successfully to:\n{file_path}",
            )

        except Exception as e:
            messagebox.showerror(
                "Export Error",
                f"Failed to export report:\n\n{type(e).__name__}: {e}",
            )

    def _export_text(self) -> None:
        """Export the report as plain text."""
        file_path = filedialog.asksaveasfilename(
            title="Export Report as Text",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
            initialfile="soc_audit_report.txt",
        )

        if not file_path:
            # User cancelled
            return

        try:
            # Render text using ReportRenderer
            text_content = self.renderer.render_text(self.engine_result)

            # Write to file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text_content)

            messagebox.showinfo(
                "Export Successful",
                f"Report exported successfully to:\n{file_path}",
            )

        except Exception as e:
            messagebox.showerror(
                "Export Error",
                f"Failed to export report:\n\n{type(e).__name__}: {e}",
            )
