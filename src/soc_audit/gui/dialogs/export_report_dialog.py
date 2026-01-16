"""Dialog for exporting reports (Phase 9.3)."""
from __future__ import annotations

import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from soc_audit.reporting.text_reports import format_host_report_text, format_incident_report_text


class ExportReportDialog:
    """Dialog for selecting report type and format for export."""

    def __init__(
        self,
        parent: tk.Widget,
        on_export: Callable[[str, str, str], None],  # (report_type, format, file_path)
    ):
        """
        Initialize the export report dialog.

        Args:
            parent: Parent widget.
            on_export: Callback invoked with (report_type, format, file_path).
        """
        self.parent = parent
        self.on_export = on_export
        self.file_path: str | None = None

        self._show_dialog()

    def _show_dialog(self) -> None:
        """Show the dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Export Report")
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)

        # Configure grid
        self.dialog.columnconfigure(1, weight=1)
        self.dialog.rowconfigure(2, weight=1)

        # Report type
        ttk.Label(self.dialog, text="Report Type:").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.report_type_var = tk.StringVar(value="incidents")
        report_type_combo = ttk.Combobox(
            self.dialog,
            textvariable=self.report_type_var,
            values=["incidents", "hosts"],
            state="readonly",
            width=20,
        )
        report_type_combo.grid(row=0, column=1, sticky="ew", padx=10, pady=10)

        # Format
        ttk.Label(self.dialog, text="Format:").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.format_var = tk.StringVar(value="json")
        format_combo = ttk.Combobox(
            self.dialog,
            textvariable=self.format_var,
            values=["json", "txt"],
            state="readonly",
            width=20,
        )
        format_combo.grid(row=1, column=1, sticky="ew", padx=10, pady=10)

        # Buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)

        export_button = ttk.Button(button_frame, text="Export...", command=self._on_export)
        export_button.pack(side=tk.LEFT, padx=5)

        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5)

        # Focus on dialog
        self.dialog.focus_set()

    def _on_export(self) -> None:
        """Handle export button click."""
        report_type = self.report_type_var.get()
        format_type = self.format_var.get()

        # Determine file extension
        ext = ".json" if format_type == "json" else ".txt"
        default_name = f"{report_type}_report{ext}"

        # File save dialog
        file_path = filedialog.asksaveasfilename(
            parent=self.dialog,
            defaultextension=ext,
            filetypes=[
                (f"{format_type.upper()} files", f"*{ext}"),
                ("All files", "*.*"),
            ],
            initialfile=default_name,
        )

        if file_path:
            self.on_export(report_type, format_type, file_path)
            self.dialog.destroy()
