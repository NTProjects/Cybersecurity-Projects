"""Scanner configuration and execution view for the SOC Audit GUI.

This module provides the interface for configuring and running security scans.
Users can select a configuration file and trigger scan execution through
this view.

The ScannerView is designed as a thin wrapper around the GuiCliBridge,
delegating all actual scanning logic to the core engine while providing
a user-friendly interface for configuration and execution.
"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Callable

from soc_audit.gui.cli_bridge import GuiCliBridge


class ScannerView(tk.Frame):
    """
    Scanner configuration and execution view.

    This view allows users to:
    - Select a configuration file via file browser
    - Execute a security scan using the selected configuration
    - View basic status updates during execution

    The view does not display scan results - that responsibility
    belongs to a separate FindingsView component.

    Attributes:
        set_status: Callback function to update the main window status bar.
        config_path: Path to the selected configuration file, or None.
        config_entry: Entry widget displaying the selected config path.
        run_button: Button to execute the scan.
    """

    def __init__(
        self,
        parent: tk.Widget,
        set_status_callback: Callable[[str], None],
    ) -> None:
        """
        Initialize the scanner view.

        Args:
            parent: Parent widget (typically MainWindow's main_frame).
            set_status_callback: Function to update the main window status bar.
        """
        super().__init__(parent)
        self.set_status = set_status_callback
        self.config_path: Path | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the scanner view UI components."""
        # Configure grid weights for resizing
        self.columnconfigure(1, weight=1)

        # Title label
        title_label = tk.Label(
            self,
            text="Scan Configuration",
            font=("TkDefaultFont", 12, "bold"),
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(10, 15), sticky="w")

        # Config path label
        config_label = tk.Label(self, text="Config File:")
        config_label.grid(row=1, column=0, padx=(10, 5), pady=5, sticky="w")

        # Config path entry (read-only)
        self.config_var = tk.StringVar(value="No configuration file selected")
        self.config_entry = tk.Entry(
            self,
            textvariable=self.config_var,
            width=60,
            state="readonly",
        )
        self.config_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Browse button
        browse_button = tk.Button(
            self,
            text="Browse...",
            command=self._on_browse,
            width=12,
        )
        browse_button.grid(row=1, column=2, padx=(5, 10), pady=5)

        # Run scan button (initially disabled)
        self.run_button = tk.Button(
            self,
            text="Run Scan",
            command=self._on_run_scan,
            width=15,
            state=tk.DISABLED,
        )
        self.run_button.grid(row=2, column=0, columnspan=3, pady=(20, 10))

    def _on_browse(self) -> None:
        """Handle the Browse button click to select a config file."""
        file_path = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[
                ("JSON files", "*.json"),
                ("YAML files", "*.yaml *.yml"),
                ("All files", "*.*"),
            ],
            initialdir=".",
        )

        if file_path:
            self.config_path = Path(file_path)
            self.config_var.set(str(self.config_path))
            self.run_button.config(state=tk.NORMAL)
            self.set_status("Config loaded: " + self.config_path.name)

    def _on_run_scan(self) -> None:
        """Handle the Run Scan button click to execute a scan."""
        # Validate config is selected
        if self.config_path is None:
            messagebox.showwarning(
                "No Configuration",
                "Please select a configuration file before running a scan.",
            )
            return

        # Validate config file exists
        if not self.config_path.exists():
            messagebox.showerror(
                "File Not Found",
                f"Configuration file not found:\n{self.config_path}",
            )
            self.set_status("Error: Config file not found")
            return

        # Update status and disable button during scan
        self.set_status("Running scan...")
        self.run_button.config(state=tk.DISABLED)
        self.update()  # Force UI update before blocking operation

        try:
            # Execute scan via bridge
            bridge = GuiCliBridge(self.config_path)
            result = bridge.run()

            # Count findings for summary
            total_findings = sum(
                len(list(mr.findings)) for mr in result.module_results
            )
            modules_run = len(result.module_results)

            # Show success message
            self.set_status("Scan completed successfully")
            messagebox.showinfo(
                "Scan Complete",
                f"Scan completed successfully.\n\n"
                f"Modules executed: {modules_run}\n"
                f"Total findings: {total_findings}",
            )

        except FileNotFoundError as e:
            self.set_status("Scan failed: File not found")
            messagebox.showerror("Scan Error", f"File not found:\n{e}")

        except Exception as e:
            self.set_status("Scan failed")
            messagebox.showerror(
                "Scan Error",
                f"An error occurred during the scan:\n\n{type(e).__name__}: {e}",
            )

        finally:
            # Re-enable run button
            self.run_button.config(state=tk.NORMAL)
