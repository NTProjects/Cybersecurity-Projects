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
from typing import Any, Callable

from soc_audit.gui.cli_bridge import GuiCliBridge


class ScannerView(tk.Frame):
    """
    Scanner configuration and execution view.

    This view allows users to:
    - Select a configuration file via file browser
    - Execute a security scan using the selected configuration
    - View basic status updates during execution

    Scan results are passed to the FindingsView via the on_scan_complete
    callback provided during initialization.

    Attributes:
        set_status: Callback function to update the main window status bar.
        on_scan_complete: Optional callback invoked with EngineResult on success.
        config_path: Path to the selected configuration file, or None.
        config_entry: Entry widget displaying the selected config path.
        run_button: Button to execute the scan.
    """

    # Dark theme colors
    BG_COLOR = "#1e1e1e"
    BG_LIGHTER = "#252526"
    FG_COLOR = "#d4d4d4"
    ACCENT_COLOR = "#3e3e42"

    def __init__(
        self,
        parent: tk.Widget,
        set_status_callback: Callable[[str], None],
        on_scan_complete: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Initialize the scanner view.

        Args:
            parent: Parent widget (typically MainWindow's main_frame).
            set_status_callback: Function to update the main window status bar.
            on_scan_complete: Optional callback invoked with EngineResult after
                a successful scan. Used to pass results to FindingsView.
        """
        super().__init__(parent, bg=self.BG_COLOR)
        self.set_status = set_status_callback
        self.on_scan_complete = on_scan_complete
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
            bg=self.BG_COLOR,
            fg=self.FG_COLOR,
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(10, 15), sticky="w")

        # Config path label
        config_label = tk.Label(
            self,
            text="Config File:",
            bg=self.BG_COLOR,
            fg=self.FG_COLOR,
        )
        config_label.grid(row=1, column=0, padx=(10, 5), pady=5, sticky="w")

        # Config path entry (read-only, dark theme)
        self.config_var = tk.StringVar(value="No configuration file selected")
        self.config_entry = tk.Entry(
            self,
            textvariable=self.config_var,
            width=60,
            state="readonly",
            bg=self.BG_LIGHTER,
            fg=self.FG_COLOR,
            readonlybackground=self.BG_LIGHTER,
            insertbackground=self.FG_COLOR,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=self.ACCENT_COLOR,
            highlightcolor=self.ACCENT_COLOR,
        )
        self.config_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Browse button (dark theme)
        browse_button = tk.Button(
            self,
            text="Browse...",
            command=self._on_browse,
            width=12,
            bg=self.ACCENT_COLOR,
            fg=self.FG_COLOR,
            activebackground="#4a90d9",
            activeforeground="#ffffff",
            relief=tk.FLAT,
            cursor="hand2",
        )
        browse_button.grid(row=1, column=2, padx=(5, 10), pady=5)

        # Run scan button (initially disabled, dark theme)
        self.run_button = tk.Button(
            self,
            text="Run Scan",
            command=self._on_run_scan,
            width=15,
            state=tk.DISABLED,
            bg=self.ACCENT_COLOR,
            fg=self.FG_COLOR,
            activebackground="#4a90d9",
            activeforeground="#ffffff",
            disabledforeground="#666666",
            relief=tk.FLAT,
            cursor="hand2",
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

            # Pass results to callback (e.g., FindingsView)
            if self.on_scan_complete:
                self.on_scan_complete(result)

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
