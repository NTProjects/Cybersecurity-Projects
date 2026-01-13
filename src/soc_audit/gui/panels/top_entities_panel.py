"""Top entities panel for the SOC dashboard.

This module provides a panel displaying top entities (IPs, users, ports)
in a Splunk ES-style tabbed format.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class TopEntitiesPanel(ttk.LabelFrame):
    """
    Panel displaying top entities with tabbed navigation.

    Shows tabs for Top IPs, Top Users, and Top Ports, each with
    a table showing entity names and counts.

    Attributes:
        notebook: Notebook widget containing entity tabs.
        ip_tree: Treeview for top IPs.
        user_tree: Treeview for top users.
        port_tree: Treeview for top ports.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the top entities panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Top Entities", padding=10)
        self._build_ui()
        self.set_placeholder_data()

    def _build_ui(self) -> None:
        """Build the panel UI components."""
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        # Top IPs tab
        ip_frame = ttk.Frame(self.notebook)
        self.notebook.add(ip_frame, text="Top IPs")
        self.ip_tree = self._create_entity_tree(ip_frame)

        # Top Users tab
        user_frame = ttk.Frame(self.notebook)
        self.notebook.add(user_frame, text="Top Users")
        self.user_tree = self._create_entity_tree(user_frame)

        # Top Ports tab
        port_frame = ttk.Frame(self.notebook)
        self.notebook.add(port_frame, text="Top Ports")
        self.port_tree = self._create_entity_tree(port_frame)

    def _create_entity_tree(self, parent: ttk.Frame) -> ttk.Treeview:
        """
        Create a treeview for displaying entities.

        Args:
            parent: Parent frame for the treeview.

        Returns:
            Configured Treeview widget.
        """
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        columns = ("entity", "count")
        tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")

        tree.heading("entity", text="Entity")
        tree.heading("count", text="Count")

        tree.column("entity", width=150, minwidth=100)
        tree.column("count", width=60, minwidth=40)

        tree.grid(row=0, column=0, sticky="nsew")

        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scrollbar.set)

        return tree

    def set_placeholder_data(self) -> None:
        """Set placeholder entity data for demonstration."""
        self.clear()

        # Top IPs
        ip_data = [
            ("10.0.0.50", "15"),
            ("192.168.1.100", "12"),
            ("172.16.0.25", "8"),
            ("10.0.0.1", "5"),
        ]
        for entity, count in ip_data:
            self.ip_tree.insert("", tk.END, values=(entity, count))

        # Top Users
        user_data = [
            ("admin", "23"),
            ("root", "18"),
            ("service_account", "12"),
            ("backup_user", "7"),
        ]
        for entity, count in user_data:
            self.user_tree.insert("", tk.END, values=(entity, count))

        # Top Ports
        port_data = [
            ("22 (SSH)", "45"),
            ("80 (HTTP)", "38"),
            ("443 (HTTPS)", "32"),
            ("3389 (RDP)", "15"),
        ]
        for entity, count in port_data:
            self.port_tree.insert("", tk.END, values=(entity, count))

    def clear(self) -> None:
        """Clear all entity data from the tables."""
        for tree in [self.ip_tree, self.user_tree, self.port_tree]:
            for item in tree.get_children():
                tree.delete(item)
