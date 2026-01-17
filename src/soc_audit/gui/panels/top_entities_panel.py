"""Top entities panel for the SOC dashboard.

This module provides a panel displaying top entities (IPs, users, ports)
in a Splunk ES-style tabbed format with live aggregation support.
"""
from __future__ import annotations

import re
import tkinter as tk
from collections import defaultdict
from tkinter import ttk
from typing import TYPE_CHECKING, Any

# Note: self.after() is available via Tkinter widget inheritance

if TYPE_CHECKING:
    from soc_audit.core.interfaces import Finding


class TopEntitiesPanel(ttk.LabelFrame):
    """
    Panel displaying top entities with tabbed navigation and live aggregation.

    Shows tabs for Top IPs, Top Users, and Top Ports, each with
    a table showing entity names and counts. Supports incremental
    updates as findings stream in.

    Attributes:
        notebook: Notebook widget containing entity tabs.
        ip_tree: Treeview for top IPs.
        user_tree: Treeview for top users.
        port_tree: Treeview for top ports.
        ip_counts: Counter for IP occurrences.
        user_counts: Counter for user occurrences.
        port_counts: Counter for port occurrences.
    """

    def __init__(self, parent: tk.Widget) -> None:
        """
        Initialize the top entities panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent, text="Top Entities", padding=10)
        
        # Aggregation counters
        self.ip_counts: dict[str, int] = defaultdict(int)
        self.user_counts: dict[str, int] = defaultdict(int)
        self.port_counts: dict[str, int] = defaultdict(int)
        
        # Performance: Throttle entity updates (rebuilds are expensive!)
        self._update_count = 0
        self._refresh_pending = False
        self._refresh_delay_ms = 750  # Performance: Increased to 750ms (was 500ms) to reduce lag
        self._last_counts_snapshot: dict[str, dict[str, int]] = {}  # Cache for change detection
        
        self._build_ui()

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

    def update_from_finding(self, finding: Finding) -> None:
        """
        Update entity counts from a finding's evidence (throttled for performance).

        Extracts IPs, users, and ports from the finding's evidence
        and updates the aggregation counters. UI refresh is throttled.

        Args:
            finding: The Finding object to process.
        """
        evidence = finding.evidence or {}

        # Extract IPs
        self._extract_ips(evidence)

        # Extract users
        self._extract_users(evidence)

        # Extract ports
        self._extract_ports(evidence, finding.title)

        # Performance: Throttle UI refresh (rebuilding trees is expensive!)
        self._update_count += 1
        if not self._refresh_pending:
            self._refresh_pending = True
            # Schedule refresh after delay (batches multiple updates)
            self.after(self._refresh_delay_ms, self._throttled_refresh)

    def increment_entity(self, entity_type: str, entity_name: str) -> None:
        """
        Increment count for a specific entity (throttled for performance).

        Args:
            entity_type: Type of entity ("IPs", "Users", "Ports").
            entity_name: Name/value of the entity.
        """
        if entity_type == "IPs":
            self.ip_counts[entity_name] += 1
        elif entity_type == "Users":
            self.user_counts[entity_name] += 1
        elif entity_type == "Ports":
            self.port_counts[entity_name] += 1
        
        # Performance: Throttle UI refresh (rebuilding trees is expensive!)
        self._update_count += 1
        if not self._refresh_pending:
            self._refresh_pending = True
            # Schedule refresh after delay (batches multiple updates)
            self.after(self._refresh_delay_ms, self._throttled_refresh)

    def _extract_ips(self, evidence: dict[str, Any]) -> None:
        """Extract IP addresses from evidence."""
        # Common evidence field names for IPs
        ip_fields = ["source_ip", "ip", "src_ip", "dest_ip", "remote_ip", "host"]
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        for field in ip_fields:
            if field in evidence:
                value = str(evidence[field])
                # Extract IP from the value
                matches = ip_pattern.findall(value)
                for ip in matches:
                    self.ip_counts[ip] += 1

        # Also check the entire evidence for embedded IPs
        evidence_str = str(evidence)
        for ip in ip_pattern.findall(evidence_str):
            if ip not in ["0.0.0.0", "255.255.255.255"]:
                # Only count if not already counted from specific fields
                pass  # Avoid double counting

    def _extract_users(self, evidence: dict[str, Any]) -> None:
        """Extract usernames from evidence."""
        user_fields = ["username", "user", "account", "login"]

        for field in user_fields:
            if field in evidence:
                user = str(evidence[field])
                if user and user.lower() not in ["none", "unknown", ""]:
                    self.user_counts[user] += 1

    def _extract_ports(self, evidence: dict[str, Any], title: str) -> None:
        """Extract port numbers from evidence and title."""
        port_fields = ["port", "dest_port", "src_port", "service_port"]

        for field in port_fields:
            if field in evidence:
                port = evidence[field]
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
                    port_str = self._format_port(int(port))
                    self.port_counts[port_str] += 1

        # Also try to extract port from title like "Port 22 (SSH)"
        port_match = re.search(r"port\s*(\d+)", title.lower())
        if port_match:
            port_num = int(port_match.group(1))
            port_str = self._format_port(port_num)
            self.port_counts[port_str] += 1

    def _format_port(self, port: int) -> str:
        """Format port number with service name if known."""
        well_known = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        if port in well_known:
            return f"{port} ({well_known[port]})"
        return str(port)

    def _throttled_refresh(self) -> None:
        """Throttled refresh of all trees (called after delay to batch updates)."""
        self._refresh_pending = False
        # Performance: Only refresh trees that actually changed
        self._refresh_all_trees()
        # Update snapshot for change detection
        self._last_counts_snapshot = {
            "ip": dict(self.ip_counts),
            "user": dict(self.user_counts),
            "port": dict(self.port_counts),
        }
    
    def _refresh_all_trees(self) -> None:
        """Refresh all entity trees with current counts."""
        self._refresh_tree(self.ip_tree, self.ip_counts)
        self._refresh_tree(self.user_tree, self.user_counts)
        self._refresh_tree(self.port_tree, self.port_counts)

    def _refresh_tree(self, tree: ttk.Treeview, counts: dict[str, int]) -> None:
        """Refresh a single tree with sorted counts (optimized)."""
        # Performance: Skip update if counts are empty
        if not counts:
            # Just clear the tree
            for item in tree.get_children():
                tree.delete(item)
            return
        
        # Performance: Only refresh if counts changed significantly
        # Get current items
        current_items = {}
        for item in tree.get_children():
            values = tree.item(item, "values")
            if len(values) >= 2:
                current_items[values[0]] = int(values[1]) if values[1].isdigit() else 0
        
        # Check if we need to update (counts changed)
        if current_items == dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:20]):
            return  # No change needed, skip expensive rebuild
        
        # Clear current items
        for item in tree.get_children():
            tree.delete(item)

        # Sort by count descending (cache sorted result)
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        # Insert top items (limit to 20)
        for entity, count in sorted_items[:20]:
            tree.insert("", tk.END, values=(entity, str(count)))

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
        """Clear all entity data from the tables and reset counters."""
        for tree in [self.ip_tree, self.user_tree, self.port_tree]:
            for item in tree.get_children():
                tree.delete(item)
        
        self.ip_counts.clear()
        self.user_counts.clear()
        self.port_counts.clear()
